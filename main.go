package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	quic "github.com/quic-go/quic-go"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"quic-bench/trace"
	"strings"
	"sync"
	"time"
)

const dataSize = 500_000

func main() {
	var listenAddr string
	flag.StringVar(&listenAddr, "listen", "0.0.0.0:4242", "Address to listen on")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-listen address] [peer1:port1] [peer2:port2] ...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	externalIP, err := getExternalIP()
	if err != nil {
		log.Fatal(err)
	}
	peers := filterOutHostIP(flag.Args(), externalIP)

	tlsConfig, err := generateTLSConfig()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	tracer, err := trace.NewLocalTracer(ctx)
	if err != nil {
		log.Fatal(err)
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     10_000_000_000,
		MaxStreamReceiveWindow:         10_000_000_000,
		InitialConnectionReceiveWindow: 10_000_000_000,
		MaxConnectionReceiveWindow:     10_000_000_000,
		MaxIncomingStreams:             1000000000,
		MaxIncomingUniStreams:          1000000000,
		MaxIdleTimeout:                 time.Hour,
		KeepAlivePeriod:                1 * time.Second,
		EnableDatagrams:                true,
	}

	var wg sync.WaitGroup

	// Start server in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := startServer(ctx, tracer, listenAddr, tlsConfig, quicConfig)
		if err != nil {
			log.Fatal(err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(1 * time.Second)

	// Start clients to connect to peers
	for _, addr := range peers {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			err := startClient(ctx, addr, quicConfig, tracer)
			if err != nil {
				log.Printf("Error connecting to %s: %v", addr, err)
			}
		}(addr)
	}

	wg.Wait()
}

// getExternalIP fetches the host's external IP address
func getExternalIP() (string, error) {
	// Make an HTTP GET request to an external service
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body, which contains the IP address
	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Convert bytes to string and trim any whitespace
	ip := strings.TrimSpace(string(ipBytes))
	return ip, nil
}

// filterOutHostIP filters out entries from the list that match the host's IP
func filterOutHostIP(ipList []string, hostIP string) []string {
	filtered := []string{}
	for _, entry := range ipList {
		// Split the IP:PORT string
		ipPort := strings.Split(entry, ":")
		if len(ipPort) != 2 {
			// Skip invalid entries
			continue
		}
		ip := ipPort[0]

		// Compare with host's IP
		if ip != hostIP {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func generateTLSConfig() (*tls.Config, error) {
	// Generate a self-signed certificate for TLS
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"QUIC Benchmark"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-benchmark"},
	}
	return tlsConfig, nil
}

func startServer(ctx context.Context, tracer *trace.LocalTracer, listenAddr string, tlsConfig *tls.Config, quicConfig *quic.Config) error {
	listener, err := quic.ListenAddr(listenAddr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}
	log.Printf("Server listening on %s", listenAddr)

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go handleSession(ctx, tracer, sess)
	}
}

func handleSession(ctx context.Context, tracer *trace.LocalTracer, sess quic.Connection) {
	defer sess.CloseWithError(0, "")

	// Open a stream to send data to the peer
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		log.Println("Failed to open stream:", err)
		return
	}
	go func() {
		defer stream.Close()
		log.Printf("Sending data to %s", sess.RemoteAddr())
		for {
			err = sendData(stream)
			if err != nil {
				log.Println("Error sending data:", err)
				break
			}
			trace.WriteTimedSentBytes(tracer, "peer", sess.RemoteAddr().String(), 0x01, dataSize, time.Now())
		}
	}()

	// Accept incoming streams from the peer
	for {
		incomingStream, err := sess.AcceptStream(ctx)
		if err != nil {
			log.Println("Failed to accept stream:", err)
			return
		}
		go handleStream(incomingStream, sess.RemoteAddr().String(), tracer)
	}
}

func handleStream(stream quic.Stream, addr string, tracer *trace.LocalTracer) {
	defer stream.Close()

	log.Printf("Received stream %d", stream.StreamID())

	// Read data from the stream
	for {
		buf := make([]byte, dataSize)
		_, err := stream.Read(buf)
		if err != nil {
			return
		}
		trace.WriteTimedReceivedBytes(tracer, "peer", addr, 0x01, dataSize, time.Now())
	}
}

func startClient(ctx context.Context, addr string, quicConfig *quic.Config, tracer *trace.LocalTracer) error {
	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-benchmark"},
	}

	session, err := quic.DialAddr(ctx, addr, tlsClientConfig, quicConfig)
	if err != nil {
		return err
	}
	defer session.CloseWithError(0, "")

	// Open a stream to send data
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	go func() {
		defer stream.Close()
		log.Printf("Sending data to %s", addr)
		for {
			err = sendData(stream)
			if err != nil {
				log.Println("Error sending data:", err)
				break
			}
			trace.WriteTimedSentBytes(tracer, "peer", session.RemoteAddr().String(), 0x01, dataSize, time.Now())
		}
	}()

	// Accept incoming streams from the server
	for {
		incomingStream, err := session.AcceptStream(ctx)
		if err != nil {
			log.Println("Failed to accept stream:", err)
			return err
		}
		go handleStream(incomingStream, session.RemoteAddr().String(), tracer)
	}
}

func sendData(stream quic.Stream) error {
	data := make([]byte, dataSize)
	_, err := rand.Read(data)
	if err != nil {
		return err
	}
	n, err := stream.Write(data)
	if err != nil {
		return err
	}
	if n < dataSize {
		return errors.New("short write")
	}
	return nil
}
