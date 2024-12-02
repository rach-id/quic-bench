package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	quic "github.com/quic-go/quic-go"
	rand2 "golang.org/x/exp/rand"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"quic-bench/trace"
	"strings"
	"sync"
	"time"
)

const (
	dataSize        = 500_000
	numberOfStreams = 4
	listenPort      = "4242"
	maxValidators   = 10
)

type Validator struct {
	Name           string `json:"name"`
	IP             string `json:"ip"`
	NetworkAddress string `json:"network_address"`
	Region         string `json:"region"`
}

func main() {
	_, err := rand.Read(data)
	if err != nil {
		log.Fatal(err)
	}

	var listenAddr string
	var peersFile string
	flag.StringVar(&listenAddr, "listen", "0.0.0.0:4242", "Address to listen on")
	flag.StringVar(&peersFile, "peersFile", "peers.json", "Path to the peers JSON file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-listen address] [-peersFile path] [peer1:port1] [peer2:port2] ...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Determine peers to connect to
	var peers []string
	if len(flag.Args()) > 0 {
		// Use peers specified as command-line arguments
		peers = flag.Args()
	} else {
		// Read peers from the JSON file
		var err error
		peers, err = readPeersFromFile(peersFile)
		if err != nil {
			log.Fatalf("Error reading peers from file: %v", err)
		}
	}

	externalIP, err := getExternalIP()
	if err != nil {
		log.Fatal(err)
	}
	peers = filterOutHostIP(peers, externalIP)

	fmt.Printf("connecting to %d peers\n", len(peers))
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

func readPeersFromFile(filename string) ([]string, error) {
	fileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var validatorsMap map[string]Validator
	err = json.Unmarshal(fileBytes, &validatorsMap)
	if err != nil {
		return nil, err
	}

	// Convert map to slice
	validators := make([]Validator, 0, len(validatorsMap))
	for _, v := range validatorsMap {
		validators = append(validators, v)
	}

	// Seed the random number generator
	rand2.Seed(uint64(time.Now().UnixNano()))

	// Shuffle the validators slice
	rand2.Shuffle(len(validators), func(i, j int) {
		validators[i], validators[j] = validators[j], validators[i]
	})

	// Select up to maxPeers validators
	if len(validators) > maxValidators {
		validators = validators[:maxValidators]
	}

	var peers []string
	for _, v := range validators {
		// Use default port for all connections
		peerAddr := fmt.Sprintf("%s:%s", v.IP, listenPort)
		peers = append(peers, peerAddr)
	}
	return peers, nil
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
		} else {
			fmt.Printf("Filtered out self IP: %s\n", ip)
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
		sess, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		go handleSession(ctx, tracer, sess)
	}
}

func handleSession(ctx context.Context, tracer *trace.LocalTracer, sess quic.Connection) {
	defer sess.CloseWithError(0, "")

	// Open multiple streams to send data to the peer
	for i := 0; i < numberOfStreams; i++ {
		stream, err := sess.OpenStreamSync(ctx)
		if err != nil {
			log.Println("Failed to open stream:", err)
			return
		}
		go func(s quic.Stream) {
			defer s.Close()
			log.Printf("Sending data to %s", sess.RemoteAddr())
			for {
				err = sendData(s)
				if err != nil {
					log.Println("Error sending data:", err)
					continue
				}
				trace.WriteTimedSentBytes(tracer, sess.RemoteAddr().String(), sess.RemoteAddr().String(), 0x01, dataSize, time.Now())
			}
		}(stream)
	}

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

	log.Printf("Received stream %d from %s", stream.StreamID(), addr)

	count := 0
	// Read data from the stream
	for {
		buf := make([]byte, dataSize)
		n, err := stream.Read(buf)
		if err != nil {
			log.Println("Error reading from stream:", err)
			continue
		}
		if count > 500_000 {
			trace.WriteTimedReceivedBytes(tracer, addr, addr, 0x01, count, time.Now())
			count = 0
		} else {
			count += n
		}
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

	// Open multiple streams to send data
	for i := 0; i < numberOfStreams; i++ {
		stream, err := session.OpenStreamSync(ctx)
		if err != nil {
			log.Println("Failed to open stream:", err)
			return err
		}
		go func(s quic.Stream) {
			defer s.Close()
			log.Printf("Sending data to %s", addr)
			for {
				err = sendData(s)
				if err != nil {
					log.Println("Error sending data:", err)
					break
				}
				trace.WriteTimedSentBytes(tracer, addr, session.RemoteAddr().String(), 0x01, dataSize, time.Now())
			}
		}(stream)
	}

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

var data = make([]byte, dataSize)

func sendData(stream quic.Stream) error {
	n, err := stream.Write(data)
	if err != nil {
		return err
	}
	if n < dataSize {
		return errors.New("short write")
	}
	return nil
}
