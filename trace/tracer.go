package trace

// Entry is an interface for all structs that are used to define the schema for
// traces.
type Entry interface {
	// Table defines which table the struct belongs to.
	Table() string
}
