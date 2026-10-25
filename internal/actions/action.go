package actions

// Action defines a single operation that works in both CLI and TUI modes.
type Action struct {
	ID          string
	Name        string
	Description string
	Category    string
	Inputs      []InputField
	Handler     Handler
	Hidden      bool // hide from TUI menu
}

// Handler executes an action with the given context.
type Handler func(ctx *Context) error

// Context carries everything an action handler needs.
type Context struct {
	Args   map[string]string
	Output OutputWriter
	Config interface{} // *config.Config, set by caller to avoid import cycle
}

// GetArg returns a context argument or empty string.
func (c *Context) GetArg(key string) string {
	if c.Args == nil {
		return ""
	}
	return c.Args[key]
}

// InputField describes a single input parameter for an action.
type InputField struct {
	Key         string
	Label       string
	Required    bool
	Default     string
	Options     []SelectOption // if non-empty, present as select
	Validate    func(string) error
	DependsOn       string   // only show if this key has a value
	DependsOnValues []string // if set, only show when DependsOn value is one of these
	Description string
	CLIOnly     bool // register as CLI flag but skip interactive prompt
	Bool        bool // CLI flag without a value (--key); its arg is "true" when given
}

// SelectOption is a choice in a select input.
type SelectOption struct {
	Value string
	Label string
}
