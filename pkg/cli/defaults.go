package cli

import "github.com/spf13/cobra"

// Defaults applies default settings to a cobra.Command to improve the help output.
func Defaults(c *cobra.Command) *cobra.Command {
	c.SilenceUsage = true
	c.SilenceErrors = true
	c.DisableFlagsInUseLine = true

	return c
}
