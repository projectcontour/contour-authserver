package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/projectcontour/contour-authserver/pkg/cli"
	"github.com/projectcontour/contour-authserver/pkg/version"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func main() {
	ctrl.SetLogger(zap.New(
		zap.UseDevMode(isatty.IsTerminal(os.Stdout.Fd())),
	))

	root := cli.Defaults(&cobra.Command{
		Use:     version.Progname,
		Short:   "Authentication server for the Envoy proxy",
		Version: fmt.Sprintf("%s/%s, built %s", version.Version, version.Sha, version.BuildDate),
	})

	root.AddCommand(cli.Defaults(cli.NewTestserverCommand()))
	root.AddCommand(cli.Defaults(cli.NewHtpasswdCommand()))

	if err := root.Execute(); err != nil {
		if msg := err.Error(); msg != "" {
			fmt.Fprintf(os.Stderr, "%s: %s\n", version.Progname, msg)
		}

		var exit *cli.ExitError
		if errors.As(err, &exit) {
			os.Exit(int(exit.Code))
		}

		os.Exit(int(cli.EX_FAIL))
	}
}
