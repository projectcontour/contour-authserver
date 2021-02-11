// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	root.AddCommand(cli.Defaults(cli.NewOIDCConnect()))

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
