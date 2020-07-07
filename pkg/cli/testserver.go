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

package cli

import (
	"fmt"
	"net"
	"os"

	"github.com/projectcontour/contour-authserver/pkg/auth"
	"github.com/projectcontour/contour-authserver/pkg/version"
	"google.golang.org/grpc"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/spf13/cobra"
)

func mustString(s string, err error) string {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", version.Progname, err)
		os.Exit(int(EX_CONFIG))
	}

	return s
}

func anyString(values ...string) bool {
	for _, s := range values {
		if s != "" {
			return true
		}
	}

	return false
}

// NewTestserverCommand ...
func NewTestserverCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "testserver [OPTIONS]",
		Short: "Run a testing authentication server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := ctrl.Log.WithName("auth.testserver")

			listener, err := net.Listen("tcp", mustString(cmd.Flags().GetString("address")))
			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			opts := []grpc.ServerOption{
				grpc.MaxConcurrentStreams(1 << 20),
			}

			if anyString(
				mustString(cmd.Flags().GetString("tls-cert-path")),
				mustString(cmd.Flags().GetString("tls-key-path")),
				mustString(cmd.Flags().GetString("tls-ca-path")),
			) {
				creds, err := auth.NewServerCredentials(
					mustString(cmd.Flags().GetString("tls-cert-path")),
					mustString(cmd.Flags().GetString("tls-key-path")),
					mustString(cmd.Flags().GetString("tls-ca-path")),
				)
				if err != nil {
					return ExitErrorf(EX_CONFIG, "invalid TLS configuration: %s", err)
				}

				opts = append(opts, grpc.Creds(creds))
			}

			srv := grpc.NewServer(opts...)
			auth.RegisterServer(srv, &auth.Htpasswd{Log: log})

			log.Info("started serving", "address", mustString(cmd.Flags().GetString("address")))
			return auth.RunServer(listener, srv, ctrl.SetupSignalHandler())
		},
	}

	cmd.Flags().String("address", ":9090", "The address the authentication endpoint binds to.")
	cmd.Flags().String("tls-cert-path", "", "Path to the TLS server certificate.")
	cmd.Flags().String("tls-ca-path", "", "Path to the TLS CA certificate bundle.")
	cmd.Flags().String("tls-key-path", "", "Path to the TLS server key.")

	return &cmd
}
