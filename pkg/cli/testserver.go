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
	"net"

	"github.com/projectcontour/contour-authserver/pkg/auth"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
)

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

			srv, err := DefaultServer(cmd)
			if err != nil {
				return ExitErrorf(EX_CONFIG, "invalid TLS configuration: %s", err)
			}

			auth.RegisterServer(srv, &auth.Testserver{Log: log})

			log.Info("started serving", "address", mustString(cmd.Flags().GetString("address")))
			return auth.RunServer(ctrl.SetupSignalHandler(), listener, srv)
		},
	}

	cmd.Flags().String("address", ":9090", "The address the authentication endpoint binds to.")
	cmd.Flags().String("tls-cert-path", "", "Path to the TLS server certificate.")
	cmd.Flags().String("tls-ca-path", "", "Path to the TLS CA certificate bundle.")
	cmd.Flags().String("tls-key-path", "", "Path to the TLS server key.")

	return &cmd
}
