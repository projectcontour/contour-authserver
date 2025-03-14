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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrl_cache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrl_metrics_server "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// NewHttokenCommand ...
func NewHttokenCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "static-token [OPTIONS]",
		Short: "Run a static token authentication server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := ctrl.Log.WithName("auth.httoken")
			s := runtime.NewScheme()

			scheme.AddToScheme(s) //nolint:gosec,errcheck

			log.Info("debug version cli.httoken.go")

			options := ctrl.Options{
				Scheme: s,
				Metrics: ctrl_metrics_server.Options{
					BindAddress: mustString(cmd.Flags().GetString("metrics-address")),
				},
			}

			if namespaces, err := cmd.Flags().GetStringSlice("watch-namespaces"); err == nil && len(namespaces) > 0 {
				// Maps namespaces to cache configs. We will set an empty config
				// so the higher level defaults are used.
				options.Cache.DefaultNamespaces = make(map[string]ctrl_cache.Config)
				for _, ns := range namespaces {
					options.Cache.DefaultNamespaces[ns] = ctrl_cache.Config{}
				}
			}

			mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
			if err != nil {
				return ExitErrorf(EX_CONFIG, "failed to create controller manager: %s", err)
			}

			tokens, _ := cmd.Flags().GetStringSlice("token")
			httoken := &auth.Httoken{
				Log:         log,
				StaticToken: tokens,
			}

			listener, err := net.Listen("tcp", mustString(cmd.Flags().GetString("address")))
			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			srv, err := DefaultServer(cmd)
			if err != nil {
				return ExitErrorf(EX_CONFIG, "invalid TLS configuration: %s", err)
			}

			auth.RegisterServer(srv, httoken)

			errChan := make(chan error)
			ctx := ctrl.SetupSignalHandler()

			go func() {
				log.Info("started authorization server",
					"address", mustString(cmd.Flags().GetString("address")))

				if err := auth.RunServer(ctx, listener, srv); err != nil {
					errChan <- ExitErrorf(EX_FAIL, "authorization server failed: %w", err)
				}

				errChan <- nil
			}()

			go func() {
				log.Info("started controller")

				if err := mgr.Start(ctx); err != nil {
					errChan <- ExitErrorf(EX_FAIL, "controller manager failed: %w", err)
				}

				errChan <- nil
			}()

			select {
			case err := <-errChan:
				return err
			case <-ctx.Done():
				return nil
			}
		},
	}

	// Controller flags.
	cmd.Flags().String("metrics-address", ":8080", "The address the metrics endpoint binds to.")
	cmd.Flags().StringSlice("watch-namespaces", []string{}, "The list of namespaces to watch for Secrets.")
	cmd.Flags().String("selector", "", "Selector (label-query) to filter Secrets, supports '=', '==', and '!='.")

	// GRPC flags.
	cmd.Flags().String("address", ":9090", "The address the authentication endpoint binds to.")
	cmd.Flags().String("tls-cert-path", "", "Path to the TLS server certificate.")
	cmd.Flags().String("tls-ca-path", "", "Path to the TLS CA certificate bundle.")
	cmd.Flags().String("tls-key-path", "", "Path to the TLS server key.")
	cmd.Flags().StringSlice("token", []string{}, "The token to use for authentication.")

	// Authorization flags.
	cmd.Flags().String("auth-realm", "default", "Basic authentication realm.")

	return &cmd
}
