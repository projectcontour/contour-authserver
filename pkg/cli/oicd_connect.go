package cli

import (
	"net"
	"net/http"
	"time"

	"github.com/projectcontour/contour-authserver/pkg/auth"
	"github.com/projectcontour/contour-authserver/pkg/config"
	"github.com/spf13/cobra"

	"github.com/allegro/bigcache"

	ctrl "sigs.k8s.io/controller-runtime"
)

//NewOIDCConnect - start server as OIDC and take in 'config' file as parameter...
func NewOIDCConnect() *cobra.Command {
	cmd := cobra.Command{
		Use:   "oidc Server [OPTIONS]",
		Short: "Run a OIDC authentication server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := ctrl.Log.WithName("auth.oidcConnect")

			cfgFile, err := cmd.Flags().GetString("config")
			cfg, err := config.NewConfig(cfgFile)

			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			if cfg == nil {
				log.Info("config is empty ")
			}

			log.Info("init oidc... ")

			// default hardcode timeout value to 40 mins...
			bigCache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(40 * time.Minute))

			authOidc := &auth.OIDCConnect{
				Log:        log,
				OidcConfig: cfg,
				Cache:      bigCache,
				HTTPClient: http.DefaultClient, // need to handle client creation with TLS
			}

			listener, err := net.Listen("tcp", authOidc.OidcConfig.Address)
			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			srv, err := DefaultServer(cmd)
			if err != nil {
				return ExitErrorf(EX_CONFIG, "invalid TLS configuration: %s", err)
			}

			auth.RegisterServer(srv, authOidc)

			log.Info("started serving", "address", authOidc.OidcConfig.Address)
			return auth.RunServer(listener, srv, ctrl.SetupSignalHandler())
		},
	}

	cmd.Flags().String("config", "", "Path to config file ( Yaml format ).")
	cmd.Flags().String("tls-cert-path", "", "Path to the TLS server certificate.")
	cmd.Flags().String("tls-ca-path", "", "Path to the TLS CA certificate bundle.")
	cmd.Flags().String("tls-key-path", "", "Path to the TLS server key.")
	return &cmd
}
