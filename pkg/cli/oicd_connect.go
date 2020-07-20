package cli

import (
	"net"
	"net/http"
	"time"

	"github.com/projectcontour/contour-authserver/pkg/auth"
	"github.com/projectcontour/contour-authserver/pkg/config"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/allegro/bigcache"

	ctrl "sigs.k8s.io/controller-runtime"
)

//NewOidcConnect - start server as OIDC and take in 'config' file as parameter...
func NewOidcConnect() *cobra.Command {
	cmd := cobra.Command{
		Use:   "oidc Server [OPTIONS]",
		Short: "Run a OIDC authentication server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := ctrl.Log.WithName("auth.oidcConnect")

			cfgFile, err := cmd.Flags().GetString("config")
			cfg, err := config.NewConfig(cfgFile)
			if cfg == nil {
				log.Info("config is empty ")
			}

			// default hardcode timeout value to 40 mins...
			bigCache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(40 * time.Minute))

			authOidc := &auth.OidcConnect{
				Log:        log,
				OidcConfig: cfg,
				Cache:      bigCache,
				HTTPClient: http.DefaultClient, // need to handle client creation with TLS
			}

			listener, err := net.Listen("tcp", authOidc.OidcConfig.Address)
			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			opts := []grpc.ServerOption{
				grpc.MaxConcurrentStreams(1 << 20),
			}

			if anyString(cfg.GrpcTLSCertPath, cfg.GrpcTLSKeyPath, cfg.GrpcTLSCAPath) {

				creds, err := auth.NewServerCredentials(cfg.GrpcTLSCertPath, cfg.GrpcTLSKeyPath, cfg.GrpcTLSCAPath)
				if err != nil {
					return ExitErrorf(EX_CONFIG, "invalid TLS configuration: %s", err)
				}

				opts = append(opts, grpc.Creds(creds))
			}

			srv := grpc.NewServer(opts...)
			auth.RegisterServer(srv, authOidc)

			log.Info("started serving", "address", authOidc.OidcConfig.Address)
			return auth.RunServer(listener, srv, ctrl.SetupSignalHandler())
		},
	}

	cmd.Flags().String("config", "", "The config file to use.")
	return &cmd
}
