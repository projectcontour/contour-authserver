# contour-authserver

`contour-authserver` implements the Envoy [external authorization][4]
GRPC protocol (both v2 and v3). It can be used for testing Envoy
external authorization. `contour-authserver` has two authorization
backends that are selected by subcommands.

# testserver

Usage:

```
Run a testing authentication server

Usage:
  contour-authserver testserver [OPTIONS]

Flags:
      --address string         The address the authentication endpoint binds to. (default ":9090")
  -h, --help                   help for testserver
      --tls-ca-path string     Path to the TLS CA certificate bundle.
      --tls-cert-path string   Path to the TLS server certificate.
      --tls-key-path string    Path to the TLS server key.
```

`testserver` will authorize any path that contains the string
`allow`, and will reject other requests with a 401 status code.

# htpasswd

Usage:

```
Run a htpasswd basic authentication server

Usage:
  contour-authserver htpasswd [OPTIONS]

Flags:
      --address string             The address the authentication endpoint binds to. (default ":9090")
      --auth-realm string          Basic authentication realm. (default "default")
  -h, --help                       help for htpasswd
      --metrics-address string     The address the metrics endpoint binds to. (default ":8080")
      --tls-ca-path string         Path to the TLS CA certificate bundle.
      --tls-cert-path string       Path to the TLS server certificate.
      --tls-key-path string        Path to the TLS server key.
      --watch-namespaces strings   The list of namespaces to watch for Secrets.
```

## htpasswd Secrets

The `htpasswd` backend implements [HTTP basic authentication][3]
against a set of Secrets that contain [htpasswd][1] formatted data.
The htpasswd data must be stored in the `data` key, which is compatible
with ingress-nginx [`auth-file` Secrets][2].

The `htpasswd` backend only accesses Secrets that are
labeled with `projectcontour.io/auth-type: basic`. If the
only be used if its value matches the value of the `--auth-realm` flag.
The label `projectcontour.io/auth-realm: *` can be used to specify that a
Secret can be used for all realms.

When it authenticates a request, the `htpassd` backend injects the
`Auth-Username` and  `Auth-Realm` headers, which contain the
authenticated user name basic authentication nd realm.

# Request Headers

Both authorization backends emit the `Auth-Handler` header, which
publishes the name of the backend that approved or rejected the
authorization.

The authorization context is also reflected into HTTP headers
prefixed with `Auth-Context-`. Note that This can generate malformed
HTTP headers. The `testserver` backend always creates the context
headers, but the `htpasswd` backend only does so for authenticated
requests (i.e. the origin server gets them bu the client never
does.)

# Deploying `contour-authserver`

The recommended way to deploe `contour-authserver` is to use the Kustomize
[deployment YAML](./config/default). This sill deploy services for both
the `testserver` and `htpasswd` backends. For developer deployments,
[Skaffold](https://skaffold.dev/) seems to work reasonably well.

There are no versioned releases or container images yet.

[1]: https://httpd.apache.org/docs/current/programs/htpasswd.html
[2]: https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#authentication
[3]: https://tools.ietf.org/html/rfc7617
[4]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter
