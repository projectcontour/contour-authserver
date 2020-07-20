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
      --selector string            Selector (label-query) to filter Secrets, supports '=', '==', and '!='.
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
annotated with `projectcontour.io/auth-type: basic`.

Secrets that are annotated with the `projectcontour.io/auth-realm`
will only be used if the annotation value matches the value of the
`--auth-realm` flag.
The `projectcontour.io/auth-realm: *` annotation explicitly marks
a Secret as being valid for all realms.
This is equivalent to omitting the annotation.

When it authenticates a request, the `htpasswd` backend injects the
`Auth-Username` and  `Auth-Realm` headers, which contain the
authenticated user name and the basic authentication realm respectively.

The `--watch-namespaces` flag specifies the namespaces where the
`htpasswd` backend will discover Secrets.
If this flag is empty, Secrets from all namespaces will be used.

The `--selector` flag accepts a [label selector][5] that can be
used to further restrict which Secrets the `htpasswd` backend will consume.

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

The recommended way to deploy `contour-authserver` is to use the Kustomize
[deployment YAML](./config/default). This will deploy services for both
the `testserver` and `htpasswd` backends. For developer deployments,
[Skaffold](https://skaffold.dev/) seems to work reasonably well.

There are no versioned releases or container images yet.

# Releasing `contour-authserver`

Maintainers who need to release a new version of `contour-authserver`
can follow the following steps:

```bash
# Ensure that you have a Github token either in $GITHUB_TOKEN or in ~/.config/goreleaser/github_token.
# Ensure that goreleaser is installed.

# Tag the release.
$ ./hack/make-release-tag.sh $OLDVERS $NEWVERS

# Push the release tag to Github.
$ git push origin $NEWVERS

# Build and release binaries and Docker images.
$ make release

# Log in with the Contour build account to push the images.
$ docker login -u projectcontourbuilder
$ docker push projectcontour/contour-authserver:$NEWVERS
$ docker push projectcontour/contour-authserver:latest

# Log out of the Contour build account.
$ docker logout
```

[1]: https://httpd.apache.org/docs/current/programs/htpasswd.html
[2]: https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#authentication
[3]: https://tools.ietf.org/html/rfc7617
[4]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter
[5]: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
