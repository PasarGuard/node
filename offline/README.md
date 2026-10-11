# offline/

Holds the vendored module trees `Dockerfile.singbox` uses when you need to
build with **no module proxy at all**. Produced by `../make-offline-vendor.sh`
on a networked machine; never committed (see `../.gitignore`).

| file | contents |
|---|---|
| `node-vendor.tar.gz` | `go mod vendor` of this module |
| `singbox-vendor.tar.gz` | `go mod vendor` of the pinned sing-box tree, quota patch applied |

Both are optional. Absent, `Dockerfile.singbox` behaves exactly as it always
has: `go mod download` + whatever `GOPROXY` names. Present, it extracts them
and builds with `-mod=vendor`, which makes Go ignore the proxy entirely.

Prove a build really was offline with `--build-arg GOPROXY=off`: with the
network path disabled, any module that was not vendored fails the build.
