package main

import (
	"fmt"
	"os"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/devhatro/zero-trust-proxy/modules/ztagents"
	_ "github.com/devhatro/zero-trust-proxy/modules/ztrouter"
)

// Populated by -ldflags "-X main.Version=... -X main.BuildTime=..." in scripts/build.sh.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	fmt.Fprintf(os.Stderr, "zero-trust-proxy %s (built %s)\n", Version, BuildTime)
	caddycmd.Main()
}
