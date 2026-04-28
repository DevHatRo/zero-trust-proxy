// Command zero-trust-proxy is the custom server entrypoint that
// replaces the legacy custom-Caddy binary. It owns TLS termination,
// HTTP routing, and the agent mTLS control plane.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/devhatro/zero-trust-proxy/internal/server"
	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// Populated by -ldflags "-X main.Version=... -X main.BuildTime=..." in
// scripts/build.sh.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

const usage = `zero-trust-proxy — custom HTTP/HTTPS proxy with mTLS agent control plane.

Usage:
  zero-trust-proxy run      --config <path> [--http :addr] [--https :addr]
  zero-trust-proxy validate --config <path>
  zero-trust-proxy version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(runCmd(os.Args[2:]))
	case "validate":
		os.Exit(validateCmd(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Fprintf(os.Stdout, "zero-trust-proxy %s (built %s)\n", Version, BuildTime)
		os.Exit(0)
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "config/server.yaml", "path to YAML config")
	httpOverride := fs.String("http", "", "override listen.http")
	httpsOverride := fs.String("https", "", "override listen.https")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	fmt.Fprintf(os.Stderr, "zero-trust-proxy %s (built %s)\n", Version, BuildTime)
	server.BuildVersion = Version

	if *httpOverride == "" && *httpsOverride == "" {
		if err := server.Run(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "run: %v\n", err)
			return 1
		}
		return 0
	}

	cfg, err := serverconfig.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}
	if *httpOverride != "" {
		cfg.Listen.HTTP = *httpOverride
	}
	if *httpsOverride != "" {
		cfg.Listen.HTTPS = *httpsOverride
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config invalid after overrides: %v\n", err)
		return 1
	}
	if err := server.RunWithConfig(cfg, *cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	return 0
}

func validateCmd(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "config/server.yaml", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if _, err := serverconfig.Load(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "invalid: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "config %s OK\n", *cfgPath)
	return 0
}
