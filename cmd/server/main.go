package main

import (
	"flag"
	"os"

	"github.com/devhatro/zero-trust-proxy/internal/logger"
	"github.com/devhatro/zero-trust-proxy/internal/server"
)

var (
	configFile = flag.String("config", "/config/server.yaml", "Configuration file path")
	listenAddr = flag.String("listen", "", "Server listen address (overrides config file)")
	apiAddr    = flag.String("api", "", "API server listen address (overrides config file)")
	certFile   = flag.String("cert", "", "Certificate file (overrides config file)")
	keyFile    = flag.String("key", "", "Key file (overrides config file)")
	caFile     = flag.String("ca", "", "CA certificate file (overrides config file)")
	logLevel   = flag.String("log-level", "", "Log level (DEBUG, INFO, WARN, ERROR, FATAL) (overrides config file)")
)

func main() {
	flag.Parse()

	logger.Info("🚀 0Trust Server Starting...")
	logger.Info("🔧 Loading configuration from: %s", *configFile)

	// Load configuration from file
	config, err := server.LoadServerConfig(*configFile)
	if err != nil {
		logger.Error("❌ Failed to load configuration: %v", err)
		os.Exit(1)
	}

	// Override config with command line arguments if provided
	if *listenAddr != "" {
		config.Server.ListenAddr = *listenAddr
	}
	if *apiAddr != "" {
		config.API.ListenAddr = *apiAddr
	}
	if *certFile != "" {
		config.Server.CertFile = *certFile
	}
	if *keyFile != "" {
		config.Server.KeyFile = *keyFile
	}
	if *caFile != "" {
		config.Server.CAFile = *caFile
	}
	if *logLevel != "" {
		config.LogLevel = *logLevel
	}

	// Set log level from config or environment variable
	level := config.LogLevel
	if level == "" {
		level = os.Getenv("LOG_LEVEL")
	}
	if level == "" {
		level = "INFO"
	}
	logger.SetLogLevel(level)

	logger.Info("🔧 Configuration: Listen=%s, API=%s, LogLevel=%s", config.Server.ListenAddr, config.API.ListenAddr, level)

	// Validate required configuration
	if config.Server.CertFile == "" || config.Server.KeyFile == "" || config.Server.CAFile == "" {
		logger.Error("❌ Missing required certificate files in configuration")
		os.Exit(1)
	}

	logger.Debug("🔐 Certificate files: cert=%s, key=%s, ca=%s", config.Server.CertFile, config.Server.KeyFile, config.Server.CAFile)

	// Create and start server with configuration
	s := server.NewServerWithConfig(config)
	logger.Info("🌐 Starting server on %s (API on %s)", config.Server.ListenAddr, config.API.ListenAddr)
	if err := s.Start(); err != nil {
		logger.Error("💥 Server error: %v", err)
		os.Exit(1)
	}

	// Keep the program running
	logger.Info("✅ Server is running and ready to accept connections")
	select {}
}
