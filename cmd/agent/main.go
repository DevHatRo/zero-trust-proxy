package main

import (
	"flag"
	"os"

	"github.com/devhatro/zero-trust-proxy/internal/agent"
	"github.com/devhatro/zero-trust-proxy/internal/common"
	"github.com/devhatro/zero-trust-proxy/internal/logger"
)

var (
	configFile = flag.String("config", "/config/agent.yaml", "Configuration file path")
	id         = flag.String("id", "", "Agent ID (overrides config file)")
	serverAddr = flag.String("server", "", "Server address (overrides config file)")
	certFile   = flag.String("cert", "", "Certificate file (overrides config file)")
	keyFile    = flag.String("key", "", "Key file (overrides config file)")
	caFile     = flag.String("ca", "", "CA certificate file (overrides config file)")
	logLevel   = flag.String("log-level", "", "Log level (DEBUG, INFO, WARN, ERROR, FATAL) (overrides config file)")
)

func main() {
	flag.Parse()

	logger.Info("🤖 0Trust Agent Starting...")
	logger.Info("🔧 Loading configuration from: %s", *configFile)

	// Debug: Check environment variables that might be interfering
	envVars := []string{"SERVER_ADDR", "AGENT_ID", "CERT_FILE", "KEY_FILE", "CA_FILE", "LOG_LEVEL", "CONFIG_FILE"}
	logger.Debug("🔍 Environment variables:")
	for _, env := range envVars {
		if value := os.Getenv(env); value != "" {
			logger.Debug("  📋 %s=%s", env, value)
		}
	}

	// Load configuration from file
	config, err := agent.LoadConfig(*configFile)
	if err != nil {
		logger.Error("❌ Failed to load configuration: %v", err)
		os.Exit(1)
	}

	// Debug: Show loaded config values
	logger.Debug("🔍 Loaded from config file - ID=%s, Server=%s", config.Agent.ID, config.Server.Address)

	// Debug: Show command line flag values
	logger.Debug("🔍 Command line flags - id=%s, server=%s, config=%s", *id, *serverAddr, *configFile)

	// Override config with command line arguments if provided
	if *id != "" {
		logger.Debug("🔄 Overriding agent ID from flag: %s -> %s", config.Agent.ID, *id)
		config.Agent.ID = *id
	}
	if *serverAddr != "" {
		logger.Debug("🔄 Overriding server address from flag: %s -> %s", config.Server.Address, *serverAddr)
		config.Server.Address = *serverAddr
	}
	if *certFile != "" {
		logger.Debug("🔄 Overriding cert file from flag: %s -> %s", config.Server.Cert, *certFile)
		config.Server.Cert = *certFile
	}
	if *keyFile != "" {
		logger.Debug("🔄 Overriding key file from flag: %s -> %s", config.Server.Key, *keyFile)
		config.Server.Key = *keyFile
	}
	if *caFile != "" {
		logger.Debug("🔄 Overriding CA file from flag: %s -> %s", config.Server.CACert, *caFile)
		config.Server.CACert = *caFile
	}
	if *logLevel != "" {
		logger.Debug("🔄 Overriding log level from flag: %s -> %s", config.LogLevel, *logLevel)
		config.LogLevel = *logLevel
	}

	// Set log level from config or environment variable (only if not set in config)
	level := config.LogLevel
	if level == "" {
		level = os.Getenv("LOG_LEVEL")
		if level != "" {
			logger.Debug("🔄 Using LOG_LEVEL environment variable: %s", level)
		}
	}
	if level == "" {
		level = "INFO"
	}
	logger.SetLogLevel(level)

	// Debug: Show final config values
	logger.Debug("🎯 Final configuration - ID=%s, Server=%s", config.Agent.ID, config.Server.Address)

	logger.Info("🔧 Configuration: ID=%s, Server=%s, LogLevel=%s", config.Agent.ID, config.Server.Address, level)

	// Validate required configuration
	if config.Agent.ID == "" {
		logger.Error("❌ Agent ID is required (set in config file or use -id flag)")
		os.Exit(1)
	}
	if config.Server.Address == "" {
		logger.Error("❌ Server address is required (set in config file or use -server flag)")
		os.Exit(1)
	}

	logger.Debug("🔐 Certificate files: cert=%s, key=%s, ca=%s", config.Server.Cert, config.Server.Key, config.Server.CACert)

	// Load TLS configuration
	tlsConfig, err := common.LoadTLSConfig(config.Server.Cert, config.Server.Key, config.Server.CACert)
	if err != nil {
		logger.Error("❌ Failed to load TLS configuration: %v", err)
		os.Exit(1)
	}

	logger.Debug("🔒 TLS configuration loaded successfully")

	// Create agent with configuration (configPath is now stored in config.ConfigPath)
	a := agent.NewAgentWithConfig(config, tlsConfig)

	// Start agent
	logger.Info("🚀 Starting agent %s", config.Agent.ID)
	if err := a.Start(); err != nil {
		logger.Error("💥 Agent error: %v", err)
		os.Exit(1)
	}

	// Keep the program running
	logger.Info("✅ Agent is running and ready to handle requests")
	select {}
}
