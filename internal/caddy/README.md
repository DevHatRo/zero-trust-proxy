# Caddy Package

The `internal/caddy` package provides a **unified, comprehensive** Caddy configuration management system for the zero-trust-proxy project. All Caddy-related functionality has been consolidated into a single package for better architecture, maintainability, and consistency.

## Architecture

### Unified Package Structure
```
internal/caddy/
├── manager.go         # Complete Caddy management (906 lines)
├── validation.go      # Multi-method validation (483 lines)
├── types.go          # Configuration types (146 lines)
├── config_test.go    # Configuration tests (409 lines)
├── validation_test.go # Validation tests (471 lines)
└── README.md         # Documentation (this file)
```

### Key Benefits
- **Single Source of Truth**: All Caddy configuration logic in one place
- **Eliminated Duplication**: Removed 896 lines of duplicated server code
- **Better Architecture**: Clear separation (server = networking, caddy = configuration)
- **Enhanced Testing**: Isolated, comprehensive test coverage
- **Future-Ready**: Solid foundation for additional Caddy features

## Features

### Unified Manager
- **Simple Service Configuration**: Direct backend proxying with validation
- **Enhanced Service Configuration**: Advanced routing, middleware, zero-trust features
- **WebSocket Support**: Automatic HTTP/1.1 configuration for WebSocket services
- **HTTP Redirects**: Automatic HTTP to HTTPS redirect handling
- **TLS Management**: Automatic certificate management and TLS policies
- **Flexible Protocol Binding**: Support for HTTP, HTTPS, or both protocols
- **State Management**: Thread-safe service configuration management
- **Admin API Integration**: Direct Caddy configuration loading

### Validation Methods
The package provides multiple validation methods with graceful fallback:

1. **Structural Validation** (Always Available)
   - Validates basic Caddy configuration structure
   - Checks required fields and data types
   - Validates handlers, routes, and server configurations

2. **JSON Validation** (Always Available)
   - Ensures proper JSON marshaling/unmarshaling
   - Validates data type consistency

3. **Caddy CLI Validation** (When Available)
   - Uses `caddy validate` command for comprehensive validation
   - Provides real Caddy engine validation
   - Available when Caddy binary is installed (included in Docker containers)

4. **Admin API Validation** (Server Only)
   - Validates against running Caddy instance
   - Useful for server-side validation

## Usage

### Unified Manager Approach

```go
import "github.com/devhatro/zero-trust-proxy/internal/caddy"

// Create unified Caddy manager
manager := caddy.NewManager("http://localhost:2019") // Admin API endpoint

// Add simple service (direct backend proxying)
err := manager.AddSimpleService(
    "example.com",          // hostname
    "localhost:8080",       // backend
    "https",                // protocol
    false,                  // websocket
    true,                   // http redirect
    "",                     // listen on (empty for default)
)

if err != nil {
    log.Printf("Failed to add service: %v", err)
}
```

### Enhanced Service Configuration

```go
// Create enhanced service with advanced features
enhancedService := &caddy.EnhancedServiceConfig{
    ID:           "api-service",
    Hosts:        []string{"api.example.com"},
    Protocol:     "https",
    WebSocket:    true,
    HTTPRedirect: true,
    ListenOn:     "",
    Routes: []caddy.RouteConfig{
        {
            Match: caddy.MatchConfig{
                Path: "/api/*",
            },
            Handle: []caddy.MiddlewareConfig{
                {
                    Type: "headers",
                    Config: map[string]interface{}{
                        "request": map[string]interface{}{
                            "set": map[string]interface{}{
                                "X-API-Version": []string{"v1"},
                            },
                        },
                    },
                },
                {
                    Type: "reverse_proxy",
                },
            },
        },
    },
}

err := manager.AddEnhancedService(enhancedService)
if err != nil {
    log.Printf("Failed to add enhanced service: %v", err)
}
```

### Standalone Configuration Generation (Testing)

```go
// Generate configuration for testing or validation
config := caddy.GenerateServiceConfig(
    "test-service",
    "test.example.com",
    "localhost:3000",
    "https",
    true,  // Enable WebSocket support
    true,  // Enable HTTP redirect
    "",    // Use default listen addresses
)

// Validate the generated configuration
validator := caddy.NewValidator("") 
err := validator.ValidateConfig(config)
if err != nil {
    log.Printf("Configuration invalid: %v", err)
}
```

## Logging

The package uses structured logging with contextual icons for easy identification:

### Icon System
- **🚀🤖🔧✅💥** - Startup/Lifecycle
- **🔌🔗📞💔🗑️** - Connections  
- **🌐📡🎉📤📥** - HTTP/WebSocket
- **🔐🔑🖥️👤⚙️** - Certificates
- **💓✅❌⚠️🚨** - Health/Status

### Example Log Output

```
[DEBUG] 🔧 Generating Caddy config for service: my-app
[DEBUG] 🔧 Parameters: hostname=app.example.com, backend=localhost:3000, protocol=https, websocket=false, httpRedirect=true, listenOn=
[DEBUG] 🔌 Listen addresses: [:443]
[DEBUG] 🔐 Adding TLS configuration for HTTPS
[DEBUG] 🌐 Adding headers handler for proxy headers
[DEBUG] 🔗 Adding reverse proxy handler for backend: localhost:3000
[DEBUG] ✅ Created 2 handlers for service
[DEBUG] ✅ Caddy configuration generated successfully
[DEBUG] 🔧 Starting Caddy configuration validation
[DEBUG] 🔧 Running structural validation
[DEBUG] ✅ Structural validation passed
[DEBUG] 🔧 Running JSON validation
[DEBUG] ✅ JSON validation passed
[DEBUG] 🚀 Running Caddy CLI validation
[DEBUG] ⚙️ Creating temporary config file for Caddy CLI validation
[DEBUG] 🚀 Running 'caddy validate --config /tmp/caddy-config-123456.json'
[DEBUG] 🗑️ Cleaned up temporary config file: /tmp/caddy-config-123456.json
[DEBUG] ✅ Caddy CLI validation passed
[DEBUG] ✅ Configuration validation completed successfully
```

### Production vs Development Logging

**Development Mode** (DEBUG level):
- Detailed validation steps
- Configuration generation process
- Temporary file operations
- Comprehensive error context

**Production Mode** (INFO level):
- Service configuration results
- Validation outcomes
- Critical errors and warnings
- Performance metrics

## Error Handling

The package provides comprehensive error detection and reporting:

### Configuration Errors Detected
- Empty hostnames or backends
- Invalid handler configurations
- Missing required fields
- Invalid upstream configurations
- Malformed JSON structures
- Invalid status codes
- Malformed listen addresses

### Validation Error Types
```go
// Input validation errors
err := caddy.ValidateServiceInput("", "localhost:8080")
// Returns: "hostname cannot be empty"

// Configuration generation errors
config := caddy.GenerateServiceConfig("test", "", "localhost:8080", "https", false, false, "")
// config["error"] will contain: "hostname cannot be empty"

// Validation errors
err := validator.ValidateConfig(invalidConfig)
// Returns detailed error with validation method and specific issue
```

## Integration Examples

### Agent Integration (Validation Only)
```go
// In agent code - validate before sending to server
validator := caddy.NewValidator("") // No admin API for agents
err := validator.ValidateServiceConfig(serviceName, hostname, backend, protocol, websocket, httpRedirect, listenOn)
if err != nil {
    return fmt.Errorf("service configuration validation failed: %w", err)
}
// Send to server only if validation passes
```

### Server Integration (Full Management)
```go
// In server code - unified Caddy management
manager := caddy.NewManager("http://localhost:2019")

// Add simple service (validates and applies automatically)
err := manager.AddSimpleService(hostname, backend, protocol, websocket, httpRedirect, listenOn)
if err != nil {
    return fmt.Errorf("failed to configure service: %w", err)
}

// Or add enhanced service with advanced features
err = manager.AddEnhancedService(enhancedServiceConfig)
if err != nil {
    return fmt.Errorf("failed to configure enhanced service: %w", err)
}

// Get service statistics
count := manager.GetServiceCount()
services := manager.GetServiceList()
log.Printf("Managing %d services: %v", count, services)
```

### Migration from Old Architecture
```go
// OLD: Separate validation and configuration
validator := caddy.NewValidator(adminAPI)
config := caddy.GenerateServiceConfig(...)
err := validator.ValidateConfig(config)
// Apply to Caddy separately

// NEW: Unified manager approach
manager := caddy.NewManager(adminAPI)
err := manager.AddSimpleService(hostname, backend, protocol, websocket, httpRedirect, listenOn)
// Validation and application happen automatically
```

## Testing

The package includes comprehensive tests covering:

- Valid service configurations (HTTPS, WebSocket, HTTP with redirect)
- Invalid configurations (empty hostname/backend)
- Configuration generation edge cases
- Validation method fallbacks
- Error condition handling

Run tests:
```bash
go test ./internal/caddy -v
```

## Configuration Examples

### HTTPS Service with WebSocket
```json
{
  "apps": {
    "http": {
      "servers": {
        "websocket-service": {
          "listen": [":443"],
          "routes": [{
            "match": [{"host": ["ws.example.com"]}],
            "handle": [
              {
                "handler": "headers",
                "request": {
                  "set": {
                    "Host": ["{http.reverse_proxy.upstream.hostport}"],
                    "X-Forwarded-For": ["{http.request.remote}"],
                    "X-Forwarded-Proto": ["{http.request.scheme}"],
                    "Connection": ["{http.request.header.Connection}"],
                    "Upgrade": ["{http.request.header.Upgrade}"]
                  }
                }
              },
              {
                "handler": "reverse_proxy",
                "versions": ["1.1"],
                "upstreams": [{"dial": "localhost:8080"}]
              }
            ]
          }],
          "tls_connection_policies": [{
            "match": {"sni": ["ws.example.com"]}
          }]
        }
      }
    },
    "tls": {
      "automation": {
        "policies": [{"subjects": ["ws.example.com"]}]
      }
    }
  }
}
```

### HTTP to HTTPS Redirect
```json
{
  "apps": {
    "http": {
      "servers": {
        "redirect-service": {
          "listen": [":80"],
          "routes": [{
            "match": [{"host": ["example.com"]}],
            "handle": [{
              "handler": "static_response",
              "headers": {
                "Location": ["https://{http.request.host}{http.request.uri}"]
              },
              "status_code": 301
            }]
          }]
        }
      }
    }
  }
}
```

## Best Practices

1. **Always Validate Before Deployment**
   ```go
   // Generate configuration
   config := caddy.GenerateServiceConfig(...)
   
   // Validate before using
   if err := validator.ValidateConfig(config); err != nil {
       return err
   }
   
   // Safe to deploy
   ```

2. **Use Appropriate Validation Method**
   ```go
   // Check what's available
   if validator.IsCaddyAvailable() {
       log.Println("Using Caddy CLI validation")
   } else {
       log.Println("Using structural validation")
   }
   ```

3. **Handle Validation Gracefully**
   ```go
   if err := validator.ValidateConfig(config); err != nil {
       // Log the error with context
       logger.Error("💥 Configuration validation failed: %v", err)
       
       // Don't deploy invalid configuration
       return fmt.Errorf("invalid configuration: %w", err)
   }
   ```

4. **Use Input Validation**
   ```go
   // Validate inputs before generation
   if err := caddy.ValidateServiceInput(hostname, backend); err != nil {
       return fmt.Errorf("invalid service parameters: %w", err)
   }
   ```

## Troubleshooting

### Common Issues

**🚨 "Caddy CLI not found"**
- Caddy binary not installed or not in PATH
- Package will fall back to structural validation
- Install Caddy or use Docker container with Caddy included

**🚨 "Admin API not reachable"**
- Caddy server not running
- Admin API disabled or on different port
- Check Caddy server status and admin configuration

**🚨 "Structural validation failed"**
- Invalid configuration structure
- Missing required fields
- Check error message for specific issue

**🚨 "JSON validation failed"**
- Configuration contains non-serializable data
- Data type inconsistencies
- Review configuration generation logic

### Debug Mode

Enable debug logging to see detailed validation process:
```go
// Set log level to DEBUG to see all validation steps
logger.SetLevel(logger.DEBUG)
```

This will show:
- Configuration generation steps
- Each validation method attempted
- Temporary file operations
- Detailed error context
- Performance timing

The Caddy package provides a robust foundation for configuration management with comprehensive validation, detailed logging, and graceful error handling, ensuring reliable service deployment in the zero-trust-proxy system.
