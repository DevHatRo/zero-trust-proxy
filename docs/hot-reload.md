# Hot Reload System

This document describes the shared hot reload system used by both the 0Trust agent and server components.

## Overview

The hot reload system allows configuration changes to be applied automatically without restarting services. It's implemented as a shared system in `internal/common/hotreload.go` and can be used by any component that implements the `ConfigReloader` interface.

## Features

- **File Watching**: Monitors configuration files for changes using `fsnotify`
- **Debouncing**: Prevents rapid successive reloads from multiple file events
- **Thread Safety**: Safe concurrent access with proper synchronization
- **Rate Limiting**: Prevents excessive reload attempts
- **Graceful Error Handling**: Validates configuration before applying changes
- **Multi-Component Support**: Single manager can handle multiple components
- **Atomic Write Support**: Handles editors that write via temporary files

## Configuration

### Hot Reload Settings

```yaml
hot_reload:
  enabled: true                    # Enable/disable hot reload
  watch_config: true              # Watch config file for changes
  debounce_delay: "100ms"         # Delay before reloading after file change
  graceful_timeout: "30s"         # Timeout for graceful operations
  reload_signal: "SIGHUP"         # Optional: future signal-based reload
```

### Environment Variables

For flexible port configuration (no hardcoded assumptions):

```bash
# Server address configuration
export ZERO_TRUST_SERVER="server.example.com:9443"
# Or alternatively:
export SERVER_ADDRESS="server.example.com:9443"  
export SERVER_PORT="9443"  # Used with localhost if no full address
```

## Component Integration

### Agent Hot Reload

The agent implements the `ConfigReloader` interface and supports:

- **Service Configuration Changes**: Add, update, or remove services dynamically
- **Load Balancing Updates**: Change upstream weights and policies
- **Health Check Modifications**: Update health check settings
- **Log Level Changes**: Adjust logging without restart
- **Protocol Changes**: Update service protocols (http/https/ws/wss)

**Supported Changes:**
- Add new services
- Remove existing services  
- Update upstream addresses and weights
- Modify health check paths and intervals
- Change load balancing policies
- Update WebSocket configurations
- Adjust log levels

**Example:**
```yaml
services:
  - id: "web-app"
    hostname: "app.example.com" 
    protocol: "https"  # Can be changed to http
    upstreams:
      - address: "localhost:3000"  # Can change port
        weight: 100                # Can adjust weight
```

### Server Hot Reload

The server implements hot reload for:

- **Log Level Changes**: Adjust server logging dynamically
- **Caddy Configuration**: Update Caddy admin API settings
- **Certificate Monitoring**: Detect certificate changes (requires restart)
- **Port Changes**: Detect port changes (requires restart)

**Supported Changes:**
- Log level adjustments
- Caddy admin API address updates

**Restart Required For:**
- TLS certificate changes
- Listen address changes
- Major structural changes

## Implementation Details

### ConfigReloader Interface

```go
type ConfigReloader interface {
    ReloadConfig() error
    GetConfigPath() string
    IsHotReloadEnabled() bool
    GetComponentName() string
}
```

### Key Components

1. **FileWatcher**: Monitors individual configuration files
2. **HotReloadManager**: Manages multiple file watchers
3. **Debouncing**: Prevents reload storms from rapid file changes
4. **Rate Limiting**: Prevents excessive reload attempts

### File Change Detection

The system watches both:
- **Direct file modifications**: Normal file edits
- **Atomic writes**: Temporary file + rename (common with editors)

## Port Flexibility Improvements

### Before (Hardcoded Assumptions)
```go
// OLD: Hardcoded port assumptions
if strings.HasSuffix(backendAddr, ":443") {
    needsTLS = true
}
```

### After (Flexible Configuration)
```go
// NEW: Intelligent protocol detection
func needsTLS(service *common.ServiceConfig, backendAddr string) bool {
    // Priority 1: Service protocol setting
    if service.Protocol == "https" || service.Protocol == "wss" {
        return true
    }
    // Priority 2: Explicit protocol in backend address
    _, _, protocol := parseAddress(backendAddr)
    return protocol == "https" || protocol == "wss"
}
```

### Configuration Examples

```yaml
# Service with custom port
- id: "api-service"
  hostname: "api.example.com"
  protocol: "https"          # Explicit protocol
  upstreams:
    - address: "localhost:8443"  # Custom port

# Service with full URL
- id: "backend-service"  
  hostname: "backend.example.com"
  upstreams:
    - address: "https://backend:9999"  # Full URL with custom port
```


### Testing Hot Reload

1. **Start the service** with hot reload enabled
2. **Edit the configuration file** (change log level, add service, etc.)
3. **Save the file** - changes should be applied automatically
4. **Check logs** for reload confirmation

Example log output:
```
🔥 Hot reload enabled for agent: watching /config/agent.yaml for changes
🔥 Config file changed: /config/agent.yaml (event: WRITE) for agent
🔄 Reloading configuration for agent from /config/agent.yaml
✅ Configuration reloaded successfully for agent (took 45ms)
📝 Config changes: services: 2 → 3, log_level: INFO → DEBUG
```

## Best Practices

1. **Use Explicit Protocols**: Always specify `protocol: "https"` instead of relying on port detection
2. **Environment Variables**: Use `ZERO_TRUST_SERVER` for flexible server addresses
3. **Validation**: Always validate configuration before applying changes
4. **Graceful Fallback**: Handle reload failures gracefully
5. **Monitoring**: Monitor hot reload logs for issues
6. **Testing**: Test configuration changes in development first

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure config files are readable
2. **File Locking**: Some editors may lock files during writes
3. **Rapid Changes**: Debouncing prevents reload storms
4. **Invalid Config**: Validation prevents applying broken configurations

### Debug Logging

Enable debug logging to see detailed hot reload activity:
```yaml
log_level: "DEBUG"
```

### Manual Recovery

If hot reload fails, you can:
1. Fix the configuration file
2. Restart the service
3. Check file permissions
4. Verify configuration syntax

## Security Considerations

- Configuration files should have proper file permissions
- Validate all configuration changes before applying
- Monitor for unauthorized configuration changes
- Consider using signed configurations for production

## Future Enhancements

- Signal-based reload (SIGHUP support)
- Configuration validation APIs
- Rollback on failed reloads
- Configuration change notifications
- Remote configuration management
- Configuration versioning and history 
