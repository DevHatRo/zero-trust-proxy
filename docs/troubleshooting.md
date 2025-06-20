# 🚨 Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the Zero Trust Proxy system.

## 🔧 Quick Diagnostics

### System Health Check
```bash
# Check if components are running
ps aux | grep -E "(server|agent)"

# Check listening ports
sudo netstat -tlnp | grep -E ':(8443|9443|80|443|2019)'

# Check recent logs
tail -n 50 /var/log/zero-trust-server.log
tail -n 50 /var/log/zero-trust-agent.log
```

### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG

# Start components with debug output
./bin/server --log-level DEBUG --config config/server.yaml
./bin/agent --log-level DEBUG --config config/agent.yaml
```

## 🔐 Certificate Issues

### Certificate Validation Errors

#### Symptoms
- `tls: bad certificate` errors in logs
- Agent unable to connect to server
- `certificate verify failed` messages

#### Diagnosis
```bash
# Check certificate validity
openssl x509 -in certs/server.crt -text -noout | grep -E "(Valid|Subject|Issuer)"
openssl x509 -in certs/agent1.crt -text -noout | grep -E "(Valid|Subject|Issuer)"

# Verify certificate chain
openssl verify -CAfile certs/ca.crt certs/server.crt
openssl verify -CAfile certs/ca.crt certs/agent1.crt

# Check certificate expiration
openssl x509 -in certs/server.crt -noout -dates
openssl x509 -in certs/agent1.crt -noout -dates
```

#### Solutions
```bash
# Regenerate expired certificates
rm certs/server.crt certs/server.key
./bin/certgen --ca certs/ca.crt --ca-key certs/ca.key --out certs --name server --type server

# Regenerate agent certificate
rm certs/agent1.crt certs/agent1.key  
./bin/certgen --ca certs/ca.crt --ca-key certs/ca.key --out certs --name agent1 --type agent

# Fix certificate permissions
chmod 600 certs/*.key
chmod 644 certs/*.crt
chown -R $(whoami):$(whoami) certs/
```

## 🌐 Connection Issues

### Agent Cannot Connect to Server

#### Symptoms
- `connection refused` errors
- `no route to host` errors
- Agent constantly reconnecting

#### Diagnosis
```bash
# Test server connectivity
telnet server.example.com 8443
nc -zv server.example.com 8443


# Verify server is listening
sudo netstat -tlnp | grep :8443

# Check firewall rules
sudo iptables -L INPUT | grep 8443
sudo ufw status | grep 8443
```

#### Solutions
```bash
# Open firewall ports
sudo ufw allow 8443/tcp
sudo ufw allow 9443/tcp

# Check DNS resolution
nslookup server.example.com
dig server.example.com

# Use IP address instead of hostname temporarily
./bin/agent --server 192.168.1.100:8443 --id agent1
```

### Caddy Integration Issues

#### Symptoms
- HTTP 502 Bad Gateway errors
- Services not accessible via Caddy
- Caddy cannot connect to internal API

#### Diagnosis
```bash

# Check Caddy configuration
curl http://localhost:2019/config/

```

## 📊 Service Configuration Issues

### Services Not Registering

#### Symptoms
- Services not appearing in Caddy
- Backend connections failing
- Empty service list in API

#### Diagnosis
```bash

# Verify agent configuration
./bin/agent --config config/agent.yaml

# Check backend connectivity from agent
curl -H "Host: app.example.com" http://localhost:3000/health
```

### Health Check Failures

```bash
# Adjust health check settings
# In config/agent.yaml:
health_check:
  path: "/health"
  interval: "60s"      # Increase interval
  timeout: "10s"       # Increase timeout
  unhealthy_threshold: 5  # More failures before marking unhealthy

# Create simple health endpoint
echo "OK" > /var/www/html/health
```

## 🔄 Hot Reload Issues

### Configuration Not Reloading

#### Symptoms
- Changes not applied automatically
- Hot reload enabled but not working
- File watcher errors in logs

#### Diagnosis
```bash
# Check hot reload status
docker logs -f zero-trust-agent/server

# Test file watching
touch config/agent.yaml
# Check if reload triggered in logs

# Verify file permissions
ls -la config/agent.yaml
```

#### Solutions
```bash
# Manually trigger reload by editing config
echo "# trigger reload" >> config/agent.yaml


# Check for file locking issues
lsof config/agent.yaml
```

## 📡 WebSocket Issues

### WebSocket Connections Failing

#### Symptoms
- WebSocket upgrade failures
- Real-time features not working
- HTTP 400 Bad Request on WebSocket upgrade

#### Diagnosis
```bash
# Test WebSocket upgrade
curl -v \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://app.example.com/

# Check WebSocket configuration
grep -A 5 "websocket" config/agent.yaml

```

#### Solutions
```bash
# Enable WebSocket support in service configuration
services:
  - id: "web-app"
    hostname: "app.example.com"
    websocket: true    # Add this line
    upstreams:
      - address: "localhost:3000"

# Verify backend WebSocket support
wscat -c ws://localhost:3000/
```

## 🚀 Performance Issues

### High Memory Usage

#### Symptoms
- Components consuming excessive memory
- System becoming unresponsive
- Out of memory errors

#### Diagnosis
```bash
# Monitor memory usage
top -p $(pgrep -d, -f "server|agent")
ps aux | grep -E "(server|agent)" | awk '{print $6}'

# Check for memory leaks
valgrind --tool=memcheck ./bin/agent --config config/agent.yaml
```

#### Solutions
```bash
# Configure resource limits
# In systemd service files:
[Service]
MemoryLimit=1G
MemoryMax=1G

# Reduce connection pool sizes
# In configuration:
load_balancing:
  max_connections: 100  # Reduce from default
```

### Slow Response Times

#### Symptoms
- High response times
- Timeouts occurring frequently
- Poor application performance

#### Diagnosis
```bash
# Test response times
time curl https://app.example.com/

# Check upstream response times
curl -w "@curl-format.txt" https://app.example.com/

# Monitor connection statistics
ss -tuln | grep -E ':(8443|9443)'
```

#### Solutions
```bash
# Adjust timeout settings
# In agent configuration:
load_balancing:
  timeout: "30s"           # Increase timeout
  keep_alive_timeout: "60s" # Increase keep-alive

# Optimize upstream configuration
upstreams:
  - address: "localhost:3000"
    weight: 100
    max_connections: 50    # Limit concurrent connections
```

## 🐳 Docker Issues

### Container Startup Problems

#### Symptoms
- Containers failing to start
- Exit code 1 errors
- Configuration not found errors

#### Diagnosis
```bash
# Check container logs
docker logs zero-trust-server
docker logs zero-trust-agent

# Inspect container configuration
docker inspect zero-trust-server
docker inspect zero-trust-agent

# Test container networking
docker exec zero-trust-agent ping zero-trust-server
```

#### Solutions
```bash
# Fix volume mounts
docker run -v $(pwd)/config:/config:ro -v $(pwd)/certs:/certs:ro ...

# Use absolute paths
docker run -v /opt/zero-trust/config:/config:ro ...

# Check container networking
docker network ls
docker network inspect zero-trust-network
```

## 📋 Log Analysis

#### Log Levels
- **🚀 INFO**: Normal operations (startup, service registration)
- **⚠️ WARN**: Potential issues (health check failures, retries)
- **❌ ERROR**: Error conditions (connection failures, invalid config)
- **🔧 DEBUG**: Detailed debugging information


## 🛠️ Advanced Debugging

### Network Debugging
```bash
# Monitor network traffic
sudo tcpdump -i any port 8443
sudo tcpdump -i any port 9443

# Trace network calls
strace -e network ./bin/agent --config config/agent.yaml

# Monitor DNS resolution
dig +trace app.example.com
```

### Process Debugging
```bash
# Attach debugger
gdb ./bin/agent
(gdb) run --config config/agent.yaml

# Generate core dump
kill -SIGQUIT $(pgrep agent)

# Analyze with delve
dlv exec ./bin/agent -- --config config/agent.yaml
```


### Support Channels
- **🐛 Bug Reports**: [GitHub Issues](https://github.com/devhatro/zero-trust-proxy/issues)
- **💬 Questions**: [GitHub Discussions](https://github.com/devhatro/zero-trust-proxy/discussions)
- **📖 Documentation**: [Complete Docs](README.md)
