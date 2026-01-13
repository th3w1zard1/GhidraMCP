# Running Ghidra in Docker on ARM64/Linux for Cross-Platform Analysis and Collaboration

## Key Points

### ✅ Cross-Platform Analysis Support

**Yes, you can analyze Windows x86/x64 executables on ARM64/Linux!**

Ghidra's analysis is **architecture-independent**. The processor modules (x86, x64, ARM, etc.) are software-based analyzers that work regardless of the host platform. Running Ghidra on ARM64/Linux can analyze:

- Windows x86 (32-bit) executables
- Windows x64 (AMD64) executables  
- Linux binaries (any architecture)
- macOS binaries
- And any other architecture Ghidra supports

The analysis happens at the software level, not by executing the binary natively.

### 🐳 Docker Architecture Considerations

**Important**: The Docker image you build/run needs to match your host architecture:

1. **Native ARM64 build**: Build the Docker image on your ARM64 machine - it will work perfectly for analysis
2. **Multi-arch images**: Docker supports multi-architecture images, but you'll need to build for ARM64
3. **QEMU emulation**: You could run AMD64 images on ARM64 via QEMU, but it's slower and unnecessary for Ghidra analysis

**Recommendation**: Build the Docker image natively on your ARM64 machine. Analysis performance will be the same since Ghidra doesn't execute the binaries.

## Collaboration Setup: Ghidra Server Mode

The `ghidra-server` mode is exactly what you need for collaboration! Multiple users can connect to the same server and work on shared projects.

### Quick Start: Ghidra Server in Docker

```bash
# Build the Docker image (on your ARM64 machine)
cd /path/to/ghidra_12.0_PUBLIC
./docker/build-docker-image.sh

# Run Ghidra Server
docker run \
    --env MODE=ghidra-server \
    --name ghidra-server \
    -d \
    --restart unless-stopped \
    --volume /path/to/ghidra/repositories:/ghidra/repositories \
    --volume /path/to/ghidra/server/config:/ghidra/server \
    -p 13100:13100 \
    -p 13101:13101 \
    -p 13102:13102 \
    ghidra/ghidra:12.0_PUBLIC
```

### Server Ports

- **13100**: RMI Registry (default)
- **13101**: Server (default)  
- **13102**: Debug port (default)

### Connecting Clients

Users connect to the server using:

- **GUI mode**: File → Connect to Repository → `ghidra://your-server-ip:13101`
- **Headless mode**: Use `ghidra://` URLs in commands

### Server Administration

To administer the server, exec into the container:

```bash
docker exec -it ghidra-server bash
/ghidra/server/svrAdmin
```

Common operations:

- Create users: `svrAdmin -add <username>`
- List repositories: `svrAdmin -list`
- Create repository: `svrAdmin -add <repo-name>`

### Volume Configuration

Important directories to mount:

```bash
--volume /host/repositories:/ghidra/repositories  # Shared project repositories
--volume /host/server-config:/ghidra/server       # Server configuration (server.conf, users, etc.)
```

**Permissions**: The container runs as user `ghidra` (UID/GID 1001). Ensure mounted volumes are accessible:

```bash
sudo chown -R 1001:1001 /host/repositories
sudo chown -R 1001:1001 /host/server-config
```

## Alternative Modes

### Headless Mode (Automated Analysis)

For automated analysis without GUI:

```bash
docker run \
    --env MODE=headless \
    --rm \
    --volume /path/to/project:/home/ghidra/project \
    --volume /path/to/binary:/home/ghidra/binary \
    ghidra/ghidra:12.0_PUBLIC \
    /home/ghidra/project MyProgram -import /home/ghidra/binary -processor x86:LE:64:default -analysisTimeoutPerFile 300
```

### PyGhidra Mode (Python Scripts)

For running Python scripts with Ghidra:

```bash
docker run \
    --env MODE=pyghidra \
    --rm \
    --volume /path/to/project:/myproject \
    ghidra/ghidra:12.0_PUBLIC \
    -H /myproject MyProgram -import /path/to/binary
```

## Workflow for Collaboration

1. **Setup Server** (one-time):
   - Build Docker image on your ARM64 machine
   - Run `ghidra-server` container with persistent volumes
   - Create repositories and users via `svrAdmin`

2. **Clients Connect**:
   - Team members connect using Ghidra GUI or headless mode
   - All connect to: `ghidra://your-server-ip:13101`
   - Multiple users can work on the same project simultaneously

3. **Shared Analysis**:
   - All users see the same project data
   - Changes are synchronized through the server
   - Version control and locking prevent conflicts

## Network Configuration

For remote access, ensure:

- Firewall allows ports 13100-13102
- Server is accessible to all team members
- Consider using VPN or SSH tunneling for security

## Performance Notes

- **Analysis speed**: Same on ARM64 vs AMD64 (software-based analysis)
- **Memory**: Configure with `--env MAXMEM=4G` (or higher for large binaries)
- **Network**: Server performance depends on network latency for collaborative work

## Example: Complete Setup Script

```bash
#!/bin/bash
# Setup Ghidra Server for Collaboration

GHIDRA_DIR="/path/to/ghidra_12.0_PUBLIC"
REPOS_DIR="/data/ghidra/repositories"
CONFIG_DIR="/data/ghidra/server-config"

# Create directories
mkdir -p "$REPOS_DIR" "$CONFIG_DIR"
sudo chown -R 1001:1001 "$REPOS_DIR" "$CONFIG_DIR"

# Build image (if not already built)
cd "$GHIDRA_DIR"
./docker/build-docker-image.sh

# Run server
docker run \
    --env MODE=ghidra-server \
    --name ghidra-collab-server \
    -d \
    --restart unless-stopped \
    --volume "$REPOS_DIR:/ghidra/repositories" \
    --volume "$CONFIG_DIR:/ghidra/server" \
    -p 13100:13100 \
    -p 13101:13101 \
    -p 13102:13102 \
    ghidra/ghidra:12.0_PUBLIC

echo "Server started! Connect clients to: ghidra://$(hostname -I | awk '{print $1}'):13101"
```

## Summary

✅ **Cross-platform analysis**: Yes, works perfectly on ARM64/Linux for Windows x86/x64 binaries  
✅ **Collaboration**: Use `ghidra-server` mode for multi-user access  
✅ **Performance**: No performance penalty for cross-architecture analysis  
✅ **Docker**: Build natively on ARM64 for best results
