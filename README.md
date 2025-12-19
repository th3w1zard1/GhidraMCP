[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

# GhidraMCP - AI-Powered Reverse Engineering with Ghidra

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-light.svg)](https://cursor.com/en/install-mcp?name=ghidra&config=eyJjb21tYW5kIjoicHl0aG9uIiwiYXJncyI6WyIvQUJTT0xVVEVfUEFUSF9UTy9icmlkZ2VfbWNwX2doaWRyYS5weSIsIi0tZ2hpZHJhLXNlcnZlciIsImh0dHA6Ly8xMjcuMC4wLjE6ODA4MC8iXX0%3D)

GhidraMCP is a Model Context Protocol (MCP) server that enables AI language models to autonomously reverse engineer applications using Ghidra's powerful analysis capabilities. It exposes 39 comprehensive tools covering decompilation, call graphs, data flow analysis, vtable detection, and much more.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9

## ❌ The Problem: Manual Reverse Engineering is Slow

- Time-consuming manual analysis of binaries
- Repetitive tasks like renaming functions and variables
- Difficult to trace data flow and call relationships
- Hard to discover patterns across large codebases
- Limited automation for reverse engineering workflows

## ✅ The Solution: AI-Assisted Reverse Engineering

- **39 comprehensive tools** for binary analysis
- **Automated decompilation** and variable renaming
- **Call graph analysis** to understand function relationships
- **Data flow tracing** to track value origins and uses
- **Vtable detection** for C++ binary analysis
- **Constants search** to find magic numbers and error codes
- **Bookmark management** for organizing analysis findings
- **Memory analysis** with hex dumps and block inspection

GhidraMCP bridges Ghidra's powerful reverse engineering capabilities with AI agents, enabling autonomous binary analysis.

Just tell your AI agent to **analyze the binary**:

```txt
Analyze the main function and trace where user input flows. Use GhidraMCP tools.
```

## 🛠️ Installation

### 📋 Requirements

- [Ghidra](https://ghidra-sre.org) (any recent version)
- Python 3.10+ with `requests` and `mcp` packages
- MCP-compatible client (Cursor, Claude Desktop, VS Code, etc.)

### Step 1: Install Ghidra Plugin

1. Download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository
2. Run Ghidra
3. Select `File` -> `Install Extensions`
4. Click the `+` button
5. Select the `GhidraMCP-*.zip` file from the downloaded release
6. Restart Ghidra
7. Enable the plugin: `File` -> `Configure` -> `Developer` -> Check `GhidraMCPPlugin`
8. *Optional*: Configure the port in `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server` (default: 8080)

**Video Installation Guide:**

<https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3>

### Step 2: Install Python Dependencies

```bash
pip install requests mcp
```

Or using the provided requirements file:

```bash
pip install -r requirements.txt
```

### Step 3: Configure MCP Client

<details>
<summary><b>Install in Cursor</b></summary>
  
Go to: `Settings` -> `Cursor Settings` -> `Tools & Integrations` -> `Add a custom MCP server`

Paste the following config into your Cursor `~/.cursor/mcp.json` file:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Replace `/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py` with the actual path to the `bridge_mcp_ghidra.py` file in this repository.

The `--ghidra-server` argument should point to your Ghidra HTTP server (default: `http://127.0.0.1:8080/`).

</details>

<details>
<summary><b>Install in Claude Desktop</b></summary>

### Install in Claude Desktop

Add this to your Claude Desktop `claude_desktop_config.json` file. See [Claude Desktop MCP docs](https://modelcontextprotocol.io/quickstart/user) for more info.

**Location:**

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Replace `/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py` with the actual path to the `bridge_mcp_ghidra.py` file.

</details>

<details>
<summary><b>Install in Claude Code</b></summary>

### Install in Claude Code

Run this command. See [Claude Code MCP docs](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/tutorials#set-up-model-context-protocol-mcp) for more info.

```sh
claude mcp add ghidra -- python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
```

Or for SSE transport (if you run the bridge with `--transport sse`):

```sh
claude mcp add --transport sse ghidra http://127.0.0.1:8081/sse
```

</details>

<details>
<summary><b>Install in VS Code</b></summary>

### Install in VS Code

Add this to your VS Code MCP config. See [VS Code MCP docs](https://code.visualstudio.com/docs/copilot/chat/mcp-servers) for more info.

```json
{
  "mcpServers": {
    "ghidra": {
      "type": "stdio",
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

</details>

<details>
<summary><b>Install in Cline</b></summary>

### Install in Cline

To use GhidraMCP with [Cline](https://cline.bot), you can either:

**Option 1: Local Server (Recommended)**

1. Open Cline
2. Click the hamburger menu (☰) to enter the **MCP Servers** section
3. Click **Add Server**
4. Enter the following configuration:

```json
{
  "command": "python",
  "args": [
    "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
    "--ghidra-server",
    "http://127.0.0.1:8080/"
  ]
}
```

**Option 2: Remote Server (SSE)**

First, run the MCP server manually:

```bash
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

Then in Cline:

1. Select `MCP Servers` at the top
2. Select `Remote Servers`
3. Add:
   - Server Name: `GhidraMCP`
   - Server URL: `http://127.0.0.1:8081/sse`

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

</details>

<details>
<summary><b>Install in Windsurf</b></summary>

### Install in Windsurf

Add this to your Windsurf MCP config. See [Windsurf MCP docs](https://docs.windsurf.com/windsurf/mcp) for more info.

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

</details>

<details>
<summary><b>Install in 5ire</b></summary>

### Install in 5ire

To set up GhidraMCP in [5ire](https://github.com/nanbingxyz/5ire):

1. Open 5ire
2. Go to `Tools` -> `New`
3. Set the following configurations:
   - Tool Key: `ghidra`
   - Name: `GhidraMCP`
   - Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/`

</details>

<details>
<summary><b>Install in Zed</b></summary>

### Install in Zed

Manual config:

```json
{
  "context_servers": {
    "ghidra": {
      "command": {
        "path": "python",
        "args": [
          "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
          "--ghidra-server",
          "http://127.0.0.1:8080/"
        ]
      },
      "settings": {}
    }
  }
}
```

</details>

<details>
<summary><b>Install in BoltAI</b></summary>

### Install in BoltAI

Open the "Settings" page of the app, navigate to "Plugins," and enter the following JSON:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

More info is available on [BoltAI's Documentation site](https://docs.boltai.com/docs/plugins/mcp-servers).

</details>

<details>
<summary><b>Install in Windows</b></summary>

### Install in Windows

On Windows, use `python` or `py` depending on your Python installation:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "C:\\FULL\\PATH\\TO\\bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Or if Python is not in PATH:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "py",
      "args": [
        "-3",
        "C:\\FULL\\PATH\\TO\\bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

</details>

<details>
<summary><b>Using Docker</b></summary>

### Using Docker

If you prefer to run the MCP bridge in a Docker container:

1. **Create a Dockerfile:**

```Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Copy the bridge script
COPY bridge_mcp_ghidra.py .

# Install dependencies
RUN pip install requests mcp

# Default command
CMD ["python", "bridge_mcp_ghidra.py", "--ghidra-server", "http://host.docker.internal:8080/"]
```

2. **Build the image:**

```bash
docker build -t ghidramcp-bridge .
```

3. **Configure Your MCP Client:**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--network", "host", "ghidramcp-bridge"]
    }
  }
}
```

Note: Use `host.docker.internal` to access the Ghidra server running on the host machine.

</details>

## 🔨 Available Tools

GhidraMCP provides **39 comprehensive tools** organized into 10 categories:

### Core Analysis Tools

- **`decompile_function`**: Decompile a function by name to C pseudocode
- **`decompile_function_by_address`**: Decompile a function at a specific address
- **`disassemble_function`**: Get assembly code for a function
- **`get_function_by_address`**: Get function information by address
- **`get_function_info`**: Get detailed function info with parameters and locals
- **`list_functions`**: List all functions in the program
- **`list_methods`**: List all function names with pagination
- **`list_function_calls`**: List all function calls within a function
- **`search_functions_by_name`**: Search functions by name substring

### Call Graph & Relationships

- **`get_call_graph`**: Get bidirectional call graph (callers + callees) up to specified depth
- **`get_function_callers`**: List all functions that call a specific function
- **`get_function_callees`**: List all functions called by a specific function
- **`get_function_xrefs`**: Get all references to a function by name

### Cross-References

- **`get_xrefs_to`**: Get all references TO a specific address
- **`get_xrefs_from`**: Get all references FROM a specific address
- **`find_cross_references`**: Find cross-references with directional filtering (to/from/both)

### Data Flow Analysis

- **`trace_data_flow_backward`**: Trace where a value at an address comes from (origins)
- **`trace_data_flow_forward`**: Trace where a value at an address flows to (uses)

### Constants & Values

- **`find_constant_uses`**: Find all uses of a specific constant value (supports hex, decimal, negative)
- **`find_constants_in_range`**: Find constants within a numeric range (useful for error codes, enums)

### Strings

- **`list_strings`**: List all defined strings with addresses and optional filter
- **`search_strings_regex`**: Search strings using regex patterns
- **`get_strings_count`**: Get total count of defined strings

### Memory & Data

- **`get_memory_blocks`**: List all memory blocks with properties (R/W/X, size, etc.)
- **`read_memory`**: Read memory at address with hex dump and ASCII representation
- **`get_data_at_address`**: Get detailed data information (type, size, label, value)
- **`list_data_items`**: List defined data labels and their values
- **`list_segments`**: List all memory segments

### Bookmarks & Annotations

- **`set_bookmark`**: Create or update a bookmark at an address (Note, Warning, TODO, Bug, Analysis)
- **`get_bookmarks`**: Retrieve bookmarks by address or type
- **`search_bookmarks`**: Search bookmarks by comment text

### Comments

- **`set_decompiler_comment`**: Set a comment in function pseudocode
- **`set_disassembly_comment`**: Set a comment in assembly listing

### Vtable Analysis (C++)

- **`analyze_vtable`**: Analyze virtual function table to extract function pointers
- **`find_vtable_callers`**: Find indirect calls that could invoke a function via vtable

### Symbols & Labels

- **`list_classes`**: List all namespace/class names
- **`list_namespaces`**: List all non-global namespaces
- **`list_imports`**: List imported symbols
- **`list_exports`**: List exported functions/symbols
- **`create_label`**: Create or update a label at an address

### Function & Variable Manipulation

- **`rename_function`**: Rename a function by name
- **`rename_function_by_address`**: Rename a function by address
- **`rename_data`**: Rename a data label at an address
- **`rename_variable`**: Rename a local variable within a function
- **`set_function_prototype`**: Set a function's prototype/signature
- **`set_local_variable_type`**: Set a local variable's data type

### Current Context

- **`get_current_address`**: Get the address currently selected in Ghidra GUI
- **`get_current_function`**: Get the function currently selected in Ghidra GUI

## 💡 Usage Tips

### Start with High-Level Analysis

Begin by understanding the binary structure:

```txt
List all functions in the program and show me the main function's call graph
```

### Trace Data Flow

Understand how data moves through the program:

```txt
Trace data flow backward from address 0x401234 to find where the value comes from
```

### Find Patterns

Search for specific patterns:

```txt
Find all uses of the constant 0xdeadbeef and show me where it's used
```

### Organize Findings

Use bookmarks to track important discoveries:

```txt
Set a bookmark at 0x401000 with type "Analysis" and comment "Encryption function"
```

### Analyze C++ Binaries

For C++ programs, analyze vtables:

```txt
Analyze the vtable at 0x405000 and find all potential callers of the virtual methods
```

## 🚨 Troubleshooting

<details>
<summary><b>Ghidra Server Not Running</b></summary>

**Error:** `Request failed: Connection refused` or `Failed to connect to Ghidra server`

**Solution:**

1. Ensure Ghidra is running with a project open
2. Verify the GhidraMCPPlugin is enabled: `File` -> `Configure` -> `Developer` -> Check `GhidraMCPPlugin`
3. Check the server port in `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server` (default: 8080)
4. Verify the `--ghidra-server` argument in your MCP config matches the Ghidra server URL
5. Test the connection: Open `http://127.0.0.1:8080/methods` in a browser (should return function names)

</details>

<details>
<summary><b>Python Module Not Found</b></summary>

**Error:** `ModuleNotFoundError: No module named 'mcp'` or `No module named 'requests'`

**Solution:**

```bash
pip install requests mcp
```

Or install from requirements:

```bash
pip install -r requirements.txt
```

</details>

<details>
<summary><b>Python Path Issues</b></summary>

**Error:** `python: command not found` or `python3: command not found`

**Solution:**

- Use `python3` instead of `python` in your MCP config
- Or use the full path to Python: `/usr/bin/python3` or `C:\Python310\python.exe`
- On Windows, try `py` or `py -3`

</details>

<details>
<summary><b>Bridge Script Not Found</b></summary>

**Error:** `No such file or directory: bridge_mcp_ghidra.py`

**Solution:**

- Use the absolute path to `bridge_mcp_ghidra.py` in your MCP config
- On Windows, use forward slashes or escaped backslashes: `C:/path/to/bridge_mcp_ghidra.py`
- Verify the file exists at the specified path

</details>

<details>
<summary><b>Port Already in Use</b></summary>

**Error:** `Port 8080 is already in use`

**Solution:**

1. Change the Ghidra server port: `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server` -> Set custom port
2. Update your MCP config `--ghidra-server` argument to match the new port
3. Or stop the process using port 8080

</details>

<details>
<summary><b>No Program Loaded in Ghidra</b></summary>

**Error:** `No program loaded` responses from tools

**Solution:**

1. Open a program in Ghidra: `File` -> `New Project` or `File` -> `Import File`
2. Wait for analysis to complete (if auto-analysis is enabled)
3. Ensure the program is open in the active Code Browser window

</details>

<details>
<summary><b>SSE Transport Issues (Cline)</b></summary>

**Error:** SSE connection fails or times out

**Solution:**

1. Ensure the bridge is running with `--transport sse` flag
2. Verify the `--mcp-port` matches the URL in Cline (default: 8081)
3. Check firewall settings allow connections on the specified port
4. Try using stdio transport instead (local server option)

</details>

<details>
<summary><b>General MCP Client Errors</b></summary>

1. **Restart your MCP client** after configuration changes
2. **Check MCP client logs** for detailed error messages
3. **Verify Python version**: Requires Python 3.10+
4. **Test the bridge manually**: Run `python bridge_mcp_ghidra.py --help` to verify it works
5. **Check file permissions**: Ensure the bridge script is executable

</details>

## 🏗️ Building from Source

To build the Ghidra plugin from source:

1. **Copy Ghidra JAR files** from your Ghidra installation to this project's `lib/` directory:
   - `Ghidra/Features/Base/lib/Base.jar`
   - `Ghidra/Features/Decompiler/lib/Decompiler.jar`
   - `Ghidra/Framework/Docking/lib/Docking.jar`
   - `Ghidra/Framework/Generic/lib/Generic.jar`
   - `Ghidra/Framework/Project/lib/Project.jar`
   - `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
   - `Ghidra/Framework/Utility/lib/Utility.jar`
   - `Ghidra/Framework/Gui/lib/Gui.jar`

2. **Build with Maven:**

   ```bash
   mvn clean package assembly:single
   ```

3. **Install the generated ZIP:**
   - The build creates a `GhidraMCP-*.zip` file
   - Install it in Ghidra via `File` -> `Install Extensions`

## 📚 Development

### Project Structure

```
GhidraMCP/
├── src/main/java/com/lauriewired/
│   └── GhidraMCPPlugin.java    # Main Ghidra plugin (HTTP server)
├── bridge_mcp_ghidra.py         # Python MCP bridge
├── pom.xml                       # Maven build configuration
└── requirements.txt              # Python dependencies
```

### Running Tests

The bridge can be tested manually:

```bash
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/ --verbose
```

### Environment Variables

The bridge supports the following environment variables:

- `GHIDRA_SERVER_URL`: Default Ghidra server URL (default: `http://127.0.0.1:8080/`)
- `MCP_HOST`: Host for SSE transport (default: `127.0.0.1`)
- `MCP_PORT`: Port for SSE transport (default: `8081`)

## 📖 Documentation

- **Implementation Summary**: See [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md) for detailed tool documentation
- **Ghidra Documentation**: [https://ghidra-sre.org](https://ghidra-sre.org)
- **MCP Specification**: [https://modelcontextprotocol.io](https://modelcontextprotocol.io)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

GhidraMCP is provided as-is for reverse engineering and security research purposes. Users are responsible for ensuring they have proper authorization before analyzing binaries. The authors make no warranties about the accuracy or completeness of analysis results.

## 🌟 Acknowledgments

- Built on [Ghidra](https://ghidra-sre.org) by the National Security Agency
- Uses the [Model Context Protocol](https://modelcontextprotocol.io) specification
- Inspired by reverse engineering workflows and AI-assisted analysis

## 📄 License

Apache License 2.0 - See [LICENSE](./LICENSE) file for details.

## 🔗 Links

- **GitHub**: [https://github.com/LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- **Releases**: [https://github.com/LaurieWired/GhidraMCP/releases](https://github.com/LaurieWired/GhidraMCP/releases)
- **Follow**: [@lauriewired](https://twitter.com/lauriewired)
