[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

# GhidraMCP - AI-Powered Reverse Engineering with Ghidra

GhidraMCP is a Model Context Protocol (MCP) server that enables AI language models to autonomously reverse engineer applications using Ghidra's powerful analysis capabilities. It exposes 39 comprehensive tools for binary analysis, decompilation, data flow tracking, and more.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9

## ❌ The Problem: Manual Reverse Engineering is Slow

- Time-consuming manual analysis of binaries
- Repetitive tasks like renaming functions and variables
- Difficult to track data flow and call relationships
- Limited AI assistance in reverse engineering workflows

## ✅ The Solution: AI-Assisted Reverse Engineering

- **39 comprehensive tools** for binary analysis and manipulation
- **Direct Ghidra integration** - works with your existing Ghidra projects
- **Automated analysis** - let AI handle repetitive reverse engineering tasks
- **Real-time collaboration** - AI agents can work alongside you in Ghidra

GhidraMCP bridges the gap between Ghidra's powerful reverse engineering capabilities and AI language models, enabling autonomous binary analysis, decompilation, and code understanding.

Just tell your AI assistant to **analyze the binary**:

```txt
Analyze the main function in this binary and explain what it does. Use GhidraMCP to decompile and trace data flow.
```

## 🛠️ Installation

### 📋 Requirements

- [Ghidra](https://ghidra-sre.org) installed and configured
- Python 3.10+ (for MCP bridge)
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

https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3

### Step 2: Configure MCP Client

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

Replace `/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py` with the actual path to the bridge file in this repository.

You can also install in a specific project by creating `.cursor/mcp.json` in your project folder. See [Cursor MCP docs](https://docs.cursor.com/context/model-context-protocol) for more info.

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

Replace `/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py` with the actual path to the bridge file.

</details>

<details>
<summary><b>Install in Claude Code</b></summary>

### Install in Claude Code

Run this command. See [Claude Code MCP docs](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/tutorials#set-up-model-context-protocol-mcp) for more info.

```sh
claude mcp add ghidra -- python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
```

Or for SSE transport:

```sh
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
claude mcp add --transport sse ghidra -- http://127.0.0.1:8081/sse
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

To use GhidraMCP with [Cline](https://cline.bot), you need to run the MCP server with SSE transport:

1. Start the bridge server:
```bash
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

2. In Cline, select `MCP Servers` at the top
3. Select `Remote Servers` and add:
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

1. Open 5ire and go to `Tools` -> `New`
2. Set the following configurations:
   - Tool Key: `ghidra`
   - Name: `GhidraMCP`
   - Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

</details>

<details>
<summary><b>Install in Zed</b></summary>

### Install in Zed

Add this to your Zed configuration:

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

Open the "Settings" page, navigate to "Plugins," and enter:

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

More info: [BoltAI Documentation](https://docs.boltai.com/docs/plugins/mcp-servers)

</details>

<details>
<summary><b>Install in Windows</b></summary>

### Install in Windows

On Windows, use `cmd` with `/c` flag:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "cmd",
      "args": [
        "/c",
        "python",
        "C:\\FULL\\PATH\\TO\\bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

</details>

## 🔨 Available Tools

GhidraMCP provides **39 comprehensive tools** for reverse engineering:

### Core Analysis Tools

- **`decompile_function`** / **`decompile_function_by_address`**: Decompile functions to C-like pseudocode
- **`disassemble_function`**: Get assembly code for functions
- **`list_methods`** / **`list_functions`**: List all functions in the program
- **`get_function_by_address`** / **`get_function_info`**: Get detailed function information
- **`get_current_function`** / **`get_current_address`**: Get currently selected function/address
- **`search_functions_by_name`**: Search functions by name substring

### Function Manipulation

- **`rename_function`** / **`rename_function_by_address`**: Rename functions
- **`set_function_prototype`**: Set function signatures
- **`rename_variable`**: Rename local variables in functions
- **`set_local_variable_type`**: Change variable data types
- **`list_function_calls`**: List all function calls within a function

### Call Graph & Relationships

- **`get_call_graph`**: Get bidirectional call graph (callers + callees) with configurable depth
- **`get_function_callers`**: List all functions that call a specific function
- **`get_function_callees`**: List all functions called by a specific function

### Cross-References

- **`get_xrefs_to`**: Get all references TO an address
- **`get_xrefs_from`**: Get all references FROM an address
- **`get_function_xrefs`**: Get references to a function by name
- **`find_cross_references`**: Find cross-references with directional filtering

### Strings Analysis

- **`list_strings`**: List all defined strings with addresses (with filtering)
- **`search_strings_regex`**: Search strings using regex patterns
- **`get_strings_count`**: Get total count of strings in program

### Constants & Data Flow

- **`find_constant_uses`**: Find all uses of a specific constant value
- **`find_constants_in_range`**: Find constants within a numeric range
- **`trace_data_flow_backward`**: Trace data flow backward to find origins
- **`trace_data_flow_forward`**: Trace data flow forward to find uses

### Memory & Data

- **`get_memory_blocks`**: List all memory blocks with permissions
- **`read_memory`**: Read memory at address with hex dump
- **`get_data_at_address`**: Get detailed data information at address
- **`list_data_items`**: List defined data labels and values
- **`rename_data`**: Rename data labels at addresses
- **`create_label`**: Create or update labels at addresses

### Vtable Analysis (C++)

- **`analyze_vtable`**: Analyze virtual function tables
- **`find_vtable_callers`**: Find indirect calls via vtable slots

### Bookmarks & Annotations

- **`set_bookmark`**: Create bookmarks with type/category/comment
- **`get_bookmarks`**: Retrieve bookmarks by address or type
- **`search_bookmarks`**: Search bookmarks by comment text
- **`set_decompiler_comment`** / **`set_disassembly_comment`**: Set comments at addresses

### Program Information

- **`list_classes`** / **`list_namespaces`**: List namespaces and classes
- **`list_segments`**: List memory segments
- **`list_imports`**: List imported symbols
- **`list_exports`**: List exported functions/symbols

## 💡 Tips

### Start with High-Level Analysis

Begin by understanding the program structure before diving into specific functions:

```txt
List all functions in this binary and identify the main entry point. Then analyze the main function's call graph.
```

### Use Data Flow for Understanding

Trace how values flow through the program to understand algorithms:

```txt
Trace data flow backward from address 0x401234 to find where this value originates.
```

### Leverage Bookmarks for Organization

Use bookmarks to mark important findings during analysis:

```txt
Set a bookmark at address 0x401000 with type "Analysis" and comment "Encryption function identified"
```

### Search for Patterns

Use regex and constant searches to find interesting code patterns:

```txt
Search for strings matching the pattern "password|secret|key" and find all uses of constant 0xdeadbeef
```

### Analyze C++ Binaries

For C++ binaries, use vtable analysis to understand class hierarchies:

```txt
Analyze the vtable at address 0x405000 and find all callers of virtual methods
```

## 🏗️ Building from Source

### Prerequisites

1. Java Development Kit (JDK) 11 or higher
2. Maven 3.6+
3. Ghidra installation

### Build Steps

1. **Copy Ghidra JARs** to the project's `lib/` directory:
   - `Ghidra/Features/Base/lib/Base.jar`
   - `Ghidra/Features/Decompiler/lib/Decompiler.jar`
   - `Ghidra/Framework/Docking/lib/Docking.jar`
   - `Ghidra/Framework/Generic/lib/Generic.jar`
   - `Ghidra/Framework/Project/lib/Project.jar`
   - `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
   - `Ghidra/Framework/Utility/lib/Utility.jar`
   - `Ghidra/Framework/Gui/lib/Gui.jar`

2. **Build with Maven**:
   ```bash
   mvn clean package assembly:single
   ```

3. **Install the extension**:
   - The generated zip file (`target/GhidraMCP-*.zip`) contains:
     - `lib/GhidraMCP.jar`
     - `extension.properties`
     - `Module.manifest`
   - Install via Ghidra's `File` -> `Install Extensions`

### Python Bridge Setup

The Python bridge requires:

```bash
pip install -r requirements.txt
```

Or install dependencies manually:
- `requests>=2,<3`
- `mcp>=1.2.0,<2`

## 🚨 Troubleshooting

<details>
<summary><b>Ghidra Plugin Not Loading</b></summary>

1. Ensure Ghidra is restarted after installing the extension
2. Check that the plugin is enabled: `File` -> `Configure` -> `Developer` -> `GhidraMCPPlugin`
3. Verify the extension is installed: `File` -> `Install Extensions` (should show as installed)
4. Check Ghidra's console for error messages

</details>

<details>
<summary><b>HTTP Server Not Starting</b></summary>

1. Check if port 8080 is already in use:
   ```bash
   # Linux/macOS
   lsof -i :8080
   
   # Windows
   netstat -ano | findstr :8080
   ```

2. Change the port in Ghidra: `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server` -> `Server Port`

3. Update your MCP client configuration to use the new port

</details>

<details>
<summary><b>Python Bridge Connection Errors</b></summary>

1. Verify Ghidra is running and the HTTP server is active
2. Check the `--ghidra-server` URL matches your Ghidra instance (default: `http://127.0.0.1:8080/`)
3. Ensure Python can access the bridge script:
   ```bash
   python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
   ```
4. For SSE transport issues, ensure the MCP port (default: 8081) is available

</details>

<details>
<summary><b>MCP Client Not Recognizing Tools</b></summary>

1. Restart your MCP client after configuration changes
2. Verify the bridge script path is absolute and correct
3. Check Python version (requires 3.10+):
   ```bash
   python --version
   ```
4. Ensure all Python dependencies are installed:
   ```bash
   pip install -r requirements.txt
   ```

</details>

<details>
<summary><b>Program Not Found Errors</b></summary>

1. Ensure a program is loaded in Ghidra (not just a project)
2. The program must be analyzed (run auto-analysis if needed)
3. Some tools require specific program states (e.g., decompilation requires analyzed functions)

</details>

<details>
<summary><b>Decompilation Failures</b></summary>

1. Ensure the function has been analyzed by Ghidra
2. Some functions may fail to decompile (e.g., obfuscated code, incomplete analysis)
3. Try running auto-analysis: `Analysis` -> `Auto Analyze`
4. Check Ghidra's console for decompiler error messages

</details>

## 📚 Additional Resources

- [Ghidra Official Documentation](https://ghidra-sre.org/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [Implementation Summary](./IMPLEMENTATION_SUMMARY.md) - Detailed tool documentation

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

GhidraMCP is provided as-is for reverse engineering and security research purposes. Users are responsible for ensuring they have proper authorization before analyzing binaries. The authors make no warranties about the accuracy or completeness of analysis results.

## 🌟 Let's Connect!

- 🐦 Follow [@lauriewired](https://twitter.com/lauriewired) on X for updates
- 📧 Report issues on [GitHub Issues](https://github.com/LaurieWired/GhidraMCP/issues)
- 💬 Join discussions in [GitHub Discussions](https://github.com/LaurieWired/GhidraMCP/discussions)

## License

Apache License 2.0 - see [LICENSE](./LICENSE) file for details.
