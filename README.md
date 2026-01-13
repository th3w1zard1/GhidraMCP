[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/th3w1zard1/GhidraMCP)](https://github.com/th3w1zard1/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/th3w1zard1/GhidraMCP)](https://github.com/th3w1zard1/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/th3w1zard1/GhidraMCP)](https://github.com/th3w1zard1/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/th3w1zard1/GhidraMCP)](https://github.com/th3w1zard1/GhidraMCP/graphs/contributors)
[![Follow @th3w1zard1](https://img.shields.io/twitter/follow/th3w1zard1?style=social)](https://twitter.com/th3w1zard1)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

# GhidraMCP - AI-Powered Reverse Engineering with Ghidra

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-light.svg)](https://cursor.com/en/install-mcp?name=ghidra&config=eyJjb21tYW5kIjoicHl0aG9uIiwiYXJncyI6WyIvQUJTT0xVVEVfUEFUSF9UTy9icmlkZ2VfbWNwX2doaWRyYS5weSIsIi0tZ2hpZHJhLXNlcnZlciIsImh0dHA6Ly8xMjcuMC4wLjE6ODA4MC8iXX0%3D)

GhidraMCP is a Model Context Protocol (MCP) server that enables AI language models to autonomously reverse engineer applications using Ghidra's powerful analysis capabilities. It exposes 90 comprehensive tools covering decompilation, call graphs, data flow analysis, vtable detection, structures, data types, and much more.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9

## ❌ The Problem: Manual Reverse Engineering is Slow

- Time-consuming manual analysis of binaries
- Repetitive tasks like renaming functions and variables
- Difficult to trace data flow and call relationships
- Hard to discover patterns across large codebases
- Limited automation for reverse engineering workflows

## ✅ The Solution: AI-Assisted Reverse Engineering

- **90 comprehensive tools** for binary analysis
- **Automated decompilation** and variable renaming
- **Call graph analysis** to understand function relationships
- **Data flow tracing** to track value origins and uses
- **Vtable detection** for C++ binary analysis
- **Constants search** to find magic numbers and error codes
- **Bookmark management** for organizing analysis findings
- **Memory analysis** with hex dumps and block inspection

GhidraMCP bridges Ghidra's powerful reverse engineering capabilities with AI language models, enabling autonomous binary analysis.

## Ghidra
First, download the latest [release](https://github.com/th3w1zard1/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

```txt
Analyze the main function and trace where user input flows. Use GhidraMCP tools.
```

## 🛠️ Installation

### 📋 Requirements

- [Ghidra](https://ghidra-sre.org) 12.0 or later
- Python 3.10+ with `requests` and `mcp` packages
- MCP-compatible client (Cursor, Claude Desktop, VS Code, etc.)

### Step 1: Install Ghidra Plugin

1. Download the latest [release](https://github.com/th3w1zard1/GhidraMCP/releases) from this repository
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

GhidraMCP provides **17 consolidated tools** that replace the original 90 tools through intelligent parameterization. This design reduces LLM context overhead, improves tool selection reliability, and maintains 100% feature coverage. Each tool uses enums, optional parameters, and defaults to provide flexible, powerful functionality.

### 1. `get_function`

Unified function retrieval tool that replaces: `decompile_function`, `decompile_function_by_address`, `get_decompilation`, `disassemble_function`, `get_function_by_address`, `get_function_info`, `list_function_calls`

Get function details in various formats: decompiled code, assembly, function information, or internal calls.

Args:
    identifier: Function name or address (required) - accepts either function name or hex address (e.g., "main" or "0x401000")
    view: View mode enum ('decompile', 'disassemble', 'info', 'calls'; default: 'decompile')
    offset: Line number to start reading from when view='decompile' (1-based, default: 1)
    limit: Number of lines to return when view='decompile' (default: 50)
    include_callers: Include list of functions that call this one when view='decompile' (default: False)
    include_callees: Include list of functions this one calls when view='decompile' (default: False)
    include_comments: Whether to include comments in the decompilation when view='decompile' (default: False)
    include_incoming_references: Whether to include incoming cross references when view='decompile' (default: True)
    include_reference_context: Whether to include code context snippets from calling functions when view='decompile' (default: True)

Returns:
    - When view='decompile': JSON with decompiled C code and optional metadata
    - When view='disassemble': List of assembly instructions (address: instruction; comment)
    - When view='info': Detailed function information including parameters and local variables
    - When view='calls': List of function calls made within the function

### 2. `list_functions`

Comprehensive function listing and search tool that replaces: `list_functions`, `list_methods`, `search_functions_by_name`, `get_functions_by_similarity`, `get_undefined_function_candidates`, `get_function_count`

List, search, or count functions in the program with various filtering and search modes.

Args:
    mode: Operation mode enum ('all', 'search', 'similarity', 'undefined', 'count'; default: 'all')
    query: Substring to search for when mode='search' (required for search mode)
    search_string: Function name to compare against for similarity when mode='similarity' (required for similarity mode)
    min_reference_count: Minimum number of references required when mode='undefined' (default: 1)
    start_index: Starting index for pagination (0-based, default: 0)
    max_count: Maximum number of functions to return (default: 100)
    offset: Alternative pagination offset parameter (default: 0, used for backward compatibility)
    limit: Alternative pagination limit parameter (default: 100, used for backward compatibility)
    filter_default_names: Whether to filter out default Ghidra generated names like FUN_, DAT_, etc. (default: True)

Returns:
    - When mode='all': List of all function names with pagination
    - When mode='search': List of functions whose name contains the query substring
    - When mode='similarity': JSON with matching functions sorted by similarity to search_string
    - When mode='undefined': JSON with undefined function candidates (addresses referenced but not defined as functions)
    - When mode='count': JSON with total function count

### 3. `manage_function`

Function and variable manipulation tool that replaces: `create_function`, `rename_function`, `rename_function_by_address`, `rename_variable`, `rename_variables`, `set_function_prototype`, `set_local_variable_type`, `change_variable_datatypes`

Create, rename, or modify functions and their variables.

Args:
    action: Action to perform enum ('create', 'rename_function', 'rename_variable', 'set_prototype', 'set_variable_type', 'change_datatypes'; required)
    address: Address where the function should be created when action='create' (e.g., '0x401000', required for create)
    function_identifier: Function name or address for rename/modify operations (required for rename_function, rename_variable, set_prototype, set_variable_type, change_datatypes)
    name: New function name when action='rename_function' or optional name when action='create' (optional)
    old_name: Old variable name when action='rename_variable' (required for rename_variable)
    new_name: New variable name when action='rename_variable' (required for rename_variable)
    variable_mappings: Mapping of old to new variable names when action='rename_variable' (format: "oldName1:newName1,oldName2:newName2", required for rename_variable with multiple variables)
    prototype: Function prototype/signature string when action='set_prototype' (required for set_prototype)
    variable_name: Variable name when action='set_variable_type' (required for set_variable_type)
    new_type: New data type for variable when action='set_variable_type' (required for set_variable_type)
    datatype_mappings: Mapping of variable names to new data type strings when action='change_datatypes' (format: "varName1:type1,varName2:type2", required for change_datatypes)
    archive_name: Optional name of the data type archive to search for data types when action='change_datatypes' (optional, default: "")

Returns:
    Success or failure message for all actions

### 4. `get_call_graph`

Call graph and relationship analysis tool that replaces: `get_call_graph`, `get_call_tree`, `get_function_callers`, `get_function_callees`, `get_callers_decompiled`, `find_common_callers`

Analyze function call relationships in various formats: bidirectional graphs, hierarchical trees, caller/callee lists, decompiled callers, or common callers.

Args:
    function_identifier: Function name or address (required)
    mode: Analysis mode enum ('graph', 'tree', 'callers', 'callees', 'callers_decomp', 'common_callers'; default: 'graph')
    depth: Depth of call graph to retrieve when mode='graph' (default: 1)
    direction: Direction to traverse when mode='tree' or 'callers' or 'callees' enum ('callers', 'callees'; default: 'callees' for tree)
    max_depth: Maximum depth to traverse when mode='tree' (default: 3, max: 10)
    start_index: Starting index for pagination when mode='callers_decomp' (0-based, default: 0)
    max_callers: Maximum number of calling functions to decompile when mode='callers_decomp' (default: 10)
    include_call_context: Whether to highlight the line containing the call in each decompilation when mode='callers_decomp' (default: True)
    function_addresses: Comma-separated list of function addresses or names when mode='common_callers' (required for common_callers mode)

Returns:
    - When mode='graph': Call graph information showing both callers and callees
    - When mode='tree': Hierarchical call tree as formatted text
    - When mode='callers': List of functions that call the specified function
    - When mode='callees': List of functions called by the specified function
    - When mode='callers_decomp': JSON with decompiled callers
    - When mode='common_callers': List of functions that call ALL of the specified target functions

### 5. `get_references`

Comprehensive cross-reference analysis tool that replaces: `get_xrefs_to`, `get_xrefs_from`, `find_cross_references`, `get_function_xrefs`, `get_referencers_decompiled`, `find_import_references`, `resolve_thunk`

Find and analyze references to/from addresses, symbols, functions, or imports, with optional decompilation of referencers.

Args:
    target: Target address, symbol name, function name, or import name (required)
    mode: Reference mode enum ('to', 'from', 'both', 'function', 'referencers_decomp', 'import', 'thunk'; default: 'both')
    direction: Direction filter when mode='both' enum ('to', 'from', 'both'; default: 'both')
    offset: Pagination offset (default: 0)
    limit: Maximum number of references to return (default: 100)
    max_results: Alternative limit parameter for import mode (default: 100)
    library_name: Optional specific library name to narrow search when mode='import' (case-insensitive, optional)
    start_index: Starting index for pagination when mode='referencers_decomp' (0-based, default: 0)
    max_referencers: Maximum number of referencing functions to decompile when mode='referencers_decomp' (default: 10)
    include_ref_context: Whether to include reference line numbers in decompilation when mode='referencers_decomp' (default: True)
    include_data_refs: Whether to include data references (reads/writes), not just calls when mode='referencers_decomp' (default: True)

Returns:
    - When mode='to': List of references TO the specified address
    - When mode='from': List of references FROM the specified address
    - When mode='both': List of cross-references in both directions
    - When mode='function': List of references to the specified function by name
    - When mode='referencers_decomp': JSON with decompiled referencers
    - When mode='import': JSON with references to the imported function
    - When mode='thunk': JSON with thunk chain information

### 6. `analyze_data_flow`

Data flow analysis tool that replaces: `trace_data_flow_backward`, `trace_data_flow_forward`, `find_variable_accesses`

Trace data flow backward (origins), forward (uses), or find variable accesses within a function.

Args:
    function_address: Address of the function to analyze (required)
    start_address: Address within the function to trace from when direction='backward' or 'forward' (required for backward/forward)
    variable_name: Name of the variable to find accesses for when direction='variable_accesses' (required for variable_accesses)
    direction: Analysis direction enum ('backward', 'forward', 'variable_accesses'; required)

Returns:
    - When direction='backward': Data flow information showing where values come from
    - When direction='forward': Data flow information showing where values are used
    - When direction='variable_accesses': List of variable accesses (reads and writes)

### 7. `search_constants`

Constant value search and analysis tool that replaces: `find_constant_uses`, `find_constants_in_range`, `list_common_constants`

Find specific constants, constants in ranges, or list the most common constants in the program.

Args:
    mode: Search mode enum ('specific', 'range', 'common'; required)
    value: Constant value to search for when mode='specific' (supports hex with 0x, decimal, negative; required for specific mode)
    min_value: Minimum value when mode='range' or filter minimum when mode='common' (inclusive, supports hex/decimal; required for range mode)
    max_value: Maximum value when mode='range' (inclusive, supports hex/decimal; required for range mode)
    max_results: Maximum number of results to return when mode='specific' or 'range' (default: 500)
    include_small_values: Include small values (0-255) which are often noise when mode='common' (default: False)
    top_n: Number of most common constants to return when mode='common' (default: 50)

Returns:
    - When mode='specific': List of instructions using the constant
    - When mode='range': List of constants found in the range with occurrence counts
    - When mode='common': JSON with most common constants

### 8. `manage_strings`

String listing, searching, and analysis tool that replaces: `list_strings`, `get_strings`, `search_strings_regex`, `get_strings_count`, `get_strings_by_similarity`

List, search, count, or find similar strings in the program.

Args:
    mode: Operation mode enum ('list', 'regex', 'count', 'similarity'; default: 'list')
    pattern: Regular expression pattern to search for when mode='regex' (required for regex mode)
    search_string: String to compare against for similarity when mode='similarity' (required for similarity mode)
    filter: Optional filter to match within string content when mode='list' (optional)
    start_index: Starting index for pagination when mode='list' or 'similarity' (0-based, default: 0)
    max_count: Maximum number of strings to return when mode='list' or 'similarity' (default: 100)
    offset: Alternative pagination offset when mode='list' (default: 0, used for backward compatibility)
    limit: Alternative pagination limit when mode='list' (default: 2000, used for backward compatibility)
    max_results: Maximum number of results to return when mode='regex' (default: 100)
    include_referencing_functions: Include list of functions that reference each string when mode='list' or 'similarity' (default: False)

Returns:
    - When mode='list': JSON with strings list and pagination info, or list of strings with their addresses
    - When mode='regex': List of strings matching the regex pattern
    - When mode='count': Total number of defined strings
    - When mode='similarity': JSON with matching strings sorted by similarity

### 9. `inspect_memory`

Memory and data inspection tool that replaces: `get_memory_blocks`, `read_memory`, `get_data_at_address`, `list_data_items`, `list_segments`

Inspect memory blocks, read memory, get data information, list data items, or list memory segments.

Args:
    mode: Inspection mode enum ('blocks', 'read', 'data_at', 'data_items', 'segments'; required)
    address: Address to read from when mode='read' or address to query when mode='data_at' (required for read/data_at modes)
    length: Number of bytes to read when mode='read' (default: 16)
    offset: Pagination offset when mode='data_items' or 'segments' (default: 0)
    limit: Maximum number of items to return when mode='data_items' or 'segments' (default: 100)

Returns:
    - When mode='blocks': List of memory blocks with their properties (R/W/X, size, etc.)
    - When mode='read': Hex dump of memory content with ASCII representation
    - When mode='data_at': Data type, size, label, and value information
    - When mode='data_items': List of defined data labels and their values
    - When mode='segments': List of all memory segments in the program

### 10. `manage_bookmarks`

Bookmark management tool that replaces: `set_bookmark`, `get_bookmarks`, `search_bookmarks`, `remove_bookmark`, `list_bookmark_categories`

Create, retrieve, search, remove bookmarks, or list bookmark categories.

Args:
    action: Action to perform enum ('set', 'get', 'search', 'remove', 'categories'; required)
    address: Address where to set/get/remove the bookmark (required for set/remove, optional for get)
    address_or_symbol: Address or symbol name (alternative parameter name, used for remove action)
    type: Bookmark type enum ('Note', 'Warning', 'TODO', 'Bug', 'Analysis'; required for set/remove, optional for get/categories)
    category: Bookmark category for organization (required for set, optional for remove)
    comment: Bookmark comment text (required for set)
    search_text: Text to search for in bookmark comments when action='search' (required for search)
    max_results: Maximum number of results to return when action='search' (default: 100)

Returns:
    - When action='set': Success or failure message
    - When action='get': List of bookmarks
    - When action='search': List of matching bookmarks
    - When action='remove': Success or failure message
    - When action='categories': JSON with bookmark categories

### 11. `manage_comments`

Comment management and search tool that replaces: `set_decompiler_comment`, `set_disassembly_comment`, `set_decompilation_comment`, `set_comment`, `get_comments`, `remove_comment`, `search_comments`, `search_decompilation`

Set, get, remove, or search comments in decompiled code, disassembly, or at addresses. Also search patterns across all decompilations.

Args:
    action: Action to perform enum ('set', 'get', 'remove', 'search', 'search_decomp'; required)
    address: Address where to set/get/remove the comment (required for set/remove when not using function/line_number)
    address_or_symbol: Address or symbol name (alternative parameter, used for set/get/remove)
    function: Function name or address when setting decompilation line comment or searching decompilation (required for set with line_number, optional for search_decomp)
    function_name_or_address: Function name or address (alternative parameter name)
    line_number: Line number in the decompiled function when action='set' with decompilation (1-based, required for decompilation line comments)
    comment: The comment text to set (required for set)
    comment_type: Type of comment enum ('pre', 'eol', 'post', 'plate', 'repeatable'; default: 'eol')
    start: Start address of the range when action='get' (optional)
    end: End address of the range when action='get' (optional)
    comment_types: Types of comments to retrieve/search (comma-separated: pre,eol,post,plate,repeatable; optional)
    search_text: Text to search for in comments when action='search' (required for search)
    pattern: Regular expression pattern to search for when action='search_decomp' (required for search_decomp)
    case_sensitive: Whether search is case sensitive when action='search' or 'search_decomp' (default: False)
    max_results: Maximum number of results to return when action='search' or 'search_decomp' (default: 100 for search, 50 for search_decomp)
    override_max_functions_limit: Whether to override the maximum function limit for decompiler searches when action='search_decomp' (default: False)

Returns:
    - When action='set': Success or failure message, or JSON with success status for decompilation line comments
    - When action='get': JSON with comments
    - When action='remove': Success or failure message
    - When action='search': JSON with matching comments
    - When action='search_decomp': JSON with search results from decompiled functions

### 12. `analyze_vtables`

Virtual function table analysis tool that replaces: `analyze_vtable`, `find_vtable_callers`, `find_vtables_containing_function`

Analyze vtables, find vtable callers, or find vtables containing a specific function.

Args:
    mode: Analysis mode enum ('analyze', 'callers', 'containing'; required)
    vtable_address: Address of the vtable to analyze when mode='analyze' (required for analyze mode)
    function_address: Address or name of the virtual function when mode='callers' or function to search for when mode='containing' (required for callers/containing modes)
    max_entries: Maximum number of vtable entries to read when mode='analyze' (default: 200)

Returns:
    - When mode='analyze': Vtable structure with function pointers and slot information
    - When mode='callers': List of potential caller sites for the virtual method
    - When mode='containing': JSON with vtables containing the function

### 13. `manage_symbols`

Symbol and label management tool that replaces: `list_classes`, `list_namespaces`, `list_imports`, `list_exports`, `create_label`, `get_symbols`, `get_symbols_count`, `rename_data`

List classes, namespaces, imports, exports, create labels, get symbols, count symbols, or rename data labels.

Args:
    mode: Operation mode enum ('classes', 'namespaces', 'imports', 'exports', 'create_label', 'symbols', 'count', 'rename_data'; required)
    address: Address where to create the label when mode='create_label' or address of data to rename when mode='rename_data' (required for create_label/rename_data)
    label_name: Name for the label when mode='create_label' (required for create_label)
    new_name: New name for the data label when mode='rename_data' (required for rename_data)
    library_filter: Optional library name to filter by when mode='imports' (case-insensitive, optional)
    max_results: Maximum number of imports/exports to return when mode='imports' or 'exports' (default: 500)
    start_index: Starting index for pagination (0-based, default: 0)
    offset: Alternative pagination offset parameter (default: 0, used for backward compatibility)
    limit: Alternative pagination limit parameter (default: 100, used for backward compatibility)
    group_by_library: Whether to group imports by library name when mode='imports' (default: True)
    include_external: Whether to include external symbols when mode='symbols' or 'count' (default: False)
    max_count: Maximum number of symbols to return when mode='symbols' (default: 200)
    filter_default_names: Whether to filter out default Ghidra generated names when mode='symbols' or 'count' (default: True)

Returns:
    - When mode='classes': List of all namespace/class names with pagination
    - When mode='namespaces': List of all non-global namespaces with pagination
    - When mode='imports': JSON with imports list or grouped by library
    - When mode='exports': JSON with exports list
    - When mode='create_label': Success or failure message
    - When mode='symbols': JSON with symbols
    - When mode='count': JSON with symbol count
    - When mode='rename_data': Success or failure message

### 14. `manage_structures`

Structure management tool that replaces: `parse_c_structure`, `validate_c_structure`, `create_structure`, `add_structure_field`, `modify_structure_field`, `modify_structure_from_c`, `get_structure_info`, `list_structures`, `apply_structure`, `delete_structure`, `parse_c_header`

Parse, validate, create, modify, query, list, apply, or delete structures. Also parse entire C header files.

Args:
    action: Action to perform enum ('parse', 'validate', 'create', 'add_field', 'modify_field', 'modify_from_c', 'info', 'list', 'apply', 'delete', 'parse_header'; required)
    c_definition: C-style structure definition when action='parse', 'validate', or 'modify_from_c' (required for parse/validate/modify_from_c)
    header_content: C header file content when action='parse_header' (required for parse_header)
    structure_name: Name of the structure (required for add_field, modify_field, info, apply, delete; optional for list)
    name: Name of the structure when action='create' (required for create)
    size: Initial size when action='create' (0 for auto-sizing, default: 0)
    type: Structure type when action='create' enum ('structure', 'union'; default: 'structure')
    category: Category path (default: '/')
    packed: Whether structure should be packed when action='create' (default: False)
    description: Description of the structure when action='create' (optional)
    field_name: Name of the field when action='add_field' or 'modify_field' (required for add_field, optional for modify_field)
    data_type: Data type when action='add_field' (e.g., 'int', 'char[32]', required for add_field)
    offset: Field offset when action='add_field' or 'modify_field' (optional, omit to append for add_field)
    comment: Field comment when action='add_field' (optional)
    new_data_type: New data type for the field when action='modify_field' (optional)
    new_field_name: New name for the field when action='modify_field' (optional)
    new_comment: New comment for the field when action='modify_field' (optional)
    new_length: New length for the field when action='modify_field' (advanced, optional)
    address_or_symbol: Address or symbol name to apply structure when action='apply' (required for apply)
    clear_existing: Clear existing data when action='apply' (default: True)
    force: Force deletion even if structure is referenced when action='delete' (default: False)
    name_filter: Filter by name (substring match) when action='list' (optional)
    include_built_in: Include built-in types when action='list' (default: False)

Returns:
    - When action='parse': JSON with created structure info
    - When action='validate': JSON with validation result
    - When action='create': JSON with created structure info
    - When action='add_field': JSON with success status
    - When action='modify_field': JSON with success status
    - When action='modify_from_c': JSON with success status
    - When action='info': JSON with structure info including all fields
    - When action='list': JSON with list of structures
    - When action='apply': JSON with success status
    - When action='delete': JSON with success status or reference warnings
    - When action='parse_header': JSON with created types info

### Structures

### 15. `manage_data_types`

Data type management tool that replaces: `get_data_type_archives`, `get_data_types`, `get_data_type_by_string`, `apply_data_type`

Get data type archives, list data types, get data type by string representation, or apply data types to addresses/symbols.

Args:
    action: Action to perform enum ('archives', 'list', 'by_string', 'apply'; required)
    archive_name: Name of the data type archive when action='list', 'by_string', or 'apply' (required for list, optional for by_string/apply)
    category_path: Path to category to list data types from when action='list' (e.g., '/Structure', use '/' for root, default: '/')
    include_subcategories: Whether to include data types from subcategories when action='list' (default: False)
    start_index: Starting index for pagination when action='list' (0-based, default: 0)
    max_count: Maximum number of data types to return when action='list' (default: 100)
    data_type_string: String representation of the data type when action='by_string' or 'apply' (e.g., 'char**', 'int[10]', required for by_string/apply)
    address_or_symbol: Address or symbol name to apply the data type to when action='apply' (required for apply)

Returns:
    - When action='archives': JSON with data type archives
    - When action='list': JSON with data types
    - When action='by_string': JSON with data type information
    - When action='apply': Success or failure message

### Data Types

### 16. `get_current_context`

Current context retrieval tool that replaces: `get_current_address`, `get_current_function`

Get the address or function currently selected in the Ghidra GUI.

Args:
    mode: Context mode enum ('address', 'function', 'both'; default: 'both')

Returns:
    - When mode='address': The address currently selected by the user
    - When mode='function': The function currently selected by the user
    - When mode='both': JSON with both current address and function

### Current Context

### 17. `manage_function_tags`

Function tag management tool that replaces: `function_tags`

Manage function tags to categorize functions (e.g., 'AI', 'rendering'). Tags can be retrieved, set, added, removed, or listed.

Args:
    function: Function name or address (required for get/set/add/remove modes, not required for list mode)
    mode: Operation mode enum ('get', 'set', 'add', 'remove', 'list'; required)
    tags: Tag names (required for add mode; optional for set/remove modes). Comma-separated format (e.g., "AI,rendering,encryption")

Returns:
    - When mode='get': JSON with tag information for the specified function
    - When mode='set': Success message after replacing all tags on the function
    - When mode='add': Success message after adding tags to the function
    - When mode='remove': Success message after removing tags from the function
    - When mode='list': JSON with all tags in the program

---

## 📊 Tool Consolidation Summary

The 17 consolidated tools above replace all 90 original tools while maintaining 100% feature coverage:

- **Function Analysis**: `get_function`, `list_functions`, `manage_function`
- **Call Analysis**: `get_call_graph`, `get_references`
- **Data Analysis**: `analyze_data_flow`, `search_constants`, `manage_strings`, `inspect_memory`
- **Annotations**: `manage_bookmarks`, `manage_comments`
- **Advanced Analysis**: `analyze_vtables`
- **Symbol Management**: `manage_symbols`
- **Structure Management**: `manage_structures`
- **Type Management**: `manage_data_types`
- **Context & Tags**: `get_current_context`, `manage_function_tags`

Each tool uses mode/action enums and optional parameters to provide the same functionality as multiple original tools, reducing LLM context size and improving tool selection reliability.

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

## 🌟 Acknowledgments

- Built on [Ghidra](https://ghidra-sre.org) by the National Security Agency
- Uses the [Model Context Protocol](https://modelcontextprotocol.io) specification
- Inspired by reverse engineering workflows and AI-assisted analysis

## 📄 License

Apache License 2.0 - See [LICENSE](./LICENSE) file for details.

## 🔗 Links

- **GitHub**: [https://github.com/th3w1zard1/GhidraMCP](https://github.com/th3w1zard1/GhidraMCP)
- **Releases**: [https://github.com/th3w1zard1/GhidraMCP/releases](https://github.com/th3w1zard1/GhidraMCP/releases)
- **Follow**: [@th3w1zard1](https://twitter.com/th3w1zard1)
