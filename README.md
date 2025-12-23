[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

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

Just tell your AI assistant to **analyze the binary**:

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

Or for SSE transport:

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

GhidraMCP provides **90 comprehensive tools** organized into 16 categories:

### Core Analysis Tools

- **`decompile_function`**: Decompile a function by name to C pseudocode
  
  Decompile a specific function by name and return the decompiled C code.

- **`decompile_function_by_address`**: Decompile a function at a specific address
  
  Decompile a function at the given address.

- **`get_decompilation`**: Get decompiled code for a function with line range support and optional metadata
  
  Get decompiled code for a function with line range support.
  
  Args:
      function_name_or_address: Function name or address to decompile
      offset: Line number to start reading from (1-based, default: 1)
      limit: Number of lines to return (default: 50)
      include_callers: Include list of functions that call this one
      include_callees: Include list of functions this one calls
      include_comments: Whether to include comments in the decompilation
      include_incoming_references: Whether to include incoming cross references
      include_reference_context: Whether to include code context snippets from calling functions
  
  Returns:
      JSON with decompiled code and optional metadata

- **`disassemble_function`**: Get assembly code for a function
  
  Get assembly code (address: instruction; comment) for a function.

- **`get_function_by_address`**: Get function information by address
  
  Get a function by its address.

- **`get_function_info`**: Get detailed function info with parameters and locals
  
  Get detailed information about a function.
  
  Args:
      address: Address of the function
  
  Returns:
      Detailed function information including parameters and local variables

- **`list_functions`**: List all functions in the program
  
  List all functions in the database.

- **`list_methods`**: List all function names with pagination
  
  List all function names in the program with pagination.

- **`list_function_calls`**: List all function calls within a function
  
  List all function calls within a specific function.
  
  Args:
      function_address: Address of the function to analyze
  
  Returns:
      List of function calls made within the function

- **`search_functions_by_name`**: Search functions by name substring
  
  Search for functions whose name contains the given substring.

- **`get_function_count`**: Get total count of functions in the program
  
  Get the total count of functions in the program.
  
  Args:
      filter_default_names: Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.
  
  Returns:
      JSON with function count

- **`get_functions_by_similarity`**: Get functions sorted by similarity to a given function name
  
  Get functions sorted by similarity to a given function name.
  
  Args:
      search_string: Function name to compare against for similarity
      start_index: Starting index for pagination (0-based)
      max_count: Maximum number of functions to return
      filter_default_names: Whether to filter out default Ghidra generated names
  
  Returns:
      JSON with matching functions sorted by similarity

- **`get_undefined_function_candidates`**: Find addresses in executable memory referenced but not defined as functions
  
  Find addresses in executable memory that are referenced but not defined as functions.
  
  Args:
      start_index: Starting index for pagination (0-based)
      max_candidates: Maximum number of candidates to return
      min_reference_count: Minimum number of references required to be a candidate
  
  Returns:
      JSON with undefined function candidates

- **`create_function`**: Create a function at an address with auto-detected signature
  
  Create a function at an address with auto-detected signature.
  
  Args:
      address: Address where the function should be created (e.g., '0x401000')
      name: Optional name for the function. If not provided, Ghidra will generate a default name
  
  Returns:
      Success or failure message

### Call Graph & Relationships

- **`get_call_graph`**: Get bidirectional call graph (callers + callees) up to specified depth
  
  Get call graph around a function showing both callers and callees.
  
  Args:
      function_address: Address or name of the function
      depth: Depth of call graph to retrieve
  
  Returns:
      Call graph information

- **`get_call_tree`**: Get hierarchical call tree starting from a function (callers or callees)
  
  Get a hierarchical call tree starting from a function.
  
  Args:
      function_address: Address or name of the function to analyze
      direction: Direction to traverse: 'callers' (who calls this) or 'callees' (what this calls)
      max_depth: Maximum depth to traverse (default: 3, max: 10)
  
  Returns:
      Call tree as formatted text

- **`get_function_callers`**: List all functions that call a specific function
  
  Get all functions that call a specific function.
  
  Args:
      function_address: Address or name of the function
  
  Returns:
      List of calling functions

- **`get_function_callees`**: List all functions called by a specific function
  
  Get all functions called by a specific function.
  
  Args:
      function_address: Address or name of the function
  
  Returns:
      List of called functions

- **`get_function_xrefs`**: Get all references to a function by name
  
  Get all references to the specified function by name.
  
  Args:
      name: Function name to search for
      offset: Pagination offset (default: 0)
      limit: Maximum number of references to return (default: 100)
  
  Returns:
      List of references to the specified function

- **`get_callers_decompiled`**: Decompile all functions that call a target function
  
  Decompile all functions that call a target function.
  
  Args:
      function_name_or_address: Target function name or address to find callers for
      start_index: Starting index for pagination (0-based)
      max_callers: Maximum number of calling functions to decompile
      include_call_context: Whether to highlight the line containing the call in each decompilation
  
  Returns:
      JSON with decompiled callers

- **`find_common_callers`**: Find functions that call ALL of the specified target functions
  
  Find functions that call ALL of the specified target functions.
  
  Args:
      function_addresses: Comma-separated list of function addresses or names
  
  Returns:
      List of common callers

### Cross-References

- **`get_xrefs_to`**: Get all references TO a specific address
  
  Get all references to the specified address (xref to).
  
  Args:
      address: Target address in hex format (e.g. "0x1400010a0")
      offset: Pagination offset (default: 0)
      limit: Maximum number of references to return (default: 100)
  
  Returns:
      List of references to the specified address

- **`get_xrefs_from`**: Get all references FROM a specific address
  
  Get all references from the specified address (xref from).
  
  Args:
      address: Source address in hex format (e.g. "0x1400010a0")
      offset: Pagination offset (default: 0)
      limit: Maximum number of references to return (default: 100)
  
  Returns:
      List of references from the specified address

- **`find_cross_references`**: Find cross-references with directional filtering (to/from/both)
  
  Find cross-references to/from a specific location.
  
  Args:
      location: Address or symbol name
      direction: Direction - 'to', 'from', or None for both (default: None)
      limit: Maximum number of references per direction (default: 100)
  
  Returns:
      List of cross-references

- **`get_referencers_decompiled`**: Decompile all functions that reference a specific address or symbol
  
  Decompile all functions that reference a specific address or symbol.
  
  Args:
      address_or_symbol: Target address or symbol name to find references to
      start_index: Starting index for pagination (0-based)
      max_referencers: Maximum number of referencing functions to decompile
      include_ref_context: Whether to include reference line numbers in decompilation
      include_data_refs: Whether to include data references (reads/writes), not just calls
  
  Returns:
      JSON with decompiled referencers

- **`find_import_references`**: Find all locations where a specific imported function is called
  
  Find all locations where a specific imported function is called.
  
  Args:
      import_name: Name of the imported function to find references for (case-insensitive)
      library_name: Optional specific library name to narrow search (case-insensitive)
      max_results: Maximum number of references to return
  
  Returns:
      JSON with references to the imported function

- **`resolve_thunk`**: Follow a thunk chain to find the actual target function
  
  Follow a thunk chain to find the actual target function.
  
  Args:
      address: Address of the thunk or jump stub to resolve
  
  Returns:
      JSON with thunk chain information

### Data Flow Analysis

- **`trace_data_flow_backward`**: Trace where a value at an address comes from (origins)
  
  Trace data flow backward from an address to find origins.
  
  Args:
      address: Address within a function to trace backward from
  
  Returns:
      Data flow information showing where values come from

- **`trace_data_flow_forward`**: Trace where a value at an address flows to (uses)
  
  Trace data flow forward from an address to find uses.
  
  Args:
      address: Address within a function to trace forward from
  
  Returns:
      Data flow information showing where values are used

- **`find_variable_accesses`**: Find all reads and writes to a variable within a function
  
  Find all reads and writes to a variable within a function.
  
  Args:
      function_address: Address of the function to analyze
      variable_name: Name of the variable to find accesses for
  
  Returns:
      List of variable accesses

### Constants & Values

- **`find_constant_uses`**: Find all uses of a specific constant value (supports hex, decimal, negative)
  
  Find all uses of a specific constant value in the program.
  
  Args:
      value: Constant value to search for (supports hex with 0x, decimal, negative)
      max_results: Maximum number of results to return
  
  Returns:
      List of instructions using the constant

- **`find_constants_in_range`**: Find constants within a numeric range (useful for error codes, enums)
  
  Find all constants within a specific numeric range.
  
  Args:
      min_value: Minimum value (inclusive, supports hex/decimal)
      max_value: Maximum value (inclusive, supports hex/decimal)
      max_results: Maximum number of results to return
  
  Returns:
      List of constants found in the range with occurrence counts

- **`list_common_constants`**: Find the most frequently used constant values in the program
  
  Find the most frequently used constant values in the program.
  
  Args:
      include_small_values: Include small values (0-255) which are often noise
      min_value: Optional minimum value to consider (filters out small constants)
      top_n: Number of most common constants to return
  
  Returns:
      JSON with most common constants

### Strings

- **`list_strings`**: List all defined strings with addresses and optional filter
  
  List all defined strings in the program with their addresses.
  
  Args:
      offset: Pagination offset (default: 0)
      limit: Maximum number of strings to return (default: 2000)
      filter: Optional filter to match within string content
  
  Returns:
      List of strings with their addresses

- **`get_strings`**: Get strings from the program with pagination
  
  Get strings from the program with pagination.
  
  Args:
      start_index: Starting index for pagination (0-based)
      max_count: Maximum number of strings to return
      include_referencing_functions: Include list of functions that reference each string
  
  Returns:
      JSON with strings list and pagination info

- **`search_strings_regex`**: Search strings using regex patterns
  
  Search for strings matching a regex pattern.
  
  Args:
      pattern: Regular expression pattern to search for
      max_results: Maximum number of results to return (default: 100)
  
  Returns:
      List of strings matching the pattern

- **`get_strings_count`**: Get total count of defined strings
  
  Get the total count of strings in the program.
  
  Returns:
      Total number of defined strings

- **`get_strings_by_similarity`**: Get strings sorted by similarity to a given string
  
  Get strings sorted by similarity to a given string.
  
  Args:
      search_string: String to compare against for similarity
      start_index: Starting index for pagination (0-based)
      max_count: Maximum number of strings to return
      include_referencing_functions: Include list of functions that reference each string
  
  Returns:
      JSON with matching strings sorted by similarity

### Memory & Data

- **`get_memory_blocks`**: List all memory blocks with properties (R/W/X, size, etc.)
  
  Get all memory blocks in the program.
  
  Returns:
      List of memory blocks with their properties

- **`read_memory`**: Read memory at address with hex dump and ASCII representation
  
  Read memory at a specific address.
  
  Args:
      address: Address to read from
      length: Number of bytes to read (default: 16)
  
  Returns:
      Hex dump of memory content

- **`get_data_at_address`**: Get detailed data information (type, size, label, value)
  
  Get data information at a specific address.
  
  Args:
      address: Address to query
  
  Returns:
      Data type, size, label, and value information

- **`list_data_items`**: List defined data labels and their values
  
  List defined data labels and their values with pagination.

- **`list_segments`**: List all memory segments
  
  List all memory segments in the program with pagination.

### Bookmarks & Annotations

- **`set_bookmark`**: Create or update a bookmark at an address (Note, Warning, TODO, Bug, Analysis)
  
  Set a bookmark at a specific address.
  
  Args:
      address: Address where to set the bookmark
      type: Bookmark type (e.g. 'Note', 'Warning', 'TODO', 'Bug', 'Analysis')
      category: Bookmark category for organization
      comment: Bookmark comment text
  
  Returns:
      Success or failure message

- **`get_bookmarks`**: Retrieve bookmarks by address or type
  
  Get bookmarks at an address or of a specific type.
  
  Args:
      address: Optional address to get bookmarks from
      type: Optional bookmark type to filter by
  
  Returns:
      List of bookmarks

- **`search_bookmarks`**: Search bookmarks by comment text
  
  Search bookmarks by text content.
  
  Args:
      search_text: Text to search for in bookmark comments
      max_results: Maximum number of results to return
  
  Returns:
      List of matching bookmarks

- **`remove_bookmark`**: Remove a bookmark at a specific address
  
  Remove a bookmark at a specific address.
  
  Args:
      address_or_symbol: Address or symbol name where to remove the bookmark
      type: Bookmark type (e.g. 'Note', 'Warning', 'TODO', 'Bug', 'Analysis')
      category: Bookmark category for organizing bookmarks (optional)
  
  Returns:
      Success or failure message

- **`list_bookmark_categories`**: List all categories for a given bookmark type
  
  List all categories for a given bookmark type.
  
  Args:
      type: Bookmark type to get categories for
  
  Returns:
      JSON with bookmark categories

### Comments

- **`set_decompiler_comment`**: Set a comment in function pseudocode
  
  Set a comment for a given address in the function pseudocode.

- **`set_disassembly_comment`**: Set a comment in assembly listing
  
  Set a comment for a given address in the function disassembly.

- **`set_decompilation_comment`**: Set a comment at a specific line in decompiled code
  
  Set a comment at a specific line in decompiled code.
  
  Args:
      function_name_or_address: Function name or address
      line_number: Line number in the decompiled function (1-based)
      comment: The comment text to set
      comment_type: Type of comment: 'pre' or 'eol' (end-of-line, default)
  
  Returns:
      JSON with success status

- **`set_comment`**: Set or update a comment at a specific address
  
  Set or update a comment at a specific address.
  
  Args:
      address_or_symbol: Address or symbol name where to set the comment
      comment: The comment text to set
      comment_type: Type of comment: 'pre', 'eol', 'post', 'plate', or 'repeatable'
  
  Returns:
      Success or failure message

- **`get_comments`**: Get comments at a specific address or within an address range
  
  Get comments at a specific address or within an address range.
  
  Args:
      address_or_symbol: Address or symbol name to get comments from (optional if using start/end)
      start: Start address of the range
      end: End address of the range
      comment_types: Types of comments to retrieve (comma-separated: pre,eol,post,plate,repeatable)
  
  Returns:
      JSON with comments

- **`remove_comment`**: Remove a specific comment at an address
  
  Remove a specific comment at an address.
  
  Args:
      address_or_symbol: Address or symbol name where to remove the comment
      comment_type: Type of comment to remove: 'pre', 'eol', 'post', 'plate', or 'repeatable'
  
  Returns:
      Success or failure message

- **`search_comments`**: Search for comments containing specific text
  
  Search for comments containing specific text.
  
  Args:
      search_text: Text to search for in comments
      case_sensitive: Whether search is case sensitive
      comment_types: Types of comments to search (comma-separated: pre,eol,post,plate,repeatable)
      max_results: Maximum number of results to return
  
  Returns:
      JSON with matching comments

- **`search_decompilation`**: Search for patterns across all function decompilations in a program
  
  Search for patterns across all function decompilations in a program.
  
  Args:
      pattern: Regular expression pattern to search for in decompiled functions
      case_sensitive: Whether the search should be case sensitive
      max_results: Maximum number of search results to return
      override_max_functions_limit: Whether to override the maximum function limit for decompiler searches
  
  Returns:
      JSON with search results

### Vtable Analysis (C++)

- **`analyze_vtable`**: Analyze virtual function table to extract function pointers
  
  Analyze a virtual function table (vtable) at a given address.
  
  Args:
      vtable_address: Address of the vtable to analyze
      max_entries: Maximum number of vtable entries to read (default: 200)
  
  Returns:
      Vtable structure with function pointers and slot information

- **`find_vtable_callers`**: Find indirect calls that could invoke a function via vtable
  
  Find all indirect calls that could invoke a function via its vtable slot.
  
  Args:
      function_address: Address or name of the virtual function
  
  Returns:
      List of potential caller sites for the virtual method

- **`find_vtables_containing_function`**: Find all vtables that contain a pointer to the given function
  
  Find all vtables that contain a pointer to the given function.
  
  Args:
      function_address: Address or name of the function to search for in vtables
  
  Returns:
      JSON with vtables containing the function

### Symbols & Labels

- **`list_classes`**: List all namespace/class names
  
  List all namespace/class names in the program with pagination.

- **`list_namespaces`**: List all non-global namespaces
  
  List all non-global namespaces in the program with pagination.

- **`list_imports`**: List imported symbols
  
  List all imported functions from external libraries with pagination.
  
  Args:
      library_filter: Optional library name to filter by (case-insensitive)
      max_results: Maximum number of imports to return (default: 500)
      start_index: Starting index for pagination (default: 0)
      group_by_library: Whether to group imports by library name (default: true)
  
  Returns:
      JSON with imports list or grouped by library

- **`list_exports`**: List exported functions/symbols
  
  List all exported symbols from the binary with pagination.
  
  Args:
      max_results: Maximum number of exports to return (default: 500)
      start_index: Starting index for pagination (default: 0)
  
  Returns:
      JSON with exports list

- **`create_label`**: Create or update a label at an address
  
  Create a label at a specific address.
  
  Args:
      address: Address where to create the label
      label_name: Name for the label
  
  Returns:
      Success or failure message

- **`get_symbols`**: Get symbols from the selected program with pagination
  
  Get symbols from the selected program with pagination.
  
  Args:
      include_external: Whether to include external symbols in the result
      start_index: Starting index for pagination (0-based)
      max_count: Maximum number of symbols to return
      filter_default_names: Whether to filter out default Ghidra generated names
  
  Returns:
      JSON with symbols

- **`get_symbols_count`**: Get total count of symbols in the program
  
  Get the total count of symbols in the program.
  
  Args:
      include_external: Whether to include external symbols in the count
      filter_default_names: Whether to filter out default Ghidra generated names
  
  Returns:
      JSON with symbol count

### Function & Variable Manipulation

- **`rename_function`**: Rename a function by name
  
  Rename a function by its current name to a new user-defined name.

- **`rename_function_by_address`**: Rename a function by address
  
  Rename a function by its address.

- **`rename_data`**: Rename a data label at an address
  
  Rename a data label at the specified address.

- **`rename_variable`**: Rename a local variable within a function
  
  Rename a local variable within a function.

- **`rename_variables`**: Rename multiple variables in a decompiled function
  
  Rename variables in a decompiled function.
  
  Args:
      function_name_or_address: Function name, address, or symbol to rename variables in
      variable_mappings: Mapping of old variable names to new variable names (format: "oldName1:newName1,oldName2:newName2")
  
  Returns:
      Success or failure message

- **`set_function_prototype`**: Set a function's prototype/signature
  
  Set a function's prototype.

- **`set_local_variable_type`**: Set a local variable's data type
  
  Set a local variable's type.

- **`change_variable_datatypes`**: Change data types of variables in a decompiled function
  
  Change data types of variables in a decompiled function.
  
  Args:
      function_name_or_address: Function name, address, or symbol to change variable data types in
      datatype_mappings: Mapping of variable names to new data type strings (format: "varName1:type1,varName2:type2")
      archive_name: Optional name of the data type archive to search for data types
  
  Returns:
      Success or failure message

### Structures

- **`parse_c_structure`**: Parse and create structures from C-style definitions
  
  Parse and create structures from C-style definitions.
  
  Args:
      c_definition: C-style structure definition
      category: Category path (default: /)
  
  Returns:
      JSON with created structure info

- **`validate_c_structure`**: Validate C-style structure definition without creating it
  
  Validate C-style structure definition without creating it.
  
  Args:
      c_definition: C-style structure definition to validate
  
  Returns:
      JSON with validation result

- **`create_structure`**: Create a new empty structure or union
  
  Create a new empty structure or union.
  
  Args:
      name: Name of the structure
      size: Initial size (0 for auto-sizing)
      type: Type: 'structure' or 'union' (default: structure)
      category: Category path (default: /)
      packed: Whether structure should be packed
      description: Description of the structure
  
  Returns:
      JSON with created structure info

- **`add_structure_field`**: Add a field to an existing structure
  
  Add a field to an existing structure.
  
  Args:
      structure_name: Name of the structure
      field_name: Name of the field
      data_type: Data type (e.g., 'int', 'char[32]')
      offset: Offset (for structures, omit to append)
      comment: Field comment
      
  Returns:
      JSON with success status

- **`modify_structure_field`**: Modify an existing field in a structure
  
  Modify an existing field in a structure.
  
  Args:
      structure_name: Name of the structure
      field_name: Name of the field to modify (use this OR offset)
      offset: Offset of the field to modify (use this OR fieldName)
      new_data_type: New data type for the field
      new_field_name: New name for the field
      new_comment: New comment for the field
      new_length: New length for the field (advanced)
      
  Returns:
      JSON with success status

- **`modify_structure_from_c`**: Modify an existing structure using a C-style definition
  
  Modify an existing structure using a C-style definition.
  
  Args:
      c_definition: Complete C structure definition with modifications
      
  Returns:
      JSON with success status

- **`get_structure_info`**: Get detailed information about a structure
  
  Get detailed information about a structure.
  
  Args:
      structure_name: Name of the structure
      
  Returns:
      JSON with structure info including all fields

- **`list_structures`**: List all structures in a program
  
  List all structures in a program.
  
  Args:
      category: Filter by category path
      name_filter: Filter by name (substring match)
      include_built_in: Include built-in types
      
  Returns:
      JSON with list of structures

- **`apply_structure`**: Apply a structure at a specific address
  
  Apply a structure at a specific address.
  
  Args:
      structure_name: Name of the structure
      address_or_symbol: Address or symbol name to apply structure
      clear_existing: Clear existing data
      
  Returns:
      JSON with success status

- **`delete_structure`**: Delete a structure from the program
  
  Delete a structure from the program.
  
  Args:
      structure_name: Name of the structure to delete
      force: Force deletion even if structure is referenced (default: false)
      
  Returns:
      JSON with success status or reference warnings

- **`parse_c_header`**: Parse an entire C header file and create all structures
  
  Parse an entire C header file and create all structures.
  
  Args:
      header_content: C header file content
      category: Category path (default: /)
      
  Returns:
      JSON with created types info

### Data Types

- **`get_data_type_archives`**: Get data type archives for a specific program
  
  Get data type archives for a specific program.
  
  Returns:
      JSON with data type archives

- **`get_data_types`**: Get data types from a data type archive
  
  Get data types from a data type archive.
  
  Args:
      archive_name: Name of the data type archive
      category_path: Path to category to list data types from (e.g., '/Structure'). Use '/' for root category.
      include_subcategories: Whether to include data types from subcategories
      start_index: Starting index for pagination (0-based)
      max_count: Maximum number of data types to return
  
  Returns:
      JSON with data types

- **`get_data_type_by_string`**: Get a data type by its string representation
  
  Get a data type by its string representation.
  
  Args:
      data_type_string: String representation of the data type (e.g., 'char**', 'int[10]')
      archive_name: Optional name of the data type archive to search in
  
  Returns:
      JSON with data type information

- **`apply_data_type`**: Apply a data type to a specific address or symbol
  
  Apply a data type to a specific address or symbol in a program.
  
  Args:
      address_or_symbol: Address or symbol name to apply the data type to
      data_type_string: String representation of the data type (e.g., 'char**', 'int[10]')
      archive_name: Optional name of the data type archive to search in
  
  Returns:
      Success or failure message

### Current Context

- **`get_current_address`**: Get the address currently selected in Ghidra GUI
  
  Get the address currently selected by the user.

- **`get_current_function`**: Get the function currently selected in Ghidra GUI
  
  Get the function currently selected by the user.

### Function Tags

- **`function_tags`**: Manage function tags (get, set, add, remove, list) to categorize functions
  
  Manage function tags. Tags categorize functions (e.g., 'AI', 'rendering').
  
  Args:
      function: Function name or address (required for get/set/add/remove modes)
      mode: Operation: 'get' (tags on function), 'set' (replace), 'add', 'remove', 'list' (all tags in program)
      tags: Tag names (required for add; optional for set/remove). Comma-separated.
  
  Returns:
      JSON with tag information or success message

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
