# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def set_bookmark(address: str, type: str, category: str, comment: str) -> str:
    """
    Set a bookmark at a specific address.
    
    Args:
        address: Address where to set the bookmark
        type: Bookmark type (e.g. 'Note', 'Warning', 'TODO', 'Bug', 'Analysis')
        category: Bookmark category for organization
        comment: Bookmark comment text
        
    Returns:
        Success or failure message
    """
    return safe_post("set_bookmark", {
        "address": address,
        "type": type,
        "category": category,
        "comment": comment
    })

@mcp.tool()
def get_bookmarks(address: str = None, type: str = None) -> str:
    """
    Get bookmarks at an address or of a specific type.
    
    Args:
        address: Optional address to get bookmarks from
        type: Optional bookmark type to filter by
        
    Returns:
        List of bookmarks
    """
    params = {}
    if address:
        params["address"] = address
    if type:
        params["type"] = type
    return "\n".join(safe_get("get_bookmarks", params))

@mcp.tool()
def search_bookmarks(search_text: str, max_results: int = 100) -> str:
    """
    Search bookmarks by text content.
    
    Args:
        search_text: Text to search for in bookmark comments
        max_results: Maximum number of results to return
        
    Returns:
        List of matching bookmarks
    """
    return "\n".join(safe_get("search_bookmarks", {
        "searchText": search_text,
        "maxResults": max_results
    }))

@mcp.tool()
def get_call_graph(function_address: str, depth: int = 1) -> str:
    """
    Get call graph around a function showing both callers and callees.
    
    Args:
        function_address: Address or name of the function
        depth: Depth of call graph to retrieve
        
    Returns:
        Call graph information
    """
    return "\n".join(safe_get("get_call_graph", {
        "functionAddress": function_address,
        "depth": depth
    }))

@mcp.tool()
def get_function_callers(function_address: str) -> str:
    """
    Get all functions that call a specific function.
    
    Args:
        function_address: Address or name of the function
        
    Returns:
        List of calling functions
    """
    return "\n".join(safe_get("get_callers", {
        "functionAddress": function_address
    }))

@mcp.tool()
def get_function_callees(function_address: str) -> str:
    """
    Get all functions called by a specific function.
    
    Args:
        function_address: Address or name of the function
        
    Returns:
        List of called functions
    """
    return "\n".join(safe_get("get_callees", {
        "functionAddress": function_address
    }))

@mcp.tool()
def find_constant_uses(value: str, max_results: int = 500) -> str:
    """
    Find all uses of a specific constant value in the program.
    
    Args:
        value: Constant value to search for (supports hex with 0x, decimal, negative)
        max_results: Maximum number of results to return
        
    Returns:
        List of instructions using the constant
    """
    return "\n".join(safe_get("find_constant", {
        "value": value,
        "maxResults": max_results
    }))

@mcp.tool()
def find_constants_in_range(min_value: str, max_value: str, max_results: int = 500) -> str:
    """
    Find all constants within a specific numeric range.
    
    Args:
        min_value: Minimum value (inclusive, supports hex/decimal)
        max_value: Maximum value (inclusive, supports hex/decimal)
        max_results: Maximum number of results to return
        
    Returns:
        List of constants found in the range with occurrence counts
    """
    return "\n".join(safe_get("find_constants_in_range", {
        "minValue": min_value,
        "maxValue": max_value,
        "maxResults": max_results
    }))

@mcp.tool()
def get_memory_blocks() -> str:
    """
    Get all memory blocks in the program.
    
    Returns:
        List of memory blocks with their properties
    """
    return "\n".join(safe_get("memory_blocks"))

@mcp.tool()
def read_memory(address: str, length: int = 16) -> str:
    """
    Read memory at a specific address.
    
    Args:
        address: Address to read from
        length: Number of bytes to read (default: 16)
        
    Returns:
        Hex dump of memory content
    """
    return "\n".join(safe_get("read_memory", {
        "address": address,
        "length": length
    }))

@mcp.tool()
def get_function_info(address: str) -> str:
    """
    Get detailed information about a function.
    
    Args:
        address: Address of the function
        
    Returns:
        Detailed function information including parameters and local variables
    """
    return "\n".join(safe_get("get_function_info", {
        "address": address
    }))

@mcp.tool()
def list_function_calls(function_address: str) -> str:
    """
    List all function calls within a specific function.
    
    Args:
        function_address: Address of the function to analyze
        
    Returns:
        List of function calls made within the function
    """
    return "\n".join(safe_get("list_function_calls", {
        "functionAddress": function_address
    }))

@mcp.tool()
def trace_data_flow_backward(address: str) -> str:
    """
    Trace data flow backward from an address to find origins.
    
    Args:
        address: Address within a function to trace backward from
        
    Returns:
        Data flow information showing where values come from
    """
    return "\n".join(safe_get("trace_data_flow_backward", {
        "address": address
    }))

@mcp.tool()
def trace_data_flow_forward(address: str) -> str:
    """
    Trace data flow forward from an address to find uses.
    
    Args:
        address: Address within a function to trace forward from
        
    Returns:
        Data flow information showing where values are used
    """
    return "\n".join(safe_get("trace_data_flow_forward", {
        "address": address
    }))

@mcp.tool()
def analyze_vtable(vtable_address: str, max_entries: int = 200) -> str:
    """
    Analyze a virtual function table (vtable) at a given address.
    
    Args:
        vtable_address: Address of the vtable to analyze
        max_entries: Maximum number of vtable entries to read (default: 200)
        
    Returns:
        Vtable structure with function pointers and slot information
    """
    return "\n".join(safe_get("analyze_vtable", {
        "vtableAddress": vtable_address,
        "maxEntries": max_entries
    }))

@mcp.tool()
def find_vtable_callers(function_address: str) -> str:
    """
    Find all indirect calls that could invoke a function via its vtable slot.
    
    Args:
        function_address: Address or name of the virtual function
        
    Returns:
        List of potential caller sites for the virtual method
    """
    return "\n".join(safe_get("find_vtable_callers", {
        "functionAddress": function_address
    }))

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

