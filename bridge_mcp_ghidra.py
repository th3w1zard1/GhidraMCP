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

@mcp.tool()
def search_strings_regex(pattern: str, max_results: int = 100) -> str:
    """
    Search for strings matching a regex pattern.
    
    Args:
        pattern: Regular expression pattern to search for
        max_results: Maximum number of results to return (default: 100)
        
    Returns:
        List of strings matching the pattern
    """
    return "\n".join(safe_get("search_strings_regex", {
        "pattern": pattern,
        "maxResults": max_results
    }))

@mcp.tool()
def get_strings_count() -> str:
    """
    Get the total count of strings in the program.
    
    Returns:
        Total number of defined strings
    """
    return "\n".join(safe_get("get_strings_count"))

@mcp.tool()
def find_cross_references(location: str, direction: str = None, limit: int = 100) -> str:
    """
    Find cross-references to/from a specific location.
    
    Args:
        location: Address or symbol name
        direction: Direction - 'to', 'from', or None for both (default: None)
        limit: Maximum number of references per direction (default: 100)
        
    Returns:
        List of cross-references
    """
    params = {"location": location, "limit": limit}
    if direction:
        params["direction"] = direction
    return "\n".join(safe_get("find_cross_references", params))

@mcp.tool()
def create_label(address: str, label_name: str) -> str:
    """
    Create a label at a specific address.
    
    Args:
        address: Address where to create the label
        label_name: Name for the label
        
    Returns:
        Success or failure message
    """
    return safe_post("create_label", {
        "address": address,
        "labelName": label_name
    })

@mcp.tool()
def get_data_at_address(address: str) -> str:
    """
    Get data information at a specific address.
    
    Args:
        address: Address to query
        
    Returns:
        Data type, size, label, and value information
    """
    return "\n".join(safe_get("get_data_at_address", {
        "address": address
    }))

# Additional tools from reverse-engineering-assistant

@mcp.tool()
def get_function_count(filter_default_names: bool = True) -> str:
    """
    Get the total count of functions in the program.
    
    Args:
        filter_default_names: Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.
        
    Returns:
        JSON with function count
    """
    return "\n".join(safe_get("functions/get_count", {
        "filterDefaultNames": filter_default_names
    }))

@mcp.tool()
def get_functions_by_similarity(search_string: str, start_index: int = 0, max_count: int = 100, filter_default_names: bool = True) -> str:
    """
    Get functions sorted by similarity to a given function name.
    
    Args:
        search_string: Function name to compare against for similarity
        start_index: Starting index for pagination (0-based)
        max_count: Maximum number of functions to return
        filter_default_names: Whether to filter out default Ghidra generated names
        
    Returns:
        JSON with matching functions sorted by similarity
    """
    return "\n".join(safe_get("functions/get_by_similarity", {
        "searchString": search_string,
        "startIndex": start_index,
        "maxCount": max_count,
        "filterDefaultNames": filter_default_names
    }))

@mcp.tool()
def get_undefined_function_candidates(start_index: int = 0, max_candidates: int = 100, min_reference_count: int = 1) -> str:
    """
    Find addresses in executable memory that are referenced but not defined as functions.
    
    Args:
        start_index: Starting index for pagination (0-based)
        max_candidates: Maximum number of candidates to return
        min_reference_count: Minimum number of references required to be a candidate
        
    Returns:
        JSON with undefined function candidates
    """
    return "\n".join(safe_get("functions/get_undefined_candidates", {
        "startIndex": start_index,
        "maxCandidates": max_candidates,
        "minReferenceCount": min_reference_count
    }))

@mcp.tool()
def create_function(address: str, name: str = "") -> str:
    """
    Create a function at an address with auto-detected signature.
    
    Args:
        address: Address where the function should be created (e.g., '0x401000')
        name: Optional name for the function. If not provided, Ghidra will generate a default name
        
    Returns:
        Success or failure message
    """
    return safe_post("functions/create", {
        "address": address,
        "name": name
    })

@mcp.tool()
def function_tags(function: str, mode: str, tags: str = "") -> str:
    """
    Manage function tags. Tags categorize functions (e.g., 'AI', 'rendering').
    
    Args:
        function: Function name or address (required for get/set/add/remove modes)
        mode: Operation: 'get' (tags on function), 'set' (replace), 'add', 'remove', 'list' (all tags in program)
        tags: Tag names (required for add; optional for set/remove). Comma-separated.
        
    Returns:
        JSON with tag information or success message
    """
    return safe_post("functions/tags", {
        "function": function,
        "mode": mode,
        "tags": tags
    })

@mcp.tool()
def get_strings_by_similarity(search_string: str, start_index: int = 0, max_count: int = 100, include_referencing_functions: bool = False) -> str:
    """
    Get strings sorted by similarity to a given string.
    
    Args:
        search_string: String to compare against for similarity
        start_index: Starting index for pagination (0-based)
        max_count: Maximum number of strings to return
        include_referencing_functions: Include list of functions that reference each string
        
    Returns:
        JSON with matching strings sorted by similarity
    """
    return "\n".join(safe_get("strings/get_by_similarity", {
        "searchString": search_string,
        "startIndex": start_index,
        "maxCount": max_count,
        "includeReferencingFunctions": include_referencing_functions
    }))

@mcp.tool()
def set_comment(address_or_symbol: str, comment: str, comment_type: str = "eol") -> str:
    """
    Set or update a comment at a specific address.
    
    Args:
        address_or_symbol: Address or symbol name where to set the comment
        comment: The comment text to set
        comment_type: Type of comment: 'pre', 'eol', 'post', 'plate', or 'repeatable'
        
    Returns:
        Success or failure message
    """
    return safe_post("comments/set", {
        "addressOrSymbol": address_or_symbol,
        "comment": comment,
        "commentType": comment_type
    })

@mcp.tool()
def get_comments(address_or_symbol: str = "", start: str = "", end: str = "", comment_types: str = "") -> str:
    """
    Get comments at a specific address or within an address range.
    
    Args:
        address_or_symbol: Address or symbol name to get comments from (optional if using start/end)
        start: Start address of the range
        end: End address of the range
        comment_types: Types of comments to retrieve (comma-separated: pre,eol,post,plate,repeatable)
        
    Returns:
        JSON with comments
    """
    params = {}
    if address_or_symbol:
        params["addressOrSymbol"] = address_or_symbol
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    if comment_types:
        params["commentTypes"] = comment_types
    return "\n".join(safe_get("comments/get", params))

@mcp.tool()
def remove_comment(address_or_symbol: str, comment_type: str) -> str:
    """
    Remove a specific comment at an address.
    
    Args:
        address_or_symbol: Address or symbol name where to remove the comment
        comment_type: Type of comment to remove: 'pre', 'eol', 'post', 'plate', or 'repeatable'
        
    Returns:
        Success or failure message
    """
    return safe_post("comments/remove", {
        "addressOrSymbol": address_or_symbol,
        "commentType": comment_type
    })

@mcp.tool()
def search_comments(search_text: str, case_sensitive: bool = False, comment_types: str = "", max_results: int = 100) -> str:
    """
    Search for comments containing specific text.
    
    Args:
        search_text: Text to search for in comments
        case_sensitive: Whether search is case sensitive
        comment_types: Types of comments to search (comma-separated: pre,eol,post,plate,repeatable)
        max_results: Maximum number of results to return
        
    Returns:
        JSON with matching comments
    """
    params = {
        "searchText": search_text,
        "caseSensitive": case_sensitive,
        "maxResults": max_results
    }
    if comment_types:
        params["commentTypes"] = comment_types
    return "\n".join(safe_get("comments/search", params))

@mcp.tool()
def apply_data_type(address_or_symbol: str, data_type_string: str, archive_name: str = "") -> str:
    """
    Apply a data type to a specific address or symbol in a program.
    
    Args:
        address_or_symbol: Address or symbol name to apply the data type to
        data_type_string: String representation of the data type (e.g., 'char**', 'int[10]')
        archive_name: Optional name of the data type archive to search in
        
    Returns:
        Success or failure message
    """
    return safe_post("data/apply_data_type", {
        "addressOrSymbol": address_or_symbol,
        "dataTypeString": data_type_string,
        "archiveName": archive_name
    })

@mcp.tool()
def get_symbols_count(include_external: bool = False, filter_default_names: bool = True) -> str:
    """
    Get the total count of symbols in the program.
    
    Args:
        include_external: Whether to include external symbols in the count
        filter_default_names: Whether to filter out default Ghidra generated names
        
    Returns:
        JSON with symbol count
    """
    return "\n".join(safe_get("symbols/get_count", {
        "includeExternal": include_external,
        "filterDefaultNames": filter_default_names
    }))

@mcp.tool()
def get_symbols(include_external: bool = False, start_index: int = 0, max_count: int = 200, filter_default_names: bool = True) -> str:
    """
    Get symbols from the selected program with pagination.
    
    Args:
        include_external: Whether to include external symbols in the result
        start_index: Starting index for pagination (0-based)
        max_count: Maximum number of symbols to return
        filter_default_names: Whether to filter out default Ghidra generated names
        
    Returns:
        JSON with symbols
    """
    return "\n".join(safe_get("symbols/get", {
        "includeExternal": include_external,
        "startIndex": start_index,
        "maxCount": max_count,
        "filterDefaultNames": filter_default_names
    }))

@mcp.tool()
def find_import_references(import_name: str, library_name: str = "", max_results: int = 100) -> str:
    """
    Find all locations where a specific imported function is called.
    
    Args:
        import_name: Name of the imported function to find references for (case-insensitive)
        library_name: Optional specific library name to narrow search (case-insensitive)
        max_results: Maximum number of references to return
        
    Returns:
        JSON with references to the imported function
    """
    params = {
        "importName": import_name,
        "maxResults": max_results
    }
    if library_name:
        params["libraryName"] = library_name
    return "\n".join(safe_get("imports/find_references", params))

@mcp.tool()
def resolve_thunk(address: str) -> str:
    """
    Follow a thunk chain to find the actual target function.
    
    Args:
        address: Address of the thunk or jump stub to resolve
        
    Returns:
        JSON with thunk chain information
    """
    return "\n".join(safe_get("imports/resolve_thunk", {
        "address": address
    }))

@mcp.tool()
def get_call_tree(function_address: str, direction: str = "callees", max_depth: int = 3) -> str:
    """
    Get a hierarchical call tree starting from a function.
    
    Args:
        function_address: Address or name of the function to analyze
        direction: Direction to traverse: 'callers' (who calls this) or 'callees' (what this calls)
        max_depth: Maximum depth to traverse (default: 3, max: 10)
        
    Returns:
        Call tree as formatted text
    """
    return "\n".join(safe_get("callgraph/get_tree", {
        "functionAddress": function_address,
        "direction": direction,
        "maxDepth": max_depth
    }))

@mcp.tool()
def find_common_callers(function_addresses: str) -> str:
    """
    Find functions that call ALL of the specified target functions.
    
    Args:
        function_addresses: Comma-separated list of function addresses or names
        
    Returns:
        List of common callers
    """
    return safe_post("callgraph/find_common_callers", {
        "functionAddresses": function_addresses
    })

@mcp.tool()
def list_common_constants(include_small_values: bool = False, min_value: str = "", top_n: int = 50) -> str:
    """
    Find the most frequently used constant values in the program.
    
    Args:
        include_small_values: Include small values (0-255) which are often noise
        min_value: Optional minimum value to consider (filters out small constants)
        top_n: Number of most common constants to return
        
    Returns:
        JSON with most common constants
    """
    params = {
        "includeSmallValues": include_small_values,
        "topN": top_n
    }
    if min_value:
        params["minValue"] = min_value
    return "\n".join(safe_get("constants/list_common", params))

@mcp.tool()
def find_variable_accesses(function_address: str, variable_name: str) -> str:
    """
    Find all reads and writes to a variable within a function.
    
    Args:
        function_address: Address of the function to analyze
        variable_name: Name of the variable to find accesses for
        
    Returns:
        List of variable accesses
    """
    return "\n".join(safe_get("dataflow/find_variable_accesses", {
        "functionAddress": function_address,
        "variableName": variable_name
    }))

@mcp.tool()
def find_vtables_containing_function(function_address: str) -> str:
    """
    Find all vtables that contain a pointer to the given function.
    
    Args:
        function_address: Address or name of the function to search for in vtables
        
    Returns:
        JSON with vtables containing the function
    """
    return "\n".join(safe_get("vtable/find_containing_function", {
        "functionAddress": function_address
    }))

@mcp.tool()
def remove_bookmark(address_or_symbol: str, type: str, category: str = "") -> str:
    """
    Remove a bookmark at a specific address.
    
    Args:
        address_or_symbol: Address or symbol name where to remove the bookmark
        type: Bookmark type (e.g. 'Note', 'Warning', 'TODO', 'Bug', 'Analysis')
        category: Bookmark category for organizing bookmarks (optional)
        
    Returns:
        Success or failure message
    """
    return safe_post("bookmarks/remove", {
        "addressOrSymbol": address_or_symbol,
        "type": type,
        "category": category
    })

@mcp.tool()
def list_bookmark_categories(type: str = "Note") -> str:
    """
    List all categories for a given bookmark type.
    
    Args:
        type: Bookmark type to get categories for
        
    Returns:
        JSON with bookmark categories
    """
    return "\n".join(safe_get("bookmarks/list_categories", {
        "type": type
    }))

@mcp.tool()
def search_decompilation(pattern: str, case_sensitive: bool = False, max_results: int = 50, override_max_functions_limit: bool = False) -> str:
    """
    Search for patterns across all function decompilations in a program.
    
    Args:
        pattern: Regular expression pattern to search for in decompiled functions
        case_sensitive: Whether the search should be case sensitive
        max_results: Maximum number of search results to return
        override_max_functions_limit: Whether to override the maximum function limit for decompiler searches
        
    Returns:
        JSON with search results
    """
    return "\n".join(safe_get("decompiler/search", {
        "pattern": pattern,
        "caseSensitive": case_sensitive,
        "maxResults": max_results,
        "overrideMaxFunctionsLimit": override_max_functions_limit
    }))

@mcp.tool()
def rename_variables(function_name_or_address: str, variable_mappings: str) -> str:
    """
    Rename variables in a decompiled function.
    
    Args:
        function_name_or_address: Function name, address, or symbol to rename variables in
        variable_mappings: Mapping of old variable names to new variable names (format: "oldName1:newName1,oldName2:newName2")
        
    Returns:
        Success or failure message
    """
    return safe_post("decompiler/rename_variables", {
        "functionNameOrAddress": function_name_or_address,
        "variableMappings": variable_mappings
    })

@mcp.tool()
def change_variable_datatypes(function_name_or_address: str, datatype_mappings: str, archive_name: str = "") -> str:
    """
    Change data types of variables in a decompiled function.
    
    Args:
        function_name_or_address: Function name, address, or symbol to change variable data types in
        datatype_mappings: Mapping of variable names to new data type strings (format: "varName1:type1,varName2:type2")
        archive_name: Optional name of the data type archive to search for data types
        
    Returns:
        Success or failure message
    """
    return safe_post("decompiler/change_variable_datatypes", {
        "functionNameOrAddress": function_name_or_address,
        "datatypeMappings": datatype_mappings,
        "archiveName": archive_name
    })

@mcp.tool()
def get_callers_decompiled(function_name_or_address: str, start_index: int = 0, max_callers: int = 10, include_call_context: bool = True) -> str:
    """
    Decompile all functions that call a target function.
    
    Args:
        function_name_or_address: Target function name or address to find callers for
        start_index: Starting index for pagination (0-based)
        max_callers: Maximum number of calling functions to decompile
        include_call_context: Whether to highlight the line containing the call in each decompilation
        
    Returns:
        JSON with decompiled callers
    """
    return "\n".join(safe_get("decompiler/get_callers_decompiled", {
        "functionNameOrAddress": function_name_or_address,
        "startIndex": start_index,
        "maxCallers": max_callers,
        "includeCallContext": include_call_context
    }))

@mcp.tool()
def get_referencers_decompiled(address_or_symbol: str, start_index: int = 0, max_referencers: int = 10, include_ref_context: bool = True, include_data_refs: bool = True) -> str:
    """
    Decompile all functions that reference a specific address or symbol.
    
    Args:
        address_or_symbol: Target address or symbol name to find references to
        start_index: Starting index for pagination (0-based)
        max_referencers: Maximum number of referencing functions to decompile
        include_ref_context: Whether to include reference line numbers in decompilation
        include_data_refs: Whether to include data references (reads/writes), not just calls
        
    Returns:
        JSON with decompiled referencers
    """
    return "\n".join(safe_get("decompiler/get_referencers_decompiled", {
        "addressOrSymbol": address_or_symbol,
        "startIndex": start_index,
        "maxReferencers": max_referencers,
        "includeRefContext": include_ref_context,
        "includeDataRefs": include_data_refs
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

