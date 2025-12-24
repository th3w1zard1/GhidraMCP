# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///
from __future__ import annotations

import argparse
import logging
from urllib.parse import urljoin

import requests
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
        response.encoding = "utf-8"
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
        response.encoding = "utf-8"
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


@mcp.tool()
def get_function(
    identifier: str,
    view: str = "decompile",
    offset: int = 1,
    limit: int = 50,
    include_callers: bool = False,
    include_callees: bool = False,
    include_comments: bool = False,
    include_incoming_references: bool = True,
    include_reference_context: bool = True,
) -> str:
    """
    Unified function retrieval tool that replaces: decompile_function, decompile_function_by_address,
    get_decompilation, disassemble_function, get_function_by_address, get_function_info, list_function_calls

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
    """
    if view == "decompile":
        return "\n".join(
            safe_get(
                "decompiler/get_decompilation",
                {
                    "functionNameOrAddress": identifier,
                    "offset": offset,
                    "limit": limit,
                    "includeCallers": include_callers,
                    "includeCallees": include_callees,
                    "includeComments": include_comments,
                    "includeIncomingReferences": include_incoming_references,
                    "includeReferenceContext": include_reference_context,
                },
            )
        )
    elif view == "disassemble":
        return "\n".join(safe_get("disassemble_function", {"address": identifier}))
    elif view == "info":
        return "\n".join(safe_get("get_function_info", {"address": identifier}))
    elif view == "calls":
        return "\n".join(
            safe_get("list_function_calls", {"functionAddress": identifier})
        )
    else:
        return f"Error: Invalid view mode '{view}'. Must be 'decompile', 'disassemble', 'info', or 'calls'"


@mcp.tool()
def list_functions(
    mode: str = "all",
    query: str = "",
    search_string: str = "",
    min_reference_count: int = 1,
    start_index: int = 0,
    max_count: int = 100,
    offset: int = 0,
    limit: int = 100,
    filter_default_names: bool = True,
) -> str:
    """
    Comprehensive function listing and search tool that replaces: list_functions, list_methods,
    search_functions_by_name, get_functions_by_similarity, get_undefined_function_candidates, get_function_count

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
    """
    if mode == "all":
        return "\n".join(
            safe_get(
                "methods",
                {"offset": offset or start_index, "limit": limit or max_count},
            )
        )
    elif mode == "search":
        if not query:
            return "Error: query string is required for search mode"
        return "\n".join(
            safe_get(
                "searchFunctions",
                {
                    "query": query,
                    "offset": offset or start_index,
                    "limit": limit or max_count,
                },
            )
        )
    elif mode == "similarity":
        if not search_string:
            return "Error: search_string is required for similarity mode"
        return "\n".join(
            safe_get(
                "functions/get_by_similarity",
                {
                    "searchString": search_string,
                    "startIndex": start_index,
                    "maxCount": max_count,
                    "filterDefaultNames": filter_default_names,
                },
            )
        )
    elif mode == "undefined":
        return "\n".join(
            safe_get(
                "functions/get_undefined_candidates",
                {
                    "startIndex": start_index,
                    "maxCandidates": max_count,
                    "minReferenceCount": min_reference_count,
                },
            )
        )
    elif mode == "count":
        return "\n".join(
            safe_get(
                "functions/get_count", {"filterDefaultNames": filter_default_names}
            )
        )
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'all', 'search', 'similarity', 'undefined', or 'count'"


@mcp.tool()
def manage_function(
    action: str,
    address: str = "",
    function_identifier: str = "",
    name: str = "",
    old_name: str = "",
    new_name: str = "",
    variable_mappings: str = "",
    prototype: str = "",
    variable_name: str = "",
    new_type: str = "",
    datatype_mappings: str = "",
    archive_name: str = "",
) -> str:
    """
    Function and variable manipulation tool that replaces: create_function, rename_function,
    rename_function_by_address, rename_variable, rename_variables, set_function_prototype,
    set_local_variable_type, change_variable_datatypes

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
    """
    if action == "create":
        if not address:
            return "Error: address is required for create action"
        return safe_post("functions/create", {"address": address, "name": name})
    elif action == "rename_function":
        if not function_identifier:
            return "Error: function_identifier is required for rename_function action"
        if not new_name:
            return "Error: new_name is required for rename_function action"
        return safe_post(
            "renameFunction", {"oldName": function_identifier, "newName": new_name}
        )
    elif action == "rename_variable":
        if not function_identifier:
            return "Error: function_identifier is required for rename_variable action"
        if variable_mappings:
            return safe_post(
                "decompiler/rename_variables",
                {
                    "functionNameOrAddress": function_identifier,
                    "variableMappings": variable_mappings,
                },
            )
        elif old_name and new_name:
            return safe_post(
                "renameVariable",
                {
                    "functionName": function_identifier,
                    "oldName": old_name,
                    "newName": new_name,
                },
            )
        else:
            return "Error: either variable_mappings or both old_name and new_name are required for rename_variable action"
    elif action == "set_prototype":
        if not function_identifier:
            return "Error: function_identifier is required for set_prototype action"
        if not prototype:
            return "Error: prototype is required for set_prototype action"
        return safe_post(
            "set_function_prototype",
            {"function_address": function_identifier, "prototype": prototype},
        )
    elif action == "set_variable_type":
        if not function_identifier:
            return "Error: function_identifier is required for set_variable_type action"
        if not variable_name:
            return "Error: variable_name is required for set_variable_type action"
        if not new_type:
            return "Error: new_type is required for set_variable_type action"
        return safe_post(
            "set_local_variable_type",
            {
                "function_address": function_identifier,
                "variable_name": variable_name,
                "new_type": new_type,
            },
        )
    elif action == "change_datatypes":
        if not function_identifier:
            return "Error: function_identifier is required for change_datatypes action"
        if not datatype_mappings:
            return "Error: datatype_mappings is required for change_datatypes action"
        return safe_post(
            "decompiler/change_variable_datatypes",
            {
                "functionNameOrAddress": function_identifier,
                "datatypeMappings": datatype_mappings,
                "archiveName": archive_name,
            },
        )
    else:
        return f"Error: Invalid action '{action}'. Must be 'create', 'rename_function', 'rename_variable', 'set_prototype', 'set_variable_type', or 'change_datatypes'"


@mcp.tool()
def get_call_graph(
    function_identifier: str,
    mode: str = "graph",
    depth: int = 1,
    direction: str = "callees",
    max_depth: int = 3,
    start_index: int = 0,
    max_callers: int = 10,
    include_call_context: bool = True,
    function_addresses: str = "",
) -> str:
    """
    Call graph and relationship analysis tool that replaces: get_call_graph, get_call_tree,
    get_function_callers, get_function_callees, get_callers_decompiled, find_common_callers

    Analyze function call relationships in various formats: bidirectional graphs, hierarchical trees,
    caller/callee lists, decompiled callers, or common callers.

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
    """
    if mode == "graph":
        return "\n".join(
            safe_get(
                "get_call_graph",
                {"functionAddress": function_identifier, "depth": depth},
            )
        )
    elif mode == "tree":
        return "\n".join(
            safe_get(
                "callgraph/get_tree",
                {
                    "functionAddress": function_identifier,
                    "direction": direction,
                    "maxDepth": max_depth,
                },
            )
        )
    elif mode == "callers":
        return "\n".join(
            safe_get("get_callers", {"functionAddress": function_identifier})
        )
    elif mode == "callees":
        return "\n".join(
            safe_get("get_callees", {"functionAddress": function_identifier})
        )
    elif mode == "callers_decomp":
        return "\n".join(
            safe_get(
                "decompiler/get_callers_decompiled",
                {
                    "functionNameOrAddress": function_identifier,
                    "startIndex": start_index,
                    "maxCallers": max_callers,
                    "includeCallContext": include_call_context,
                },
            )
        )
    elif mode == "common_callers":
        if not function_addresses:
            return "Error: function_addresses is required for common_callers mode"
        return safe_post(
            "callgraph/find_common_callers", {"functionAddresses": function_addresses}
        )
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'graph', 'tree', 'callers', 'callees', 'callers_decomp', or 'common_callers'"


@mcp.tool()
def get_references(
    target: str,
    mode: str = "both",
    direction: str = "both",
    offset: int = 0,
    limit: int = 100,
    max_results: int = 100,
    library_name: str = "",
    start_index: int = 0,
    max_referencers: int = 10,
    include_ref_context: bool = True,
    include_data_refs: bool = True,
) -> str:
    """
    Comprehensive cross-reference analysis tool that replaces: get_xrefs_to, get_xrefs_from,
    find_cross_references, get_function_xrefs, get_referencers_decompiled, find_import_references, resolve_thunk

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
    """
    if mode == "to":
        return "\n".join(
            safe_get("xrefs_to", {"address": target, "offset": offset, "limit": limit})
        )
    elif mode == "from":
        return "\n".join(
            safe_get(
                "xrefs_from", {"address": target, "offset": offset, "limit": limit}
            )
        )
    elif mode == "both":
        params = {"location": target, "limit": limit}
        if direction != "both":
            params["direction"] = direction
        return "\n".join(safe_get("find_cross_references", params))
    elif mode == "function":
        return "\n".join(
            safe_get(
                "function_xrefs", {"name": target, "offset": offset, "limit": limit}
            )
        )
    elif mode == "referencers_decomp":
        return "\n".join(
            safe_get(
                "decompiler/get_referencers_decompiled",
                {
                    "addressOrSymbol": target,
                    "startIndex": start_index,
                    "maxReferencers": max_referencers,
                    "includeRefContext": include_ref_context,
                    "includeDataRefs": include_data_refs,
                },
            )
        )
    elif mode == "import":
        params = {"importName": target, "maxResults": max_results}
        if library_name:
            params["libraryName"] = library_name
        return "\n".join(safe_get("imports/find_references", params))
    elif mode == "thunk":
        return "\n".join(safe_get("imports/resolve_thunk", {"address": target}))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'to', 'from', 'both', 'function', 'referencers_decomp', 'import', or 'thunk'"


@mcp.tool()
def analyze_data_flow(
    function_address: str,
    start_address: str = "",
    variable_name: str = "",
    direction: str = "backward",
) -> str:
    """
    Data flow analysis tool that replaces: trace_data_flow_backward, trace_data_flow_forward, find_variable_accesses

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
    """
    if direction == "backward":
        if not start_address:
            return "Error: start_address is required for backward direction"
        return "\n".join(
            safe_get("trace_data_flow_backward", {"address": start_address})
        )
    elif direction == "forward":
        if not start_address:
            return "Error: start_address is required for forward direction"
        return "\n".join(
            safe_get("trace_data_flow_forward", {"address": start_address})
        )
    elif direction == "variable_accesses":
        if not variable_name:
            return "Error: variable_name is required for variable_accesses direction"
        return "\n".join(
            safe_get(
                "dataflow/find_variable_accesses",
                {"functionAddress": function_address, "variableName": variable_name},
            )
        )
    else:
        return f"Error: Invalid direction '{direction}'. Must be 'backward', 'forward', or 'variable_accesses'"


@mcp.tool()
def search_constants(
    mode: str = "specific",
    value: str = "",
    min_value: str = "",
    max_value: str = "",
    max_results: int = 500,
    include_small_values: bool = False,
    min_value_filter: str = "",
    top_n: int = 50,
) -> str:
    """
    Constant value search and analysis tool that replaces: find_constant_uses, find_constants_in_range, list_common_constants

    Find specific constants, constants in ranges, or list the most common constants in the program.

    Args:
        mode: Search mode enum ('specific', 'range', 'common'; required)
        value: Constant value to search for when mode='specific' (supports hex with 0x, decimal, negative; required for specific mode)
        min_value: Minimum value when mode='range' or filter minimum when mode='common' (inclusive, supports hex/decimal; required for range mode)
        max_value: Maximum value when mode='range' (inclusive, supports hex/decimal; required for range mode)
        max_results: Maximum number of results to return when mode='specific' or 'range' (default: 500)
        include_small_values: Include small values (0-255) which are often noise when mode='common' (default: False)
        min_value_filter: Alternative minimum value filter for common mode (optional)
        top_n: Number of most common constants to return when mode='common' (default: 50)

    Returns:
        - When mode='specific': List of instructions using the constant
        - When mode='range': List of constants found in the range with occurrence counts
        - When mode='common': JSON with most common constants
    """
    if mode == "specific":
        if not value:
            return "Error: value is required for specific mode"
        return "\n".join(
            safe_get("find_constant", {"value": value, "maxResults": max_results})
        )
    elif mode == "range":
        if not min_value or not max_value:
            return "Error: min_value and max_value are required for range mode"
        return "\n".join(
            safe_get(
                "find_constants_in_range",
                {
                    "minValue": min_value,
                    "maxValue": max_value,
                    "maxResults": max_results,
                },
            )
        )
    elif mode == "common":
        params = {"includeSmallValues": include_small_values, "topN": top_n}
        if min_value_filter:
            params["minValue"] = min_value_filter
        elif min_value:
            params["minValue"] = min_value
        return "\n".join(safe_get("constants/list_common", params))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'specific', 'range', or 'common'"


@mcp.tool()
def manage_strings(
    mode: str = "list",
    pattern: str = "",
    search_string: str = "",
    filter: str = "",
    start_index: int = 0,
    max_count: int = 100,
    offset: int = 0,
    limit: int = 2000,
    max_results: int = 100,
    include_referencing_functions: bool = False,
) -> str:
    """
    String listing, searching, and analysis tool that replaces: list_strings, get_strings,
    search_strings_regex, get_strings_count, get_strings_by_similarity

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
    """
    if mode == "list":
        params = {"offset": offset or start_index, "limit": limit or max_count}
        if filter:
            params["filter"] = filter
        return "\n".join(safe_get("strings", params))
    elif mode == "regex":
        if not pattern:
            return "Error: pattern is required for regex mode"
        return "\n".join(
            safe_get(
                "search_strings_regex", {"pattern": pattern, "maxResults": max_results}
            )
        )
    elif mode == "count":
        return "\n".join(safe_get("get_strings_count"))
    elif mode == "similarity":
        if not search_string:
            return "Error: search_string is required for similarity mode"
        return "\n".join(
            safe_get(
                "strings/get_by_similarity",
                {
                    "searchString": search_string,
                    "startIndex": start_index,
                    "maxCount": max_count,
                    "includeReferencingFunctions": include_referencing_functions,
                },
            )
        )
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'list', 'regex', 'count', or 'similarity'"


@mcp.tool()
def inspect_memory(
    mode: str = "blocks",
    address: str = "",
    length: int = 16,
    offset: int = 0,
    limit: int = 100,
) -> str:
    """
    Memory and data inspection tool that replaces: get_memory_blocks, read_memory,
    get_data_at_address, list_data_items, list_segments

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
    """
    if mode == "blocks":
        return "\n".join(safe_get("memory_blocks"))
    elif mode == "read":
        if not address:
            return "Error: address is required for read mode"
        return "\n".join(
            safe_get("read_memory", {"address": address, "length": length})
        )
    elif mode == "data_at":
        if not address:
            return "Error: address is required for data_at mode"
        return "\n".join(safe_get("get_data_at_address", {"address": address}))
    elif mode == "data_items":
        return "\n".join(safe_get("data", {"offset": offset, "limit": limit}))
    elif mode == "segments":
        return "\n".join(safe_get("segments", {"offset": offset, "limit": limit}))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'blocks', 'read', 'data_at', 'data_items', or 'segments'"


@mcp.tool()
def find_cross_references(
    location: str, direction: str = None, limit: int = 100
) -> str:
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
    return safe_post("create_label", {"address": address, "labelName": label_name})


@mcp.tool()
def get_data_at_address(address: str) -> str:
    """
    Get data information at a specific address.

    Args:
        address: Address to query

    Returns:
        Data type, size, label, and value information
    """
    return "\n".join(safe_get("get_data_at_address", {"address": address}))


# Consolidated tools replacing 90 individual tools with intelligent parameterization


@mcp.tool()
def get_function(
    identifier: str,
    view: str = "decompile",
    offset: int = 1,
    limit: int = 50,
    include_callers: bool = False,
    include_callees: bool = False,
    include_comments: bool = False,
    include_incoming_references: bool = True,
    include_reference_context: bool = True,
) -> str:
    """
    Get the total count of functions in the program.

    Args:
        filter_default_names: Whether to filter out default Ghidra generated names like FUN_, DAT_, etc.

    Returns:
        JSON with function count
    """
    """
    Unified function retrieval tool that replaces: decompile_function, decompile_function_by_address,
    get_decompilation, disassemble_function, get_function_by_address, get_function_info, list_function_calls

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
    """
    if view == "decompile":
        return "\n".join(
            safe_get(
                "decompiler/get_decompilation",
                {
                    "functionNameOrAddress": identifier,
                    "offset": offset,
                    "limit": limit,
                    "includeCallers": include_callers,
                    "includeCallees": include_callees,
                    "includeComments": include_comments,
                    "includeIncomingReferences": include_incoming_references,
                    "includeReferenceContext": include_reference_context,
                },
            )
        )
    elif view == "disassemble":
        return "\n".join(safe_get("disassemble_function", {"address": identifier}))
    elif view == "info":
        return "\n".join(safe_get("get_function_info", {"address": identifier}))
    elif view == "calls":
        return "\n".join(
            safe_get("list_function_calls", {"functionAddress": identifier})
        )
    else:
        return f"Error: Invalid view mode '{view}'. Must be 'decompile', 'disassemble', 'info', or 'calls'"


@mcp.tool()
def list_functions(
    mode: str = "all",
    query: str = "",
    search_string: str = "",
    min_reference_count: int = 1,
    start_index: int = 0,
    max_count: int = 100,
    offset: int = 0,
    limit: int = 100,
    filter_default_names: bool = True,
) -> str:
    """
    Comprehensive function listing and search tool that replaces: list_functions, list_methods,
    search_functions_by_name, get_functions_by_similarity, get_undefined_function_candidates, get_function_count

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
    """
    if mode == "all":
        return "\n".join(
            safe_get(
                "methods",
                {"offset": offset or start_index, "limit": limit or max_count},
            )
        )
    elif mode == "search":
        if not query:
            return "Error: query string is required for search mode"
        return "\n".join(
            safe_get(
                "searchFunctions",
                {
                    "query": query,
                    "offset": offset or start_index,
                    "limit": limit or max_count,
                },
            )
        )
    elif mode == "similarity":
        if not search_string:
            return "Error: search_string is required for similarity mode"
        return "\n".join(
            safe_get(
                "functions/get_by_similarity",
                {
                    "searchString": search_string,
                    "startIndex": start_index,
                    "maxCount": max_count,
                    "filterDefaultNames": filter_default_names,
                },
            )
        )
    elif mode == "undefined":
        return "\n".join(
            safe_get(
                "functions/get_undefined_candidates",
                {
                    "startIndex": start_index,
                    "maxCandidates": max_count,
                    "minReferenceCount": min_reference_count,
                },
            )
        )
    elif mode == "count":
        return "\n".join(
            safe_get(
                "functions/get_count", {"filterDefaultNames": filter_default_names}
            )
        )
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'all', 'search', 'similarity', 'undefined', or 'count'"


@mcp.tool()
def manage_function(
    action: str,
    address: str = "",
    function_identifier: str = "",
    name: str = "",
    old_name: str = "",
    new_name: str = "",
    variable_mappings: str = "",
    prototype: str = "",
    variable_name: str = "",
    new_type: str = "",
    datatype_mappings: str = "",
    archive_name: str = "",
) -> str:
    """
    Function and variable manipulation tool that replaces: create_function, rename_function,
    rename_function_by_address, rename_variable, rename_variables, set_function_prototype,
    set_local_variable_type, change_variable_datatypes

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
    """
    if action == "create":
        if not address:
            return "Error: address is required for create action"
        return safe_post("functions/create", {"address": address, "name": name})
    elif action == "rename_function":
        if not function_identifier:
            return "Error: function_identifier is required for rename_function action"
        if not new_name:
            return "Error: new_name is required for rename_function action"
        return safe_post(
            "renameFunction", {"oldName": function_identifier, "newName": new_name}
        )
    elif action == "rename_variable":
        if not function_identifier:
            return "Error: function_identifier is required for rename_variable action"
        if variable_mappings:
            return safe_post(
                "decompiler/rename_variables",
                {
                    "functionNameOrAddress": function_identifier,
                    "variableMappings": variable_mappings,
                },
            )
        elif old_name and new_name:
            return safe_post(
                "renameVariable",
                {
                    "functionName": function_identifier,
                    "oldName": old_name,
                    "newName": new_name,
                },
            )
        else:
            return "Error: either variable_mappings or both old_name and new_name are required for rename_variable action"
    elif action == "set_prototype":
        if not function_identifier:
            return "Error: function_identifier is required for set_prototype action"
        if not prototype:
            return "Error: prototype is required for set_prototype action"
        return safe_post(
            "set_function_prototype",
            {"function_address": function_identifier, "prototype": prototype},
        )
    elif action == "set_variable_type":
        if not function_identifier:
            return "Error: function_identifier is required for set_variable_type action"
        if not variable_name:
            return "Error: variable_name is required for set_variable_type action"
        if not new_type:
            return "Error: new_type is required for set_variable_type action"
        return safe_post(
            "set_local_variable_type",
            {
                "function_address": function_identifier,
                "variable_name": variable_name,
                "new_type": new_type,
            },
        )
    elif action == "change_datatypes":
        if not function_identifier:
            return "Error: function_identifier is required for change_datatypes action"
        if not datatype_mappings:
            return "Error: datatype_mappings is required for change_datatypes action"
        return safe_post(
            "decompiler/change_variable_datatypes",
            {
                "functionNameOrAddress": function_identifier,
                "datatypeMappings": datatype_mappings,
                "archiveName": archive_name,
            },
        )
    else:
        return f"Error: Invalid action '{action}'. Must be 'create', 'rename_function', 'rename_variable', 'set_prototype', 'set_variable_type', or 'change_datatypes'"


@mcp.tool()
def get_call_graph(
    function_identifier: str,
    mode: str = "graph",
    depth: int = 1,
    direction: str = "callees",
    max_depth: int = 3,
    start_index: int = 0,
    max_callers: int = 10,
    include_call_context: bool = True,
    function_addresses: str = "",
) -> str:
    """
    Call graph and relationship analysis tool that replaces: get_call_graph, get_call_tree,
    get_function_callers, get_function_callees, get_callers_decompiled, find_common_callers

    Analyze function call relationships in various formats: bidirectional graphs, hierarchical trees,
    caller/callee lists, decompiled callers, or common callers.

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
    """
    if mode == "graph":
        return "\n".join(
            safe_get(
                "get_call_graph",
                {"functionAddress": function_identifier, "depth": depth},
            )
        )
    elif mode == "tree":
        return "\n".join(
            safe_get(
                "callgraph/get_tree",
                {
                    "functionAddress": function_identifier,
                    "direction": direction,
                    "maxDepth": max_depth,
                },
            )
        )
    elif mode == "callers":
        return "\n".join(
            safe_get("get_callers", {"functionAddress": function_identifier})
        )
    elif mode == "callees":
        return "\n".join(
            safe_get("get_callees", {"functionAddress": function_identifier})
        )
    elif mode == "callers_decomp":
        return "\n".join(
            safe_get(
                "decompiler/get_callers_decompiled",
                {
                    "functionNameOrAddress": function_identifier,
                    "startIndex": start_index,
                    "maxCallers": max_callers,
                    "includeCallContext": include_call_context,
                },
            )
        )
    elif mode == "common_callers":
        if not function_addresses:
            return "Error: function_addresses is required for common_callers mode"
        return safe_post(
            "callgraph/find_common_callers", {"functionAddresses": function_addresses}
        )
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'graph', 'tree', 'callers', 'callees', 'callers_decomp', or 'common_callers'"


@mcp.tool()
def get_references(
    target: str,
    mode: str = "both",
    direction: str = "both",
    offset: int = 0,
    limit: int = 100,
    max_results: int = 100,
    library_name: str = "",
    start_index: int = 0,
    max_referencers: int = 10,
    include_ref_context: bool = True,
    include_data_refs: bool = True,
) -> str:
    """
    Comprehensive cross-reference analysis tool that replaces: get_xrefs_to, get_xrefs_from,
    find_cross_references, get_function_xrefs, get_referencers_decompiled, find_import_references, resolve_thunk

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
    """
    if mode == "to":
        return "\n".join(
            safe_get("xrefs_to", {"address": target, "offset": offset, "limit": limit})
        )
    elif mode == "from":
        return "\n".join(
            safe_get(
                "xrefs_from", {"address": target, "offset": offset, "limit": limit}
            )
        )
    elif mode == "both":
        params = {"location": target, "limit": limit}
        if direction != "both":
            params["direction"] = direction
        return "\n".join(safe_get("find_cross_references", params))
    elif mode == "function":
        return "\n".join(
            safe_get(
                "function_xrefs", {"name": target, "offset": offset, "limit": limit}
            )
        )
    elif mode == "referencers_decomp":
        return "\n".join(
            safe_get(
                "decompiler/get_referencers_decompiled",
                {
                    "addressOrSymbol": target,
                    "startIndex": start_index,
                    "maxReferencers": max_referencers,
                    "includeRefContext": include_ref_context,
                    "includeDataRefs": include_data_refs,
                },
            )
        )
    elif mode == "import":
        params = {"importName": target, "maxResults": max_results}
        if library_name:
            params["libraryName"] = library_name
        return "\n".join(safe_get("imports/find_references", params))
    elif mode == "thunk":
        return "\n".join(safe_get("imports/resolve_thunk", {"address": target}))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'to', 'from', 'both', 'function', 'referencers_decomp', 'import', or 'thunk'"


@mcp.tool()
def analyze_data_flow(
    function_address: str,
    start_address: str = "",
    variable_name: str = "",
    direction: str = "backward",
) -> str:
    """
    Data flow analysis tool that replaces: trace_data_flow_backward, trace_data_flow_forward, find_variable_accesses

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
    """
    if direction == "backward":
        if not start_address:
            return "Error: start_address is required for backward direction"
        return "\n".join(
            safe_get("trace_data_flow_backward", {"address": start_address})
        )
    elif direction == "forward":
        if not start_address:
            return "Error: start_address is required for forward direction"
        return "\n".join(
            safe_get("trace_data_flow_forward", {"address": start_address})
        )
    elif direction == "variable_accesses":
        if not variable_name:
            return "Error: variable_name is required for variable_accesses direction"
        return "\n".join(
            safe_get(
                "dataflow/find_variable_accesses",
                {"functionAddress": function_address, "variableName": variable_name},
            )
        )
    else:
        return f"Error: Invalid direction '{direction}'. Must be 'backward', 'forward', or 'variable_accesses'"


@mcp.tool()
def search_constants(
    mode: str = "specific",
    value: str = "",
    min_value: str = "",
    max_value: str = "",
    max_results: int = 500,
    include_small_values: bool = False,
    min_value_filter: str = "",
    top_n: int = 50,
) -> str:
    """
    Constant value search and analysis tool that replaces: find_constant_uses, find_constants_in_range, list_common_constants

    Find specific constants, constants in ranges, or list the most common constants in the program.

    Args:
        mode: Search mode enum ('specific', 'range', 'common'; required)
        value: Constant value to search for when mode='specific' (supports hex with 0x, decimal, negative; required for specific mode)
        min_value: Minimum value when mode='range' or filter minimum when mode='common' (inclusive, supports hex/decimal; required for range mode)
        max_value: Maximum value when mode='range' (inclusive, supports hex/decimal; required for range mode)
        max_results: Maximum number of results to return when mode='specific' or 'range' (default: 500)
        include_small_values: Include small values (0-255) which are often noise when mode='common' (default: False)
        min_value_filter: Alternative minimum value filter for common mode (optional)
        top_n: Number of most common constants to return when mode='common' (default: 50)

    Returns:
        - When mode='specific': List of instructions using the constant
        - When mode='range': List of constants found in the range with occurrence counts
        - When mode='common': JSON with most common constants
    """
    if mode == "specific":
        if not value:
            return "Error: value is required for specific mode"
        return "\n".join(
            safe_get("find_constant", {"value": value, "maxResults": max_results})
        )
    elif mode == "range":
        if not min_value or not max_value:
            return "Error: min_value and max_value are required for range mode"
        return "\n".join(
            safe_get(
                "find_constants_in_range",
                {
                    "minValue": min_value,
                    "maxValue": max_value,
                    "maxResults": max_results,
                },
            )
        )
    elif mode == "common":
        params = {"includeSmallValues": include_small_values, "topN": top_n}
        if min_value_filter:
            params["minValue"] = min_value_filter
        elif min_value:
            params["minValue"] = min_value
        return "\n".join(safe_get("constants/list_common", params))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'specific', 'range', or 'common'"


@mcp.tool()
def manage_strings(
    mode: str = "list",
    pattern: str = "",
    search_string: str = "",
    filter: str = "",
    start_index: int = 0,
    max_count: int = 100,
    offset: int = 0,
    limit: int = 2000,
    max_results: int = 100,
    include_referencing_functions: bool = False,
) -> str:
    """
    String listing, searching, and analysis tool that replaces: list_strings, get_strings,
    search_strings_regex, get_strings_count, get_strings_by_similarity

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
    """
    if mode == "list":
        params = {"offset": offset or start_index, "limit": limit or max_count}
        if filter:
            params["filter"] = filter
        return "\n".join(safe_get("strings", params))
    elif mode == "regex":
        if not pattern:
            return "Error: pattern is required for regex mode"
        return "\n".join(
            safe_get(
                "search_strings_regex", {"pattern": pattern, "maxResults": max_results}
            )
        )
    elif mode == "count":
        return "\n".join(safe_get("get_strings_count"))
    elif mode == "similarity":
        if not search_string:
            return "Error: search_string is required for similarity mode"
        return "\n".join(
            safe_get(
                "strings/get_by_similarity",
                {
                    "searchString": search_string,
                    "startIndex": start_index,
                    "maxCount": max_count,
                    "includeReferencingFunctions": include_referencing_functions,
                },
            )
        )
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'list', 'regex', 'count', or 'similarity'"


@mcp.tool()
def inspect_memory(
    mode: str = "blocks",
    address: str = "",
    length: int = 16,
    offset: int = 0,
    limit: int = 100,
) -> str:
    """
    Memory and data inspection tool that replaces: get_memory_blocks, read_memory,
    get_data_at_address, list_data_items, list_segments

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
    """
    if mode == "blocks":
        return "\n".join(safe_get("memory_blocks"))
    elif mode == "read":
        if not address:
            return "Error: address is required for read mode"
        return "\n".join(
            safe_get("read_memory", {"address": address, "length": length})
        )
    elif mode == "data_at":
        if not address:
            return "Error: address is required for data_at mode"
        return "\n".join(safe_get("get_data_at_address", {"address": address}))
    elif mode == "data_items":
        return "\n".join(safe_get("data", {"offset": offset, "limit": limit}))
    elif mode == "segments":
        return "\n".join(safe_get("segments", {"offset": offset, "limit": limit}))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'blocks', 'read', 'data_at', 'data_items', or 'segments'"


@mcp.tool()
def manage_bookmarks(
    action: str = "get",
    address: str = "",
    address_or_symbol: str = "",
    type: str = "",
    category: str = "",
    comment: str = "",
    search_text: str = "",
    max_results: int = 100,
) -> str:
    """
    Bookmark management tool that replaces: set_bookmark, get_bookmarks, search_bookmarks,
    remove_bookmark, list_bookmark_categories

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
    """
    if action == "set":
        if not address or not type or not category or not comment:
            return "Error: address, type, category, and comment are required for set action"
        return safe_post(
            "set_bookmark",
            {
                "address": address,
                "type": type,
                "category": category,
                "comment": comment,
            },
        )
    elif action == "get":
        params = {}
        if address:
            params["address"] = address
        if type:
            params["type"] = type
        return "\n".join(safe_get("get_bookmarks", params))
    elif action == "search":
        if not search_text:
            return "Error: search_text is required for search action"
        return "\n".join(
            safe_get(
                "search_bookmarks",
                {"searchText": search_text, "maxResults": max_results},
            )
        )
    elif action == "remove":
        addr = address_or_symbol or address
        if not addr or not type:
            return "Error: address_or_symbol/address and type are required for remove action"
        params = {"addressOrSymbol": addr, "type": type}
        if category:
            params["category"] = category
        return safe_post("bookmarks/remove", params)
    elif action == "categories":
        bookmark_type = type or "Note"
        return "\n".join(safe_get("bookmarks/list_categories", {"type": bookmark_type}))
    else:
        return f"Error: Invalid action '{action}'. Must be 'set', 'get', 'search', 'remove', or 'categories'"


@mcp.tool()
def manage_comments(
    action: str = "get",
    address: str = "",
    address_or_symbol: str = "",
    function: str = "",
    function_name_or_address: str = "",
    line_number: int = 0,
    comment: str = "",
    comment_type: str = "eol",
    start: str = "",
    end: str = "",
    comment_types: str = "",
    search_text: str = "",
    pattern: str = "",
    case_sensitive: bool = False,
    max_results: int = 100,
    override_max_functions_limit: bool = False,
) -> str:
    """
    Comment management and search tool that replaces: set_decompiler_comment, set_disassembly_comment,
    set_decompilation_comment, set_comment, get_comments, remove_comment, search_comments, search_decompilation

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
    """
    if action == "set":
        if line_number > 0:
            # Decompilation line comment
            func = function_name_or_address or function
            if not func:
                return "Error: function_name_or_address or function is required for decompilation line comments"
            return safe_post(
                "decompiler/set_decompilation_comment",
                {
                    "functionNameOrAddress": func,
                    "lineNumber": line_number,
                    "comment": comment,
                    "commentType": comment_type,
                },
            )
        else:
            # Regular address comment
            addr = address_or_symbol or address
            if not addr or not comment:
                return "Error: address_or_symbol/address and comment are required for set action"
            return safe_post(
                "comments/set",
                {
                    "addressOrSymbol": addr,
                    "comment": comment,
                    "commentType": comment_type,
                },
            )
    elif action == "get":
        params = {}
        addr = address_or_symbol or address
        if addr:
            params["addressOrSymbol"] = addr
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        if comment_types:
            params["commentTypes"] = comment_types
        return "\n".join(safe_get("comments/get", params))
    elif action == "remove":
        addr = address_or_symbol or address
        if not addr:
            return "Error: address_or_symbol or address is required for remove action"
        return safe_post(
            "comments/remove", {"addressOrSymbol": addr, "commentType": comment_type}
        )
    elif action == "search":
        if not search_text:
            return "Error: search_text is required for search action"
        params = {
            "searchText": search_text,
            "caseSensitive": case_sensitive,
            "maxResults": max_results,
        }
        if comment_types:
            params["commentTypes"] = comment_types
        return "\n".join(safe_get("comments/search", params))
    elif action == "search_decomp":
        if not pattern:
            return "Error: pattern is required for search_decomp action"
        return "\n".join(
            safe_get(
                "decompiler/search",
                {
                    "pattern": pattern,
                    "caseSensitive": case_sensitive,
                    "maxResults": max_results,
                    "overrideMaxFunctionsLimit": override_max_functions_limit,
                },
            )
        )
    else:
        return f"Error: Invalid action '{action}'. Must be 'set', 'get', 'remove', 'search', or 'search_decomp'"


@mcp.tool()
def analyze_vtables(
    mode: str = "analyze",
    vtable_address: str = "",
    function_address: str = "",
    max_entries: int = 200,
) -> str:
    """
    Virtual function table analysis tool that replaces: analyze_vtable, find_vtable_callers, find_vtables_containing_function

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
    """
    if mode == "analyze":
        if not vtable_address:
            return "Error: vtable_address is required for analyze mode"
        return "\n".join(
            safe_get(
                "analyze_vtable",
                {"vtableAddress": vtable_address, "maxEntries": max_entries},
            )
        )
    elif mode == "callers":
        if not function_address:
            return "Error: function_address is required for callers mode"
        return "\n".join(
            safe_get("find_vtable_callers", {"functionAddress": function_address})
        )
    elif mode == "containing":
        if not function_address:
            return "Error: function_address is required for containing mode"
        return "\n".join(
            safe_get(
                "vtable/find_containing_function", {"functionAddress": function_address}
            )
        )
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'analyze', 'callers', or 'containing'"


@mcp.tool()
def manage_symbols(
    mode: str = "symbols",
    address: str = "",
    label_name: str = "",
    new_name: str = "",
    library_filter: str = "",
    max_results: int = 500,
    start_index: int = 0,
    offset: int = 0,
    limit: int = 100,
    group_by_library: bool = True,
    include_external: bool = False,
    max_count: int = 200,
    filter_default_names: bool = True,
) -> str:
    """
    Symbol and label management tool that replaces: list_classes, list_namespaces, list_imports,
    list_exports, create_label, get_symbols, get_symbols_count, rename_data

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
    """
    if mode == "classes":
        return "\n".join(
            safe_get(
                "classes",
                {"offset": offset or start_index, "limit": limit or max_count},
            )
        )
    elif mode == "namespaces":
        return "\n".join(
            safe_get(
                "namespaces",
                {"offset": offset or start_index, "limit": limit or max_count},
            )
        )
    elif mode == "imports":
        params = {
            "maxResults": max_results,
            "startIndex": start_index,
            "groupByLibrary": group_by_library,
        }
        if library_filter:
            params["libraryFilter"] = library_filter
        return "\n".join(safe_get("imports/list", params))
    elif mode == "exports":
        return "\n".join(
            safe_get(
                "exports/list", {"maxResults": max_results, "startIndex": start_index}
            )
        )
    elif mode == "create_label":
        if not address or not label_name:
            return "Error: address and label_name are required for create_label mode"
        return safe_post("create_label", {"address": address, "labelName": label_name})
    elif mode == "symbols":
        return "\n".join(
            safe_get(
                "symbols/get",
                {
                    "includeExternal": include_external,
                    "startIndex": start_index,
                    "maxCount": max_count,
                    "filterDefaultNames": filter_default_names,
                },
            )
        )
    elif mode == "count":
        return "\n".join(
            safe_get(
                "symbols/get_count",
                {
                    "includeExternal": include_external,
                    "filterDefaultNames": filter_default_names,
                },
            )
        )
    elif mode == "rename_data":
        if not address or not new_name:
            return "Error: address and new_name are required for rename_data mode"
        return safe_post("renameData", {"address": address, "newName": new_name})
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'classes', 'namespaces', 'imports', 'exports', 'create_label', 'symbols', 'count', or 'rename_data'"


@mcp.tool()
def manage_structures(
    action: str = "list",
    c_definition: str = "",
    header_content: str = "",
    structure_name: str = "",
    name: str = "",
    size: int = 0,
    type: str = "structure",
    category: str = "/",
    packed: bool = False,
    description: str = "",
    field_name: str = "",
    data_type: str = "",
    offset: int = None,
    comment: str = "",
    new_data_type: str = "",
    new_field_name: str = "",
    new_comment: str = "",
    new_length: int = None,
    address_or_symbol: str = "",
    clear_existing: bool = True,
    force: bool = False,
    name_filter: str = "",
    include_built_in: bool = False,
) -> str:
    """
    Structure management tool that replaces: parse_c_structure, validate_c_structure, create_structure,
    add_structure_field, modify_structure_field, modify_structure_from_c, get_structure_info,
    list_structures, apply_structure, delete_structure, parse_c_header

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
    """
    if action == "parse":
        if not c_definition:
            return "Error: c_definition is required for parse action"
        return safe_post(
            "structures/parse_c_structure",
            {"cDefinition": c_definition, "category": category},
        )
    elif action == "validate":
        if not c_definition:
            return "Error: c_definition is required for validate action"
        return safe_post(
            "structures/validate_c_structure", {"cDefinition": c_definition}
        )
    elif action == "create":
        if not name:
            return "Error: name is required for create action"
        params = {
            "name": name,
            "size": size,
            "type": type,
            "category": category,
            "packed": packed,
        }
        if description:
            params["description"] = description
        return safe_post("structures/create_structure", params)
    elif action == "add_field":
        if not structure_name or not field_name or not data_type:
            return "Error: structure_name, field_name, and data_type are required for add_field action"
        params = {
            "structureName": structure_name,
            "fieldName": field_name,
            "dataType": data_type,
        }
        if offset is not None:
            params["offset"] = offset
        if comment:
            params["comment"] = comment
        return safe_post("structures/add_structure_field", params)
    elif action == "modify_field":
        if not structure_name:
            return "Error: structure_name is required for modify_field action"
        params = {"structureName": structure_name}
        if field_name:
            params["fieldName"] = field_name
        if offset is not None:
            params["offset"] = offset
        if new_data_type:
            params["newDataType"] = new_data_type
        if new_field_name:
            params["newFieldName"] = new_field_name
        if new_comment:
            params["newComment"] = new_comment
        if new_length is not None:
            params["newLength"] = new_length
        return safe_post("structures/modify_structure_field", params)
    elif action == "modify_from_c":
        if not c_definition:
            return "Error: c_definition is required for modify_from_c action"
        return safe_post(
            "structures/modify_structure_from_c", {"cDefinition": c_definition}
        )
    elif action == "info":
        if not structure_name:
            return "Error: structure_name is required for info action"
        return "\n".join(
            safe_get("structures/get_structure_info", {"structureName": structure_name})
        )
    elif action == "list":
        params = {"includeBuiltIn": include_built_in}
        if category:
            params["category"] = category
        if name_filter:
            params["nameFilter"] = name_filter
        return "\n".join(safe_get("structures/list_structures", params))
    elif action == "apply":
        if not structure_name or not address_or_symbol:
            return "Error: structure_name and address_or_symbol are required for apply action"
        return safe_post(
            "structures/apply_structure",
            {
                "structureName": structure_name,
                "addressOrSymbol": address_or_symbol,
                "clearExisting": clear_existing,
            },
        )
    elif action == "delete":
        if not structure_name:
            return "Error: structure_name is required for delete action"
        return safe_post(
            "structures/delete_structure",
            {"structureName": structure_name, "force": force},
        )
    elif action == "parse_header":
        if not header_content:
            return "Error: header_content is required for parse_header action"
        return safe_post(
            "structures/parse_c_header",
            {"headerContent": header_content, "category": category},
        )
    else:
        return f"Error: Invalid action '{action}'. Must be 'parse', 'validate', 'create', 'add_field', 'modify_field', 'modify_from_c', 'info', 'list', 'apply', 'delete', or 'parse_header'"


@mcp.tool()
def manage_data_types(
    action: str = "list",
    archive_name: str = "",
    category_path: str = "/",
    include_subcategories: bool = False,
    start_index: int = 0,
    max_count: int = 100,
    data_type_string: str = "",
    address_or_symbol: str = "",
) -> str:
    """
    Data type management tool that replaces: get_data_type_archives, get_data_types, get_data_type_by_string, apply_data_type

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
    """
    if action == "archives":
        return "\n".join(safe_get("datatypes/get_archives", {}))
    elif action == "list":
        if not archive_name:
            return "Error: archive_name is required for list action"
        return "\n".join(
            safe_get(
                "datatypes/get_types",
                {
                    "archiveName": archive_name,
                    "categoryPath": category_path,
                    "includeSubcategories": include_subcategories,
                    "startIndex": start_index,
                    "maxCount": max_count,
                },
            )
        )
    elif action == "by_string":
        if not data_type_string:
            return "Error: data_type_string is required for by_string action"
        params = {"dataTypeString": data_type_string}
        if archive_name:
            params["archiveName"] = archive_name
        return "\n".join(safe_get("datatypes/get_by_string", params))
    elif action == "apply":
        if not data_type_string or not address_or_symbol:
            return "Error: data_type_string and address_or_symbol are required for apply action"
        return safe_post(
            "data/apply_data_type",
            {
                "addressOrSymbol": address_or_symbol,
                "dataTypeString": data_type_string,
                "archiveName": archive_name,
            },
        )
    else:
        return f"Error: Invalid action '{action}'. Must be 'archives', 'list', 'by_string', or 'apply'"


@mcp.tool()
def get_current_context(mode: str = "both") -> str:
    """
    Current context retrieval tool that replaces: get_current_address, get_current_function

    Get the address or function currently selected in the Ghidra GUI.

    Args:
        mode: Context mode enum ('address', 'function', 'both'; default: 'both')

    Returns:
        - When mode='address': The address currently selected by the user
        - When mode='function': The function currently selected by the user
        - When mode='both': JSON with both current address and function
    """
    if mode == "address":
        return "\n".join(safe_get("get_current_address"))
    elif mode == "function":
        return "\n".join(safe_get("get_current_function"))
    elif mode == "both":
        address = "\n".join(safe_get("get_current_address"))
        function = "\n".join(safe_get("get_current_function"))
        return f"Current Address: {address}\nCurrent Function: {function}"
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'address', 'function', or 'both'"


@mcp.tool()
def manage_function_tags(function: str, mode: str, tags: str = "") -> str:
    """
    Function tag management tool that replaces: function_tags

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
    """
    if mode in ["get", "set", "add", "remove"]:
        if not function:
            return f"Error: function is required for {mode} mode"
    if mode in ["add"] and not tags:
        return f"Error: tags are required for {mode} mode"

    return safe_post(
        "functions/tags", {"function": function, "mode": mode, "tags": tags}
    )
    """
    Manage function tags. Tags categorize functions (e.g., 'AI', 'rendering').

    Args:
        function: Function name or address (required for get/set/add/remove modes)
        mode: Operation: 'get' (tags on function), 'set' (replace), 'add', 'remove', 'list' (all tags in program)
        tags: Tag names (required for add; optional for set/remove). Comma-separated.

    Returns:
        JSON with tag information or success message
    """
    return safe_post(
        "functions/tags", {"function": function, "mode": mode, "tags": tags}
    )


@mcp.tool()
def get_strings_by_similarity(
    search_string: str,
    start_index: int = 0,
    max_count: int = 100,
    include_referencing_functions: bool = False,
) -> str:
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
    return "\n".join(
        safe_get(
            "strings/get_by_similarity",
            {
                "searchString": search_string,
                "startIndex": start_index,
                "maxCount": max_count,
                "includeReferencingFunctions": include_referencing_functions,
            },
        )
    )


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
    return safe_post(
        "comments/set",
        {
            "addressOrSymbol": address_or_symbol,
            "comment": comment,
            "commentType": comment_type,
        },
    )


@mcp.tool()
def get_comments(
    address_or_symbol: str = "", start: str = "", end: str = "", comment_types: str = ""
) -> str:
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
    return safe_post(
        "comments/remove",
        {"addressOrSymbol": address_or_symbol, "commentType": comment_type},
    )


@mcp.tool()
def search_comments(
    search_text: str,
    case_sensitive: bool = False,
    comment_types: str = "",
    max_results: int = 100,
) -> str:
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
        "maxResults": max_results,
    }
    if comment_types:
        params["commentTypes"] = comment_types
    return "\n".join(safe_get("comments/search", params))


@mcp.tool()
def apply_data_type(
    address_or_symbol: str, data_type_string: str, archive_name: str = ""
) -> str:
    """
    Apply a data type to a specific address or symbol in a program.

    Args:
        address_or_symbol: Address or symbol name to apply the data type to
        data_type_string: String representation of the data type (e.g., 'char**', 'int[10]')
        archive_name: Optional name of the data type archive to search in

    Returns:
        Success or failure message
    """
    return safe_post(
        "data/apply_data_type",
        {
            "addressOrSymbol": address_or_symbol,
            "dataTypeString": data_type_string,
            "archiveName": archive_name,
        },
    )


@mcp.tool()
def get_symbols_count(
    include_external: bool = False, filter_default_names: bool = True
) -> str:
    """
    Get the total count of symbols in the program.

    Args:
        include_external: Whether to include external symbols in the count
        filter_default_names: Whether to filter out default Ghidra generated names

    Returns:
        JSON with symbol count
    """
    return "\n".join(
        safe_get(
            "symbols/get_count",
            {
                "includeExternal": include_external,
                "filterDefaultNames": filter_default_names,
            },
        )
    )


@mcp.tool()
def get_symbols(
    include_external: bool = False,
    start_index: int = 0,
    max_count: int = 200,
    filter_default_names: bool = True,
) -> str:
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
    return "\n".join(
        safe_get(
            "symbols/get",
            {
                "includeExternal": include_external,
                "startIndex": start_index,
                "maxCount": max_count,
                "filterDefaultNames": filter_default_names,
            },
        )
    )


@mcp.tool()
def find_import_references(
    import_name: str, library_name: str = "", max_results: int = 100
) -> str:
    """
    Find all locations where a specific imported function is called.

    Args:
        import_name: Name of the imported function to find references for (case-insensitive)
        library_name: Optional specific library name to narrow search (case-insensitive)
        max_results: Maximum number of references to return

    Returns:
        JSON with references to the imported function
    """
    params = {"importName": import_name, "maxResults": max_results}
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
    return "\n".join(safe_get("imports/resolve_thunk", {"address": address}))


@mcp.tool()
def get_call_tree(
    function_address: str, direction: str = "callees", max_depth: int = 3
) -> str:
    """
    Get a hierarchical call tree starting from a function.

    Args:
        function_address: Address or name of the function to analyze
        direction: Direction to traverse: 'callers' (who calls this) or 'callees' (what this calls)
        max_depth: Maximum depth to traverse (default: 3, max: 10)

    Returns:
        Call tree as formatted text
    """
    return "\n".join(
        safe_get(
            "callgraph/get_tree",
            {
                "functionAddress": function_address,
                "direction": direction,
                "maxDepth": max_depth,
            },
        )
    )


@mcp.tool()
def find_common_callers(function_addresses: str) -> str:
    """
    Find functions that call ALL of the specified target functions.

    Args:
        function_addresses: Comma-separated list of function addresses or names

    Returns:
        List of common callers
    """
    return safe_post(
        "callgraph/find_common_callers", {"functionAddresses": function_addresses}
    )


@mcp.tool()
def list_common_constants(
    include_small_values: bool = False, min_value: str = "", top_n: int = 50
) -> str:
    """
    Find the most frequently used constant values in the program.

    Args:
        include_small_values: Include small values (0-255) which are often noise
        min_value: Optional minimum value to consider (filters out small constants)
        top_n: Number of most common constants to return

    Returns:
        JSON with most common constants
    """
    params = {"includeSmallValues": include_small_values, "topN": top_n}
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
    return "\n".join(
        safe_get(
            "dataflow/find_variable_accesses",
            {"functionAddress": function_address, "variableName": variable_name},
        )
    )


@mcp.tool()
def find_vtables_containing_function(function_address: str) -> str:
    """
    Find all vtables that contain a pointer to the given function.

    Args:
        function_address: Address or name of the function to search for in vtables

    Returns:
        JSON with vtables containing the function
    """
    return "\n".join(
        safe_get(
            "vtable/find_containing_function", {"functionAddress": function_address}
        )
    )


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
    return safe_post(
        "bookmarks/remove",
        {"addressOrSymbol": address_or_symbol, "type": type, "category": category},
    )


@mcp.tool()
def list_bookmark_categories(type: str = "Note") -> str:
    """
    List all categories for a given bookmark type.

    Args:
        type: Bookmark type to get categories for

    Returns:
        JSON with bookmark categories
    """
    return "\n".join(safe_get("bookmarks/list_categories", {"type": type}))


@mcp.tool()
def search_decompilation(
    pattern: str,
    case_sensitive: bool = False,
    max_results: int = 50,
    override_max_functions_limit: bool = False,
) -> str:
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
    return "\n".join(
        safe_get(
            "decompiler/search",
            {
                "pattern": pattern,
                "caseSensitive": case_sensitive,
                "maxResults": max_results,
                "overrideMaxFunctionsLimit": override_max_functions_limit,
            },
        )
    )


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
    return safe_post(
        "decompiler/rename_variables",
        {
            "functionNameOrAddress": function_name_or_address,
            "variableMappings": variable_mappings,
        },
    )


@mcp.tool()
def change_variable_datatypes(
    function_name_or_address: str, datatype_mappings: str, archive_name: str = ""
) -> str:
    """
    Change data types of variables in a decompiled function.

    Args:
        function_name_or_address: Function name, address, or symbol to change variable data types in
        datatype_mappings: Mapping of variable names to new data type strings (format: "varName1:type1,varName2:type2")
        archive_name: Optional name of the data type archive to search for data types

    Returns:
        Success or failure message
    """
    return safe_post(
        "decompiler/change_variable_datatypes",
        {
            "functionNameOrAddress": function_name_or_address,
            "datatypeMappings": datatype_mappings,
            "archiveName": archive_name,
        },
    )


@mcp.tool()
def get_callers_decompiled(
    function_name_or_address: str,
    start_index: int = 0,
    max_callers: int = 10,
    include_call_context: bool = True,
) -> str:
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
    return "\n".join(
        safe_get(
            "decompiler/get_callers_decompiled",
            {
                "functionNameOrAddress": function_name_or_address,
                "startIndex": start_index,
                "maxCallers": max_callers,
                "includeCallContext": include_call_context,
            },
        )
    )


@mcp.tool()
def get_referencers_decompiled(
    address_or_symbol: str,
    start_index: int = 0,
    max_referencers: int = 10,
    include_ref_context: bool = True,
    include_data_refs: bool = True,
) -> str:
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
    return "\n".join(
        safe_get(
            "decompiler/get_referencers_decompiled",
            {
                "addressOrSymbol": address_or_symbol,
                "startIndex": start_index,
                "maxReferencers": max_referencers,
                "includeRefContext": include_ref_context,
                "includeDataRefs": include_data_refs,
            },
        )
    )


@mcp.tool()
def get_data_type_archives() -> str:
    """
    Get data type archives for a specific program.

    Returns:
        JSON with data type archives
    """
    return "\n".join(safe_get("datatypes/get_archives", {}))


@mcp.tool()
def get_data_types(
    archive_name: str,
    category_path: str = "/",
    include_subcategories: bool = False,
    start_index: int = 0,
    max_count: int = 100,
) -> str:
    """
    Get data types from a data type archive.

    Args:
        archive_name: Name of the data type archive
        category_path: Path to category to list data types from (e.g., '/Structure'). Use '/' for root category.
        include_subcategories: Whether to include data types from subcategories
        start_index: Starting index for pagination (0-based)
        max_count: Maximum number of data types to return

    Returns:
        JSON with data types
    """
    return "\n".join(
        safe_get(
            "datatypes/get_types",
            {
                "archiveName": archive_name,
                "categoryPath": category_path,
                "includeSubcategories": include_subcategories,
                "startIndex": start_index,
                "maxCount": max_count,
            },
        )
    )


@mcp.tool()
def get_data_type_by_string(data_type_string: str, archive_name: str = "") -> str:
    """
    Get a data type by its string representation.

    Args:
        data_type_string: String representation of the data type (e.g., 'char**', 'int[10]')
        archive_name: Optional name of the data type archive to search in

    Returns:
        JSON with data type information
    """
    params = {"dataTypeString": data_type_string}
    if archive_name:
        params["archiveName"] = archive_name
    return "\n".join(safe_get("datatypes/get_by_string", params))


@mcp.tool()
def list_imports(
    library_filter: str = None,
    max_results: int = 500,
    start_index: int = 0,
    group_by_library: bool = True,
) -> str:
    """
    List all imported functions from external libraries with pagination.

    Args:
        library_filter: Optional library name to filter by (case-insensitive)
        max_results: Maximum number of imports to return (default: 500)
        start_index: Starting index for pagination (default: 0)
        group_by_library: Whether to group imports by library name (default: true)

    Returns:
        JSON with imports list or grouped by library
    """
    params = {
        "maxResults": max_results,
        "startIndex": start_index,
        "groupByLibrary": group_by_library,
    }
    if library_filter:
        params["libraryFilter"] = library_filter
    return "\n".join(safe_get("imports/list", params))


@mcp.tool()
def list_exports(max_results: int = 500, start_index: int = 0) -> str:
    """
    List all exported symbols from the binary with pagination.

    Args:
        max_results: Maximum number of exports to return (default: 500)
        start_index: Starting index for pagination (default: 0)

    Returns:
        JSON with exports list
    """
    return "\n".join(
        safe_get("exports/list", {"maxResults": max_results, "startIndex": start_index})
    )


@mcp.tool()
def get_strings(
    start_index: int = 0,
    max_count: int = 100,
    include_referencing_functions: bool = False,
) -> str:
    """
    Get strings from the program with pagination.

    Args:
        start_index: Starting index for pagination (0-based)
        max_count: Maximum number of strings to return
        include_referencing_functions: Include list of functions that reference each string

    Returns:
        JSON with strings list and pagination info
    """
    return "\n".join(
        safe_get(
            "strings/get",
            {
                "startIndex": start_index,
                "maxCount": max_count,
                "includeReferencingFunctions": include_referencing_functions,
            },
        )
    )


@mcp.tool()
def get_decompilation(
    function_name_or_address: str,
    offset: int = 1,
    limit: int = 50,
    include_callers: bool = False,
    include_callees: bool = False,
    include_comments: bool = False,
    include_incoming_references: bool = True,
    include_reference_context: bool = True,
) -> str:
    """
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
    """
    return "\n".join(
        safe_get(
            "decompiler/get_decompilation",
            {
                "functionNameOrAddress": function_name_or_address,
                "offset": offset,
                "limit": limit,
                "includeCallers": include_callers,
                "includeCallees": include_callees,
                "includeComments": include_comments,
                "includeIncomingReferences": include_incoming_references,
                "includeReferenceContext": include_reference_context,
            },
        )
    )


@mcp.tool()
def set_decompilation_comment(
    function_name_or_address: str,
    line_number: int,
    comment: str,
    comment_type: str = "eol",
) -> str:
    """
    Set a comment at a specific line in decompiled code.

    Args:
        function_name_or_address: Function name or address
        line_number: Line number in the decompiled function (1-based)
        comment: The comment text to set
        comment_type: Type of comment: 'pre' or 'eol' (end-of-line, default)

    Returns:
        JSON with success status
    """
    return safe_post(
        "decompiler/set_decompilation_comment",
        {
            "functionNameOrAddress": function_name_or_address,
            "lineNumber": line_number,
            "comment": comment,
            "commentType": comment_type,
        },
    )


@mcp.tool()
def get_call_tree(
    function_address: str, direction: str = "callees", max_depth: int = 3
) -> str:
    """
    Get a hierarchical call tree starting from a function.

    Args:
        function_address: Function name or address to analyze
        direction: Direction to traverse: 'callers' (who calls this) or 'callees' (what this calls, default)
        max_depth: Maximum depth to traverse (default: 3, max: 10)

    Returns:
        JSON with hierarchical call tree
    """
    return "\n".join(
        safe_get(
            "callgraph/get_tree",
            {
                "functionAddress": function_address,
                "direction": direction,
                "maxDepth": max_depth,
            },
        )
    )


@mcp.tool()
def parse_c_structure(c_definition: str, category: str = "/") -> str:
    """
    Parse and create structures from C-style definitions.

    Args:
        c_definition: C-style structure definition
        category: Category path (default: /)

    Returns:
        JSON with created structure info
    """
    return safe_post(
        "structures/parse_c_structure",
        {"cDefinition": c_definition, "category": category},
    )


@mcp.tool()
def validate_c_structure(c_definition: str) -> str:
    """
    Validate C-style structure definition without creating it.

    Args:
        c_definition: C-style structure definition to validate

    Returns:
        JSON with validation result
    """
    return safe_post("structures/validate_c_structure", {"cDefinition": c_definition})


@mcp.tool()
def create_structure(
    name: str,
    size: int = 0,
    type: str = "structure",
    category: str = "/",
    packed: bool = False,
    description: str = None,
) -> str:
    """
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
    """
    params = {
        "name": name,
        "size": size,
        "type": type,
        "category": category,
        "packed": packed,
    }
    if description:
        params["description"] = description
    return safe_post("structures/create_structure", params)


@mcp.tool()
def add_structure_field(
    structure_name: str,
    field_name: str,
    data_type: str,
    offset: int = None,
    comment: str = None,
) -> str:
    """
    Add a field to an existing structure.

    Args:
        structure_name: Name of the structure
        field_name: Name of the field
        data_type: Data type (e.g., 'int', 'char[32]')
        offset: Offset (for structures, omit to append)
        comment: Field comment

    Returns:
        JSON with success status
    """
    params = {
        "structureName": structure_name,
        "fieldName": field_name,
        "dataType": data_type,
    }
    if offset is not None:
        params["offset"] = offset
    if comment:
        params["comment"] = comment
    return safe_post("structures/add_structure_field", params)


@mcp.tool()
def modify_structure_field(
    structure_name: str,
    field_name: str = None,
    offset: int = None,
    new_data_type: str = None,
    new_field_name: str = None,
    new_comment: str = None,
    new_length: int = None,
) -> str:
    """
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
    """
    params = {"structureName": structure_name}
    if field_name:
        params["fieldName"] = field_name
    if offset is not None:
        params["offset"] = offset
    if new_data_type:
        params["newDataType"] = new_data_type
    if new_field_name:
        params["newFieldName"] = new_field_name
    if new_comment:
        params["newComment"] = new_comment
    if new_length is not None:
        params["newLength"] = new_length
    return safe_post("structures/modify_structure_field", params)


@mcp.tool()
def modify_structure_from_c(c_definition: str) -> str:
    """
    Modify an existing structure using a C-style definition.

    Args:
        c_definition: Complete C structure definition with modifications

    Returns:
        JSON with success status
    """
    return safe_post(
        "structures/modify_structure_from_c", {"cDefinition": c_definition}
    )


@mcp.tool()
def get_structure_info(structure_name: str) -> str:
    """
    Get detailed information about a structure.

    Args:
        structure_name: Name of the structure

    Returns:
        JSON with structure info including all fields
    """
    return "\n".join(
        safe_get("structures/get_structure_info", {"structureName": structure_name})
    )


@mcp.tool()
def list_structures(
    category: str = None, name_filter: str = None, include_built_in: bool = False
) -> str:
    """
    List all structures in a program.

    Args:
        category: Filter by category path
        name_filter: Filter by name (substring match)
        include_built_in: Include built-in types

    Returns:
        JSON with list of structures
    """
    params = {"includeBuiltIn": include_built_in}
    if category:
        params["category"] = category
    if name_filter:
        params["nameFilter"] = name_filter
    return "\n".join(safe_get("structures/list_structures", params))


@mcp.tool()
def apply_structure(
    structure_name: str, address_or_symbol: str, clear_existing: bool = True
) -> str:
    """
    Apply a structure at a specific address.

    Args:
        structure_name: Name of the structure
        address_or_symbol: Address or symbol name to apply structure
        clear_existing: Clear existing data

    Returns:
        JSON with success status
    """
    return safe_post(
        "structures/apply_structure",
        {
            "structureName": structure_name,
            "addressOrSymbol": address_or_symbol,
            "clearExisting": clear_existing,
        },
    )


@mcp.tool()
def delete_structure(structure_name: str, force: bool = False) -> str:
    """
    Delete a structure from the program.

    Args:
        structure_name: Name of the structure to delete
        force: Force deletion even if structure is referenced (default: false)

    Returns:
        JSON with success status or reference warnings
    """
    return safe_post(
        "structures/delete_structure", {"structureName": structure_name, "force": force}
    )


@mcp.tool()
def parse_c_header(header_content: str, category: str = "/") -> str:
    """
    Parse an entire C header file and create all structures.

    Args:
        header_content: C header file content
        category: Category path (default: /)

    Returns:
        JSON with created types info
    """
    return safe_post(
        "structures/parse_c_header",
        {"headerContent": header_content, "category": category},
    )


# Consolidated tools replacing 90 individual tools with intelligent parameterization

@mcp.tool()
def get_function_consolidated(identifier: str, view: str = "decompile", offset: int = 1, limit: int = 50,
                include_callers: bool = False, include_callees: bool = False,
                include_comments: bool = False, include_incoming_references: bool = True,
                include_reference_context: bool = True) -> str:
    """
    Unified function retrieval tool that replaces: decompile_function, decompile_function_by_address,
    get_decompilation, disassemble_function, get_function_by_address, get_function_info, list_function_calls

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
    """
    if view == "decompile":
        return "\n".join(safe_get("decompiler/get_decompilation", {
            "functionNameOrAddress": identifier,
            "offset": offset,
            "limit": limit,
            "includeCallers": include_callers,
            "includeCallees": include_callees,
            "includeComments": include_comments,
            "includeIncomingReferences": include_incoming_references,
            "includeReferenceContext": include_reference_context
        }))
    elif view == "disassemble":
        return "\n".join(safe_get("disassemble_function", {"address": identifier}))
    elif view == "info":
        return "\n".join(safe_get("get_function_info", {"address": identifier}))
    elif view == "calls":
        return "\n".join(safe_get("list_function_calls", {"functionAddress": identifier}))
    else:
        return f"Error: Invalid view mode '{view}'. Must be 'decompile', 'disassemble', 'info', or 'calls'"


@mcp.tool()
def list_functions_consolidated(mode: str = "all", query: str = "", search_string: str = "",
                  min_reference_count: int = 1, start_index: int = 0, max_count: int = 100,
                  offset: int = 0, limit: int = 100, filter_default_names: bool = True) -> str:
    """
    Comprehensive function listing and search tool that replaces: list_functions, list_methods,
    search_functions_by_name, get_functions_by_similarity, get_undefined_function_candidates, get_function_count

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
    """
    if mode == "all":
        return "\n".join(safe_get("methods", {"offset": offset or start_index, "limit": limit or max_count}))
    elif mode == "search":
        if not query:
            return "Error: query string is required for search mode"
        return "\n".join(safe_get("searchFunctions", {
            "query": query,
            "offset": offset or start_index,
            "limit": limit or max_count
        }))
    elif mode == "similarity":
        if not search_string:
            return "Error: search_string is required for similarity mode"
        return "\n".join(safe_get("functions/get_by_similarity", {
            "searchString": search_string,
            "startIndex": start_index,
            "maxCount": max_count,
            "filterDefaultNames": filter_default_names
        }))
    elif mode == "undefined":
        return "\n".join(safe_get("functions/get_undefined_candidates", {
            "startIndex": start_index,
            "maxCandidates": max_count,
            "minReferenceCount": min_reference_count
        }))
    elif mode == "count":
        return "\n".join(safe_get("functions/get_count", {"filterDefaultNames": filter_default_names}))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'all', 'search', 'similarity', 'undefined', or 'count'"


@mcp.tool()
def manage_function_consolidated(action: str, address: str = "", function_identifier: str = "", name: str = "",
                   old_name: str = "", new_name: str = "", variable_mappings: str = "",
                   prototype: str = "", variable_name: str = "", new_type: str = "",
                   datatype_mappings: str = "", archive_name: str = "") -> str:
    """
    Function and variable manipulation tool that replaces: create_function, rename_function,
    rename_function_by_address, rename_variable, rename_variables, set_function_prototype,
    set_local_variable_type, change_variable_datatypes

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
    """
    if action == "create":
        if not address:
            return "Error: address is required for create action"
        return safe_post("functions/create", {"address": address, "name": name})
    elif action == "rename_function":
        if not function_identifier:
            return "Error: function_identifier is required for rename_function action"
        if not new_name:
            return "Error: new_name is required for rename_function action"
        return safe_post("renameFunction", {"oldName": function_identifier, "newName": new_name})
    elif action == "rename_variable":
        if not function_identifier:
            return "Error: function_identifier is required for rename_variable action"
        if variable_mappings:
            return safe_post("decompiler/rename_variables", {
                "functionNameOrAddress": function_identifier,
                "variableMappings": variable_mappings
            })
        elif old_name and new_name:
            return safe_post("renameVariable", {
                "functionName": function_identifier,
                "oldName": old_name,
                "newName": new_name
            })
        else:
            return "Error: either variable_mappings or both old_name and new_name are required for rename_variable action"
    elif action == "set_prototype":
        if not function_identifier:
            return "Error: function_identifier is required for set_prototype action"
        if not prototype:
            return "Error: prototype is required for set_prototype action"
        return safe_post("set_function_prototype", {
            "function_address": function_identifier,
            "prototype": prototype
        })
    elif action == "set_variable_type":
        if not function_identifier:
            return "Error: function_identifier is required for set_variable_type action"
        if not variable_name:
            return "Error: variable_name is required for set_variable_type action"
        if not new_type:
            return "Error: new_type is required for set_variable_type action"
        return safe_post("set_local_variable_type", {
            "function_address": function_identifier,
            "variable_name": variable_name,
            "new_type": new_type
        })
    elif action == "change_datatypes":
        if not function_identifier:
            return "Error: function_identifier is required for change_datatypes action"
        if not datatype_mappings:
            return "Error: datatype_mappings is required for change_datatypes action"
        return safe_post("decompiler/change_variable_datatypes", {
            "functionNameOrAddress": function_identifier,
            "datatypeMappings": datatype_mappings,
            "archiveName": archive_name
        })
    else:
        return f"Error: Invalid action '{action}'. Must be 'create', 'rename_function', 'rename_variable', 'set_prototype', 'set_variable_type', or 'change_datatypes'"


@mcp.tool()
def get_call_graph_consolidated(function_identifier: str, mode: str = "graph", depth: int = 1,
                  direction: str = "callees", max_depth: int = 3, start_index: int = 0,
                  max_callers: int = 10, include_call_context: bool = True,
                  function_addresses: str = "") -> str:
    """
    Call graph and relationship analysis tool that replaces: get_call_graph, get_call_tree,
    get_function_callers, get_function_callees, get_callers_decompiled, find_common_callers

    Analyze function call relationships in various formats: bidirectional graphs, hierarchical trees,
    caller/callee lists, decompiled callers, or common callers.

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
    """
    if mode == "graph":
        return "\n".join(safe_get("get_call_graph", {"functionAddress": function_identifier, "depth": depth}))
    elif mode == "tree":
        return "\n".join(safe_get("callgraph/get_tree", {
            "functionAddress": function_identifier,
            "direction": direction,
            "maxDepth": max_depth
        }))
    elif mode == "callers":
        return "\n".join(safe_get("get_callers", {"functionAddress": function_identifier}))
    elif mode == "callees":
        return "\n".join(safe_get("get_callees", {"functionAddress": function_identifier}))
    elif mode == "callers_decomp":
        return "\n".join(safe_get("decompiler/get_callers_decompiled", {
            "functionNameOrAddress": function_identifier,
            "startIndex": start_index,
            "maxCallers": max_callers,
            "includeCallContext": include_call_context
        }))
    elif mode == "common_callers":
        if not function_addresses:
            return "Error: function_addresses is required for common_callers mode"
        return safe_post("callgraph/find_common_callers", {"functionAddresses": function_addresses})
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'graph', 'tree', 'callers', 'callees', 'callers_decomp', or 'common_callers'"


@mcp.tool()
def get_references_consolidated(target: str, mode: str = "both", direction: str = "both", offset: int = 0,
                  limit: int = 100, max_results: int = 100, library_name: str = "",
                  start_index: int = 0, max_referencers: int = 10,
                  include_ref_context: bool = True, include_data_refs: bool = True) -> str:
    """
    Comprehensive cross-reference analysis tool that replaces: get_xrefs_to, get_xrefs_from,
    find_cross_references, get_function_xrefs, get_referencers_decompiled, find_import_references, resolve_thunk

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
    """
    if mode == "to":
        return "\n".join(safe_get("xrefs_to", {"address": target, "offset": offset, "limit": limit}))
    elif mode == "from":
        return "\n".join(safe_get("xrefs_from", {"address": target, "offset": offset, "limit": limit}))
    elif mode == "both":
        params = {"location": target, "limit": limit}
        if direction != "both":
            params["direction"] = direction
        return "\n".join(safe_get("find_cross_references", params))
    elif mode == "function":
        return "\n".join(safe_get("function_xrefs", {"name": target, "offset": offset, "limit": limit}))
    elif mode == "referencers_decomp":
        return "\n".join(safe_get("decompiler/get_referencers_decompiled", {
            "addressOrSymbol": target,
            "startIndex": start_index,
            "maxReferencers": max_referencers,
            "includeRefContext": include_ref_context,
            "includeDataRefs": include_data_refs
        }))
    elif mode == "import":
        params = {"importName": target, "maxResults": max_results}
        if library_name:
            params["libraryName"] = library_name
        return "\n".join(safe_get("imports/find_references", params))
    elif mode == "thunk":
        return "\n".join(safe_get("imports/resolve_thunk", {"address": target}))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'to', 'from', 'both', 'function', 'referencers_decomp', 'import', or 'thunk'"


@mcp.tool()
def analyze_data_flow_consolidated(function_address: str, start_address: str = "", variable_name: str = "",
                     direction: str = "backward") -> str:
    """
    Data flow analysis tool that replaces: trace_data_flow_backward, trace_data_flow_forward, find_variable_accesses

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
    """
    if direction == "backward":
        if not start_address:
            return "Error: start_address is required for backward direction"
        return "\n".join(safe_get("trace_data_flow_backward", {"address": start_address}))
    elif direction == "forward":
        if not start_address:
            return "Error: start_address is required for forward direction"
        return "\n".join(safe_get("trace_data_flow_forward", {"address": start_address}))
    elif direction == "variable_accesses":
        if not variable_name:
            return "Error: variable_name is required for variable_accesses direction"
        return "\n".join(safe_get("dataflow/find_variable_accesses", {
            "functionAddress": function_address,
            "variableName": variable_name
        }))
    else:
        return f"Error: Invalid direction '{direction}'. Must be 'backward', 'forward', or 'variable_accesses'"


@mcp.tool()
def search_constants_consolidated(mode: str = "specific", value: str = "", min_value: str = "",
                    max_value: str = "", max_results: int = 500, include_small_values: bool = False,
                    min_value_filter: str = "", top_n: int = 50) -> str:
    """
    Constant value search and analysis tool that replaces: find_constant_uses, find_constants_in_range, list_common_constants

    Find specific constants, constants in ranges, or list the most common constants in the program.

    Args:
        mode: Search mode enum ('specific', 'range', 'common'; required)
        value: Constant value to search for when mode='specific' (supports hex with 0x, decimal, negative; required for specific mode)
        min_value: Minimum value when mode='range' or filter minimum when mode='common' (inclusive, supports hex/decimal; required for range mode)
        max_value: Maximum value when mode='range' (inclusive, supports hex/decimal; required for range mode)
        max_results: Maximum number of results to return when mode='specific' or 'range' (default: 500)
        include_small_values: Include small values (0-255) which are often noise when mode='common' (default: False)
        min_value_filter: Alternative minimum value filter for common mode (optional)
        top_n: Number of most common constants to return when mode='common' (default: 50)

    Returns:
        - When mode='specific': List of instructions using the constant
        - When mode='range': List of constants found in the range with occurrence counts
        - When mode='common': JSON with most common constants
    """
    if mode == "specific":
        if not value:
            return "Error: value is required for specific mode"
        return "\n".join(safe_get("find_constant", {"value": value, "maxResults": max_results}))
    elif mode == "range":
        if not min_value or not max_value:
            return "Error: min_value and max_value are required for range mode"
        return "\n".join(safe_get("find_constants_in_range", {
            "minValue": min_value,
            "maxValue": max_value,
            "maxResults": max_results
        }))
    elif mode == "common":
        params = {"includeSmallValues": include_small_values, "topN": top_n}
        if min_value_filter:
            params["minValue"] = min_value_filter
        elif min_value:
            params["minValue"] = min_value
        return "\n".join(safe_get("constants/list_common", params))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'specific', 'range', or 'common'"


@mcp.tool()
def manage_strings_consolidated(mode: str = "list", pattern: str = "", search_string: str = "",
                  filter: str = "", start_index: int = 0, max_count: int = 100,
                  offset: int = 0, limit: int = 2000, max_results: int = 100,
                  include_referencing_functions: bool = False) -> str:
    """
    String listing, searching, and analysis tool that replaces: list_strings, get_strings,
    search_strings_regex, get_strings_count, get_strings_by_similarity

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
    """
    if mode == "list":
        params = {"offset": offset or start_index, "limit": limit or max_count}
        if filter:
            params["filter"] = filter
        return "\n".join(safe_get("strings", params))
    elif mode == "regex":
        if not pattern:
            return "Error: pattern is required for regex mode"
        return "\n".join(safe_get("search_strings_regex", {"pattern": pattern, "maxResults": max_results}))
    elif mode == "count":
        return "\n".join(safe_get("get_strings_count"))
    elif mode == "similarity":
        if not search_string:
            return "Error: search_string is required for similarity mode"
        return "\n".join(safe_get("strings/get_by_similarity", {
            "searchString": search_string,
            "startIndex": start_index,
            "maxCount": max_count,
            "includeReferencingFunctions": include_referencing_functions
        }))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'list', 'regex', 'count', or 'similarity'"


@mcp.tool()
def inspect_memory_consolidated(mode: str = "blocks", address: str = "", length: int = 16,
                  offset: int = 0, limit: int = 100) -> str:
    """
    Memory and data inspection tool that replaces: get_memory_blocks, read_memory,
    get_data_at_address, list_data_items, list_segments

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
    """
    if mode == "blocks":
        return "\n".join(safe_get("memory_blocks"))
    elif mode == "read":
        if not address:
            return "Error: address is required for read mode"
        return "\n".join(safe_get("read_memory", {"address": address, "length": length}))
    elif mode == "data_at":
        if not address:
            return "Error: address is required for data_at mode"
        return "\n".join(safe_get("get_data_at_address", {"address": address}))
    elif mode == "data_items":
        return "\n".join(safe_get("data", {"offset": offset, "limit": limit}))
    elif mode == "segments":
        return "\n".join(safe_get("segments", {"offset": offset, "limit": limit}))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'blocks', 'read', 'data_at', 'data_items', or 'segments'"


@mcp.tool()
def manage_bookmarks_consolidated(action: str = "get", address: str = "", address_or_symbol: str = "",
                    type: str = "", category: str = "", comment: str = "",
                    search_text: str = "", max_results: int = 100) -> str:
    """
    Bookmark management tool that replaces: set_bookmark, get_bookmarks, search_bookmarks,
    remove_bookmark, list_bookmark_categories

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
    """
    if action == "set":
        if not address or not type or not category or not comment:
            return "Error: address, type, category, and comment are required for set action"
        return safe_post("set_bookmark", {
            "address": address,
            "type": type,
            "category": category,
            "comment": comment
        })
    elif action == "get":
        params = {}
        if address:
            params["address"] = address
        if type:
            params["type"] = type
        return "\n".join(safe_get("get_bookmarks", params))
    elif action == "search":
        if not search_text:
            return "Error: search_text is required for search action"
        return "\n".join(safe_get("search_bookmarks", {
            "searchText": search_text,
            "maxResults": max_results
        }))
    elif action == "remove":
        addr = address_or_symbol or address
        if not addr or not type:
            return "Error: address_or_symbol/address and type are required for remove action"
        params = {"addressOrSymbol": addr, "type": type}
        if category:
            params["category"] = category
        return safe_post("bookmarks/remove", params)
    elif action == "categories":
        bookmark_type = type or "Note"
        return "\n".join(safe_get("bookmarks/list_categories", {"type": bookmark_type}))
    else:
        return f"Error: Invalid action '{action}'. Must be 'set', 'get', 'search', 'remove', or 'categories'"


@mcp.tool()
def manage_comments_consolidated(action: str = "get", address: str = "", address_or_symbol: str = "",
                   function: str = "", function_name_or_address: str = "", line_number: int = 0,
                   comment: str = "", comment_type: str = "eol", start: str = "", end: str = "",
                   comment_types: str = "", search_text: str = "", pattern: str = "",
                   case_sensitive: bool = False, max_results: int = 100,
                   override_max_functions_limit: bool = False) -> str:
    """
    Comment management and search tool that replaces: set_decompiler_comment, set_disassembly_comment,
    set_decompilation_comment, set_comment, get_comments, remove_comment, search_comments, search_decompilation

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
    """
    if action == "set":
        if line_number > 0:
            # Decompilation line comment
            func = function_name_or_address or function
            if not func:
                return "Error: function_name_or_address or function is required for decompilation line comments"
            return safe_post("decompiler/set_decompilation_comment", {
                "functionNameOrAddress": func,
                "lineNumber": line_number,
                "comment": comment,
                "commentType": comment_type
            })
        else:
            # Regular address comment
            addr = address_or_symbol or address
            if not addr or not comment:
                return "Error: address_or_symbol/address and comment are required for set action"
            return safe_post("comments/set", {
                "addressOrSymbol": addr,
                "comment": comment,
                "commentType": comment_type
            })
    elif action == "get":
        params = {}
        addr = address_or_symbol or address
        if addr:
            params["addressOrSymbol"] = addr
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        if comment_types:
            params["commentTypes"] = comment_types
        return "\n".join(safe_get("comments/get", params))
    elif action == "remove":
        addr = address_or_symbol or address
        if not addr:
            return "Error: address_or_symbol or address is required for remove action"
        return safe_post("comments/remove", {
            "addressOrSymbol": addr,
            "commentType": comment_type
        })
    elif action == "search":
        if not search_text:
            return "Error: search_text is required for search action"
        params = {
            "searchText": search_text,
            "caseSensitive": case_sensitive,
            "maxResults": max_results
        }
        if comment_types:
            params["commentTypes"] = comment_types
        return "\n".join(safe_get("comments/search", params))
    elif action == "search_decomp":
        if not pattern:
            return "Error: pattern is required for search_decomp action"
        return "\n".join(safe_get("decompiler/search", {
            "pattern": pattern,
            "caseSensitive": case_sensitive,
            "maxResults": max_results,
            "overrideMaxFunctionsLimit": override_max_functions_limit
        }))
    else:
        return f"Error: Invalid action '{action}'. Must be 'set', 'get', 'remove', 'search', or 'search_decomp'"


@mcp.tool()
def analyze_vtables_consolidated(mode: str = "analyze", vtable_address: str = "", function_address: str = "",
                   max_entries: int = 200) -> str:
    """
    Virtual function table analysis tool that replaces: analyze_vtable, find_vtable_callers, find_vtables_containing_function

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
    """
    if mode == "analyze":
        if not vtable_address:
            return "Error: vtable_address is required for analyze mode"
        return "\n".join(safe_get("analyze_vtable", {
            "vtableAddress": vtable_address,
            "maxEntries": max_entries
        }))
    elif mode == "callers":
        if not function_address:
            return "Error: function_address is required for callers mode"
        return "\n".join(safe_get("find_vtable_callers", {"functionAddress": function_address}))
    elif mode == "containing":
        if not function_address:
            return "Error: function_address is required for containing mode"
        return "\n".join(safe_get("vtable/find_containing_function", {"functionAddress": function_address}))
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'analyze', 'callers', or 'containing'"


@mcp.tool()
def manage_symbols_consolidated(mode: str = "symbols", address: str = "", label_name: str = "",
                  new_name: str = "", library_filter: str = "", max_results: int = 500,
                  start_index: int = 0, offset: int = 0, limit: int = 100,
                  group_by_library: bool = True, include_external: bool = False,
                  max_count: int = 200, filter_default_names: bool = True) -> str:
    """
    Symbol and label management tool that replaces: list_classes, list_namespaces, list_imports,
    list_exports, create_label, get_symbols, get_symbols_count, rename_data

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
    """
    if mode == "classes":
        return "\n".join(safe_get("classes", {"offset": offset or start_index, "limit": limit or max_count}))
    elif mode == "namespaces":
        return "\n".join(safe_get("namespaces", {"offset": offset or start_index, "limit": limit or max_count}))
    elif mode == "imports":
        params = {
            "maxResults": max_results,
            "startIndex": start_index,
            "groupByLibrary": group_by_library
        }
        if library_filter:
            params["libraryFilter"] = library_filter
        return "\n".join(safe_get("imports/list", params))
    elif mode == "exports":
        return "\n".join(safe_get("exports/list", {
            "maxResults": max_results,
            "startIndex": start_index
        }))
    elif mode == "create_label":
        if not address or not label_name:
            return "Error: address and label_name are required for create_label mode"
        return safe_post("create_label", {"address": address, "labelName": label_name})
    elif mode == "symbols":
        return "\n".join(safe_get("symbols/get", {
            "includeExternal": include_external,
            "startIndex": start_index,
            "maxCount": max_count,
            "filterDefaultNames": filter_default_names
        }))
    elif mode == "count":
        return "\n".join(safe_get("symbols/get_count", {
            "includeExternal": include_external,
            "filterDefaultNames": filter_default_names
        }))
    elif mode == "rename_data":
        if not address or not new_name:
            return "Error: address and new_name are required for rename_data mode"
        return safe_post("renameData", {"address": address, "newName": new_name})
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'classes', 'namespaces', 'imports', 'exports', 'create_label', 'symbols', 'count', or 'rename_data'"


@mcp.tool()
def manage_structures_consolidated(action: str = "list", c_definition: str = "", header_content: str = "",
                     structure_name: str = "", name: str = "", size: int = 0, type: str = "structure",
                     category: str = "/", packed: bool = False, description: str = "",
                     field_name: str = "", data_type: str = "", offset: int = None, comment: str = "",
                     new_data_type: str = "", new_field_name: str = "", new_comment: str = "",
                     new_length: int = None, address_or_symbol: str = "", clear_existing: bool = True,
                     force: bool = False, name_filter: str = "", include_built_in: bool = False) -> str:
    """
    Structure management tool that replaces: parse_c_structure, validate_c_structure, create_structure,
    add_structure_field, modify_structure_field, modify_structure_from_c, get_structure_info,
    list_structures, apply_structure, delete_structure, parse_c_header

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
    """
    if action == "parse":
        if not c_definition:
            return "Error: c_definition is required for parse action"
        return safe_post("structures/parse_c_structure", {
            "cDefinition": c_definition,
            "category": category
        })
    elif action == "validate":
        if not c_definition:
            return "Error: c_definition is required for validate action"
        return safe_post("structures/validate_c_structure", {"cDefinition": c_definition})
    elif action == "create":
        if not name:
            return "Error: name is required for create action"
        params = {
            "name": name,
            "size": size,
            "type": type,
            "category": category,
            "packed": packed
        }
        if description:
            params["description"] = description
        return safe_post("structures/create_structure", params)
    elif action == "add_field":
        if not structure_name or not field_name or not data_type:
            return "Error: structure_name, field_name, and data_type are required for add_field action"
        params = {
            "structureName": structure_name,
            "fieldName": field_name,
            "dataType": data_type
        }
        if offset is not None:
            params["offset"] = offset
        if comment:
            params["comment"] = comment
        return safe_post("structures/add_structure_field", params)
    elif action == "modify_field":
        if not structure_name:
            return "Error: structure_name is required for modify_field action"
        params = {"structureName": structure_name}
        if field_name:
            params["fieldName"] = field_name
        if offset is not None:
            params["offset"] = offset
        if new_data_type:
            params["newDataType"] = new_data_type
        if new_field_name:
            params["newFieldName"] = new_field_name
        if new_comment:
            params["newComment"] = new_comment
        if new_length is not None:
            params["newLength"] = new_length
        return safe_post("structures/modify_structure_field", params)
    elif action == "modify_from_c":
        if not c_definition:
            return "Error: c_definition is required for modify_from_c action"
        return safe_post("structures/modify_structure_from_c", {"cDefinition": c_definition})
    elif action == "info":
        if not structure_name:
            return "Error: structure_name is required for info action"
        return "\n".join(safe_get("structures/get_structure_info", {"structureName": structure_name}))
    elif action == "list":
        params = {"includeBuiltIn": include_built_in}
        if category:
            params["category"] = category
        if name_filter:
            params["nameFilter"] = name_filter
        return "\n".join(safe_get("structures/list_structures", params))
    elif action == "apply":
        if not structure_name or not address_or_symbol:
            return "Error: structure_name and address_or_symbol are required for apply action"
        return safe_post("structures/apply_structure", {
            "structureName": structure_name,
            "addressOrSymbol": address_or_symbol,
            "clearExisting": clear_existing
        })
    elif action == "delete":
        if not structure_name:
            return "Error: structure_name is required for delete action"
        return safe_post("structures/delete_structure", {
            "structureName": structure_name,
            "force": force
        })
    elif action == "parse_header":
        if not header_content:
            return "Error: header_content is required for parse_header action"
        return safe_post("structures/parse_c_header", {
            "headerContent": header_content,
            "category": category
        })
    else:
        return f"Error: Invalid action '{action}'. Must be 'parse', 'validate', 'create', 'add_field', 'modify_field', 'modify_from_c', 'info', 'list', 'apply', 'delete', or 'parse_header'"


@mcp.tool()
def manage_data_types_consolidated(action: str = "list", archive_name: str = "", category_path: str = "/",
                     include_subcategories: bool = False, start_index: int = 0, max_count: int = 100,
                     data_type_string: str = "", address_or_symbol: str = "") -> str:
    """
    Data type management tool that replaces: get_data_type_archives, get_data_types, get_data_type_by_string, apply_data_type

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
    """
    if action == "archives":
        return "\n".join(safe_get("datatypes/get_archives", {}))
    elif action == "list":
        if not archive_name:
            return "Error: archive_name is required for list action"
        return "\n".join(safe_get("datatypes/get_types", {
            "archiveName": archive_name,
            "categoryPath": category_path,
            "includeSubcategories": include_subcategories,
            "startIndex": start_index,
            "maxCount": max_count
        }))
    elif action == "by_string":
        if not data_type_string:
            return "Error: data_type_string is required for by_string action"
        params = {"dataTypeString": data_type_string}
        if archive_name:
            params["archiveName"] = archive_name
        return "\n".join(safe_get("datatypes/get_by_string", params))
    elif action == "apply":
        if not data_type_string or not address_or_symbol:
            return "Error: data_type_string and address_or_symbol are required for apply action"
        return safe_post("data/apply_data_type", {
            "addressOrSymbol": address_or_symbol,
            "dataTypeString": data_type_string,
            "archiveName": archive_name
        })
    else:
        return f"Error: Invalid action '{action}'. Must be 'archives', 'list', 'by_string', or 'apply'"


@mcp.tool()
def get_current_context_consolidated(mode: str = "both") -> str:
    """
    Current context retrieval tool that replaces: get_current_address, get_current_function

    Get the address or function currently selected in the Ghidra GUI.

    Args:
        mode: Context mode enum ('address', 'function', 'both'; default: 'both')

    Returns:
        - When mode='address': The address currently selected by the user
        - When mode='function': The function currently selected by the user
        - When mode='both': JSON with both current address and function
    """
    if mode == "address":
        return "\n".join(safe_get("get_current_address"))
    elif mode == "function":
        return "\n".join(safe_get("get_current_function"))
    elif mode == "both":
        address = "\n".join(safe_get("get_current_address"))
        function = "\n".join(safe_get("get_current_function"))
        return f"Current Address: {address}\nCurrent Function: {function}"
    else:
        return f"Error: Invalid mode '{mode}'. Must be 'address', 'function', or 'both'"


@mcp.tool()
def manage_function_tags_consolidated(function: str, mode: str, tags: str = "") -> str:
    """
    Function tag management tool that replaces: function_tags

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
    """
    if mode in ['get', 'set', 'add', 'remove']:
        if not function:
            return f"Error: function is required for {mode} mode"
    if mode in ['add'] and not tags:
        return f"Error: tags are required for {mode} mode"

    return safe_post("functions/tags", {"function": function, "mode": mode, "tags": tags})


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument(
        "--ghidra-server",
        type=str,
        default=DEFAULT_GHIDRA_SERVER,
        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}",
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        help="Port to run MCP server on (only used for sse), default: 8081",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport protocol for MCP, default: stdio",
    )
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
            logger.info(
                f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse"
            )
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
