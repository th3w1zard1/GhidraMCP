package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // Bookmarks endpoints
        server.createContext("/set_bookmark", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String type = params.get("type");
            String category = params.get("category");
            String comment = params.get("comment");
            boolean success = setBookmark(address, type, category, comment);
            sendResponse(exchange, success ? "Bookmark set successfully" : "Failed to set bookmark");
        });

        server.createContext("/get_bookmarks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String type = qparams.get("type");
            sendResponse(exchange, getBookmarks(address, type));
        });

        server.createContext("/search_bookmarks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchText = qparams.get("searchText");
            int maxResults = parseIntOrDefault(qparams.get("maxResults"), 100);
            sendResponse(exchange, searchBookmarks(searchText, maxResults));
        });

        // Call graph endpoints
        server.createContext("/get_call_graph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("functionAddress");
            int depth = parseIntOrDefault(qparams.get("depth"), 1);
            sendResponse(exchange, getCallGraph(functionAddress, depth));
        });

        server.createContext("/get_callers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("functionAddress");
            sendResponse(exchange, getFunctionCallers(functionAddress));
        });

        server.createContext("/get_callees", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("functionAddress");
            sendResponse(exchange, getFunctionCallees(functionAddress));
        });

        // Constants search endpoints
        server.createContext("/find_constant", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String value = qparams.get("value");
            int maxResults = parseIntOrDefault(qparams.get("maxResults"), 500);
            sendResponse(exchange, findConstantUses(value, maxResults));
        });

        server.createContext("/find_constants_in_range", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String minValue = qparams.get("minValue");
            String maxValue = qparams.get("maxValue");
            int maxResults = parseIntOrDefault(qparams.get("maxResults"), 500);
            sendResponse(exchange, findConstantsInRange(minValue, maxValue, maxResults));
        });

        // Memory blocks endpoint
        server.createContext("/memory_blocks", exchange -> {
            sendResponse(exchange, getMemoryBlocks());
        });

        server.createContext("/read_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            sendResponse(exchange, readMemory(address, length));
        });

        // Enhanced function endpoints
        server.createContext("/get_function_info", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionInfo(address));
        });

        server.createContext("/list_function_calls", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("functionAddress");
            sendResponse(exchange, listFunctionCalls(functionAddress));
        });

        // Data flow analysis endpoints
        server.createContext("/trace_data_flow_backward", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, traceDataFlowBackward(address));
        });

        server.createContext("/trace_data_flow_forward", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, traceDataFlowForward(address));
        });

        // Vtable analysis endpoints
        server.createContext("/analyze_vtable", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String vtableAddress = qparams.get("vtableAddress");
            int maxEntries = parseIntOrDefault(qparams.get("maxEntries"), 200);
            sendResponse(exchange, analyzeVtable(vtableAddress, maxEntries));
        });

        server.createContext("/find_vtable_callers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("functionAddress");
            sendResponse(exchange, findVtableCallers(functionAddress));
        });

        // Enhanced string tools
        server.createContext("/search_strings_regex", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            int maxResults = parseIntOrDefault(qparams.get("maxResults"), 100);
            sendResponse(exchange, searchStringsRegex(pattern, maxResults));
        });

        server.createContext("/get_strings_count", exchange -> {
            sendResponse(exchange, getStringsCount());
        });

        // Enhanced cross-reference tools
        server.createContext("/find_cross_references", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String location = qparams.get("location");
            String direction = qparams.get("direction");
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, findCrossReferences(location, direction, limit));
        });

        // Data type and label tools
        server.createContext("/create_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String labelName = params.get("labelName");
            boolean success = createLabel(address, labelName);
            sendResponse(exchange, success ? "Label created successfully" : "Failed to create label");
        });

        server.createContext("/get_data_at_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getDataAtAddress(address));
        });

        // Additional missing tools from reverse-engineering-assistant
        
        // Functions tools
        server.createContext("/functions/get_count", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean filterDefaultNames = Boolean.parseBoolean(qparams.getOrDefault("filterDefaultNames", "true"));
            sendResponse(exchange, getFunctionCount(filterDefaultNames));
        });

        server.createContext("/functions/get_by_similarity", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchString = qparams.get("searchString");
            int startIndex = parseIntOrDefault(qparams.get("startIndex"), 0);
            int maxCount = parseIntOrDefault(qparams.get("maxCount"), 100);
            boolean filterDefaultNames = Boolean.parseBoolean(qparams.getOrDefault("filterDefaultNames", "true"));
            sendResponse(exchange, getFunctionsBySimilarity(searchString, startIndex, maxCount, filterDefaultNames));
        });

        server.createContext("/functions/get_undefined_candidates", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int startIndex = parseIntOrDefault(qparams.get("startIndex"), 0);
            int maxCandidates = parseIntOrDefault(qparams.get("maxCandidates"), 100);
            int minReferenceCount = parseIntOrDefault(qparams.get("minReferenceCount"), 1);
            sendResponse(exchange, getUndefinedFunctionCandidates(startIndex, maxCandidates, minReferenceCount));
        });

        server.createContext("/functions/create", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            sendResponse(exchange, createFunction(address, name));
        });

        server.createContext("/functions/tags", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String function = params.get("function");
            String mode = params.get("mode");
            String tagsStr = params.get("tags");
            sendResponse(exchange, manageFunctionTags(function, mode, tagsStr));
        });

        // Strings tools
        server.createContext("/strings/get_by_similarity", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchString = qparams.get("searchString");
            int startIndex = parseIntOrDefault(qparams.get("startIndex"), 0);
            int maxCount = parseIntOrDefault(qparams.get("maxCount"), 100);
            boolean includeReferencingFunctions = Boolean.parseBoolean(qparams.getOrDefault("includeReferencingFunctions", "false"));
            sendResponse(exchange, getStringsBySimilarity(searchString, startIndex, maxCount, includeReferencingFunctions));
        });

        // Comments tools
        server.createContext("/comments/set", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addressOrSymbol = params.get("addressOrSymbol");
            String commentType = params.getOrDefault("commentType", "eol");
            String comment = params.get("comment");
            sendResponse(exchange, setComment(addressOrSymbol, commentType, comment));
        });

        server.createContext("/comments/get", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String addressOrSymbol = qparams.get("addressOrSymbol");
            String startAddr = qparams.get("start");
            String endAddr = qparams.get("end");
            String commentTypesStr = qparams.get("commentTypes");
            sendResponse(exchange, getComments(addressOrSymbol, startAddr, endAddr, commentTypesStr));
        });

        server.createContext("/comments/remove", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addressOrSymbol = params.get("addressOrSymbol");
            String commentType = params.get("commentType");
            sendResponse(exchange, removeComment(addressOrSymbol, commentType));
        });

        server.createContext("/comments/search", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchText = qparams.get("searchText");
            boolean caseSensitive = Boolean.parseBoolean(qparams.getOrDefault("caseSensitive", "false"));
            String commentTypesStr = qparams.get("commentTypes");
            int maxResults = parseIntOrDefault(qparams.get("maxResults"), 100);
            sendResponse(exchange, searchComments(searchText, caseSensitive, commentTypesStr, maxResults));
        });

        // Data tools
        server.createContext("/data/apply_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addressOrSymbol = params.get("addressOrSymbol");
            String dataTypeString = params.get("dataTypeString");
            String archiveName = params.getOrDefault("archiveName", "");
            sendResponse(exchange, applyDataType(addressOrSymbol, dataTypeString, archiveName));
        });

        // Symbols tools
        server.createContext("/symbols/get_count", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean includeExternal = Boolean.parseBoolean(qparams.getOrDefault("includeExternal", "false"));
            boolean filterDefaultNames = Boolean.parseBoolean(qparams.getOrDefault("filterDefaultNames", "true"));
            sendResponse(exchange, getSymbolsCount(includeExternal, filterDefaultNames));
        });

        server.createContext("/symbols/get", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean includeExternal = Boolean.parseBoolean(qparams.getOrDefault("includeExternal", "false"));
            int startIndex = parseIntOrDefault(qparams.get("startIndex"), 0);
            int maxCount = parseIntOrDefault(qparams.get("maxCount"), 200);
            boolean filterDefaultNames = Boolean.parseBoolean(qparams.getOrDefault("filterDefaultNames", "true"));
            sendResponse(exchange, getSymbols(includeExternal, startIndex, maxCount, filterDefaultNames));
        });

        // Imports/Exports tools
        server.createContext("/imports/find_references", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String importName = qparams.get("importName");
            String libraryName = qparams.get("libraryName");
            int maxResults = parseIntOrDefault(qparams.get("maxResults"), 100);
            sendResponse(exchange, findImportReferences(importName, libraryName, maxResults));
        });

        server.createContext("/imports/resolve_thunk", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, resolveThunk(address));
        });

        // Call Graph tools
        server.createContext("/callgraph/get_tree", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("functionAddress");
            String direction = qparams.getOrDefault("direction", "callees");
            int maxDepth = parseIntOrDefault(qparams.get("maxDepth"), 3);
            sendResponse(exchange, getCallTree(functionAddress, direction, maxDepth));
        });

        server.createContext("/callgraph/find_common_callers", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddressesStr = params.get("functionAddresses");
            sendResponse(exchange, findCommonCallers(functionAddressesStr));
        });

        // Constants tools
        server.createContext("/constants/list_common", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean includeSmallValues = Boolean.parseBoolean(qparams.getOrDefault("includeSmallValues", "false"));
            String minValue = qparams.get("minValue");
            int topN = parseIntOrDefault(qparams.get("topN"), 50);
            sendResponse(exchange, listCommonConstants(includeSmallValues, minValue, topN));
        });

        // Data Flow tools
        server.createContext("/dataflow/find_variable_accesses", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("functionAddress");
            String variableName = qparams.get("variableName");
            sendResponse(exchange, findVariableAccesses(functionAddress, variableName));
        });

        // Vtable tools
        server.createContext("/vtable/find_containing_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("functionAddress");
            sendResponse(exchange, findVtablesContainingFunction(functionAddress));
        });

        // Bookmarks tools
        server.createContext("/bookmarks/remove", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addressOrSymbol = params.get("addressOrSymbol");
            String type = params.get("type");
            String category = params.get("category");
            sendResponse(exchange, removeBookmark(addressOrSymbol, type, category));
        });

        server.createContext("/bookmarks/list_categories", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String type = qparams.get("type");
            sendResponse(exchange, listBookmarkCategories(type));
        });

        // Decompiler tools
        server.createContext("/decompiler/search", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            boolean caseSensitive = Boolean.parseBoolean(qparams.getOrDefault("caseSensitive", "false"));
            int maxResults = parseIntOrDefault(qparams.get("maxResults"), 50);
            boolean overrideMaxFunctionsLimit = Boolean.parseBoolean(qparams.getOrDefault("overrideMaxFunctionsLimit", "false"));
            sendResponse(exchange, searchDecompilation(pattern, caseSensitive, maxResults, overrideMaxFunctionsLimit));
        });

        server.createContext("/decompiler/rename_variables", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionNameOrAddress = params.get("functionNameOrAddress");
            String variableMappingsStr = params.get("variableMappings");
            sendResponse(exchange, renameVariables(functionNameOrAddress, variableMappingsStr));
        });

        server.createContext("/decompiler/change_variable_datatypes", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionNameOrAddress = params.get("functionNameOrAddress");
            String datatypeMappingsStr = params.get("datatypeMappings");
            String archiveName = params.getOrDefault("archiveName", "");
            sendResponse(exchange, changeVariableDataTypes(functionNameOrAddress, datatypeMappingsStr, archiveName));
        });

        server.createContext("/decompiler/get_callers_decompiled", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionNameOrAddress = qparams.get("functionNameOrAddress");
            int startIndex = parseIntOrDefault(qparams.get("startIndex"), 0);
            int maxCallers = parseIntOrDefault(qparams.get("maxCallers"), 10);
            boolean includeCallContext = Boolean.parseBoolean(qparams.getOrDefault("includeCallContext", "true"));
            sendResponse(exchange, getCallersDecompiled(functionNameOrAddress, startIndex, maxCallers, includeCallContext));
        });

        server.createContext("/decompiler/get_referencers_decompiled", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String addressOrSymbol = qparams.get("addressOrSymbol");
            int startIndex = parseIntOrDefault(qparams.get("startIndex"), 0);
            int maxReferencers = parseIntOrDefault(qparams.get("maxReferencers"), 10);
            boolean includeRefContext = Boolean.parseBoolean(qparams.getOrDefault("includeRefContext", "true"));
            boolean includeDataRefs = Boolean.parseBoolean(qparams.getOrDefault("includeDataRefs", "true"));
            sendResponse(exchange, getReferencersDecompiled(addressOrSymbol, startIndex, maxReferencers, includeRefContext, includeDataRefs));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Enhanced string search methods
    // ----------------------------------------------------------------------------------

    /**
     * Search strings using regex pattern
     */
    private String searchStringsRegex(String patternStr, int maxResults) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (patternStr == null || patternStr.isEmpty()) return "Pattern is required";

        try {
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(patternStr);
            List<String> results = new ArrayList<>();
            DataIterator dataIt = program.getListing().getDefinedData(true);
            
            int count = 0;
            while (dataIt.hasNext() && count < maxResults) {
                Data data = dataIt.next();
                
                if (data != null && isStringData(data)) {
                    String value = data.getValue() != null ? data.getValue().toString() : "";
                    
                    if (pattern.matcher(value).find()) {
                        String escapedValue = escapeString(value);
                        results.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                        count++;
                    }
                }
            }
            
            if (results.isEmpty()) {
                return "No strings matching pattern: " + patternStr;
            }
            
            return String.format("Found %d string(s) matching /%s/:\n%s",
                results.size(), patternStr, String.join("\n", results));
                
        } catch (java.util.regex.PatternSyntaxException e) {
            return "Invalid regex pattern: " + e.getMessage();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get total count of strings in the program
     */
    private String getStringsCount() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        int count = 0;
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data != null && isStringData(data)) {
                count++;
            }
        }
        
        return "Total strings in program: " + count;
    }

    // ----------------------------------------------------------------------------------
    // Cross-reference methods
    // ----------------------------------------------------------------------------------

    /**
     * Find cross-references with options
     */
    private String findCrossReferences(String location, String direction, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (location == null) return "Location is required";

        try {
            Address addr = program.getAddressFactory().getAddress(location);
            ReferenceManager refMgr = program.getReferenceManager();
            List<String> results = new ArrayList<>();

            if ("to".equalsIgnoreCase(direction) || direction == null || direction.isEmpty()) {
                // Get references TO this address
                ReferenceIterator refsTo = refMgr.getReferencesTo(addr);
                int count = 0;
                while (refsTo.hasNext() && count < limit) {
                    Reference ref = refsTo.next();
                    Address fromAddr = ref.getFromAddress();
                    RefType refType = ref.getReferenceType();
                    
                    Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                    String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                    
                    results.add(String.format("FROM %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    count++;
                }
            }

            if ("from".equalsIgnoreCase(direction) || direction == null || direction.isEmpty()) {
                // Get references FROM this address
                Reference[] refsFrom = refMgr.getReferencesFrom(addr);
                int count = 0;
                for (Reference ref : refsFrom) {
                    if (count >= limit) break;
                    
                    Address toAddr = ref.getToAddress();
                    RefType refType = ref.getReferenceType();
                    
                    Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                    String targetInfo = (toFunc != null) ? " to function " + toFunc.getName() : "";
                    
                    results.add(String.format("TO %s%s [%s]", toAddr, targetInfo, refType.getName()));
                    count++;
                }
            }

            if (results.isEmpty()) {
                return "No cross-references found at: " + location;
            }

            return String.format("Cross-references at %s:\n%s",
                addr, String.join("\n", results));

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Data and label methods
    // ----------------------------------------------------------------------------------

    /**
     * Create a label at a specific address
     */
    private boolean createLabel(String addressStr, String labelName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || labelName == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create Label");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    SymbolTable symTable = program.getSymbolTable();
                    
                    // Check if label already exists
                    Symbol existing = symTable.getPrimarySymbol(addr);
                    if (existing != null && !existing.getName().startsWith("FUN_") && !existing.getName().startsWith("DAT_")) {
                        // Label already exists, set name
                        existing.setName(labelName, SourceType.USER_DEFINED);
                    } else {
                        // Create new label
                        symTable.createLabel(addr, labelName, SourceType.USER_DEFINED);
                    }
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error creating label", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute create label on Swing thread", e);
        }
        return success.get();
    }

    /**
     * Get data at a specific address
     */
    private String getDataAtAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Data data = program.getListing().getDataAt(addr);
            
            if (data == null) {
                return "No defined data at address: " + addressStr;
            }

            StringBuilder result = new StringBuilder();
            result.append("Data at ").append(addr).append(":\n");
            result.append("Type: ").append(data.getDataType().getName()).append("\n");
            result.append("Size: ").append(data.getLength()).append(" bytes\n");
            
            String label = data.getLabel();
            if (label != null) {
                result.append("Label: ").append(label).append("\n");
            }
            
            Object value = data.getValue();
            if (value != null) {
                result.append("Value: ").append(value.toString()).append("\n");
            }
            
            String valRepr = data.getDefaultValueRepresentation();
            if (valRepr != null) {
                result.append("Representation: ").append(valRepr).append("\n");
            }

            return result.toString();

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * List all defined strings in the program with their addresses
     */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    // ----------------------------------------------------------------------------------
    // Bookmarks methods
    // ----------------------------------------------------------------------------------

    /**
     * Set a bookmark at a specific address
     */
    private boolean setBookmark(String addressStr, String type, String category, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || type == null || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set Bookmark");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    ghidra.program.model.listing.BookmarkManager bookmarkMgr = program.getBookmarkManager();
                    
                    String cat = (category != null && !category.isEmpty()) ? category : "";
                    bookmarkMgr.setBookmark(addr, type, cat, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting bookmark", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set bookmark on Swing thread", e);
        }
        return success.get();
    }

    /**
     * Get bookmarks at an address or of a specific type
     */
    private String getBookmarks(String addressStr, String type) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        ghidra.program.model.listing.BookmarkManager bookmarkMgr = program.getBookmarkManager();
        List<String> results = new ArrayList<>();

        if (addressStr != null && !addressStr.isEmpty()) {
            try {
                Address addr = program.getAddressFactory().getAddress(addressStr);
                ghidra.program.model.listing.Bookmark[] bookmarks = bookmarkMgr.getBookmarks(addr);
                for (ghidra.program.model.listing.Bookmark bookmark : bookmarks) {
                    if (type == null || type.isEmpty() || bookmark.getTypeString().equals(type)) {
                        results.add(formatBookmark(bookmark));
                    }
                }
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        } else if (type != null && !type.isEmpty()) {
            Iterator<ghidra.program.model.listing.Bookmark> iter = bookmarkMgr.getBookmarksIterator(type);
            while (iter.hasNext()) {
                results.add(formatBookmark(iter.next()));
            }
        } else {
            Iterator<ghidra.program.listing.Bookmark> iter = bookmarkMgr.getBookmarksIterator();
            while (iter.hasNext()) {
                results.add(formatBookmark(iter.next()));
            }
        }

        return results.isEmpty() ? "No bookmarks found" : String.join("\n", results);
    }

    /**
     * Search bookmarks by text
     */
    private String searchBookmarks(String searchText, int maxResults) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchText == null || searchText.isEmpty()) return "Search text is required";

        ghidra.program.model.listing.BookmarkManager bookmarkMgr = program.getBookmarkManager();
        List<String> results = new ArrayList<>();
        int count = 0;

        Iterator<ghidra.program.model.listing.Bookmark> iter = bookmarkMgr.getBookmarksIterator();
        while (iter.hasNext() && count < maxResults) {
            ghidra.program.model.listing.Bookmark bookmark = iter.next();
            String comment = bookmark.getComment();
            if (comment != null && comment.toLowerCase().contains(searchText.toLowerCase())) {
                results.add(formatBookmark(bookmark));
                count++;
            }
        }

        return results.isEmpty() ? "No matching bookmarks found" : String.join("\n", results);
    }

    /**
     * Format a bookmark for display
     */
    private String formatBookmark(ghidra.program.model.listing.Bookmark bookmark) {
        return String.format("%s [%s/%s]: %s",
            bookmark.getAddress(),
            bookmark.getTypeString(),
            bookmark.getCategory() != null ? bookmark.getCategory() : "",
            bookmark.getComment());
    }

    // ----------------------------------------------------------------------------------
    // Call graph methods
    // ----------------------------------------------------------------------------------

    /**
     * Get call graph around a function
     */
    private String getCallGraph(String functionAddrStr, int depth) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddrStr == null) return "Function address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function function = getFunctionForAddress(program, addr);
            if (function == null) return "No function at address: " + functionAddrStr;

            StringBuilder result = new StringBuilder();
            result.append("Function: ").append(function.getName()).append(" @ ").append(function.getEntryPoint()).append("\n\n");

            // Get callers
            result.append("Callers:\n");
            Set<Function> callers = function.getCallingFunctions(new ConsoleTaskMonitor());
            if (callers.isEmpty()) {
                result.append("  (none)\n");
            } else {
                for (Function caller : callers) {
                    result.append("  ").append(caller.getName()).append(" @ ").append(caller.getEntryPoint()).append("\n");
                }
            }

            // Get callees
            result.append("\nCallees:\n");
            Set<Function> callees = function.getCalledFunctions(new ConsoleTaskMonitor());
            if (callees.isEmpty()) {
                result.append("  (none)\n");
            } else {
                for (Function callee : callees) {
                    result.append("  ").append(callee.getName()).append(" @ ").append(callee.getEntryPoint()).append("\n");
                }
            }

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get functions that call a specific function
     */
    private String getFunctionCallers(String functionAddrStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddrStr == null) return "Function address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function function = getFunctionForAddress(program, addr);
            if (function == null) return "No function at address: " + functionAddrStr;

            Set<Function> callers = function.getCallingFunctions(new ConsoleTaskMonitor());
            if (callers.isEmpty()) {
                return "No callers found for function: " + function.getName();
            }

            StringBuilder result = new StringBuilder();
            result.append("Callers of ").append(function.getName()).append(":\n");
            for (Function caller : callers) {
                result.append(String.format("%s @ %s\n", caller.getName(), caller.getEntryPoint()));
            }
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get functions called by a specific function
     */
    private String getFunctionCallees(String functionAddrStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddrStr == null) return "Function address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function function = getFunctionForAddress(program, addr);
            if (function == null) return "No function at address: " + functionAddrStr;

            Set<Function> callees = function.getCalledFunctions(new ConsoleTaskMonitor());
            if (callees.isEmpty()) {
                return "No callees found for function: " + function.getName();
            }

            StringBuilder result = new StringBuilder();
            result.append("Functions called by ").append(function.getName()).append(":\n");
            for (Function callee : callees) {
                result.append(String.format("%s @ %s\n", callee.getName(), callee.getEntryPoint()));
            }
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Constants search methods
    // ----------------------------------------------------------------------------------

    /**
     * Find uses of a specific constant value
     */
    private String findConstantUses(String valueStr, int maxResults) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (valueStr == null || valueStr.isEmpty()) return "Value is required";

        try {
            long targetValue = parseConstantValue(valueStr);
            List<String> results = new ArrayList<>();
            Listing listing = program.getListing();
            InstructionIterator instructions = listing.getInstructions(true);

            int count = 0;
            while (instructions.hasNext() && count < maxResults) {
                Instruction instr = instructions.next();
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    ghidra.program.model.scalar.Scalar scalar = instr.getScalar(i);
                    if (scalar != null) {
                        long unsignedValue = scalar.getUnsignedValue();
                        long signedValue = scalar.getSignedValue();
                        
                        if (unsignedValue == targetValue || signedValue == targetValue) {
                            Function func = program.getFunctionManager().getFunctionContaining(instr.getAddress());
                            String funcName = (func != null) ? func.getName() : "(no function)";
                            results.add(String.format("%s: %s [in %s]",
                                instr.getAddress(), instr.toString(), funcName));
                            count++;
                            break; // Only count once per instruction
                        }
                    }
                }
            }

            if (results.isEmpty()) {
                return "No uses found for constant: " + valueStr;
            }

            return String.format("Found %d use(s) of %s:\n%s",
                results.size(), valueStr, String.join("\n", results));

        } catch (NumberFormatException e) {
            return "Invalid constant value: " + valueStr;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find constants within a specific range
     */
    private String findConstantsInRange(String minValueStr, String maxValueStr, int maxResults) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (minValueStr == null || maxValueStr == null) return "Min and max values are required";

        try {
            long minValue = parseConstantValue(minValueStr);
            long maxValue = parseConstantValue(maxValueStr);
            
            Map<Long, Integer> valueCounts = new HashMap<>();
            List<String> results = new ArrayList<>();
            Listing listing = program.getListing();
            InstructionIterator instructions = listing.getInstructions(true);

            int count = 0;
            while (instructions.hasNext() && count < maxResults * 2) {
                Instruction instr = instructions.next();
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    ghidra.program.model.scalar.Scalar scalar = instr.getScalar(i);
                    if (scalar != null) {
                        long unsignedValue = scalar.getUnsignedValue();
                        
                        if (Long.compareUnsigned(unsignedValue, minValue) >= 0 &&
                            Long.compareUnsigned(unsignedValue, maxValue) <= 0) {
                            valueCounts.put(unsignedValue, valueCounts.getOrDefault(unsignedValue, 0) + 1);
                            count++;
                        }
                    }
                }
            }

            if (valueCounts.isEmpty()) {
                return String.format("No constants found in range [%s, %s]", minValueStr, maxValueStr);
            }

            StringBuilder result = new StringBuilder();
            result.append(String.format("Found %d unique constant(s) in range [%s, %s]:\n",
                valueCounts.size(), minValueStr, maxValueStr));
            
            valueCounts.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(maxResults)
                .forEach(entry -> result.append(String.format("0x%x (%d): %d occurrences\n",
                    entry.getKey(), entry.getKey(), entry.getValue())));

            return result.toString();

        } catch (NumberFormatException e) {
            return "Invalid constant value";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Parse a constant value from string (supports hex with 0x, decimal, negative)
     */
    private long parseConstantValue(String valueStr) throws NumberFormatException {
        valueStr = valueStr.trim();
        if (valueStr.toLowerCase().startsWith("0x")) {
            return Long.parseUnsignedLong(valueStr.substring(2), 16);
        }
        if (valueStr.startsWith("-")) {
            return Long.parseLong(valueStr);
        }
        return Long.parseUnsignedLong(valueStr);
    }

    // ----------------------------------------------------------------------------------
    // Memory methods
    // ----------------------------------------------------------------------------------

    /**
     * Get memory blocks
     */
    private String getMemoryBlocks() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        result.append("Memory Blocks:\n");
        
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            result.append(String.format("%s: %s - %s (size: %d, R:%s W:%s X:%s)\n",
                block.getName(),
                block.getStart(),
                block.getEnd(),
                block.getSize(),
                block.isRead() ? "Y" : "N",
                block.isWrite() ? "Y" : "N",
                block.isExecute() ? "Y" : "N"));
        }

        return result.toString();
    }

    /**
     * Read memory at address
     */
    private String readMemory(String addressStr, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            byte[] bytes = new byte[length];
            int bytesRead = program.getMemory().getBytes(addr, bytes);
            
            StringBuilder result = new StringBuilder();
            result.append(String.format("Memory at %s (%d bytes):\n", addr, bytesRead));
            
            // Format as hex dump
            for (int i = 0; i < bytesRead; i += 16) {
                result.append(String.format("%s: ", addr.add(i)));
                
                // Hex bytes
                for (int j = 0; j < 16 && i + j < bytesRead; j++) {
                    result.append(String.format("%02x ", bytes[i + j] & 0xFF));
                }
                
                // ASCII representation
                result.append(" |");
                for (int j = 0; j < 16 && i + j < bytesRead; j++) {
                    byte b = bytes[i + j];
                    result.append((b >= 32 && b < 127) ? (char)b : '.');
                }
                result.append("|\n");
            }
            
            return result.toString();
        } catch (Exception e) {
            return "Error reading memory: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Data flow analysis methods
    // ----------------------------------------------------------------------------------

    /**
     * Trace data flow backward from an address to find origins
     */
    private String traceDataFlowBackward(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function function = program.getFunctionManager().getFunctionContaining(addr);
            if (function == null) {
                return "No function contains address: " + addressStr;
            }

            // Use decompiler to get high-level representation
            DecompInterface decomp = new DecompInterface();
            decomp.toggleCCode(false);
            decomp.toggleSyntaxTree(true);
            decomp.setSimplificationStyle("decompile");
            decomp.openProgram(program);

            try {
                DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                if (!results.decompileCompleted()) {
                    return "Decompilation failed: " + results.getErrorMessage();
                }

                ghidra.program.model.pcode.HighFunction highFunc = results.getHighFunction();
                if (highFunc == null) {
                    return "Could not get high-level function representation";
                }

                // Find varnodes at address
                StringBuilder result = new StringBuilder();
                result.append("Data flow backward from ").append(addressStr).append(" in ").append(function.getName()).append(":\n\n");

                Iterator<ghidra.program.model.pcode.PcodeOpAST> ops = highFunc.getPcodeOps(addr);
                boolean found = false;
                while (ops.hasNext()) {
                    ghidra.program.model.pcode.PcodeOpAST op = ops.next();
                    found = true;
                    result.append("Operation: ").append(op.getMnemonic()).append("\n");
                    
                    // Show inputs (where data comes from)
                    for (int i = 0; i < op.getNumInputs(); i++) {
                        ghidra.program.model.pcode.Varnode input = op.getInput(i);
                        result.append("  Input ").append(i).append(": ");
                        result.append(describeVarnode(input, program)).append("\n");
                    }
                }

                if (!found) {
                    result.append("No data flow information at this address\n");
                }

                return result.toString();
            } finally {
                decomp.dispose();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Trace data flow forward from an address to find uses
     */
    private String traceDataFlowForward(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function function = program.getFunctionManager().getFunctionContaining(addr);
            if (function == null) {
                return "No function contains address: " + addressStr;
            }

            // Use decompiler to get high-level representation
            DecompInterface decomp = new DecompInterface();
            decomp.toggleCCode(false);
            decomp.toggleSyntaxTree(true);
            decomp.setSimplificationStyle("decompile");
            decomp.openProgram(program);

            try {
                DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                if (!results.decompileCompleted()) {
                    return "Decompilation failed: " + results.getErrorMessage();
                }

                ghidra.program.model.pcode.HighFunction highFunc = results.getHighFunction();
                if (highFunc == null) {
                    return "Could not get high-level function representation";
                }

                // Find varnodes at address
                StringBuilder result = new StringBuilder();
                result.append("Data flow forward from ").append(addressStr).append(" in ").append(function.getName()).append(":\n\n");

                Iterator<ghidra.program.model.pcode.PcodeOpAST> ops = highFunc.getPcodeOps(addr);
                boolean found = false;
                while (ops.hasNext()) {
                    ghidra.program.model.pcode.PcodeOpAST op = ops.next();
                    found = true;
                    result.append("Operation: ").append(op.getMnemonic()).append("\n");
                    
                    // Show output (where data goes)
                    ghidra.program.model.pcode.Varnode output = op.getOutput();
                    if (output != null) {
                        result.append("  Output: ");
                        result.append(describeVarnode(output, program)).append("\n");
                        
                        // Show descendants (uses of this output)
                        Iterator<ghidra.program.model.pcode.PcodeOp> descendants = output.getDescendants();
                        while (descendants.hasNext()) {
                            ghidra.program.model.pcode.PcodeOp use = descendants.next();
                            Address useAddr = use.getSeqnum().getTarget();
                            result.append("    Used at: ").append(useAddr).append(" (").append(use.getMnemonic()).append(")\n");
                        }
                    }
                }

                if (!found) {
                    result.append("No data flow information at this address\n");
                }

                return result.toString();
            } finally {
                decomp.dispose();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Describe a varnode for human reading
     */
    private String describeVarnode(ghidra.program.model.pcode.Varnode vn, Program program) {
        if (vn.isConstant()) {
            return "Constant 0x" + Long.toHexString(vn.getOffset());
        } else if (vn.isRegister()) {
            return "Register (offset=" + vn.getOffset() + ", size=" + vn.getSize() + ")";
        } else if (vn.isUnique()) {
            return "Temporary";
        } else if (vn.isAddress()) {
            return "Memory " + vn.getAddress();
        }
        
        // Try to get variable name
        ghidra.program.model.pcode.HighVariable high = vn.getHigh();
        if (high != null && high.getName() != null) {
            return "Variable '" + high.getName() + "'";
        }
        
        return "Unknown";
    }

    // ----------------------------------------------------------------------------------
    // Vtable analysis methods
    // ----------------------------------------------------------------------------------

    /**
     * Analyze a vtable to extract function pointers
     */
    private String analyzeVtable(String vtableAddrStr, int maxEntries) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (vtableAddrStr == null) return "Vtable address is required";

        try {
            Address vtableAddr = program.getAddressFactory().getAddress(vtableAddrStr);
            Memory memory = program.getMemory();
            FunctionManager funcMgr = program.getFunctionManager();
            int pointerSize = program.getDefaultPointerSize();

            StringBuilder result = new StringBuilder();
            result.append("Vtable at ").append(vtableAddr).append(":\n\n");

            Address current = vtableAddr;
            int slot = 0;
            int consecutiveNonFunction = 0;

            while (slot < maxEntries && consecutiveNonFunction < 2) {
                try {
                    // Read pointer value
                    long pointerValue;
                    if (pointerSize == 8) {
                        pointerValue = memory.getLong(current);
                    } else {
                        pointerValue = memory.getInt(current) & 0xFFFFFFFFL;
                    }

                    // Try to resolve as address
                    Address targetAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(pointerValue);
                    Function func = funcMgr.getFunctionAt(targetAddr);

                    if (func != null) {
                        result.append(String.format("Slot %d (offset 0x%x): %s @ %s\n",
                            slot, slot * pointerSize, func.getName(), targetAddr));
                        consecutiveNonFunction = 0;
                    } else {
                        result.append(String.format("Slot %d (offset 0x%x): 0x%x (not a function)\n",
                            slot, slot * pointerSize, pointerValue));
                        consecutiveNonFunction++;
                    }

                    current = current.add(pointerSize);
                    slot++;

                } catch (ghidra.program.model.mem.MemoryAccessException e) {
                    break; // End of readable memory
                }
            }

            if (slot == 0) {
                return "No vtable entries found at address: " + vtableAddrStr;
            }

            result.append("\nTotal entries: ").append(slot).append("\n");
            return result.toString();

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find indirect calls that could call a function via vtable
     */
    private String findVtableCallers(String functionAddrStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddrStr == null) return "Function address is required";

        try {
            Address funcAddr = program.getAddressFactory().getAddress(functionAddrStr);
            Function targetFunc = program.getFunctionManager().getFunctionAt(funcAddr);
            if (targetFunc == null) {
                targetFunc = program.getFunctionManager().getFunctionContaining(funcAddr);
            }
            if (targetFunc == null) {
                return "No function at address: " + functionAddrStr;
            }

            // Find vtable slots containing this function
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refs = refMgr.getReferencesTo(funcAddr);
            
            List<Integer> vtableOffsets = new ArrayList<>();
            int pointerSize = program.getDefaultPointerSize();

            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (ref.getReferenceType().isData()) {
                    // This is a data reference - could be in a vtable
                    // Calculate offset would be needed here for full implementation
                    // For now, just note that we found it in a vtable
                }
            }

            // Search for indirect calls
            List<String> indirectCalls = new ArrayList<>();
            Listing listing = program.getListing();
            InstructionIterator instructions = listing.getInstructions(true);

            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                FlowType flowType = instr.getFlowType();
                
                if (flowType.isCall() && flowType.isComputed()) {
                    // This is an indirect call
                    String operand = instr.getDefaultOperandRepresentation(0);
                    indirectCalls.add(String.format("%s: %s", instr.getAddress(), instr.toString()));
                    
                    if (indirectCalls.size() >= 100) {
                        break; // Limit results
                    }
                }
            }

            if (indirectCalls.isEmpty()) {
                return "No indirect calls found (vtable callers cannot be determined)";
            }

            StringBuilder result = new StringBuilder();
            result.append("Potential vtable callers for ").append(targetFunc.getName()).append(":\n");
            result.append("(Note: These are all indirect calls - manual verification needed)\n\n");
            result.append(String.join("\n", indirectCalls));
            
            return result.toString();

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Enhanced function methods
    // ----------------------------------------------------------------------------------

    /**
     * Get detailed function information
     */
    private String getFunctionInfo(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function at address: " + addressStr;

            StringBuilder result = new StringBuilder();
            result.append("Function: ").append(func.getName()).append("\n");
            result.append("Address: ").append(func.getEntryPoint()).append("\n");
            result.append("Signature: ").append(func.getSignature()).append("\n");
            result.append("Body: ").append(func.getBody().getMinAddress()).append(" - ").append(func.getBody().getMaxAddress()).append("\n");
            
            // Parameters
            result.append("\nParameters:\n");
            Parameter[] params = func.getParameters();
            if (params.length == 0) {
                result.append("  (none)\n");
            } else {
                for (Parameter param : params) {
                    result.append("  ").append(param.getDataType().getName()).append(" ").append(param.getName()).append("\n");
                }
            }
            
            // Local variables
            result.append("\nLocal Variables:\n");
            Variable[] locals = func.getLocalVariables();
            if (locals.length == 0) {
                result.append("  (none)\n");
            } else {
                for (Variable local : locals) {
                    result.append("  ").append(local.getDataType().getName()).append(" ").append(local.getName()).append("\n");
                }
            }

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * List function calls within a function
     */
    private String listFunctionCalls(String functionAddrStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddrStr == null) return "Function address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function function = getFunctionForAddress(program, addr);
            if (function == null) return "No function at address: " + functionAddrStr;

            List<String> calls = new ArrayList<>();
            Listing listing = program.getListing();
            InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                FlowType flowType = instr.getFlowType();
                
                if (flowType.isCall()) {
                    Address[] flows = instr.getFlows();
                    for (Address flow : flows) {
                        Function calledFunc = program.getFunctionManager().getFunctionAt(flow);
                        String funcName = (calledFunc != null) ? calledFunc.getName() : flow.toString();
                        calls.add(String.format("%s: CALL %s", instr.getAddress(), funcName));
                    }
                }
            }

            if (calls.isEmpty()) {
                return "No function calls found in: " + function.getName();
            }

            return String.format("Function calls in %s:\n%s",
                function.getName(), String.join("\n", calls));

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Additional helper methods for missing tools
    // ----------------------------------------------------------------------------------

    /**
     * Get function count
     */
    private String getFunctionCount(boolean filterDefaultNames) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator functions = funcMgr.getFunctions(true);
            int count = 0;
            while (functions.hasNext()) {
                Function func = functions.next();
                if (filterDefaultNames && func.getName().startsWith("FUN_")) {
                    continue;
                }
                count++;
            }
            return "{\"count\":" + count + "}";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get functions by similarity
     */
    private String getFunctionsBySimilarity(String searchString, int startIndex, int maxCount, boolean filterDefaultNames) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchString == null || searchString.trim().isEmpty()) return "Search string is required";
        try {
            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator functions = funcMgr.getFunctions(true);
            List<Function> matchingFunctions = new ArrayList<>();
            
            while (functions.hasNext()) {
                Function func = functions.next();
                if (filterDefaultNames && func.getName().startsWith("FUN_")) {
                    continue;
                }
                if (func.getName().toLowerCase().contains(searchString.toLowerCase())) {
                    matchingFunctions.add(func);
                }
            }
            
            // Sort by similarity (simple substring match for now)
            matchingFunctions.sort((a, b) -> {
                int aScore = longestCommonSubstring(searchString.toLowerCase(), a.getName().toLowerCase());
                int bScore = longestCommonSubstring(searchString.toLowerCase(), b.getName().toLowerCase());
                return Integer.compare(bScore, aScore);
            });
            
            int endIndex = Math.min(startIndex + maxCount, matchingFunctions.size());
            StringBuilder result = new StringBuilder("{\"functions\":[");
            for (int i = startIndex; i < endIndex; i++) {
                Function func = matchingFunctions.get(i);
                if (i > startIndex) result.append(",");
                result.append("{\"name\":\"").append(func.getName()).append("\",");
                result.append("\"address\":\"").append(func.getEntryPoint()).append("\"}");
            }
            result.append("],\"totalCount\":").append(matchingFunctions.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Helper for longest common substring
     */
    private int longestCommonSubstring(String s1, String s2) {
        int max = 0;
        for (int i = 0; i < s1.length(); i++) {
            for (int j = i + 1; j <= s1.length(); j++) {
                String substr = s1.substring(i, j);
                if (s2.contains(substr)) {
                    max = Math.max(max, substr.length());
                }
            }
        }
        return max;
    }

    /**
     * Get undefined function candidates
     */
    private String getUndefinedFunctionCandidates(int startIndex, int maxCandidates, int minReferenceCount) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            FunctionManager funcMgr = program.getFunctionManager();
            ReferenceManager refMgr = program.getReferenceManager();
            Map<Address, Integer> candidates = new HashMap<>();
            
            ReferenceIterator refIter = refMgr.getReferenceIterator(program.getMinAddress());
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                if (!ref.getReferenceType().isCall() && !ref.getReferenceType().isData()) {
                    continue;
                }
                Address target = ref.getToAddress();
                if (funcMgr.getFunctionAt(target) == null && !target.isExternalAddress()) {
                    MemoryBlock block = program.getMemory().getBlock(target);
                    if (block != null && block.isExecute()) {
                        candidates.put(target, candidates.getOrDefault(target, 0) + 1);
                    }
                }
            }
            
            List<Map.Entry<Address, Integer>> sorted = new ArrayList<>(candidates.entrySet());
            sorted.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
            sorted.removeIf(e -> e.getValue() < minReferenceCount);
            
            int endIndex = Math.min(startIndex + maxCandidates, sorted.size());
            StringBuilder result = new StringBuilder("{\"candidates\":[");
            for (int i = startIndex; i < endIndex; i++) {
                Map.Entry<Address, Integer> entry = sorted.get(i);
                if (i > startIndex) result.append(",");
                result.append("{\"address\":\"").append(entry.getKey()).append("\",");
                result.append("\"referenceCount\":").append(entry.getValue()).append("}");
            }
            result.append("],\"totalCandidates\":").append(sorted.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Create function at address
     */
    private String createFunction(String address, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (address == null) return "Address is required";
        try {
            Address addr = program.getAddressFactory().getAddress(address);
            FunctionManager funcMgr = program.getFunctionManager();
            if (funcMgr.getFunctionAt(addr) != null) {
                return "Function already exists at " + address;
            }
            
            int txId = program.startTransaction("Create Function");
            try {
                ghidra.app.cmd.function.CreateFunctionCmd cmd = new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                boolean success = cmd.applyTo(program);
                if (success && name != null && !name.trim().isEmpty()) {
                    Function func = funcMgr.getFunctionAt(addr);
                    if (func != null) {
                        func.setName(name, SourceType.USER_DEFINED);
                    }
                }
                program.endTransaction(txId, true);
                return success ? "Function created successfully" : "Failed to create function";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Manage function tags
     */
    private String manageFunctionTags(String function, String mode, String tagsStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (function == null || mode == null) return "Function and mode are required";
        try {
            FunctionManager funcMgr = program.getFunctionManager();
            Function func = funcMgr.getFunction(function);
            if (func == null) {
                Address addr = program.getAddressFactory().getAddress(function);
                func = funcMgr.getFunctionAt(addr);
            }
            if (func == null) return "Function not found: " + function;
            
            int txId = program.startTransaction("Manage Function Tags");
            try {
                if ("get".equals(mode)) {
                    Set<ghidra.program.model.listing.FunctionTag> tags = func.getTags();
                    StringBuilder result = new StringBuilder("{\"tags\":[");
                    boolean first = true;
                    for (ghidra.program.model.listing.FunctionTag tag : tags) {
                        if (!first) result.append(",");
                        result.append("\"").append(tag.getName()).append("\"");
                        first = false;
                    }
                    result.append("]}");
                    program.endTransaction(txId, false);
                    return result.toString();
                } else if ("set".equals(mode) || "add".equals(mode) || "remove".equals(mode)) {
                    if (tagsStr != null && !tagsStr.trim().isEmpty()) {
                        String[] tags = tagsStr.split(",");
                        for (String tagName : tags) {
                            tagName = tagName.trim();
                            if (tagName.isEmpty()) continue;
                            if ("set".equals(mode) || "add".equals(mode)) {
                                func.addTag(tagName);
                            } else if ("remove".equals(mode)) {
                                func.removeTag(tagName);
                            }
                        }
                    }
                    program.endTransaction(txId, true);
                    return "Tags updated successfully";
                } else if ("list".equals(mode)) {
                    ghidra.program.model.listing.FunctionTagManager tagMgr = funcMgr.getFunctionTagManager();
                    List<? extends ghidra.program.model.listing.FunctionTag> allTags = tagMgr.getAllFunctionTags();
                    StringBuilder result = new StringBuilder("{\"tags\":[");
                    boolean first = true;
                    for (ghidra.program.model.listing.FunctionTag tag : allTags) {
                        if (!first) result.append(",");
                        result.append("{\"name\":\"").append(tag.getName()).append("\",");
                        result.append("\"count\":").append(tagMgr.getUseCount(tag)).append("}");
                        first = false;
                    }
                    result.append("]}");
                    program.endTransaction(txId, false);
                    return result.toString();
                }
                program.endTransaction(txId, false);
                return "Unknown mode: " + mode;
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get strings by similarity
     */
    private String getStringsBySimilarity(String searchString, int startIndex, int maxCount, boolean includeReferencingFunctions) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchString == null || searchString.trim().isEmpty()) return "Search string is required";
        try {
            Listing listing = program.getListing();
            ghidra.program.model.listing.DataIterator dataIter = listing.getDefinedData(true);
            List<ghidra.program.model.listing.Data> matchingStrings = new ArrayList<>();
            
            while (dataIter.hasNext()) {
                ghidra.program.model.listing.Data data = dataIter.next();
                if (data.getValue() instanceof String) {
                    String str = (String) data.getValue();
                    if (str.toLowerCase().contains(searchString.toLowerCase())) {
                        matchingStrings.add(data);
                    }
                }
            }
            
            // Sort by similarity
            matchingStrings.sort((a, b) -> {
                String aStr = ((String) a.getValue()).toLowerCase();
                String bStr = ((String) b.getValue()).toLowerCase();
                int aScore = longestCommonSubstring(searchString.toLowerCase(), aStr);
                int bScore = longestCommonSubstring(searchString.toLowerCase(), bStr);
                return Integer.compare(bScore, aScore);
            });
            
            int endIndex = Math.min(startIndex + maxCount, matchingStrings.size());
            StringBuilder result = new StringBuilder("{\"strings\":[");
            for (int i = startIndex; i < endIndex; i++) {
                ghidra.program.model.listing.Data data = matchingStrings.get(i);
                if (i > startIndex) result.append(",");
                result.append("{\"address\":\"").append(data.getAddress()).append("\",");
                result.append("\"content\":\"").append(escapeJson((String) data.getValue())).append("\"}");
            }
            result.append("],\"totalCount\":").append(matchingStrings.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Escape JSON string
     */
    private String escapeJson(String str) {
        return str.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    /**
     * Set comment
     */
    private String setComment(String addressOrSymbol, String commentType, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressOrSymbol == null || comment == null) return "Address and comment are required";
        try {
            Address addr = resolveAddressOrSymbol(program, addressOrSymbol);
            if (addr == null) return "Invalid address or symbol: " + addressOrSymbol;
            
            ghidra.program.model.listing.CommentType type = ghidra.program.model.listing.CommentType.EOL;
            if ("pre".equalsIgnoreCase(commentType)) type = ghidra.program.model.listing.CommentType.PRE;
            else if ("post".equalsIgnoreCase(commentType)) type = ghidra.program.model.listing.CommentType.POST;
            else if ("plate".equalsIgnoreCase(commentType)) type = ghidra.program.model.listing.CommentType.PLATE;
            else if ("repeatable".equalsIgnoreCase(commentType)) type = ghidra.program.model.listing.CommentType.REPEATABLE;
            
            int txId = program.startTransaction("Set Comment");
            try {
                Listing listing = program.getListing();
                listing.setComment(addr, type, comment);
                program.endTransaction(txId, true);
                return "Comment set successfully";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get comments
     */
    private String getComments(String addressOrSymbol, String startAddr, String endAddr, String commentTypesStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            Listing listing = program.getListing();
            List<Map<String, String>> comments = new ArrayList<>();
            
            if (addressOrSymbol != null) {
                Address addr = resolveAddressOrSymbol(program, addressOrSymbol);
                if (addr == null) return "Invalid address or symbol: " + addressOrSymbol;
                collectCommentsAtAddress(program, listing, addr, comments, commentTypesStr);
            } else if (startAddr != null && endAddr != null) {
                Address start = program.getAddressFactory().getAddress(startAddr);
                Address end = program.getAddressFactory().getAddress(endAddr);
                ghidra.program.model.address.AddressSet addrSet = new ghidra.program.model.address.AddressSet(start, end);
                ghidra.program.model.listing.CodeUnitIterator iter = listing.getCodeUnits(addrSet, true);
                while (iter.hasNext()) {
                    collectCommentsAtAddress(program, listing, iter.next().getAddress(), comments, commentTypesStr);
                }
            } else {
                return "Either addressOrSymbol or start/end addresses are required";
            }
            
            StringBuilder result = new StringBuilder("{\"comments\":[");
            for (int i = 0; i < comments.size(); i++) {
                if (i > 0) result.append(",");
                Map<String, String> comment = comments.get(i);
                result.append("{\"address\":\"").append(comment.get("address")).append("\",");
                result.append("\"type\":\"").append(comment.get("type")).append("\",");
                result.append("\"comment\":\"").append(escapeJson(comment.get("comment"))).append("\"}");
            }
            result.append("],\"count\":").append(comments.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Collect comments at address
     */
    private void collectCommentsAtAddress(Program program, Listing listing, Address addr, List<Map<String, String>> comments, String commentTypesStr) {
        ghidra.program.model.listing.CodeUnit cu = listing.getCodeUnitAt(addr);
        if (cu == null) return;
        
        List<ghidra.program.model.listing.CommentType> types = new ArrayList<>();
        if (commentTypesStr != null && !commentTypesStr.trim().isEmpty()) {
            String[] typeStrs = commentTypesStr.split(",");
            for (String typeStr : typeStrs) {
                typeStr = typeStr.trim().toLowerCase();
                if ("pre".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.PRE);
                else if ("eol".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.EOL);
                else if ("post".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.POST);
                else if ("plate".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.PLATE);
                else if ("repeatable".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.REPEATABLE);
            }
        } else {
            types.addAll(Arrays.asList(ghidra.program.model.listing.CommentType.values()));
        }
        
        for (ghidra.program.model.listing.CommentType type : types) {
            String comment = cu.getComment(type);
            if (comment != null && !comment.isEmpty()) {
                Map<String, String> commentInfo = new HashMap<>();
                commentInfo.put("address", addr.toString());
                commentInfo.put("type", type.toString());
                commentInfo.put("comment", comment);
                comments.add(commentInfo);
            }
        }
    }

    /**
     * Remove comment
     */
    private String removeComment(String addressOrSymbol, String commentType) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressOrSymbol == null || commentType == null) return "Address and comment type are required";
        try {
            Address addr = resolveAddressOrSymbol(program, addressOrSymbol);
            if (addr == null) return "Invalid address or symbol: " + addressOrSymbol;
            
            ghidra.program.model.listing.CommentType type = ghidra.program.model.listing.CommentType.EOL;
            if ("pre".equalsIgnoreCase(commentType)) type = ghidra.program.model.listing.CommentType.PRE;
            else if ("post".equalsIgnoreCase(commentType)) type = ghidra.program.model.listing.CommentType.POST;
            else if ("plate".equalsIgnoreCase(commentType)) type = ghidra.program.model.listing.CommentType.PLATE;
            else if ("repeatable".equalsIgnoreCase(commentType)) type = ghidra.program.model.listing.CommentType.REPEATABLE;
            
            int txId = program.startTransaction("Remove Comment");
            try {
                Listing listing = program.getListing();
                listing.setComment(addr, type, null);
                program.endTransaction(txId, true);
                return "Comment removed successfully";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Search comments
     */
    private String searchComments(String searchText, boolean caseSensitive, String commentTypesStr, int maxResults) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchText == null || searchText.trim().isEmpty()) return "Search text is required";
        try {
            Listing listing = program.getListing();
            List<Map<String, String>> results = new ArrayList<>();
            String searchLower = caseSensitive ? searchText : searchText.toLowerCase();
            
            List<ghidra.program.model.listing.CommentType> types = new ArrayList<>();
            if (commentTypesStr != null && !commentTypesStr.trim().isEmpty()) {
                String[] typeStrs = commentTypesStr.split(",");
                for (String typeStr : typeStrs) {
                    typeStr = typeStr.trim().toLowerCase();
                    if ("pre".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.PRE);
                    else if ("eol".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.EOL);
                    else if ("post".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.POST);
                    else if ("plate".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.PLATE);
                    else if ("repeatable".equals(typeStr)) types.add(ghidra.program.model.listing.CommentType.REPEATABLE);
                }
            } else {
                types.addAll(Arrays.asList(ghidra.program.model.listing.CommentType.values()));
            }
            
            for (ghidra.program.model.listing.CommentType type : types) {
                if (results.size() >= maxResults) break;
                ghidra.program.model.address.AddressIterator iter = listing.getCommentAddressIterator(type, program.getMemory(), true);
                while (iter.hasNext() && results.size() < maxResults) {
                    Address addr = iter.next();
                    String comment = listing.getComment(type, addr);
                    if (comment != null) {
                        String commentLower = caseSensitive ? comment : comment.toLowerCase();
                        if (commentLower.contains(searchLower)) {
                            Map<String, String> result = new HashMap<>();
                            result.put("address", addr.toString());
                            result.put("type", type.toString());
                            result.put("comment", comment);
                            results.add(result);
                        }
                    }
                }
            }
            
            StringBuilder result = new StringBuilder("{\"results\":[");
            for (int i = 0; i < results.size(); i++) {
                if (i > 0) result.append(",");
                Map<String, String> r = results.get(i);
                result.append("{\"address\":\"").append(r.get("address")).append("\",");
                result.append("\"type\":\"").append(r.get("type")).append("\",");
                result.append("\"comment\":\"").append(escapeJson(r.get("comment"))).append("\"}");
            }
            result.append("],\"count\":").append(results.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Apply data type
     */
    private String applyDataType(String addressOrSymbol, String dataTypeString, String archiveName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressOrSymbol == null || dataTypeString == null) return "Address and data type are required";
        try {
            Address addr = resolveAddressOrSymbol(program, addressOrSymbol);
            if (addr == null) return "Invalid address or symbol: " + addressOrSymbol;
            
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = dtm.getDataType(dataTypeString);
            if (dataType == null) {
                // Try parsing as a type string
                ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(dtm, dtm, null, ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);
                try {
                    dataType = parser.parse(dataTypeString);
                } catch (Exception e) {
                    return "Could not find or parse data type: " + dataTypeString;
                }
            }
            
            int txId = program.startTransaction("Apply Data Type");
            try {
                Listing listing = program.getListing();
                if (listing.getDataAt(addr) != null) {
                    listing.clearCodeUnits(addr, addr.add(dataType.getLength() - 1), false);
                }
                listing.createData(addr, dataType);
                program.endTransaction(txId, true);
                return "Data type applied successfully";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get symbols count
     */
    private String getSymbolsCount(boolean includeExternal, boolean filterDefaultNames) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator iter = symbolTable.getAllSymbols(true);
            int count = 0;
            while (iter.hasNext()) {
                Symbol sym = iter.next();
                if (!includeExternal && sym.isExternal()) continue;
                if (filterDefaultNames && (sym.getName().startsWith("FUN_") || sym.getName().startsWith("DAT_"))) continue;
                count++;
            }
            return "{\"count\":" + count + "}";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get symbols
     */
    private String getSymbols(boolean includeExternal, int startIndex, int maxCount, boolean filterDefaultNames) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator iter = symbolTable.getAllSymbols(true);
            List<Symbol> symbols = new ArrayList<>();
            
            while (iter.hasNext()) {
                Symbol sym = iter.next();
                if (!includeExternal && sym.isExternal()) continue;
                if (filterDefaultNames && (sym.getName().startsWith("FUN_") || sym.getName().startsWith("DAT_"))) continue;
                symbols.add(sym);
            }
            
            int endIndex = Math.min(startIndex + maxCount, symbols.size());
            StringBuilder result = new StringBuilder("{\"symbols\":[");
            for (int i = startIndex; i < endIndex; i++) {
                Symbol sym = symbols.get(i);
                if (i > startIndex) result.append(",");
                result.append("{\"name\":\"").append(sym.getName()).append("\",");
                result.append("\"address\":\"").append(sym.getAddress()).append("\",");
                result.append("\"namespace\":\"").append(sym.getParentNamespace().getName()).append("\",");
                result.append("\"type\":\"").append(sym.getSymbolType().toString()).append("\"}");
            }
            result.append("],\"totalCount\":").append(symbols.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find import references
     */
    private String findImportReferences(String importName, String libraryName, int maxResults) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (importName == null) return "Import name is required";
        try {
            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator externalFuncs = funcMgr.getExternalFunctions();
            List<Function> matchingImports = new ArrayList<>();
            
            while (externalFuncs.hasNext()) {
                Function func = externalFuncs.next();
                if (!func.getName().equalsIgnoreCase(importName)) continue;
                if (libraryName != null && !libraryName.isEmpty()) {
                    ghidra.program.model.symbol.ExternalLocation extLoc = func.getExternalLocation();
                    if (extLoc == null || !extLoc.getLibraryName().equalsIgnoreCase(libraryName)) continue;
                }
                matchingImports.add(func);
            }
            
            if (matchingImports.isEmpty()) {
                return "Import not found: " + importName;
            }
            
            ReferenceManager refMgr = program.getReferenceManager();
            List<Map<String, String>> references = new ArrayList<>();
            Set<Address> seen = new HashSet<>();
            
            for (Function importFunc : matchingImports) {
                if (references.size() >= maxResults) break;
                Address importAddr = importFunc.getEntryPoint();
                if (importAddr == null) continue;
                
                ReferenceIterator refIter = refMgr.getReferencesTo(importAddr);
                while (refIter.hasNext() && references.size() < maxResults) {
                    Reference ref = refIter.next();
                    Address fromAddr = ref.getFromAddress();
                    if (seen.contains(fromAddr)) continue;
                    seen.add(fromAddr);
                    
                    Map<String, String> refInfo = new HashMap<>();
                    refInfo.put("fromAddress", fromAddr.toString());
                    refInfo.put("referenceType", ref.getReferenceType().toString());
                    refInfo.put("isCall", String.valueOf(ref.getReferenceType().isCall()));
                    
                    Function containingFunc = funcMgr.getFunctionContaining(fromAddr);
                    if (containingFunc != null) {
                        refInfo.put("function", containingFunc.getName());
                        refInfo.put("functionAddress", containingFunc.getEntryPoint().toString());
                    }
                    references.add(refInfo);
                }
            }
            
            StringBuilder result = new StringBuilder("{\"references\":[");
            for (int i = 0; i < references.size(); i++) {
                if (i > 0) result.append(",");
                Map<String, String> ref = references.get(i);
                result.append("{\"fromAddress\":\"").append(ref.get("fromAddress")).append("\",");
                result.append("\"referenceType\":\"").append(ref.get("referenceType")).append("\",");
                result.append("\"isCall\":").append(ref.get("isCall"));
                if (ref.containsKey("function")) {
                    result.append(",\"function\":\"").append(ref.get("function")).append("\",");
                    result.append("\"functionAddress\":\"").append(ref.get("functionAddress")).append("\"");
                }
                result.append("}");
            }
            result.append("],\"count\":").append(references.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Resolve thunk
     */
    private String resolveThunk(String address) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (address == null) return "Address is required";
        try {
            Address addr = program.getAddressFactory().getAddress(address);
            FunctionManager funcMgr = program.getFunctionManager();
            Function func = funcMgr.getFunctionAt(addr);
            if (func == null) func = funcMgr.getFunctionContaining(addr);
            if (func == null) return "No function found at address: " + address;
            
            List<Map<String, String>> chain = new ArrayList<>();
            Function current = func;
            int depth = 0;
            int maxDepth = 10;
            
            while (current != null && depth < maxDepth) {
                Map<String, String> info = new HashMap<>();
                info.put("name", current.getName());
                info.put("address", current.getEntryPoint().toString());
                info.put("isThunk", String.valueOf(current.isThunk()));
                info.put("isExternal", String.valueOf(current.isExternal()));
                
                if (current.isExternal()) {
                    ghidra.program.model.symbol.ExternalLocation extLoc = current.getExternalLocation();
                    if (extLoc != null) {
                        info.put("library", extLoc.getLibraryName());
                    }
                }
                
                chain.add(info);
                
                if (current.isThunk()) {
                    Function next = current.getThunkedFunction(false);
                    if (next != null && !next.equals(current)) {
                        current = next;
                        depth++;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            
            StringBuilder result = new StringBuilder("{\"chain\":[");
            for (int i = 0; i < chain.size(); i++) {
                if (i > 0) result.append(",");
                Map<String, String> info = chain.get(i);
                result.append("{\"name\":\"").append(info.get("name")).append("\",");
                result.append("\"address\":\"").append(info.get("address")).append("\",");
                result.append("\"isThunk\":").append(info.get("isThunk")).append(",");
                result.append("\"isExternal\":").append(info.get("isExternal"));
                if (info.containsKey("library")) {
                    result.append(",\"library\":\"").append(info.get("library")).append("\"");
                }
                result.append("}");
            }
            result.append("],\"chainLength\":").append(chain.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get call tree
     */
    private String getCallTree(String functionAddress, String direction, int maxDepth) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddress == null) return "Function address is required";
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            FunctionManager funcMgr = program.getFunctionManager();
            Function func = funcMgr.getFunctionAt(addr);
            if (func == null) return "Function not found at: " + functionAddress;
            
            StringBuilder result = new StringBuilder();
            result.append("Call tree for ").append(func.getName()).append(" (").append(direction).append("):\n\n");
            
            if ("callers".equalsIgnoreCase(direction)) {
                buildCallerTree(func, result, 0, maxDepth, new HashSet<>());
            } else {
                buildCalleeTree(func, result, 0, maxDepth, new HashSet<>());
            }
            
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Build caller tree recursively
     */
    private void buildCallerTree(Function func, StringBuilder result, int depth, int maxDepth, Set<Address> visited) {
        if (depth >= maxDepth || visited.contains(func.getEntryPoint())) return;
        visited.add(func.getEntryPoint());
        
        for (int i = 0; i < depth; i++) result.append("  ");
        result.append(func.getName()).append("\n");
        
        Function[] callers = func.getCallingFunctions(new ConsoleTaskMonitor()).toArray(new Function[0]);
        for (Function caller : callers) {
            buildCallerTree(caller, result, depth + 1, maxDepth, visited);
        }
    }

    /**
     * Build callee tree recursively
     */
    private void buildCalleeTree(Function func, StringBuilder result, int depth, int maxDepth, Set<Address> visited) {
        if (depth >= maxDepth || visited.contains(func.getEntryPoint())) return;
        visited.add(func.getEntryPoint());
        
        for (int i = 0; i < depth; i++) result.append("  ");
        result.append(func.getName()).append("\n");
        
        Function[] callees = func.getCalledFunctions(new ConsoleTaskMonitor()).toArray(new Function[0]);
        for (Function callee : callees) {
            buildCalleeTree(callee, result, depth + 1, maxDepth, visited);
        }
    }

    /**
     * Find common callers
     */
    private String findCommonCallers(String functionAddressesStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddressesStr == null || functionAddressesStr.trim().isEmpty()) return "Function addresses are required";
        try {
            String[] addrStrs = functionAddressesStr.split(",");
            List<Function> targetFunctions = new ArrayList<>();
            FunctionManager funcMgr = program.getFunctionManager();
            
            for (String addrStr : addrStrs) {
                addrStr = addrStr.trim();
                Address addr = program.getAddressFactory().getAddress(addrStr);
                Function func = funcMgr.getFunctionAt(addr);
                if (func == null) continue;
                targetFunctions.add(func);
            }
            
            if (targetFunctions.isEmpty()) return "No valid functions found";
            
            // Find callers of first function
            Set<Function> commonCallers = new HashSet<>(targetFunctions.get(0).getCallingFunctions(new ConsoleTaskMonitor()));
            
            // Intersect with callers of other functions
            for (int i = 1; i < targetFunctions.size(); i++) {
                Set<Function> callers = new HashSet<>(targetFunctions.get(i).getCallingFunctions(new ConsoleTaskMonitor()));
                commonCallers.retainAll(callers);
            }
            
            StringBuilder result = new StringBuilder("Common callers:\n");
            for (Function caller : commonCallers) {
                result.append("  ").append(caller.getName()).append(" (").append(caller.getEntryPoint()).append(")\n");
            }
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * List common constants
     */
    private String listCommonConstants(boolean includeSmallValues, String minValue, int topN) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            Map<Long, Integer> constantCounts = new HashMap<>();
            Listing listing = program.getListing();
            ghidra.program.model.listing.InstructionIterator iter = listing.getInstructions(true);
            
            while (iter.hasNext()) {
                Instruction instr = iter.next();
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    Object[] opObjs = instr.getOpObjects(i);
                    for (Object opObj : opObjs) {
                        if (opObj instanceof ghidra.program.model.scalar.Scalar) {
                            ghidra.program.model.scalar.Scalar scalar = (ghidra.program.model.scalar.Scalar) opObj;
                            long value = scalar.getSignedValue();
                            if (!includeSmallValues && value >= 0 && value <= 255) continue;
                            if (minValue != null && !minValue.isEmpty()) {
                                try {
                                    long min = Long.parseLong(minValue);
                                    if (value < min) continue;
                                } catch (NumberFormatException e) {
                                    // Ignore invalid minValue
                                }
                            }
                            constantCounts.put(value, constantCounts.getOrDefault(value, 0) + 1);
                        }
                    }
                }
            }
            
            List<Map.Entry<Long, Integer>> sorted = new ArrayList<>(constantCounts.entrySet());
            sorted.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
            
            int count = Math.min(topN, sorted.size());
            StringBuilder result = new StringBuilder("{\"constants\":[");
            for (int i = 0; i < count; i++) {
                if (i > 0) result.append(",");
                Map.Entry<Long, Integer> entry = sorted.get(i);
                result.append("{\"value\":").append(entry.getKey()).append(",");
                result.append("\"count\":").append(entry.getValue()).append("}");
            }
            result.append("]}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find variable accesses
     */
    private String findVariableAccesses(String functionAddress, String variableName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddress == null || variableName == null) return "Function address and variable name are required";
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            FunctionManager funcMgr = program.getFunctionManager();
            Function func = funcMgr.getFunctionAt(addr);
            if (func == null) return "Function not found at: " + functionAddress;
            
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            try {
                DecompileResults results = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (!results.decompileCompleted()) {
                    return "Decompilation failed: " + results.getErrorMessage();
                }
                
                HighFunction highFunc = results.getHighFunction();
                if (highFunc == null) return "Could not get high-level function representation";
                
                LocalSymbolMap localMap = highFunc.getLocalSymbolMap();
                HighSymbol sym = localMap.getSymbol(variableName);
                if (sym == null) return "Variable not found: " + variableName;
                
                HighVariable var = sym.getHighVariable();
                if (var == null) return "Could not get high variable for: " + variableName;
                
                StringBuilder result = new StringBuilder("Variable accesses for ").append(variableName).append(":\n\n");
                Iterator<Varnode> varnodes = var.getVarnodes();
                while (varnodes.hasNext()) {
                    Varnode vn = varnodes.next();
                    Iterator<ghidra.program.model.pcode.PcodeOp> uses = vn.getDescendants();
                    while (uses.hasNext()) {
                        ghidra.program.model.pcode.PcodeOp op = uses.next();
                        Address opAddr = op.getSeqnum().getTarget();
                        result.append("  ").append(opAddr).append(": ").append(op.getMnemonic()).append("\n");
                    }
                }
                return result.toString();
            } finally {
                decomp.dispose();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find vtables containing function
     */
    private String findVtablesContainingFunction(String functionAddress) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddress == null) return "Function address is required";
        try {
            Address funcAddr = program.getAddressFactory().getAddress(functionAddress);
            FunctionManager funcMgr = program.getFunctionManager();
            Function func = funcMgr.getFunctionAt(funcAddr);
            if (func == null) return "Function not found at: " + functionAddress;
            
            Memory memory = program.getMemory();
            int pointerSize = program.getDefaultPointerSize();
            List<Map<String, String>> vtables = new ArrayList<>();
            
            // Search for vtables that might contain this function
            MemoryBlock[] blocks = memory.getBlocks();
            for (MemoryBlock block : blocks) {
                if (!block.isExecute()) continue;
                Address start = block.getStart();
                Address end = block.getEnd();
                
                for (Address addr = start; addr.compareTo(end) <= 0; addr = addr.add(pointerSize)) {
                    try {
                        long value = memory.getLong(addr);
                        Address targetAddr = memory.getAddressFactory().getAddress(value);
                        if (targetAddr != null && targetAddr.equals(funcAddr)) {
                            // Found a potential vtable entry
                            Map<String, String> vtableInfo = new HashMap<>();
                            vtableInfo.put("vtableAddress", findVtableStart(program, addr).toString());
                            vtableInfo.put("slotOffset", String.valueOf(addr.subtract(findVtableStart(program, addr))));
                            vtables.add(vtableInfo);
                        }
                    } catch (Exception e) {
                        // Continue searching
                    }
                }
            }
            
            StringBuilder result = new StringBuilder("{\"vtables\":[");
            for (int i = 0; i < vtables.size(); i++) {
                if (i > 0) result.append(",");
                Map<String, String> info = vtables.get(i);
                result.append("{\"vtableAddress\":\"").append(info.get("vtableAddress")).append("\",");
                result.append("\"slotOffset\":").append(info.get("slotOffset")).append("}");
            }
            result.append("]}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find vtable start (simple heuristic)
     */
    private Address findVtableStart(Program program, Address addr) {
        // Simple heuristic: look backwards for null pointer or different pattern
        Memory memory = program.getMemory();
        int pointerSize = program.getDefaultPointerSize();
        Address current = addr;
        int count = 0;
        while (count < 100 && current != null) {
            try {
                long value = memory.getLong(current);
                if (value == 0) break;
                current = current.subtract(pointerSize);
                count++;
            } catch (Exception e) {
                break;
            }
        }
        return current != null ? current.add(pointerSize) : addr;
    }

    /**
     * Remove bookmark
     */
    private String removeBookmark(String addressOrSymbol, String type, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressOrSymbol == null) return "Address is required";
        try {
            Address addr = resolveAddressOrSymbol(program, addressOrSymbol);
            if (addr == null) return "Invalid address or symbol: " + addressOrSymbol;
            
            int txId = program.startTransaction("Remove Bookmark");
            try {
                ghidra.program.model.listing.BookmarkManager bmMgr = program.getBookmarkManager();
                if (type != null && !type.isEmpty()) {
                    bmMgr.removeBookmark(addr, type, category);
                } else {
                    ghidra.program.model.listing.Bookmark[] bookmarks = bmMgr.getBookmarks(addr);
                    for (ghidra.program.model.listing.Bookmark bm : bookmarks) {
                        bmMgr.removeBookmark(addr, bm.getType(), bm.getCategory());
                    }
                }
                program.endTransaction(txId, true);
                return "Bookmark removed successfully";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * List bookmark categories
     */
    private String listBookmarkCategories(String type) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            ghidra.program.model.listing.BookmarkManager bmMgr = program.getBookmarkManager();
            Set<String> categories = new HashSet<>();
            
            ghidra.program.model.address.AddressIterator iter = bmMgr.getBookmarkAddressIterator(type != null ? type : "Note");
            while (iter.hasNext()) {
                Address addr = iter.next();
                ghidra.program.model.listing.Bookmark[] bookmarks = bmMgr.getBookmarks(addr);
                for (ghidra.program.model.listing.Bookmark bm : bookmarks) {
                    if (type == null || bm.getType().equals(type)) {
                        categories.add(bm.getCategory());
                    }
                }
            }
            
            StringBuilder result = new StringBuilder("{\"categories\":[");
            boolean first = true;
            for (String cat : categories) {
                if (!first) result.append(",");
                result.append("\"").append(cat).append("\"");
                first = false;
            }
            result.append("]}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Search decompilation
     */
    private String searchDecompilation(String pattern, boolean caseSensitive, int maxResults, boolean overrideMaxFunctionsLimit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (pattern == null || pattern.trim().isEmpty()) return "Pattern is required";
        try {
            java.util.regex.Pattern regex = java.util.regex.Pattern.compile(pattern, caseSensitive ? 0 : java.util.regex.Pattern.CASE_INSENSITIVE);
            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator functions = funcMgr.getFunctions(true);
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            
            List<Map<String, String>> results = new ArrayList<>();
            int functionCount = 0;
            int maxFunctions = overrideMaxFunctionsLimit ? Integer.MAX_VALUE : 10000;
            
            try {
                while (functions.hasNext() && functionCount < maxFunctions && results.size() < maxResults) {
                    Function func = functions.next();
                    functionCount++;
                    
                    DecompileResults decompResults = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                    if (decompResults.decompileCompleted()) {
                        String decompiledCode = decompResults.getDecompiledFunction().getC();
                        java.util.regex.Matcher matcher = regex.matcher(decompiledCode);
                        if (matcher.find()) {
                            Map<String, String> result = new HashMap<>();
                            result.put("function", func.getName());
                            result.put("address", func.getEntryPoint().toString());
                            // Find line number
                            int lineNum = 1;
                            int matchPos = matcher.start();
                            String beforeMatch = decompiledCode.substring(0, matchPos);
                            for (int i = 0; i < beforeMatch.length(); i++) {
                                if (beforeMatch.charAt(i) == '\n') lineNum++;
                            }
                            result.put("lineNumber", String.valueOf(lineNum));
                            results.add(result);
                        }
                    }
                }
            } finally {
                decomp.dispose();
            }
            
            StringBuilder result = new StringBuilder("{\"results\":[");
            for (int i = 0; i < results.size(); i++) {
                if (i > 0) result.append(",");
                Map<String, String> r = results.get(i);
                result.append("{\"function\":\"").append(r.get("function")).append("\",");
                result.append("\"address\":\"").append(r.get("address")).append("\",");
                result.append("\"lineNumber\":").append(r.get("lineNumber")).append("}");
            }
            result.append("],\"count\":").append(results.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Rename variables
     */
    private String renameVariables(String functionNameOrAddress, String variableMappingsStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionNameOrAddress == null || variableMappingsStr == null) return "Function and variable mappings are required";
        try {
            Function func = resolveFunction(program, functionNameOrAddress);
            if (func == null) return "Function not found: " + functionNameOrAddress;
            
            // Parse variable mappings (format: "oldName1:newName1,oldName2:newName2")
            Map<String, String> mappings = new HashMap<>();
            String[] pairs = variableMappingsStr.split(",");
            for (String pair : pairs) {
                String[] parts = pair.split(":");
                if (parts.length == 2) {
                    mappings.put(parts[0].trim(), parts[1].trim());
                }
            }
            
            if (mappings.isEmpty()) return "No valid variable mappings provided";
            
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            try {
                DecompileResults results = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (!results.decompileCompleted()) {
                    return "Decompilation failed: " + results.getErrorMessage();
                }
                
                HighFunction highFunc = results.getHighFunction();
                if (highFunc == null) return "Could not get high-level function representation";
                
                int txId = program.startTransaction("Rename Variables");
                try {
                    LocalSymbolMap localMap = highFunc.getLocalSymbolMap();
                    for (Map.Entry<String, String> entry : mappings.entrySet()) {
                        HighSymbol sym = localMap.getSymbol(entry.getKey());
                        if (sym != null) {
                            HighVariable var = sym.getHighVariable();
                            if (var != null) {
                                var.setName(entry.getValue());
                            }
                        }
                    }
                    HighFunctionDBUtil.commitLocalVariablesToDatabase(highFunc, ReturnCommitOption.COMMIT_ALL, new ConsoleTaskMonitor());
                    program.endTransaction(txId, true);
                    return "Variables renamed successfully";
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } finally {
                decomp.dispose();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Change variable data types
     */
    private String changeVariableDataTypes(String functionNameOrAddress, String datatypeMappingsStr, String archiveName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionNameOrAddress == null || datatypeMappingsStr == null) return "Function and datatype mappings are required";
        try {
            Function func = resolveFunction(program, functionNameOrAddress);
            if (func == null) return "Function not found: " + functionNameOrAddress;
            
            // Parse datatype mappings (format: "varName1:type1,varName2:type2")
            Map<String, String> mappings = new HashMap<>();
            String[] pairs = datatypeMappingsStr.split(",");
            for (String pair : pairs) {
                String[] parts = pair.split(":");
                if (parts.length == 2) {
                    mappings.put(parts[0].trim(), parts[1].trim());
                }
            }
            
            if (mappings.isEmpty()) return "No valid datatype mappings provided";
            
            DataTypeManager dtm = program.getDataTypeManager();
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            try {
                DecompileResults results = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (!results.decompileCompleted()) {
                    return "Decompilation failed: " + results.getErrorMessage();
                }
                
                HighFunction highFunc = results.getHighFunction();
                if (highFunc == null) return "Could not get high-level function representation";
                
                int txId = program.startTransaction("Change Variable Data Types");
                try {
                    LocalSymbolMap localMap = highFunc.getLocalSymbolMap();
                    for (Map.Entry<String, String> entry : mappings.entrySet()) {
                        HighSymbol sym = localMap.getSymbol(entry.getKey());
                        if (sym != null) {
                            DataType dataType = dtm.getDataType(entry.getValue());
                            if (dataType == null) {
                                ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(dtm, dtm, null, ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);
                                try {
                                    dataType = parser.parse(entry.getValue());
                                } catch (Exception e) {
                                    continue; // Skip invalid types
                                }
                            }
                            if (dataType != null) {
                                sym.setDataType(dataType);
                            }
                        }
                    }
                    HighFunctionDBUtil.commitLocalVariablesToDatabase(highFunc, ReturnCommitOption.COMMIT_ALL, new ConsoleTaskMonitor());
                    program.endTransaction(txId, true);
                    return "Variable data types changed successfully";
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } finally {
                decomp.dispose();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get callers decompiled
     */
    private String getCallersDecompiled(String functionNameOrAddress, int startIndex, int maxCallers, boolean includeCallContext) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionNameOrAddress == null) return "Function name or address is required";
        try {
            Function func = resolveFunction(program, functionNameOrAddress);
            if (func == null) return "Function not found: " + functionNameOrAddress;
            
            Function[] callers = func.getCallingFunctions(new ConsoleTaskMonitor()).toArray(new Function[0]);
            int endIndex = Math.min(startIndex + maxCallers, callers.length);
            
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            StringBuilder result = new StringBuilder("{\"callers\":[");
            
            try {
                for (int i = startIndex; i < endIndex; i++) {
                    if (i > startIndex) result.append(",");
                    Function caller = callers[i];
                    DecompileResults decompResults = decomp.decompileFunction(caller, 30, new ConsoleTaskMonitor());
                    if (decompResults.decompileCompleted()) {
                        result.append("{\"function\":\"").append(caller.getName()).append("\",");
                        result.append("\"address\":\"").append(caller.getEntryPoint()).append("\",");
                        if (includeCallContext) {
                            String code = decompResults.getDecompiledFunction().getC();
                            result.append("\"decompiledCode\":\"").append(escapeJson(code)).append("\"");
                        }
                        result.append("}");
                    }
                }
            } finally {
                decomp.dispose();
            }
            
            result.append("],\"totalCount\":").append(callers.length).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get referencers decompiled
     */
    private String getReferencersDecompiled(String addressOrSymbol, int startIndex, int maxReferencers, boolean includeRefContext, boolean includeDataRefs) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressOrSymbol == null) return "Address or symbol is required";
        try {
            Address addr = resolveAddressOrSymbol(program, addressOrSymbol);
            if (addr == null) return "Invalid address or symbol: " + addressOrSymbol;
            
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(addr);
            FunctionManager funcMgr = program.getFunctionManager();
            
            List<Function> referencerFunctions = new ArrayList<>();
            Set<Address> seen = new HashSet<>();
            
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                if (!includeDataRefs && ref.getReferenceType().isData()) continue;
                Address fromAddr = ref.getFromAddress();
                if (seen.contains(fromAddr)) continue;
                seen.add(fromAddr);
                
                Function func = funcMgr.getFunctionContaining(fromAddr);
                if (func != null && !referencerFunctions.contains(func)) {
                    referencerFunctions.add(func);
                }
            }
            
            int endIndex = Math.min(startIndex + maxReferencers, referencerFunctions.size());
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            StringBuilder result = new StringBuilder("{\"referencers\":[");
            
            try {
                for (int i = startIndex; i < endIndex; i++) {
                    if (i > startIndex) result.append(",");
                    Function referencer = referencerFunctions.get(i);
                    DecompileResults decompResults = decomp.decompileFunction(referencer, 30, new ConsoleTaskMonitor());
                    if (decompResults.decompileCompleted()) {
                        result.append("{\"function\":\"").append(referencer.getName()).append("\",");
                        result.append("\"address\":\"").append(referencer.getEntryPoint()).append("\"");
                        if (includeRefContext) {
                            String code = decompResults.getDecompiledFunction().getC();
                            result.append(",\"decompiledCode\":\"").append(escapeJson(code)).append("\"");
                        }
                        result.append("}");
                    }
                }
            } finally {
                decomp.dispose();
            }
            
            result.append("],\"totalCount\":").append(referencerFunctions.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Helper to resolve function by name or address
     */
    private Function resolveFunction(Program program, String functionNameOrAddress) {
        try {
            // Try as address first
            Address addr = program.getAddressFactory().getAddress(functionNameOrAddress);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func != null) return func;
            
            // Try as function name
            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator functions = funcMgr.getFunctions(true);
            while (functions.hasNext()) {
                Function f = functions.next();
                if (f.getName().equals(functionNameOrAddress)) {
                    return f;
                }
            }
        } catch (Exception e) {
            // Not an address, try as name
            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator functions = funcMgr.getFunctions(true);
            while (functions.hasNext()) {
                Function f = functions.next();
                if (f.getName().equals(functionNameOrAddress)) {
                    return f;
                }
            }
        }
        return null;
    }

    /**
     * Helper to resolve address or symbol
     */
    private Address resolveAddressOrSymbol(Program program, String addressOrSymbol) {
        try {
            // Try as address
            return program.getAddressFactory().getAddress(addressOrSymbol);
        } catch (Exception e) {
            // Try as symbol
            SymbolTable symbolTable = program.getSymbolTable();
            Symbol symbol = symbolTable.getSymbol(addressOrSymbol);
            if (symbol != null) {
                return symbol.getAddress();
            }
        }
        return null;
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
