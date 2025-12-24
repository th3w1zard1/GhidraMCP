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
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectLocator;
import ghidra.base.project.GhidraProject;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.lang.DefaultLanguageService;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageNotFoundException;
import java.io.File;
import org.json.JSONObject;
import org.json.JSONArray;

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

        // Consolidated endpoints for 17 parametric tools

        server.createContext("/get_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String identifier = qparams.get("identifier");
            String view = qparams.getOrDefault("view", "decompile");
            int offset = parseIntOrDefault(qparams.get("offset"), 1);
            int limit = parseIntOrDefault(qparams.get("limit"), 50);
            boolean includeCallers = Boolean.parseBoolean(qparams.getOrDefault("include_callers", "false"));
            boolean includeCallees = Boolean.parseBoolean(qparams.getOrDefault("include_callees", "false"));
            boolean includeComments = Boolean.parseBoolean(qparams.getOrDefault("include_comments", "false"));
            boolean includeIncomingRefs = Boolean.parseBoolean(qparams.getOrDefault("include_incoming_references", "true"));
            boolean includeRefContext = Boolean.parseBoolean(qparams.getOrDefault("include_reference_context", "true"));
            sendResponse(exchange, getFunction(identifier, view, offset, limit, includeCallers, includeCallees, includeComments, includeIncomingRefs, includeRefContext));
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String mode = qparams.getOrDefault("mode", "all");
            String query = qparams.get("query");
            String searchString = qparams.get("search_string");
            int minReferenceCount = parseIntOrDefault(qparams.get("min_reference_count"), 1);
            int startIndex = parseIntOrDefault(qparams.get("start_index"), 0);
            int maxCount = parseIntOrDefault(qparams.get("max_count"), 100);
            boolean filterDefaultNames = Boolean.parseBoolean(qparams.getOrDefault("filter_default_names", "true"));
            sendResponse(exchange, listFunctions(mode, query, searchString, minReferenceCount, startIndex, maxCount, filterDefaultNames));
        });

        server.createContext("/manage_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String action = params.get("action");
            String address = params.get("address");
            String functionIdentifier = params.get("function_identifier");
            String name = params.get("name");
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            String variableMappings = params.get("variable_mappings");
            String prototype = params.get("prototype");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");
            String datatypeMappings = params.get("datatype_mappings");
            String archiveName = params.get("archive_name");
            sendResponse(exchange, manageFunction(action, address, functionIdentifier, name, oldName, newName, variableMappings, prototype, variableName, newType, datatypeMappings, archiveName));
        });

        server.createContext("/get_call_graph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionIdentifier = qparams.get("function_identifier");
            String mode = qparams.getOrDefault("mode", "graph");
            int depth = parseIntOrDefault(qparams.get("depth"), 1);
            String direction = qparams.getOrDefault("direction", "callees");
            int maxDepth = parseIntOrDefault(qparams.get("max_depth"), 3);
            int startIndex = parseIntOrDefault(qparams.get("start_index"), 0);
            int maxCallers = parseIntOrDefault(qparams.get("max_callers"), 10);
            boolean includeCallContext = Boolean.parseBoolean(qparams.getOrDefault("include_call_context", "true"));
            String functionAddresses = qparams.get("function_addresses");
            sendResponse(exchange, getCallGraph(functionIdentifier, mode, depth, direction, maxDepth, startIndex, maxCallers, includeCallContext, functionAddresses));
        });

        server.createContext("/get_references", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String target = qparams.get("target");
            String mode = qparams.getOrDefault("mode", "both");
            String direction = qparams.getOrDefault("direction", "both");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 100);
            String libraryName = qparams.get("library_name");
            int startIndex = parseIntOrDefault(qparams.get("start_index"), 0);
            int maxReferencers = parseIntOrDefault(qparams.get("max_referencers"), 10);
            boolean includeRefContext = Boolean.parseBoolean(qparams.getOrDefault("include_ref_context", "true"));
            boolean includeDataRefs = Boolean.parseBoolean(qparams.getOrDefault("include_data_refs", "true"));
            sendResponse(exchange, getReferences(target, mode, direction, offset, limit, maxResults, libraryName, startIndex, maxReferencers, includeRefContext, includeDataRefs));
        });

        server.createContext("/analyze_data_flow", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("function_address");
            String startAddress = qparams.get("start_address");
            String variableName = qparams.get("variable_name");
            String direction = qparams.get("direction");
            sendResponse(exchange, analyzeDataFlow(functionAddress, startAddress, variableName, direction));
        });

        server.createContext("/search_constants", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String mode = qparams.getOrDefault("mode", "specific");
            String value = qparams.get("value");
            String minValue = qparams.get("min_value");
            String maxValue = qparams.get("max_value");
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 500);
            boolean includeSmallValues = Boolean.parseBoolean(qparams.getOrDefault("include_small_values", "false"));
            String minValueFilter = qparams.get("min_value_filter");
            int topN = parseIntOrDefault(qparams.get("top_n"), 50);
            sendResponse(exchange, searchConstants(mode, value, minValue, maxValue, maxResults, includeSmallValues, minValueFilter, topN));
        });

        server.createContext("/manage_strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String mode = qparams.getOrDefault("mode", "list");
            String pattern = qparams.get("pattern");
            String searchString = qparams.get("search_string");
            String filter = qparams.get("filter");
            int startIndex = parseIntOrDefault(qparams.get("start_index"), 0);
            int maxCount = parseIntOrDefault(qparams.get("max_count"), 100);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 2000);
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 100);
            boolean includeReferencingFunctions = Boolean.parseBoolean(qparams.getOrDefault("include_referencing_functions", "false"));
            sendResponse(exchange, manageStrings(mode, pattern, searchString, filter, startIndex, maxCount, offset, limit, maxResults, includeReferencingFunctions));
        });

        server.createContext("/inspect_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String mode = qparams.getOrDefault("mode", "blocks");
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, inspectMemory(mode, address, length, offset, limit));
        });

        server.createContext("/manage_bookmarks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String action = qparams.getOrDefault("action", "get");
            String address = qparams.get("address");
            String addressOrSymbol = qparams.get("address_or_symbol");
            String type = qparams.get("type");
            String category = qparams.get("category");
            String comment = qparams.get("comment");
            String searchText = qparams.get("search_text");
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 100);
            sendResponse(exchange, manageBookmarks(action, address, addressOrSymbol, type, category, comment, searchText, maxResults));
        });

        server.createContext("/manage_comments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String action = qparams.getOrDefault("action", "get");
            String address = qparams.get("address");
            String addressOrSymbol = qparams.get("address_or_symbol");
            String function = qparams.get("function");
            String functionNameOrAddress = qparams.get("function_name_or_address");
            int lineNumber = parseIntOrDefault(qparams.get("line_number"), 0);
            String comment = qparams.get("comment");
            String commentType = qparams.getOrDefault("comment_type", "eol");
            String start = qparams.get("start");
            String end = qparams.get("end");
            String commentTypes = qparams.get("comment_types");
            String searchText = qparams.get("search_text");
            String pattern = qparams.get("pattern");
            boolean caseSensitive = Boolean.parseBoolean(qparams.getOrDefault("case_sensitive", "false"));
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 100);
            boolean overrideMaxFunctionsLimit = Boolean.parseBoolean(qparams.getOrDefault("override_max_functions_limit", "false"));
            sendResponse(exchange, manageComments(action, address, addressOrSymbol, function, functionNameOrAddress, lineNumber, comment, commentType, start, end, commentTypes, searchText, pattern, caseSensitive, maxResults, overrideMaxFunctionsLimit));
        });

        server.createContext("/analyze_vtables", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String mode = qparams.getOrDefault("mode", "analyze");
            String vtableAddress = qparams.get("vtable_address");
            String functionAddress = qparams.get("function_address");
            int maxEntries = parseIntOrDefault(qparams.get("max_entries"), 200);
            sendResponse(exchange, analyzeVtables(mode, vtableAddress, functionAddress, maxEntries));
        });

        server.createContext("/manage_symbols", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String mode = qparams.getOrDefault("mode", "symbols");
            String address = qparams.get("address");
            String labelName = qparams.get("label_name");
            String newName = qparams.get("new_name");
            String libraryFilter = qparams.get("library_filter");
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 500);
            int startIndex = parseIntOrDefault(qparams.get("start_index"), 0);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            boolean groupByLibrary = Boolean.parseBoolean(qparams.getOrDefault("group_by_library", "true"));
            boolean includeExternal = Boolean.parseBoolean(qparams.getOrDefault("include_external", "false"));
            int maxCount = parseIntOrDefault(qparams.get("max_count"), 200);
            boolean filterDefaultNames = Boolean.parseBoolean(qparams.getOrDefault("filter_default_names", "true"));
            sendResponse(exchange, manageSymbols(mode, address, labelName, newName, libraryFilter, maxResults, startIndex, offset, limit, groupByLibrary, includeExternal, maxCount, filterDefaultNames));
        });

        server.createContext("/manage_structures", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String action = params.get("action");
            String cDefinition = params.get("c_definition");
            String headerContent = params.get("header_content");
            String structureName = params.get("structure_name");
            String name = params.get("name");
            int size = parseIntOrDefault(params.get("size"), 0);
            String type = params.getOrDefault("type", "structure");
            String category = params.getOrDefault("category", "/");
            boolean packed = Boolean.parseBoolean(params.getOrDefault("packed", "false"));
            String description = params.get("description");
            String fieldName = params.get("field_name");
            String dataType = params.get("data_type");
            Integer offset = params.get("offset") != null ? Integer.parseInt(params.get("offset")) : null;
            String comment = params.get("comment");
            String newDataType = params.get("new_data_type");
            String newFieldName = params.get("new_field_name");
            String newComment = params.get("new_comment");
            Integer newLength = params.get("new_length") != null ? Integer.parseInt(params.get("new_length")) : null;
            String addressOrSymbol = params.get("address_or_symbol");
            boolean clearExisting = Boolean.parseBoolean(params.getOrDefault("clear_existing", "true"));
            boolean force = Boolean.parseBoolean(params.getOrDefault("force", "false"));
            String nameFilter = params.get("name_filter");
            boolean includeBuiltIn = Boolean.parseBoolean(params.getOrDefault("include_built_in", "false"));
            sendResponse(exchange, manageStructures(action, cDefinition, headerContent, structureName, name, size, type, category, packed, description, fieldName, dataType, offset, comment, newDataType, newFieldName, newComment, newLength, addressOrSymbol, clearExisting, force, nameFilter, includeBuiltIn));
        });

        server.createContext("/manage_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String action = qparams.getOrDefault("action", "list");
            String archiveName = qparams.get("archive_name");
            String categoryPath = qparams.getOrDefault("category_path", "/");
            boolean includeSubcategories = Boolean.parseBoolean(qparams.getOrDefault("include_subcategories", "false"));
            int startIndex = parseIntOrDefault(qparams.get("start_index"), 0);
            int maxCount = parseIntOrDefault(qparams.get("max_count"), 100);
            String dataTypeString = qparams.get("data_type_string");
            String addressOrSymbol = qparams.get("address_or_symbol");
            sendResponse(exchange, manageDataTypes(action, archiveName, categoryPath, includeSubcategories, startIndex, maxCount, dataTypeString, addressOrSymbol));
        });

        server.createContext("/get_current_context", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String mode = qparams.getOrDefault("mode", "both");
            sendResponse(exchange, getCurrentContext(mode));
        });

        server.createContext("/manage_function_tags", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String function = qparams.get("function");
            String mode = qparams.getOrDefault("mode", "list");
            String tags = qparams.get("tags");
            sendResponse(exchange, manageFunctionTags(function, mode, tags));
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
                    // TODO: Full implementation
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

    /**
     * Get data type archives
     */
    private String getDataTypeArchives() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            StringBuilder result = new StringBuilder("{\"archives\":[");
            result.append("{\"name\":\"").append(dtm.getName()).append("\",");
            result.append("\"type\":\"PROGRAM\",");
            result.append("\"dataTypeCount\":").append(dtm.getDataTypeCount(true)).append(",");
            result.append("\"categoryCount\":").append(dtm.getCategoryCount()).append("}");
            result.append("]}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get data types from archive
     */
    private String getDataTypes(String archiveName, String categoryPath, boolean includeSubcategories, int startIndex, int maxCount) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (archiveName == null || archiveName.isEmpty()) return "Archive name is required";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            if (!dtm.getName().equals(archiveName)) {
                return "Archive not found: " + archiveName;
            }

            ghidra.program.model.data.Category category;
            if ("/".equals(categoryPath)) {
                category = dtm.getRootCategory();
            } else {
                ghidra.program.model.data.CategoryPath path = new ghidra.program.model.data.CategoryPath(categoryPath);
                category = dtm.getCategory(path);
                if (category == null) {
                    return "Category not found: " + categoryPath;
                }
            }

            List<DataType> dataTypes = new ArrayList<>();
            if (includeSubcategories) {
                addDataTypesRecursively(category, dataTypes);
            } else {
                for (DataType dt : category.getDataTypes()) {
                    dataTypes.add(dt);
                }
            }

            int endIndex = Math.min(startIndex + maxCount, dataTypes.size());
            StringBuilder result = new StringBuilder("{\"dataTypes\":[");
            for (int i = startIndex; i < endIndex; i++) {
                if (i > startIndex) result.append(",");
                DataType dt = dataTypes.get(i);
                result.append("{\"name\":\"").append(dt.getName()).append("\",");
                result.append("\"displayName\":\"").append(dt.getDisplayName()).append("\",");
                result.append("\"size\":").append(dt.getLength()).append("}");
            }
            result.append("],\"totalCount\":").append(dataTypes.size()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Add data types recursively
     */
    private void addDataTypesRecursively(ghidra.program.model.data.Category category, List<DataType> dataTypes) {
        for (DataType dt : category.getDataTypes()) {
            dataTypes.add(dt);
        }
        for (ghidra.program.model.data.Category subCategory : category.getCategories()) {
            addDataTypesRecursively(subCategory, dataTypes);
        }
    }

    /**
     * Get data type by string
     */
    private String getDataTypeByString(String dataTypeString, String archiveName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (dataTypeString == null || dataTypeString.isEmpty()) return "Data type string is required";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = dtm.getDataType(dataTypeString);
            if (dataType == null) {
                // Try parsing
                ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(dtm, dtm, null, ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);
                try {
                    dataType = parser.parse(dataTypeString);
                } catch (Exception e) {
                    return "Could not find or parse data type: " + dataTypeString;
                }
            }

            if (dataType == null) {
                return "Could not find data type: " + dataTypeString;
            }

            StringBuilder result = new StringBuilder("{\"name\":\"").append(dataType.getName()).append("\",");
            result.append("\"displayName\":\"").append(dataType.getDisplayName()).append("\",");
            result.append("\"size\":").append(dataType.getLength()).append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * List imports with pagination and optional grouping (enhanced version)
     */
    private String listImportsEnhanced(String libraryFilter, int maxResults, int startIndex, boolean groupByLibrary) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            List<Map<String, Object>> imports = new ArrayList<>();
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator externalSymbols = symbolTable.getExternalSymbols();

            while (externalSymbols.hasNext()) {
                Symbol symbol = externalSymbols.next();
                if (symbol.getSymbolType() != SymbolType.FUNCTION) continue;

                String libraryName = symbol.getParentNamespace().getName();
                if (libraryFilter != null && !libraryName.toLowerCase().contains(libraryFilter.toLowerCase())) {
                    continue;
                }

                Map<String, Object> importInfo = new HashMap<>();
                importInfo.put("name", symbol.getName());
                importInfo.put("address", symbol.getAddress().toString());
                importInfo.put("library", libraryName);
                imports.add(importInfo);
            }

            int endIndex = Math.min(startIndex + maxResults, imports.size());
            List<Map<String, Object>> paginated = startIndex < imports.size()
                ? imports.subList(startIndex, endIndex)
                : new ArrayList<>();

            StringBuilder result = new StringBuilder("{\"totalCount\":").append(imports.size()).append(",");
            result.append("\"startIndex\":").append(startIndex).append(",");
            result.append("\"returnedCount\":").append(paginated.size()).append(",");

            if (groupByLibrary) {
                Map<String, List<Map<String, Object>>> grouped = new HashMap<>();
                for (Map<String, Object> imp : paginated) {
                    String lib = (String) imp.get("library");
                    grouped.computeIfAbsent(lib, k -> new ArrayList<>()).add(imp);
                }
                result.append("\"libraries\":{");
                boolean first = true;
                for (Map.Entry<String, List<Map<String, Object>>> entry : grouped.entrySet()) {
                    if (!first) result.append(",");
                    first = false;
                    result.append("\"").append(entry.getKey()).append("\":[");
                    for (int i = 0; i < entry.getValue().size(); i++) {
                        if (i > 0) result.append(",");
                        Map<String, Object> imp = entry.getValue().get(i);
                        result.append("{\"name\":\"").append(imp.get("name")).append("\",");
                        result.append("\"address\":\"").append(imp.get("address")).append("\"}");
                    }
                    result.append("]");
                }
                result.append("}");
            } else {
                result.append("\"imports\":[");
                for (int i = 0; i < paginated.size(); i++) {
                    if (i > 0) result.append(",");
                    Map<String, Object> imp = paginated.get(i);
                    result.append("{\"name\":\"").append(imp.get("name")).append("\",");
                    result.append("\"address\":\"").append(imp.get("address")).append("\",");
                    result.append("\"library\":\"").append(imp.get("library")).append("\"}");
                }
                result.append("]");
            }
            result.append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * List exports with pagination (enhanced version)
     */
    private String listExportsEnhanced(int maxResults, int startIndex) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            List<Map<String, Object>> exports = new ArrayList<>();
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator externalSymbols = symbolTable.getExternalSymbols();

            // Also check for exported symbols in the global namespace
            SymbolIterator globalSymbols = symbolTable.getSymbols(GlobalNamespace.GLOBAL_NAMESPACE_ID);
            Set<String> seen = new HashSet<>();

            while (globalSymbols.hasNext()) {
                Symbol symbol = globalSymbols.next();
                if (symbol.getSymbolType() == SymbolType.FUNCTION || symbol.getSymbolType() == SymbolType.LABEL) {
                    String name = symbol.getName();
                    if (!seen.contains(name)) {
                        seen.add(name);
                        Map<String, Object> exportInfo = new HashMap<>();
                        exportInfo.put("name", name);
                        exportInfo.put("address", symbol.getAddress().toString());
                        exportInfo.put("type", symbol.getSymbolType().toString());
                        exports.add(exportInfo);
                    }
                }
            }

            int endIndex = Math.min(startIndex + maxResults, exports.size());
            List<Map<String, Object>> paginated = startIndex < exports.size()
                ? exports.subList(startIndex, endIndex)
                : new ArrayList<>();

            StringBuilder result = new StringBuilder("{\"totalCount\":").append(exports.size()).append(",");
            result.append("\"startIndex\":").append(startIndex).append(",");
            result.append("\"returnedCount\":").append(paginated.size()).append(",");
            result.append("\"exports\":[");
            for (int i = 0; i < paginated.size(); i++) {
                if (i > 0) result.append(",");
                Map<String, Object> exp = paginated.get(i);
                result.append("{\"name\":\"").append(exp.get("name")).append("\",");
                result.append("\"address\":\"").append(exp.get("address")).append("\",");
                result.append("\"type\":\"").append(exp.get("type")).append("\"}");
            }
            result.append("]}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get strings with pagination (enhanced version)
     */
    private String getStringsEnhanced(int startIndex, int maxCount, boolean includeReferencingFunctions) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            List<Map<String, Object>> strings = new ArrayList<>();
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            int currentIndex = 0;

            for (Data data : dataIterator) {
                if (!(data.getValue() instanceof String)) continue;

                if (currentIndex++ < startIndex) continue;
                if (strings.size() >= maxCount) break;

                Map<String, Object> stringInfo = new HashMap<>();
                stringInfo.put("address", data.getAddress().toString());
                stringInfo.put("value", data.getValue().toString());
                stringInfo.put("length", data.getLength());

                if (includeReferencingFunctions) {
                    List<String> refFunctions = new ArrayList<>();
                    ReferenceManager refMgr = program.getReferenceManager();
                    ReferenceIterator refs = refMgr.getReferencesTo(data.getAddress());
                    int refCount = 0;
                    while (refs.hasNext() && refCount < 100) {
                        Reference ref = refs.next();
                        Function func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            String funcName = func.getName();
                            if (!refFunctions.contains(funcName)) {
                                refFunctions.add(funcName);
                                refCount++;
                            }
                        }
                    }
                    stringInfo.put("referencingFunctions", refFunctions);
                }

                strings.add(stringInfo);
            }

            StringBuilder result = new StringBuilder("{\"startIndex\":").append(startIndex).append(",");
            result.append("\"requestedCount\":").append(maxCount).append(",");
            result.append("\"actualCount\":").append(strings.size()).append(",");
            result.append("\"nextStartIndex\":").append(startIndex + strings.size()).append(",");
            result.append("\"strings\":[");
            for (int i = 0; i < strings.size(); i++) {
                if (i > 0) result.append(",");
                Map<String, Object> str = strings.get(i);
                result.append("{\"address\":\"").append(str.get("address")).append("\",");
                result.append("\"value\":\"").append(escapeJsonString((String) str.get("value"))).append("\",");
                result.append("\"length\":").append(str.get("length"));
                if (includeReferencingFunctions && str.containsKey("referencingFunctions")) {
                    result.append(",\"referencingFunctions\":[");
                    @SuppressWarnings("unchecked")
                    List<String> refs = (List<String>) str.get("referencingFunctions");
                    for (int j = 0; j < refs.size(); j++) {
                        if (j > 0) result.append(",");
                        result.append("\"").append(refs.get(j)).append("\"");
                    }
                    result.append("]");
                }
                result.append("}");
            }
            result.append("]}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Escape JSON string (helper method)
     */
    private String escapeJsonString(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    /**
     * Get decompilation with line range support (enhanced version)
     */
    private String getDecompilationEnhanced(String functionNameOrAddress, int offset, int limit,
            boolean includeCallers, boolean includeCallees, boolean includeComments,
            boolean includeIncomingReferences, boolean includeReferenceContext) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            Function function = null;
            if (functionNameOrAddress != null && !functionNameOrAddress.isEmpty()) {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionNameOrAddress);
                    function = program.getFunctionManager().getFunctionAt(addr);
                } catch (Exception e) {
                    function = program.getFunctionManager().getFunction(functionNameOrAddress);
                }
            }

            if (function == null) {
                return "Function not found: " + functionNameOrAddress;
            }

            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(function, 30, null);

            if (results == null || !results.decompileCompleted()) {
                return "Decompilation failed for function: " + function.getName();
            }

            String decompiledCode = results.getDecompiledFunction().getC();
            String[] lines = decompiledCode.split("\n");

            int startLine = Math.max(0, offset - 1);
            int endLine = Math.min(lines.length, startLine + limit);

            StringBuilder result = new StringBuilder("{\"function\":\"").append(function.getName()).append("\",");
            result.append("\"address\":\"").append(function.getEntryPoint().toString()).append("\",");
            result.append("\"totalLines\":").append(lines.length).append(",");
            result.append("\"offset\":").append(offset).append(",");
            result.append("\"limit\":").append(limit).append(",");
            result.append("\"code\":\"");
            for (int i = startLine; i < endLine; i++) {
                if (i > startLine) result.append("\\n");
                result.append(escapeJsonString(lines[i]));
            }
            result.append("\"");

            if (includeCallers) {
                List<String> callers = new ArrayList<>();
                Function[] callingFunctions = function.getCallingFunctions(TaskMonitor.DUMMY);
                for (Function caller : callingFunctions) {
                    callers.add(caller.getName() + " (" + caller.getEntryPoint().toString() + ")");
                }
                result.append(",\"callers\":[");
                for (int i = 0; i < callers.size(); i++) {
                    if (i > 0) result.append(",");
                    result.append("\"").append(callers.get(i)).append("\"");
                }
                result.append("]");
            }

            if (includeCallees) {
                List<String> callees = new ArrayList<>();
                Function[] calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
                for (Function callee : calledFunctions) {
                    callees.add(callee.getName() + " (" + callee.getEntryPoint().toString() + ")");
                }
                result.append(",\"callees\":[");
                for (int i = 0; i < callees.size(); i++) {
                    if (i > 0) result.append(",");
                    result.append("\"").append(callees.get(i)).append("\"");
                }
                result.append("]");
            }

            result.append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Set decompilation comment (enhanced version)
     */
    private String setDecompilationCommentEnhanced(String functionNameOrAddress, int lineNumber, String comment, String commentType) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            Function function = null;
            if (functionNameOrAddress != null && !functionNameOrAddress.isEmpty()) {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionNameOrAddress);
                    function = program.getFunctionManager().getFunctionAt(addr);
                } catch (Exception e) {
                    function = program.getFunctionManager().getFunction(functionNameOrAddress);
                }
            }

            if (function == null) {
                return "Function not found: " + functionNameOrAddress;
            }

            // This is a simplified implementation - full implementation would need to map line numbers to addresses
            int txId = program.startTransaction("Set decompilation comment");
            try {
                // For now, set comment at function entry point
                program.getListing().setComment(function.getEntryPoint(),
                    "pre".equals(commentType) ? CodeUnit.PRE_COMMENT : CodeUnit.EOL_COMMENT, comment);
                program.endTransaction(txId, true);
                return "{\"success\":true,\"message\":\"Comment set at function entry point\"}";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error: " + e.getMessage();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get call tree (enhanced version)
     */
    private String getCallTreeEnhanced(String functionAddress, String direction, int maxDepth) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            Function function = null;
            if (functionAddress != null && !functionAddress.isEmpty()) {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    function = program.getFunctionManager().getFunctionAt(addr);
                } catch (Exception e) {
                    function = program.getFunctionManager().getFunction(functionAddress);
                }
            }

            if (function == null) {
                return "Function not found: " + functionAddress;
            }

            StringBuilder result = new StringBuilder("{\"function\":\"").append(function.getName()).append("\",");
            result.append("\"address\":\"").append(function.getEntryPoint().toString()).append("\",");
            result.append("\"direction\":\"").append(direction).append("\",");
            result.append("\"maxDepth\":").append(maxDepth).append(",");

            if ("callers".equals(direction)) {
                result.append("\"tree\":");
                buildCallerTreeRecursive(function, result, 0, maxDepth, new HashSet<>());
            } else {
                result.append("\"tree\":");
                buildCalleeTreeRecursive(function, result, 0, maxDepth, new HashSet<>());
            }

            result.append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Build caller tree recursively
     */
    private void buildCallerTreeRecursive(Function function, StringBuilder result, int depth, int maxDepth, Set<String> visited) {
        if (depth >= maxDepth) {
            result.append("null");
            return;
        }

        String funcKey = function.getEntryPoint().toString();
        if (visited.contains(funcKey)) {
            result.append("{\"name\":\"").append(function.getName()).append("\",\"cycle\":true}");
            return;
        }
        visited.add(funcKey);

        Function[] callers = function.getCallingFunctions(TaskMonitor.DUMMY);
        result.append("{\"name\":\"").append(function.getName()).append("\",");
        result.append("\"address\":\"").append(function.getEntryPoint().toString()).append("\",");
        result.append("\"callers\":[");
        for (int i = 0; i < callers.length; i++) {
            if (i > 0) result.append(",");
            buildCallerTreeRecursive(callers[i], result, depth + 1, maxDepth, new HashSet<>(visited));
        }
        result.append("]}");
    }

    /**
     * Build callee tree recursively
     */
    private void buildCalleeTreeRecursive(Function function, StringBuilder result, int depth, int maxDepth, Set<String> visited) {
        if (depth >= maxDepth) {
            result.append("null");
            return;
        }

        String funcKey = function.getEntryPoint().toString();
        if (visited.contains(funcKey)) {
            result.append("{\"name\":\"").append(function.getName()).append("\",\"cycle\":true}");
            return;
        }
        visited.add(funcKey);

        Function[] callees = function.getCalledFunctions(TaskMonitor.DUMMY);
        result.append("{\"name\":\"").append(function.getName()).append("\",");
        result.append("\"address\":\"").append(function.getEntryPoint().toString()).append("\",");
        result.append("\"callees\":[");
        for (int i = 0; i < callees.length; i++) {
            if (i > 0) result.append(",");
            buildCalleeTreeRecursive(callees[i], result, depth + 1, maxDepth, new HashSet<>(visited));
        }
        result.append("]}");
    }

    /**
     * Parse C structure
     */
    private String parseCStructure(String cDefinition, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (cDefinition == null || cDefinition.isEmpty()) return "C definition is required";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CParser parser = new CParser(dtm);

            int txId = program.startTransaction("Parse C Structure");
            try {
                DataType dt = parser.parse(cDefinition);
                if (dt == null) {
                    throw new Exception("Failed to parse structure definition");
                }

                CategoryPath catPath = new CategoryPath(category);
                Category cat = dtm.createCategory(catPath);

                DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                if (cat != null && !resolved.getCategoryPath().equals(catPath)) {
                    resolved.setName(resolved.getName());
                    cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                }

                program.endTransaction(txId, true);

                StringBuilder result = new StringBuilder("{\"success\":true,\"name\":\"").append(resolved.getName()).append("\",");
                result.append("\"size\":").append(resolved.getLength()).append("}");
                return result.toString();
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error: " + e.getMessage();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Validate C structure
     */
    private String validateCStructure(String cDefinition) {
        if (cDefinition == null || cDefinition.isEmpty()) return "C definition is required";
        try {
            DataTypeManager tempDtm = new StandAloneDataTypeManager("temp");
            CParser parser = new CParser(tempDtm);

            try {
                DataType dt = parser.parse(cDefinition);
                if (dt == null) {
                    return "{\"valid\":false,\"error\":\"Invalid structure definition\"}";
                }

                StringBuilder result = new StringBuilder("{\"valid\":true,\"parsedType\":\"").append(dt.getName()).append("\",");
                result.append("\"displayName\":\"").append(dt.getDisplayName()).append("\",");
                result.append("\"size\":").append(dt.getLength());

                if (dt instanceof Structure) {
                    Structure struct = (Structure) dt;
                    result.append(",\"fieldCount\":").append(struct.getNumComponents()).append(",\"isUnion\":false");
                } else if (dt instanceof Union) {
                    Union union = (Union) dt;
                    result.append(",\"fieldCount\":").append(union.getNumComponents()).append(",\"isUnion\":true");
                }

                result.append("}");
                return result.toString();
            } catch (Exception e) {
                return "{\"valid\":false,\"error\":\"" + escapeJsonString(e.getMessage()) + "\"}";
            } finally {
                tempDtm.close();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Create structure
     */
    private String createStructure(String name, int size, String type, String category, boolean packed, String description) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Structure name is required";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath catPath = new CategoryPath(category);

            int txId = program.startTransaction("Create Structure");
            try {
                dtm.createCategory(catPath);

                Composite composite;
                if ("union".equalsIgnoreCase(type)) {
                    composite = new UnionDataType(catPath, name, dtm);
                } else {
                    composite = new StructureDataType(catPath, name, size, dtm);
                    if (packed && composite instanceof Structure) {
                        ((Structure) composite).setPackingEnabled(true);
                    }
                }

                if (description != null) {
                    composite.setDescription(description);
                }

                DataType resolved = dtm.addDataType(composite, DataTypeConflictHandler.REPLACE_HANDLER);

                program.endTransaction(txId, true);

                StringBuilder result = new StringBuilder("{\"success\":true,\"name\":\"").append(resolved.getName()).append("\",");
                result.append("\"size\":").append(resolved.getLength()).append(",\"type\":\"").append(type).append("\"}");
                return result.toString();
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error: " + e.getMessage();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Add structure field
     */
    private String addStructureField(String structureName, String fieldName, String dataType, Integer offset, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || fieldName == null || dataType == null) {
            return "Structure name, field name, and data type are required";
        }
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = dtm.getDataType(structureName);
            if (dt == null || !(dt instanceof Composite)) {
                return "Structure not found: " + structureName;
            }

            Composite composite = (Composite) dt;
            ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(dtm, dtm, null, ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);
            DataType fieldType = parser.parse(dataType);
            if (fieldType == null) {
                return "Invalid data type: " + dataType;
            }

            int txId = program.startTransaction("Add Structure Field");
            try {
                if (composite instanceof Structure) {
                    Structure struct = (Structure) composite;
                    if (offset != null) {
                        struct.insertAtOffset(offset, fieldType, fieldType.getLength(), fieldName, comment);
                    } else {
                        struct.add(fieldType, fieldName, comment);
                    }
                } else if (composite instanceof Union) {
                    Union union = (Union) composite;
                    union.add(fieldType, fieldName, comment);
                }

                program.endTransaction(txId, true);
                return "{\"success\":true,\"message\":\"Field added successfully\"}";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error: " + e.getMessage();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Modify structure field
     */
    private String modifyStructureField(String structureName, String fieldName, Integer offset,
            String newDataType, String newFieldName, String newComment, Integer newLength) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null) return "Structure name is required";
        if (fieldName == null && offset == null) return "Either field name or offset is required";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = dtm.getDataType(structureName);
            if (dt == null || !(dt instanceof Structure)) {
                return "Structure not found: " + structureName;
            }

            Structure struct = (Structure) dt;
            DataTypeComponent targetComponent = null;
            int targetOrdinal = -1;

            if (offset != null) {
                targetComponent = struct.getComponentAt(offset);
                if (targetComponent == null) {
                    return "No field found at offset " + offset;
                }
                targetOrdinal = targetComponent.getOrdinal();
            } else {
                for (int i = 0; i < struct.getNumComponents(); i++) {
                    DataTypeComponent comp = struct.getComponent(i);
                    if (fieldName.equals(comp.getFieldName())) {
                        targetComponent = comp;
                        targetOrdinal = i;
                        break;
                    }
                }
                if (targetComponent == null) {
                    return "Field not found: " + fieldName;
                }
            }

            DataType replacementDataType = targetComponent.getDataType();
            String replacementFieldName = targetComponent.getFieldName();
            String replacementComment = targetComponent.getComment();
            int replacementLength = targetComponent.getLength();

            if (newDataType != null) {
                ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(dtm, dtm, null, ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);
                replacementDataType = parser.parse(newDataType);
                if (newLength == null) {
                    replacementLength = replacementDataType.getLength();
                }
            }
            if (newFieldName != null) replacementFieldName = newFieldName;
            if (newComment != null) replacementComment = newComment;
            if (newLength != null) replacementLength = newLength;

            int txId = program.startTransaction("Modify Structure Field");
            try {
                struct.replace(targetOrdinal, replacementDataType, replacementLength, replacementFieldName, replacementComment);
                program.endTransaction(txId, true);
                return "{\"success\":true,\"message\":\"Field modified successfully\"}";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error: " + e.getMessage();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Modify structure from C
     */
    private String modifyStructureFromC(String cDefinition) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (cDefinition == null || cDefinition.isEmpty()) return "C definition is required";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CParser parser = new CParser(dtm);
            DataType parsedDt = parser.parse(cDefinition);

            if (parsedDt == null || !(parsedDt instanceof Structure)) {
                return "Failed to parse structure definition or not a structure";
            }

            Structure parsedStruct = (Structure) parsedDt;
            String structureName = parsedStruct.getName();
            DataType existingDt = dtm.getDataType(structureName);

            if (existingDt == null || !(existingDt instanceof Structure)) {
                return "Structure not found: " + structureName;
            }

            Structure existingStruct = (Structure) existingDt;

            int txId = program.startTransaction("Modify Structure from C");
            try {
                while (existingStruct.getNumComponents() > 0) {
                    existingStruct.delete(0);
                }

                for (int i = 0; i < parsedStruct.getNumComponents(); i++) {
                    DataTypeComponent comp = parsedStruct.getComponent(i);
                    DataType fieldType = dtm.resolve(comp.getDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
                    existingStruct.add(fieldType, comp.getFieldName(), comp.getComment());
                }

                if (parsedStruct.getDescription() != null) {
                    existingStruct.setDescription(parsedStruct.getDescription());
                }
                existingStruct.setPackingEnabled(parsedStruct.isPackingEnabled());

                program.endTransaction(txId, true);
                return "{\"success\":true,\"message\":\"Structure modified successfully\"}";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error: " + e.getMessage();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get structure info
     */
    private String getStructureInfo(String structureName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = dtm.getDataType(structureName);
            if (dt == null || !(dt instanceof Composite)) {
                return "Structure not found: " + structureName;
            }

            Composite composite = (Composite) dt;
            StringBuilder result = new StringBuilder("{\"name\":\"").append(composite.getName()).append("\",");
            result.append("\"size\":").append(composite.getLength()).append(",");
            result.append("\"isUnion\":").append(dt instanceof Union).append(",");
            result.append("\"numComponents\":").append(composite.getNumComponents()).append(",");
            result.append("\"fields\":[");

            for (int i = 0; i < composite.getNumComponents(); i++) {
                if (i > 0) result.append(",");
                DataTypeComponent comp = composite.getComponent(i);
                result.append("{\"ordinal\":").append(comp.getOrdinal()).append(",");
                result.append("\"offset\":").append(comp.getOffset()).append(",");
                result.append("\"length\":").append(comp.getLength()).append(",");
                result.append("\"fieldName\":\"").append(comp.getFieldName() != null ? comp.getFieldName() : "").append("\",");
                result.append("\"dataType\":\"").append(comp.getDataType().getDisplayName()).append("\"}");
            }

            result.append("]}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * List structures
     */
    private String listStructures(String category, String nameFilter, boolean includeBuiltIn) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            List<Map<String, Object>> structures = new ArrayList<>();
            Iterator<DataType> iter = dtm.getAllDataTypes();

            while (iter.hasNext()) {
                DataType dt = iter.next();
                if (!(dt instanceof Composite)) continue;

                if (!includeBuiltIn && dt.getSourceArchive().getName().equals("BuiltInTypes")) {
                    continue;
                }

                if (category != null && !dt.getCategoryPath().getPath().startsWith(category)) {
                    continue;
                }

                if (nameFilter != null && !dt.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
                    continue;
                }

                Map<String, Object> structInfo = new HashMap<>();
                structInfo.put("name", dt.getName());
                structInfo.put("size", dt.getLength());
                structInfo.put("isUnion", dt instanceof Union);
                structInfo.put("numComponents", ((Composite) dt).getNumComponents());
                structures.add(structInfo);
            }

            StringBuilder result = new StringBuilder("{\"count\":").append(structures.size()).append(",\"structures\":[");
            for (int i = 0; i < structures.size(); i++) {
                if (i > 0) result.append(",");
                Map<String, Object> struct = structures.get(i);
                result.append("{\"name\":\"").append(struct.get("name")).append("\",");
                result.append("\"size\":").append(struct.get("size")).append(",");
                result.append("\"isUnion\":").append(struct.get("isUnion")).append(",");
                result.append("\"numComponents\":").append(struct.get("numComponents")).append("}");
            }
            result.append("]}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Apply structure
     */
    private String applyStructure(String structureName, String addressOrSymbol, boolean clearExisting) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || addressOrSymbol == null) {
            return "Structure name and address are required";
        }
        try {
            Address address;
            try {
                address = program.getAddressFactory().getAddress(addressOrSymbol);
            } catch (Exception e) {
                Symbol symbol = program.getSymbolTable().getSymbol(addressOrSymbol);
                if (symbol == null) return "Address or symbol not found: " + addressOrSymbol;
                address = symbol.getAddress();
            }

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = dtm.getDataType(structureName);
            if (dt == null || !(dt instanceof Composite)) {
                return "Structure not found: " + structureName;
            }

            if (!program.getMemory().contains(address)) {
                return "Address is not in valid memory: " + address.toString();
            }

            int txId = program.startTransaction("Apply Structure");
            try {
                Listing listing = program.getListing();
                if (clearExisting) {
                    Data existingData = listing.getDataAt(address);
                    if (existingData != null) {
                        listing.clearCodeUnits(address, address.add(existingData.getLength() - 1), false);
                    }
                }

                listing.createData(address, dt);
                program.endTransaction(txId, true);
                return "{\"success\":true,\"message\":\"Structure applied successfully\"}";
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error: " + e.getMessage();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Delete structure
     */
    private String deleteStructure(String structureName, boolean force) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = dtm.getDataType(structureName);
            if (dt == null) {
                return "Structure not found: " + structureName;
            }

            // Check for references
            List<String> references = new ArrayList<>();
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function func = functions.next();
                if (func.getReturnType().isEquivalent(dt)) {
                    references.add(func.getName() + " (return type)");
                }
                for (Parameter param : func.getParameters()) {
                    if (param.getDataType().isEquivalent(dt)) {
                        references.add(func.getName() + " (parameter: " + param.getName() + ")");
                    }
                }
            }

            if (!references.isEmpty() && !force) {
                StringBuilder result = new StringBuilder("{\"canDelete\":false,\"references\":[");
                for (int i = 0; i < references.size(); i++) {
                    if (i > 0) result.append(",");
                    result.append("\"").append(references.get(i)).append("\"");
                }
                result.append("],\"warning\":\"Structure is referenced. Use force=true to delete anyway.\"}");
                return result.toString();
            }

            int txId = program.startTransaction("Delete Structure");
            try {
                boolean removed = dtm.remove(dt);
                program.endTransaction(txId, true);
                if (removed) {
                    return "{\"success\":true,\"message\":\"Structure deleted successfully\"}";
                } else {
                    return "Error: Failed to delete structure";
                }
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error: " + e.getMessage();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Parse C header
     */
    private String parseCHeader(String headerContent, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (headerContent == null || headerContent.isEmpty()) return "Header content is required";
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CParser parser = new CParser(dtm);
            CategoryPath catPath = new CategoryPath(category);
            dtm.createCategory(catPath);

            int txId = program.startTransaction("Parse C Header");
            List<String> createdTypes = new ArrayList<>();
            try {
                DataType dt = parser.parse(headerContent);
                if (dt != null) {
                    DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                    if (!resolved.getCategoryPath().equals(catPath)) {
                        resolved.setName(resolved.getName());
                        dtm.getCategory(catPath).moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                    }
                    createdTypes.add(resolved.getName());
                }

                program.endTransaction(txId, true);
                StringBuilder result = new StringBuilder("{\"success\":true,\"createdCount\":").append(createdTypes.size()).append(",\"createdTypes\":[");
                for (int i = 0; i < createdTypes.size(); i++) {
                    if (i > 0) result.append(",");
                    result.append("\"").append(createdTypes.get(i)).append("\"");
                }
                result.append("]}");
                return result.toString();
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error: " + e.getMessage();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private Address parseAddress(String addressStr) {
        if (addressStr == null || addressStr.trim().isEmpty()) {
            return null;
        }
        try {
            Program program = getCurrentProgram();
            if (program == null) return null;
            return program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return null;
        }
    }

    private Function getFunction(String identifier) {
        if (identifier == null || identifier.trim().isEmpty()) {
            return null;
        }
        Program program = getCurrentProgram();
        if (program == null) return null;

        try {
            // Try to parse as address first
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                return program.getFunctionManager().getFunctionAt(addr);
            }
        } catch (Exception e) {
            // Not a valid address, try as function name
        }

        // Try to find by name
        FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (identifier.equals(func.getName())) {
                return func;
            }
        }

        return null;
    }

    // ----------------------------------------------------------------------------------
    // Consolidated tool methods for 17 parametric tools
    // ----------------------------------------------------------------------------------

    private String getFunction(String identifier, String view, int offset, int limit, boolean includeCallers, boolean includeCallees, boolean includeComments, boolean includeIncomingRefs, boolean includeRefContext) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            if ("decompile".equals(view)) {
                return decompileFunction(identifier, offset, limit, includeCallers, includeCallees, includeComments, includeIncomingRefs, includeRefContext);
            } else if ("disassemble".equals(view)) {
                return disassembleFunction(identifier);
            } else if ("info".equals(view)) {
                return getFunctionInfo(identifier);
            } else if ("calls".equals(view)) {
                return listFunctionCalls(identifier);
            }

            return "Invalid view: " + view;

        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    private String listFunctions(String mode, String query, String searchString, int minReferenceCount, int startIndex, int maxCount, boolean filterDefaultNames) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            if ("all".equals(mode)) {
                return getAllFunctionNames(startIndex, maxCount);
            } else if ("search".equals(mode) && query != null) {
                return searchFunctionsByName(query, startIndex, maxCount);
            } else if ("similarity".equals(mode) && searchString != null) {
                return getFunctionsBySimilarity(searchString, startIndex, maxCount, filterDefaultNames);
            } else if ("undefined".equals(mode)) {
                return getUndefinedFunctionCandidates(startIndex, maxCount, minReferenceCount);
            } else if ("count".equals(mode)) {
                return getFunctionCount(filterDefaultNames);
            }

            return "Invalid list mode: " + mode;

        } catch (Exception e) {
            return "Error listing functions: " + e.getMessage();
        }
    }

    private String manageFunction(String action, String address, String functionIdentifier, String name, String oldName, String newName, String variableMappings, String prototype, String variableName, String newType, String datatypeMappings, String archiveName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            if ("create".equals(action) && address != null && name != null) {
                return createFunction(address, name);
            } else if ("rename_function".equals(action) && functionIdentifier != null && newName != null) {
                return renameFunctionByAddress(functionIdentifier, newName);
            } else if ("rename_variable".equals(action) && functionIdentifier != null && oldName != null && newName != null) {
                return renameVariableInFunction(functionIdentifier, oldName, newName);
            } else if ("set_prototype".equals(action) && functionIdentifier != null && prototype != null) {
                return setFunctionPrototype(functionIdentifier, prototype);
            } else if ("set_variable_type".equals(action) && functionIdentifier != null && variableName != null && newType != null) {
                return setLocalVariableType(functionIdentifier, variableName, newType);
            } else if ("change_datatypes".equals(action) && functionIdentifier != null && datatypeMappings != null) {
                return changeVariableDataTypes(functionIdentifier, datatypeMappings, archiveName);
            }

            return "Invalid manage action: " + action;

        } catch (Exception e) {
            return "Error managing function: " + e.getMessage();
        }
    }

    private String getCallGraph(String functionIdentifier, String mode, int depth, String direction, int maxDepth, int startIndex, int maxCallers, boolean includeCallContext, String functionAddresses) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            if ("graph".equals(mode)) {
                return getCallGraph(functionIdentifier, depth);
            } else if ("tree".equals(mode)) {
                return getCallTree(functionIdentifier, direction, maxDepth);
            } else if ("callers".equals(mode)) {
                return getFunctionCallers(functionIdentifier);
            } else if ("callees".equals(mode)) {
                return getFunctionCallees(functionIdentifier);
            } else if ("callers_decomp".equals(mode)) {
                return getCallersDecompiled(functionIdentifier, startIndex, maxCallers, includeCallContext);
            } else if ("common_callers".equals(mode) && functionAddresses != null) {
                return findCommonCallers(functionAddresses);
            }

            return "Invalid call graph mode: " + mode;

        } catch (Exception e) {
            return "Error getting call graph: " + e.getMessage();
        }
    }

    private String getReferences(String target, String mode, String direction, int offset, int limit, int maxResults, String libraryName, int startIndex, int maxReferencers, boolean includeRefContext, boolean includeDataRefs) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            Address addr = parseAddress(target);
            if (addr == null) return "Invalid address: " + target;

            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refs = null;

            if ("to".equals(mode)) {
                refs = refMgr.getReferencesTo(addr);
            } else if ("from".equals(mode)) {
                refs = refMgr.getReferencesFrom(addr);
            } else {
                // both - combine
                List<Reference> allRefs = new ArrayList<>();
                ReferenceIterator toRefs = refMgr.getReferencesTo(addr);
                while (toRefs.hasNext()) allRefs.add(toRefs.next());
                ReferenceIterator fromRefs = refMgr.getReferencesFrom(addr);
                while (fromRefs.hasNext()) allRefs.add(fromRefs.next());
                // Apply pagination to combined list
                int endIndex = Math.min(offset + limit, allRefs.size());
                List<Reference> pagedRefs = allRefs.subList(Math.min(offset, allRefs.size()), endIndex);

                JSONArray result = new JSONArray();
                for (Reference ref : pagedRefs) {
                    JSONObject refObj = new JSONObject();
                    refObj.put("address", ref.getFromAddress().toString());
                    refObj.put("toAddress", ref.getToAddress().toString());
                    refObj.put("type", ref.getReferenceType().toString());
                    result.put(refObj);
                }
                return "{\"count\":" + allRefs.size() + ",\"references\":" + result.toString() + "}";
            }

            JSONArray result = new JSONArray();
            int count = 0;
            while (refs.hasNext() && count < maxResults) {
                Reference ref = refs.next();
                if (count >= offset) {
                    JSONObject refObj = new JSONObject();
                    refObj.put("address", ref.getFromAddress().toString());
                    refObj.put("toAddress", ref.getToAddress().toString());
                    refObj.put("type", ref.getReferenceType().toString());
                    result.put(refObj);
                }
                count++;
            }
            return "{\"count\":" + count + ",\"references\":" + result.toString() + "}";

        } catch (Exception e) {
            return "Error getting references: " + e.getMessage();
        }
    }

    private String analyzeDataFlow(String functionAddress, String startAddress, String variableName, String direction) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            Function func = getFunctionByAddress(functionAddress);
            if (func == null) return "Function not found: " + functionAddress;

            Address startAddr = parseAddress(startAddress);
            if (startAddr == null) return "Invalid start address: " + startAddress;

            // This is a simplified implementation - full data flow analysis would be much more complex
            JSONArray result = new JSONArray();

            if ("backward".equals(direction)) {
                // Trace backward - find where the value at startAddress comes from
                JSONObject flow = new JSONObject();
                flow.put("direction", "backward");
                flow.put("startAddress", startAddress);
                flow.put("message", "Backward data flow analysis not fully implemented");
                result.put(flow);
            } else if ("forward".equals(direction)) {
                // Trace forward - find where the value at startAddress is used
                JSONObject flow = new JSONObject();
                flow.put("direction", "forward");
                flow.put("startAddress", startAddress);
                flow.put("message", "Forward data flow analysis not fully implemented");
                result.put(flow);
            } else if ("variable_accesses".equals(direction) && variableName != null) {
                // Find all accesses to a specific variable
                JSONObject accesses = new JSONObject();
                accesses.put("variable", variableName);
                accesses.put("message", "Variable access analysis not fully implemented");
                result.put(accesses);
            }

            return result.toString();

        } catch (Exception e) {
            return "Error analyzing data flow: " + e.getMessage();
        }
    }

    private String searchConstants(String mode, String value, String minValue, String maxValue, int maxResults, boolean includeSmallValues, String minValueFilter, int topN) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            JSONArray result = new JSONArray();

            if ("specific".equals(mode) && value != null) {
                // Find specific constant value
                long constValue = parseLong(value);
                // This is simplified - would need to search through instructions
                JSONObject constObj = new JSONObject();
                constObj.put("value", constValue);
                constObj.put("message", "Specific constant search not fully implemented");
                result.put(constObj);
            } else if ("range".equals(mode) && minValue != null && maxValue != null) {
                // Find constants in range
                long min = parseLong(minValue);
                long max = parseLong(maxValue);
                JSONObject rangeObj = new JSONObject();
                rangeObj.put("minValue", min);
                rangeObj.put("maxValue", max);
                rangeObj.put("message", "Range constant search not fully implemented");
                result.put(rangeObj);
            } else if ("common".equals(mode)) {
                // Find most common constants
                JSONObject commonObj = new JSONObject();
                commonObj.put("message", "Common constants analysis not fully implemented");
                result.put(commonObj);
            }

            return result.toString();

        } catch (Exception e) {
            return "Error searching constants: " + e.getMessage();
        }
    }

    private String manageStrings(String mode, String pattern, String searchString, String filter, int startIndex, int maxCount, int offset, int limit, int maxResults, boolean includeReferencingFunctions) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            JSONArray result = new JSONArray();

            if ("list".equals(mode)) {
                // List strings with pagination
                Listing listing = program.getListing();
                AddressIterator addrIter = listing.getAddressIterator(true);
                int count = 0;
                int added = 0;

                while (addrIter.hasNext() && added < limit) {
                    Address addr = addrIter.next();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null && data.getDataType().getName().contains("string")) {
                        if (count >= offset) {
                            JSONObject strObj = new JSONObject();
                            strObj.put("address", addr.toString());
                            strObj.put("value", data.getValue());
                            result.put(strObj);
                            added++;
                        }
                        count++;
                    }
                }

                JSONObject response = new JSONObject();
                response.put("count", count);
                response.put("strings", result);
                return response.toString();

            } else if ("regex".equals(mode) && pattern != null) {
                // Search strings with regex
                JSONObject searchObj = new JSONObject();
                searchObj.put("pattern", pattern);
                searchObj.put("message", "Regex string search not fully implemented");
                result.put(searchObj);
                return result.toString();

            } else if ("count".equals(mode)) {
                // Count strings
                return "{\"count\":0,\"message\":\"String count not fully implemented\"}";

            } else if ("similarity".equals(mode) && searchString != null) {
                // Find similar strings
                JSONObject similarityObj = new JSONObject();
                similarityObj.put("searchString", searchString);
                similarityObj.put("message", "String similarity search not fully implemented");
                result.put(similarityObj);
                return result.toString();
            }

            return result.toString();

        } catch (Exception e) {
            return "Error managing strings: " + e.getMessage();
        }
    }

    private String inspectMemory(String mode, String address, int length, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            JSONArray result = new JSONArray();

            if ("blocks".equals(mode)) {
                // List memory blocks
                Memory memory = program.getMemory();
                MemoryBlock[] blocks = memory.getBlocks();
                for (int i = offset; i < Math.min(offset + limit, blocks.length); i++) {
                    MemoryBlock block = blocks[i];
                    JSONObject blockObj = new JSONObject();
                    blockObj.put("name", block.getName());
                    blockObj.put("start", block.getStart().toString());
                    blockObj.put("end", block.getEnd().toString());
                    blockObj.put("size", block.getSize());
                    blockObj.put("read", block.isRead());
                    blockObj.put("write", block.isWrite());
                    blockObj.put("execute", block.isExecute());
                    result.put(blockObj);
                }

                JSONObject response = new JSONObject();
                response.put("count", blocks.length);
                response.put("blocks", result);
                return response.toString();

            } else if ("read".equals(mode) && address != null) {
                // Read memory at address
                Address addr = parseAddress(address);
                if (addr == null) return "Invalid address: " + address;

                Memory memory = program.getMemory();
                byte[] bytes = new byte[length];
                int bytesRead = memory.getBytes(addr, bytes);

                StringBuilder hexDump = new StringBuilder();
                for (int i = 0; i < bytesRead; i++) {
                    hexDump.append(String.format("%02X ", bytes[i]));
                    if ((i + 1) % 16 == 0) hexDump.append("\n");
                }

                JSONObject response = new JSONObject();
                response.put("address", address);
                response.put("length", bytesRead);
                response.put("hexDump", hexDump.toString().trim());
                return response.toString();

            } else if ("data_at".equals(mode) && address != null) {
                // Get data at address
                Address addr = parseAddress(address);
                if (addr == null) return "Invalid address: " + address;

                Listing listing = program.getListing();
                Data data = listing.getDefinedDataAt(addr);

                JSONObject response = new JSONObject();
                response.put("address", address);
                if (data != null) {
                    response.put("dataType", data.getDataType().getName());
                    response.put("value", data.getValue() != null ? data.getValue().toString() : "null");
                } else {
                    response.put("message", "No defined data at address");
                }
                return response.toString();

            } else if ("data_items".equals(mode)) {
                // List defined data items
                Listing listing = program.getListing();
                AddressIterator addrIter = listing.getAddressIterator(true);
                int count = 0;
                int added = 0;

                while (addrIter.hasNext() && added < limit) {
                    Address addr = addrIter.next();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        if (count >= offset) {
                            JSONObject dataObj = new JSONObject();
                            dataObj.put("address", addr.toString());
                            dataObj.put("dataType", data.getDataType().getName());
                            dataObj.put("value", data.getValue() != null ? data.getValue().toString() : "null");
                            result.put(dataObj);
                            added++;
                        }
                        count++;
                    }
                }

                JSONObject response = new JSONObject();
                response.put("count", count);
                response.put("dataItems", result);
                return response.toString();

            } else if ("segments".equals(mode)) {
                // List memory segments (same as blocks)
                return inspectMemory("blocks", null, 0, offset, limit);
            }

            return result.toString();

        } catch (Exception e) {
            return "Error inspecting memory: " + e.getMessage();
        }
    }

    private String manageBookmarks(String action, String address, String addressOrSymbol, String type, String category, String comment, String searchText, int maxResults) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            BookmarkManager bookmarkMgr = program.getBookmarkManager();

            if ("set".equals(action) && address != null && type != null && category != null && comment != null) {
                Address addr = parseAddress(address);
                if (addr == null) return "Invalid address: " + address;

                bookmarkMgr.setBookmark(addr, type, category, comment);
                return "Bookmark set successfully";

            } else if ("get".equals(action)) {
                JSONArray result = new JSONArray();

                if (address != null) {
                    Address addr = parseAddress(address);
                    if (addr != null) {
                        Bookmark[] bookmarks = bookmarkMgr.getBookmarks(addr);
                        for (Bookmark bookmark : bookmarks) {
                            JSONObject bmObj = new JSONObject();
                            bmObj.put("address", bookmark.getAddress().toString());
                            bmObj.put("type", bookmark.getTypeString());
                            bmObj.put("category", bookmark.getCategory());
                            bmObj.put("comment", bookmark.getComment());
                            result.put(bmObj);
                        }
                    }
                } else if (type != null) {
                    Bookmark[] bookmarks = bookmarkMgr.getBookmarks(type);
                    for (Bookmark bookmark : bookmarks) {
                        JSONObject bmObj = new JSONObject();
                        bmObj.put("address", bookmark.getAddress().toString());
                        bmObj.put("type", bookmark.getTypeString());
                        bmObj.put("category", bookmark.getCategory());
                        bmObj.put("comment", bookmark.getComment());
                        result.put(bmObj);
                    }
                }

                return result.toString();

            } else if ("search".equals(action) && searchText != null) {
                JSONArray result = new JSONArray();
                // Simplified search implementation
                JSONObject searchObj = new JSONObject();
                searchObj.put("searchText", searchText);
                searchObj.put("message", "Bookmark search not fully implemented");
                result.put(searchObj);
                return result.toString();

            } else if ("remove".equals(action) && addressOrSymbol != null && type != null && category != null) {
                Address addr = parseAddress(addressOrSymbol);
                if (addr != null) {
                    bookmarkMgr.removeBookmark(addr, type, category);
                    return "Bookmark removed successfully";
                }
                return "Invalid address: " + addressOrSymbol;

            } else if ("categories".equals(action)) {
                JSONArray result = new JSONArray();
                // Simplified categories implementation
                JSONObject catsObj = new JSONObject();
                catsObj.put("message", "Bookmark categories not fully implemented");
                result.put(catsObj);
                return result.toString();
            }

            return "Invalid bookmark action";

        } catch (Exception e) {
            return "Error managing bookmarks: " + e.getMessage();
        }
    }

    private String manageComments(String action, String address, String addressOrSymbol, String function, String functionNameOrAddress, int lineNumber, String comment, String commentType, String start, String end, String commentTypes, String searchText, String pattern, boolean caseSensitive, int maxResults, boolean overrideMaxFunctionsLimit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            Listing listing = program.getListing();

            if ("set".equals(action)) {
                if (address != null) {
                    Address addr = parseAddress(address);
                    if (addr == null) return "Invalid address: " + address;

                    CodeUnit cu = listing.getCodeUnitAt(addr);
                    if (cu != null) {
                        cu.setComment(CommentType.valueOf(commentType.toUpperCase()), comment);
                        return "Comment set successfully";
                    }
                } else if (function != null && lineNumber > 0) {
                    // Set comment on decompiled function line - simplified
                    return "Decompiler comment setting not fully implemented";
                }

            } else if ("get".equals(action)) {
                JSONArray result = new JSONArray();

                if (address != null) {
                    Address addr = parseAddress(address);
                    if (addr != null) {
                        CodeUnit cu = listing.getCodeUnitAt(addr);
                        if (cu != null) {
                            JSONObject commentObj = new JSONObject();
                            commentObj.put("address", address);
                            commentObj.put("comment", cu.getComment(CommentType.EOL));
                            result.put(commentObj);
                        }
                    }
                }

                return result.toString();

            } else if ("remove".equals(action)) {
                if (address != null) {
                    Address addr = parseAddress(address);
                    if (addr == null) return "Invalid address: " + address;

                    CodeUnit cu = listing.getCodeUnitAt(addr);
                    if (cu != null) {
                        cu.setComment(CommentType.valueOf(commentType.toUpperCase()), null);
                        return "Comment removed successfully";
                    }
                }

            } else if ("search".equals(action) && searchText != null) {
                JSONArray result = new JSONArray();
                // Simplified search implementation
                JSONObject searchObj = new JSONObject();
                searchObj.put("searchText", searchText);
                searchObj.put("message", "Comment search not fully implemented");
                result.put(searchObj);
                return result.toString();

            } else if ("search_decomp".equals(action) && pattern != null) {
                JSONArray result = new JSONArray();
                // Simplified decompiler search implementation
                JSONObject searchObj = new JSONObject();
                searchObj.put("pattern", pattern);
                searchObj.put("message", "Decompiler search not fully implemented");
                result.put(searchObj);
                return result.toString();
            }

            return "Invalid comment action";

        } catch (Exception e) {
            return "Error managing comments: " + e.getMessage();
        }
    }

    private String analyzeVtables(String mode, String vtableAddress, String functionAddress, int maxEntries) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            JSONArray result = new JSONArray();

            if ("analyze".equals(mode) && vtableAddress != null) {
                Address addr = parseAddress(vtableAddress);
                if (addr == null) return "Invalid vtable address: " + vtableAddress;

                JSONObject vtableObj = new JSONObject();
                vtableObj.put("address", vtableAddress);
                vtableObj.put("message", "Vtable analysis not fully implemented");
                result.put(vtableObj);

            } else if ("callers".equals(mode) && functionAddress != null) {
                JSONObject callersObj = new JSONObject();
                callersObj.put("function", functionAddress);
                callersObj.put("message", "Vtable callers analysis not fully implemented");
                result.put(callersObj);

            } else if ("containing".equals(mode) && functionAddress != null) {
                JSONObject containingObj = new JSONObject();
                containingObj.put("function", functionAddress);
                containingObj.put("message", "Vtable containing analysis not fully implemented");
                result.put(containingObj);
            }

            return result.toString();

        } catch (Exception e) {
            return "Error analyzing vtables: " + e.getMessage();
        }
    }

    private String manageSymbols(String mode, String address, String labelName, String newName, String libraryFilter, int maxResults, int startIndex, int offset, int limit, boolean groupByLibrary, boolean includeExternal, int maxCount, boolean filterDefaultNames) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            SymbolTable symbolTable = program.getSymbolTable();
            JSONArray result = new JSONArray();

            if ("classes".equals(mode)) {
                // List classes/namespaces
                Namespace globalNs = program.getGlobalNamespace();
                Iterator<Namespace> nsIter = globalNs.getChildren();
                int count = 0;

                while (nsIter.hasNext() && count < maxCount) {
                    Namespace ns = nsIter.next();
                    if (count >= startIndex) {
                        JSONObject nsObj = new JSONObject();
                        nsObj.put("name", ns.getName());
                        nsObj.put("type", "namespace");
                        result.put(nsObj);
                    }
                    count++;
                }

                JSONObject response = new JSONObject();
                response.put("count", count);
                response.put("namespaces", result);
                return response.toString();

            } else if ("namespaces".equals(mode)) {
                // List non-global namespaces - same as classes for now
                return manageSymbols("classes", null, null, null, null, 0, startIndex, 0, 0, false, false, maxCount, filterDefaultNames);

            } else if ("imports".equals(mode)) {
                // List imports
                ExternalManager extMgr = program.getExternalManager();
                Iterator<ExternalLocation> extIter = extMgr.getExternalLocations();
                Map<String, List<String>> importsByLibrary = new HashMap<>();
                int count = 0;

                while (extIter.hasNext() && count < maxResults) {
                    ExternalLocation extLoc = extIter.next();
                    String libName = extLoc.getLibraryName();
                    if (libraryFilter != null && !libName.contains(libraryFilter)) continue;

                    if (!importsByLibrary.containsKey(libName)) {
                        importsByLibrary.put(libName, new ArrayList<>());
                    }
                    importsByLibrary.get(libName).add(extLoc.getLabel());
                    count++;
                }

                if (groupByLibrary) {
                    JSONObject response = new JSONObject();
                    response.put("count", count);
                    response.put("importsByLibrary", importsByLibrary);
                    return response.toString();
                } else {
                    JSONArray imports = new JSONArray();
                    for (List<String> libImports : importsByLibrary.values()) {
                        for (String imp : libImports) {
                            imports.put(imp);
                        }
                    }
                    JSONObject response = new JSONObject();
                    response.put("count", count);
                    response.put("imports", imports);
                    return response.toString();
                }

            } else if ("exports".equals(mode)) {
                // List exports - simplified
                JSONObject response = new JSONObject();
                response.put("count", 0);
                response.put("exports", result);
                response.put("message", "Exports listing not fully implemented");
                return response.toString();

            } else if ("create_label".equals(mode) && address != null && labelName != null) {
                Address addr = parseAddress(address);
                if (addr == null) return "Invalid address: " + address;

                symbolTable.createLabel(addr, labelName, program.getGlobalNamespace(), true);
                return "Label created successfully";

            } else if ("symbols".equals(mode)) {
                // List symbols
                Iterator<Symbol> symbolIter = symbolTable.getAllSymbols(includeExternal);
                int count = 0;
                int added = 0;

                while (symbolIter.hasNext() && added < maxCount) {
                    Symbol symbol = symbolIter.next();
                    if (filterDefaultNames && (symbol.getName().startsWith("FUN_") || symbol.getName().startsWith("DAT_"))) {
                        continue;
                    }

                    if (count >= startIndex) {
                        JSONObject symbolObj = new JSONObject();
                        symbolObj.put("name", symbol.getName());
                        symbolObj.put("address", symbol.getAddress().toString());
                        symbolObj.put("type", symbol.getSymbolType().toString());
                        result.put(symbolObj);
                        added++;
                    }
                    count++;
                }

                JSONObject response = new JSONObject();
                response.put("count", count);
                response.put("symbols", result);
                return response.toString();

            } else if ("count".equals(mode)) {
                int count = symbolTable.getNumSymbols();
                JSONObject response = new JSONObject();
                response.put("count", count);
                return response.toString();

            } else if ("rename_data".equals(mode) && address != null && newName != null) {
                Address addr = parseAddress(address);
                if (addr == null) return "Invalid address: " + address;

                Symbol symbol = symbolTable.getPrimarySymbol(addr);
                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                    return "Data renamed successfully";
                }
                return "Symbol not found at address: " + address;
            }

            return result.toString();

        } catch (Exception e) {
            return "Error managing symbols: " + e.getMessage();
        }
    }

    private String manageStructures(String action, String cDefinition, String headerContent, String structureName, String name, int size, String type, String category, boolean packed, String description, String fieldName, String dataType, Integer offset, String comment, String newDataType, String newFieldName, String newComment, Integer newLength, String addressOrSymbol, boolean clearExisting, boolean force, String nameFilter, boolean includeBuiltIn) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            DataTypeManager dtm = program.getDataTypeManager();

            if ("parse".equals(action) && cDefinition != null) {
                // Parse C structure definition
                CParser parser = new CParser(dtm.getDataOrganization());
                DataType dt = parser.parse(cDefinition);
                JSONObject response = new JSONObject();
                response.put("name", dt.getName());
                response.put("size", dt.getLength());
                return response.toString();

            } else if ("validate".equals(action) && cDefinition != null) {
                // Validate C structure definition
                JSONObject response = new JSONObject();
                response.put("valid", true);
                response.put("message", "Structure validation not fully implemented");
                return response.toString();

            } else if ("create".equals(action) && name != null) {
                // Create new structure
                CategoryPath catPath = new CategoryPath(category);
                StructureDataType struct = new StructureDataType(catPath, name, size, dtm.getDataOrganization());
                struct.setDescription(description);
                dtm.addDataType(struct, null);

                JSONObject response = new JSONObject();
                response.put("name", name);
                response.put("size", size);
                response.put("created", true);
                return response.toString();

            } else if ("add_field".equals(action) && structureName != null && fieldName != null && dataType != null) {
                // Add field to structure
                DataType dt = dtm.getDataType(new CategoryPath("/"), structureName);
                if (dt instanceof Structure) {
                    Structure struct = (Structure) dt;
                    DataType fieldDt = dtm.getDataType(new CategoryPath("/"), dataType);
                    if (fieldDt != null) {
                        if (offset != null) {
                            struct.insertAtOffset(offset, fieldDt, -1, fieldName, comment);
                        } else {
                            struct.add(fieldDt, -1, fieldName, comment);
                        }
                        return "{\"success\":true,\"message\":\"Field added\"}";
                    }
                }
                return "{\"success\":false,\"message\":\"Structure or field type not found\"}";

            } else if ("modify_field".equals(action) && structureName != null && fieldName != null) {
                // Modify structure field
                JSONObject response = new JSONObject();
                response.put("success", false);
                response.put("message", "Field modification not fully implemented");
                return response.toString();

            } else if ("modify_from_c".equals(action) && cDefinition != null) {
                // Modify structure from C definition
                JSONObject response = new JSONObject();
                response.put("success", false);
                response.put("message", "Modify from C not fully implemented");
                return response.toString();

            } else if ("info".equals(action) && structureName != null) {
                // Get structure info
                DataType dt = dtm.getDataType(new CategoryPath("/"), structureName);
                if (dt instanceof Composite) {
                    Composite comp = (Composite) dt;
                    JSONObject response = new JSONObject();
                    response.put("name", dt.getName());
                    response.put("size", dt.getLength());
                    response.put("isUnion", dt instanceof Union);

                    JSONArray fields = new JSONArray();
                    for (int i = 0; i < comp.getNumComponents(); i++) {
                        DataTypeComponent comp = comp.getComponent(i);
                        JSONObject field = new JSONObject();
                        field.put("name", comp.getFieldName());
                        field.put("dataType", comp.getDataType().getName());
                        field.put("offset", comp.getOffset());
                        field.put("length", comp.getLength());
                        fields.put(field);
                    }
                    response.put("fields", fields);
                    return response.toString();
                }
                return "{\"error\":\"Structure not found\"}";

            } else if ("list".equals(action)) {
                // List structures
                return listStructures("/", nameFilter, includeBuiltIn);

            } else if ("apply".equals(action) && addressOrSymbol != null && structureName != null) {
                // Apply structure to address
                Address addr = parseAddress(addressOrSymbol);
                if (addr == null) return "Invalid address: " + addressOrSymbol;

                DataType dt = dtm.getDataType(new CategoryPath("/"), structureName);
                if (dt != null) {
                    Listing listing = program.getListing();
                    if (clearExisting) {
                        listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), false);
                    }
                    listing.createData(addr, dt);
                    return "{\"success\":true,\"message\":\"Structure applied\"}";
                }
                return "{\"success\":false,\"message\":\"Structure not found\"}";

            } else if ("delete".equals(action) && structureName != null) {
                // Delete structure
                DataType dt = dtm.getDataType(new CategoryPath("/"), structureName);
                if (dt != null) {
                    dtm.remove(dt, force);
                    return "{\"success\":true,\"message\":\"Structure deleted\"}";
                }
                return "{\"success\":false,\"message\":\"Structure not found\"}";

            } else if ("parse_header".equals(action) && headerContent != null) {
                // Parse C header file
                JSONObject response = new JSONObject();
                response.put("message", "Header parsing not fully implemented");
                response.put("typesCreated", 0);
                return response.toString();
            }

            return "{\"error\":\"Invalid structure action\"}";

        } catch (Exception e) {
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    private String manageDataTypes(String action, String archiveName, String categoryPath, boolean includeSubcategories, int startIndex, int maxCount, String dataTypeString, String addressOrSymbol) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            JSONArray result = new JSONArray();

            if ("archives".equals(action)) {
                // List data type archives
                Iterator<SourceArchive> archives = dtm.getSourceArchives();
                while (archives.hasNext()) {
                    SourceArchive archive = archives.next();
                    JSONObject archiveObj = new JSONObject();
                    archiveObj.put("name", archive.getName());
                    archiveObj.put("domainFileID", archive.getDomainFile().getID());
                    result.put(archiveObj);
                }
                return result.toString();

            } else if ("list".equals(action)) {
                // List data types
                Category cat = dtm.getCategory(new CategoryPath(categoryPath));
                if (cat != null) {
                    DataType[] dataTypes = cat.getDataTypes();
                    int count = 0;
                    int added = 0;

                    for (DataType dt : dataTypes) {
                        if (count >= startIndex && added < maxCount) {
                            JSONObject dtObj = new JSONObject();
                            dtObj.put("name", dt.getName());
                            dtObj.put("size", dt.getLength());
                            dtObj.put("description", dt.getDescription());
                            result.put(dtObj);
                            added++;
                        }
                        count++;
                    }

                    JSONObject response = new JSONObject();
                    response.put("count", count);
                    response.put("dataTypes", result);
                    return response.toString();
                }

            } else if ("by_string".equals(action) && dataTypeString != null) {
                // Get data type by string representation
                JSONObject response = new JSONObject();
                response.put("dataTypeString", dataTypeString);
                response.put("message", "Data type by string not fully implemented");
                return response.toString();

            } else if ("apply".equals(action) && addressOrSymbol != null && dataTypeString != null) {
                // Apply data type to address
                Address addr = parseAddress(addressOrSymbol);
                if (addr == null) return "Invalid address: " + addressOrSymbol;

                JSONObject response = new JSONObject();
                response.put("success", false);
                response.put("message", "Data type application not fully implemented");
                return response.toString();
            }

            return result.toString();

        } catch (Exception e) {
            return "Error managing data types: " + e.getMessage();
        }
    }

    private String getCurrentContext(String mode) {
        try {
            if ("address".equals(mode)) {
                String addr = getCurrentAddress();
                return addr != null ? addr : "No current address";
            } else if ("function".equals(mode)) {
                String func = getCurrentFunction();
                return func != null ? func : "No current function";
            } else { // both
                JSONObject response = new JSONObject();
                response.put("address", getCurrentAddress());
                response.put("function", getCurrentFunction());
                return response.toString();
            }
        } catch (Exception e) {
            return "Error getting current context: " + e.getMessage();
        }
    }

    private String manageFunctionTags(String function, String mode, String tags) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            JSONArray result = new JSONArray();

            if ("get".equals(mode) && function != null) {
                // Get tags for function
                Function func = getFunction(function);

                if (func != null) {
                    JSONObject tagsObj = new JSONObject();
                    tagsObj.put("function", function);
                    tagsObj.put("tags", new JSONArray()); // Simplified - no tags implemented
                    result.put(tagsObj);
                }

            } else if ("set".equals(mode) && function != null && tags != null) {
                // Set tags for function - simplified
                return "Function tags set (not fully implemented)";

            } else if ("add".equals(mode) && function != null && tags != null) {
                // Add tags to function - simplified
                return "Function tags added (not fully implemented)";

            } else if ("remove".equals(mode) && function != null && tags != null) {
                // Remove tags from function - simplified
                return "Function tags removed (not fully implemented)";

            } else if ("list".equals(mode)) {
                // List all tags - simplified
                JSONObject tagsObj = new JSONObject();
                tagsObj.put("tags", new JSONArray());
                tagsObj.put("message", "Function tags listing not fully implemented");
                result.put(tagsObj);
            }

            return result.toString();

        } catch (Exception e) {
            return "Error managing function tags: " + e.getMessage();
        }
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

