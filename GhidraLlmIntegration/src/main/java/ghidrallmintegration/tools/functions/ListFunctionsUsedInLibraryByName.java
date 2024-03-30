package ghidrallmintegration.tools.functions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool; import ghidra.framework.plugintool.PluginTool;
import ghidrallmintegration.tools.SimpleSymbol;

public class ListFunctionsUsedInLibraryByName extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns a list of functions imported from the specified library";
	}

	public static final String parameter_1 = "externalLibraryName";

	public ListFunctionsUsedInLibraryByName(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "external library name"));
	}

	@Override
	public String execute(String parameterJson) {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);

		String libraryName = parameterMap.get(parameter_1);
		SymbolTable symbolTable = currentProgram.getSymbolTable();

		Symbol externalSymbol = symbolTable.getExternalSymbol(libraryName);
		if (externalSymbol == null) {
			externalSymbol = symbolTable.getExternalSymbol(libraryName.toUpperCase());
		}

		if (externalSymbol == null) {
			String errorMessage = "Requested library, \"" + libraryName + "\" was not found in symbol table.";
			Msg.error(this, errorMessage);
			return errorMessage;
		}

		SymbolIterator children = symbolTable.getChildren(externalSymbol);

		List<SimpleSymbol> symbolsList = new ArrayList<>();
		while (children.hasNext()) {
			Symbol symbol = children.next();
			symbolsList.add(new SimpleSymbol(symbol.getName(), symbol.getAddress().toString()));
		}

		Msg.info(this, "Got children for library " + libraryName + ": " + symbolsList);
		return gson.toJson(symbolsList);
	}
}