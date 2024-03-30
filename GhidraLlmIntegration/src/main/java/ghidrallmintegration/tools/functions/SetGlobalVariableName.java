package ghidrallmintegration.tools.functions;

import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool;

public class SetGlobalVariableName extends LlmTool {
	@Override
	protected String getDescription() {
		return "Renames the specified global variable.";
	}

	private final String parameter_1 = "targetName";
	private final String parameter_2 = "newName";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "target variable name"),
				Map.entry(parameter_2, "new variable name"));
	}

	public SetGlobalVariableName(Program currentProgram, TaskMonitor monitor) {
		super(currentProgram, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String targetName = parameterMap.get(parameter_1);
		String newName = parameterMap.get(parameter_2);
		if (newName == null || newName.isEmpty()) {
			throw new IllegalArgumentException("New name must be provided.");
		}

	    SymbolTable symbolTable = currentProgram.getSymbolTable();
	    SymbolIterator symbols = symbolTable.getSymbols(targetName);
	    Symbol globalVarSymbol = null;
	    while (symbols.hasNext()) {
	        Symbol symbol = symbols.next();
	        if (symbol.getSymbolType() == SymbolType.GLOBAL_VAR) {
	            globalVarSymbol = symbol;
	            break;
	        }
	    }

	    if (globalVarSymbol == null) {
	        throw new Exception("Global variable not found.");
	    }
	    
	    globalVarSymbol.setName(targetName,SourceType.USER_DEFINED);
		return "SUCCESS";
	}
}