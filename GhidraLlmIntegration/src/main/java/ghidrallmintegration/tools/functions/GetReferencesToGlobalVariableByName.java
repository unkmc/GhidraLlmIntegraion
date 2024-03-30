package ghidrallmintegration.tools.functions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool; import ghidra.framework.plugintool.PluginTool;

public class GetReferencesToGlobalVariableByName extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns references to a global variable";
	}

	public static final String parameter_1 = "variableName";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "name"));
	}

	public GetReferencesToGlobalVariableByName(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String variableName = parameterMap.get(parameter_1);

		List<Map<String, String>> referencesList = new ArrayList<>();
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Namespace globalNamespace = currentProgram.getGlobalNamespace();
		List<Symbol> symbols = symbolTable.getSymbols(variableName, globalNamespace);

		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType() != SymbolType.GLOBAL_VAR) {
				continue;
			}

			ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(symbol.getAddress());
			while (references.hasNext()) {
				Reference ref = references.next();
				Address fromAddress = ref.getFromAddress();
				String referenceType = ref.getReferenceType().getName();

				Map<String, String> referenceDetails = new HashMap<>();
				referenceDetails.put("fromAddress", fromAddress.toString());
				referenceDetails.put("referenceType", referenceType);
				referencesList.add(referenceDetails);
			}
		}

		return gson.toJson(referencesList);
	}
}