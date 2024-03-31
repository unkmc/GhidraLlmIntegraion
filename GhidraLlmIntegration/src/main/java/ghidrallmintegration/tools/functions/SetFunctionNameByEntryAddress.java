package ghidrallmintegration.tools.functions;

import java.util.Map;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool;
import ghidra.framework.plugintool.PluginTool;

public class SetFunctionNameByEntryAddress extends LlmTool {
	@Override
	protected String getDescription() {
		return "Renames the function at the specified entry address.";
	}

	private final String parameter_1 = "entryAddress";
	private final String parameter_2 = "name";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "entry address"),
				Map.entry(parameter_2, "new name"));
	}

	public SetFunctionNameByEntryAddress(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String addressString = parameterMap.get(parameter_1);
		Function function = getFunctionByEntryAddress(addressString);
		if (function == null) {
			return "Function with entryAddress \"" + addressString + "\" was not found.";
		}

		String newName = parameterMap.get(parameter_2);
		var id = currentProgram.startTransaction("Rename a function");
		try {
			Function actualFunction = function;
			actualFunction.setName(newName, SourceType.USER_DEFINED);
			actualFunction.setSignatureSource(SourceType.USER_DEFINED);
			currentProgram.endTransaction(id, true);
		} catch (Exception e) {
			currentProgram.endTransaction(id, false);
			throw e;
		}
		return gson.toJson("SUCCESS");
	}
}
