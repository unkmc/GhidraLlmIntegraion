package ghidrallmintegration.tools.functions;

import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool;

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

	public SetFunctionNameByEntryAddress(Program currentProgram, TaskMonitor monitor) {
		super(currentProgram, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String addressStr = parameterMap.get(parameter_1);
		Function function = getFunctionByEntryAddress(addressStr);

		String newName = parameterMap.get(parameter_2);
		function.setName(newName, SourceType.USER_DEFINED);
		function.setSignatureSource(SourceType.USER_DEFINED);

		return gson.toJson("SUCCESS");
	}
}