package ghidrallmintegration.tools.functions;

import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Errors;
import ghidrallmintegration.Json;
import ghidrallmintegration.tools.LlmTool;
import ghidra.framework.plugintool.PluginTool;

public class GetFunctionMetaByEntryAddress extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns details about a function like entry address, size, address, signature";
	}

	private final String parameter_1 = "entryAddress";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "entry address"));
	}

	public GetFunctionMetaByEntryAddress(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String addressString = parameterMap.get(parameter_1);
		Function function = getFunctionByEntryAddress(addressString);
		if (function == null) {
			return Errors.noFunctionFound(addressString);
		}
		return gson.toJson(Json.toMap(function));
	}
}