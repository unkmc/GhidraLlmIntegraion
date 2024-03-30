package ghidrallmintegration.tools.functions;

import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Json;
import ghidrallmintegration.tools.LlmTool; import ghidra.framework.plugintool.PluginTool;

public class GetFunctionMetaByContainingAddress extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns details about a function containing the given address like entry address, size, address, signature";
	}

	private final String parameter_1 = "address";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "address"));
	}

	public GetFunctionMetaByContainingAddress(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String address = parameterMap.get(parameter_1);
		Function function = this.findFunctionContainingAddress(address);
		if (function == null) {
			return "No function was found containing address \"" + address
					+ ". You may have better results searching for a symbol at this address.";
		}
		return gson.toJson(Json.toJson(function));
	}
}