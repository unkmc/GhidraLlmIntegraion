package ghidrallmintegration.tools.functions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Json;
import ghidrallmintegration.tools.LlmTool; import ghidra.framework.plugintool.PluginTool;

public class GetFunctionMetaByName extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns details about a function like entry address, size, address, signature";
	}

	private final String parameter_1 = "name";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "function name"));
	}

	public GetFunctionMetaByName(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String functionName = parameterMap.get(parameter_1);
		List<Function> functions = this.findFunctionsByName(functionName);

		List<Map<String, Object>> list = new ArrayList<>();
		for (Function function : functions) {
			list.add(Json.toMap(function));
		}

		return gson.toJson(list);
	}
}