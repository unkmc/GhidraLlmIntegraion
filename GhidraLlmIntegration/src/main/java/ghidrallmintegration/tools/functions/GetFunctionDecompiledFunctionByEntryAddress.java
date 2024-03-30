package ghidrallmintegration.tools.functions;

import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool;

public class GetFunctionDecompiledFunctionByEntryAddress extends LlmTool {
	@Override
	protected String getDescription() {
		return "Updates and returns the decomplication of a function";
	}

	private final String parameter_1 = "entryAddress";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "function entry address"));
	}

	public GetFunctionDecompiledFunctionByEntryAddress(Program currentProgram, TaskMonitor monitor) {
		super(currentProgram, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String addressStr = parameterMap.get(parameter_1);
		Function function = getFunctionByEntryAddress(addressStr);

		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults results = decompiler.decompileFunction(function, 30, monitor);

		return results.getCCodeMarkup().toString();
	}
}