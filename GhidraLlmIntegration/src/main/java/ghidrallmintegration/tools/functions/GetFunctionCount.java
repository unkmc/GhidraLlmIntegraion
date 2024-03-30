package ghidrallmintegration.tools.functions;

import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool; import ghidra.framework.plugintool.PluginTool;

public class GetFunctionCount extends LlmTool {
	private final FunctionManager functionManager;

	public GetFunctionCount(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
		this.functionManager = currentProgram.getFunctionManager();
	}

	@Override
	public String execute(String parameterJson) {
		return String.valueOf(functionManager.getFunctionCount());
	}

	@Override
	protected String getName() {
		return "GetFunctionCount";
	}

	@Override
	protected String getDescription() {
		return "Returns the total number of functions in the program including external functions";
	}
}