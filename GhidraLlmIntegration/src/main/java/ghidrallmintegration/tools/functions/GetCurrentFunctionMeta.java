package ghidrallmintegration.tools.functions;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Json;
import ghidrallmintegration.tools.LlmTool;

public class GetCurrentFunctionMeta extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns details about the currently selected function like entry address, size, address, signature";
	}

	public GetCurrentFunctionMeta(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Address address = this.getCurrentAddress();
		Function function = this.findFunctionContainingAddress(address.toString());

		return gson.toJson(Json.toJson(function));
	}
}