package ghidrallmintegration.tools.functions;

import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool;

public class SetLocalVariableNameInFunction extends LlmTool {
	@Override
	protected String getDescription() {
		return "Renames the specified variable inside the function at the specified entry address.";
	}

	private final String parameter_1 = "functionEntryAddress";
	private final String parameter_2 = "targetName";
	private final String parameter_3 = "newName";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "entry address"),
				Map.entry(parameter_2, "target variable name"),
				Map.entry(parameter_3, "new variable name"));
	}

	public SetLocalVariableNameInFunction(Program currentProgram, TaskMonitor monitor) {
		super(currentProgram, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String addressStr = parameterMap.get(parameter_1);
		Function function = getFunctionByEntryAddress(addressStr);

		String targetName = parameterMap.get(parameter_2);
		String newName = parameterMap.get(parameter_3);

		Variable[] localVariables = function.getLocalVariables();
		for (Variable variable : localVariables) {
			if (variable.getName().equals(targetName)) {
				variable.setName(newName, SourceType.USER_DEFINED);
			}
		}

		return "SUCCESS";
	}
}