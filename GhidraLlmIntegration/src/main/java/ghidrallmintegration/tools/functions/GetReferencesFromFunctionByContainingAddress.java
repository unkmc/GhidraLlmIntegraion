package ghidrallmintegration.tools.functions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Errors;
import ghidrallmintegration.tools.LlmTool;
import ghidra.framework.plugintool.PluginTool;

public class GetReferencesFromFunctionByContainingAddress extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns a list of references from the function that contians the specified address";
	}

	private final String parameter_1 = "address";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "an address in a function"));
	}

	public GetReferencesFromFunctionByContainingAddress(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String addressString = parameterMap.get(parameter_1);

		Address entryAddress = currentProgram.getAddressFactory().getAddress(addressString);
		if (entryAddress == null) {
			throw new IllegalArgumentException(Errors.noAddress(addressString));
		}

		Function targetFunction = this.findFunctionContainingAddress(addressString);
		if (targetFunction == null) {
			return Errors.noFunctionFound(addressString);
		}

		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		Reference[] references = referenceManager.getReferencesFrom(entryAddress);

		List<Map<String, String>> referencesList = new ArrayList<>();
		for (var reference : references) {
			Map<String, String> refMap = new HashMap<>();
			refMap.put("fromAddress", reference.getFromAddress().toString());
			refMap.put("toAddress", reference.getToAddress().toString());
			refMap.put("type", reference.getReferenceType().toString());
			referencesList.add(refMap);
		}

		return gson.toJson(referencesList);
	}
}
