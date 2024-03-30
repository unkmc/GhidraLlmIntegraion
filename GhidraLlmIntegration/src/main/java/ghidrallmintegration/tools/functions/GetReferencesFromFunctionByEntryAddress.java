package ghidrallmintegration.tools.functions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool;

public class GetReferencesFromFunctionByEntryAddress extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns a list of references from the function at the specified address";
	}

	private final String parameter_1 = "entryAddress";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "function's entry address"));
	}

	public GetReferencesFromFunctionByEntryAddress(Program currentProgram, TaskMonitor monitor) {
		super(currentProgram, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String addressStr = parameterMap.get(parameter_1);
		Address entryAddress = currentProgram.getAddressFactory().getAddress(addressStr);

		if (entryAddress == null) {
			throw new IllegalArgumentException("Invalid address format or address not found.");
		}

		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function targetFunction = functionManager.getFunctionAt(entryAddress);
		if (targetFunction == null) {
			return "No function found at the given address, \"" + addressStr + "\"";
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