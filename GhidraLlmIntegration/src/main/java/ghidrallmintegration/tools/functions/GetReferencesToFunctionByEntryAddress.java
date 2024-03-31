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
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Errors;
import ghidrallmintegration.tools.LlmTool; import ghidra.framework.plugintool.PluginTool;

public class GetReferencesToFunctionByEntryAddress extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns a list of references to the specified function by entry address";
	}

	private final String parameter_1 = "entryAddress";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "function's entry address"));
	}

	public GetReferencesToFunctionByEntryAddress(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
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

		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function targetFunction = functionManager.getFunctionAt(entryAddress);
		if (targetFunction == null) {
			return Errors.noFunctionFound(addressString);
		}

		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		ReferenceIterator references = referenceManager.getReferencesTo(entryAddress);

		List<Map<String, String>> referencesList = new ArrayList<>();
		while (references.hasNext()) {
			Reference reference = references.next();
			Map<String, String> refMap = new HashMap<>();
			refMap.put("fromAddress", reference.getFromAddress().toString());
			refMap.put("toAddress", reference.getToAddress().toString());
			refMap.put("type", reference.getReferenceType().toString());
			referencesList.add(refMap);
		}

		return gson.toJson(referencesList);
	}
}