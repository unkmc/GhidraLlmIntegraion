package ghidrallmintegration.tools.functions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool; import ghidra.framework.plugintool.PluginTool;

public class GetReferencesToAddress extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns a list of references to the specified address";
	}

	private final String parameter_1 = "address";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "address"));
	}

	public GetReferencesToAddress(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);

		String addressString = parameterMap.get(parameter_1);
		try {
			Address toAddress = currentProgram.getAddressFactory().getAddress(addressString);
			if (toAddress == null) {
				return "Invalid address format or address does not exist.";
			}

			ReferenceManager refManager = currentProgram.getReferenceManager();
			ReferenceIterator references = refManager.getReferencesTo(toAddress);

			List<Map<String, String>> referencesList = new ArrayList<>();
			while (references.hasNext()) {
				Reference reference = references.next();
				Map<String, String> refMap = new HashMap<>();
				refMap.put("id", String.valueOf(reference.getSymbolID()));
				refMap.put("fromAddress", reference.getFromAddress().toString());
				refMap.put("toAddress", reference.getToAddress().toString());
				refMap.put("type", reference.getReferenceType().toString());
				referencesList.add(refMap);
			}
			return gson.toJson(referencesList);
		} catch (Exception exception) {
			// Handle potential errors, such as Address parsing errors
			return "Error processing the request: " + exception.getMessage();
		}
	}
}