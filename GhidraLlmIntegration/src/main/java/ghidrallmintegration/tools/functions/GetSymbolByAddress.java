package ghidrallmintegration.tools.functions;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Json;
import ghidrallmintegration.tools.LlmTool;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class GetSymbolByAddress extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns symbol information for the specified address";
	}

	private final String parameter_1 = "address";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "Address of the symbol to find"));
	}

	public GetSymbolByAddress(Program currentProgram, TaskMonitor monitor) {
		super(currentProgram, monitor);
	}

	@Override
	public String execute(String parameterJson) {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String addressString = parameterMap.get(parameter_1);
		Address address = currentProgram.getAddressFactory().getAddress(addressString);
		if (address == null) {
			return "Invalid address format or address does not exist.";
		}

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(address);

		if (symbols.length == 0) {
			return "No symbol found at the given address.";
		}

		List<Symbol> symbolsList = List.of(symbols);
		List<Map<String, Object>> result = new ArrayList<>();
		for (var symbol : symbolsList) {
			Map<String, Object> map = Json.empty();
			map.put("name", symbol.getName());
			map.put("address", symbol.getAddress().toString());
			map.put("symbolType", symbol.getSymbolType().toString());
			result.add(map);
		}

		return gson.toJson(result);
	}
}