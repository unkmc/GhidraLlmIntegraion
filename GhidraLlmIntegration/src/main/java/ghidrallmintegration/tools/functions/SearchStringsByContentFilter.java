package ghidrallmintegration.tools.functions;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidrallmintegration.Json;
import ghidrallmintegration.tools.LlmTool; import ghidra.framework.plugintool.PluginTool;

public class SearchStringsByContentFilter extends LlmTool {

	private final String parameter_1 = "contentFilter";

	@Override
	protected String getDescription() {
		return "Searches for strings containing a specified content.";
	}

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "Content filter (substring to search within strings)"));
	}

	public SearchStringsByContentFilter(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String contentFilter = parameterMap.get(parameter_1);

		try {
			List<Map<String, Object>> filteredStringsList = new ArrayList<>();
			DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
			while (dataIterator.hasNext() && !monitor.isCancelled()) {
				Data data = dataIterator.next();
				if (data.hasStringValue()) {
					String stringValue = data.getValue().toString();
					if (stringValue.contains(contentFilter)) {
						Address stringAddress = data.getAddress();
						var map = Json.empty();
						map.put("string", stringValue);
						map.put("address", stringAddress.toString());
						filteredStringsList.add(map);
					}
				}
			}
			return gson.toJson(filteredStringsList);
		} catch (Exception exception) {
			return "Error processing the request: " + exception.getMessage();
		}
	}
}