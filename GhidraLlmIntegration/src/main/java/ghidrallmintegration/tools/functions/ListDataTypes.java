package ghidrallmintegration.tools.functions;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Json;
import ghidrallmintegration.tools.LlmTool; import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class ListDataTypes extends LlmTool {
	@Override
	protected String getDescription() {
		return "Lists all data types recognized in the current Ghidra project.";
	}

	public ListDataTypes(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		super(currentProgram, tool, monitor);
	}

	@Override
	public String execute(String parameterJson) {
		DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();
		Iterator<DataType> allDataTypes = dataTypeManager.getAllDataTypes();

		List<Map<String, Object>> dataTypeList = new ArrayList<>();
		while (allDataTypes.hasNext()) {
			DataType dataType = allDataTypes.next();
			dataTypeList.add(Json.toJson(dataType));
		}

		return gson.toJson(dataTypeList);
	}
}