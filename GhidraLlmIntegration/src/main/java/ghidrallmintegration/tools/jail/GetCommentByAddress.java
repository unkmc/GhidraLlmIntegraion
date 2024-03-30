package ghidrallmintegration.tools.jail;

import java.util.ArrayList;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool;
import ghidrallmintegration.tools.ToolParameters;
import ghidrallmintegration.tools.ToolParameters.Builder;

public class GetCommentByAddress extends LlmTool {
	Map<String, Integer> commentTypeEnumMap = Map.ofEntries(
			Map.entry("EOL_COMMENT", 0),
			Map.entry("PRE_COMMENT", 1),
			Map.entry("POST_COMMENT", 2),
			Map.entry("PLATE_COMMENT", 3),
			Map.entry("REPEATABLE_COMMENT", 4));

	@Override
	protected String getDescription() {
		return "Returns a comments for an address";
	}

	private final String parameter_1 = "entryAddress";
	private final String parameter_2 = "commentType";

	@Override
	protected Map<String, String> getParameterMap() {
		return Map.ofEntries(
				Map.entry(parameter_1, "entry address"));
	}

	@Override
	protected ToolParameters.Builder buildToolParameters() {
		Builder toolParameters = super.buildToolParameters();
		toolParameters.addParameter("enum", parameter_2, "type of comment", new ArrayList<>(commentTypeEnumMap.keySet()));
		return toolParameters;
	}

	public GetCommentByAddress(Program currentProgram, TaskMonitor monitor) {
		super(currentProgram, monitor);
	}

	@Override
	public String execute(String parameterJson) throws Exception {
		Map<String, String> parameterMap = parseParameterMap(parameterJson);
		String addressString = parameterMap.get(parameter_1);
		Address address = currentProgram.getAddressFactory().getAddress(addressString);
		Listing listing = currentProgram.getListing();
		CodeUnit codeUnit = listing.getCodeUnitAt(address);

		String commentTypeString = parameterMap.get(parameter_1);
		int commentType = commentTypeEnumMap.get(commentTypeString);
		String comment = codeUnit.getComment(commentType);
		return comment;
	}
}