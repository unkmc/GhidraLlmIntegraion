package ghidrallmintegration.tools.functions;

import java.util.Arrays;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool;

public class ListImportedLibraries extends LlmTool {
	private final ExternalManager externalManager;

	@Override
	protected String getDescription() {
		return "Returns a list of external libraries used in the project";
	}

	public ListImportedLibraries(Program currentProgram, TaskMonitor monitor) {
		super(currentProgram, monitor);
		this.externalManager = currentProgram.getExternalManager();
	}

	@Override
	public String execute(String parameterJson) {
		String[] libraryNames = externalManager.getExternalLibraryNames();
		return Arrays.toString(libraryNames);
	}

}