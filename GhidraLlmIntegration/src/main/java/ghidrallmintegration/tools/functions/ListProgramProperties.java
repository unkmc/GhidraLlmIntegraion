package ghidrallmintegration.tools.functions;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Json;
import ghidrallmintegration.tools.LlmTool;

public class ListProgramProperties extends LlmTool {
	@Override
	protected String getDescription() {
		return "Returns a list of key properties of the current program";
	}

	public ListProgramProperties(Program currentProgram, TaskMonitor monitor) {
		super(currentProgram, monitor);
	}

	@Override
	public String execute(String parameterJson) {
		Language language = currentProgram.getLanguage();
		CompilerSpec compilerSpec = currentProgram.getCompilerSpec();

		Map<String, Object> properties = new HashMap<>();
		properties.put("Program Name", currentProgram.getDomainFile().getName());
		properties.put("Compiler", compilerSpec.getCompilerSpecDescription().getCompilerSpecName());
		properties.put("Creation Date", currentProgram.getCreationDate().toString());

		var languageMap = Json.empty();
		languageMap.put("id", language.getLanguageDescription().getLanguageID().toString());
		languageMap.put("processor", language.getLanguageDescription().getProcessor().toString());
		languageMap.put("endian", language.getLanguageDescription().getEndian().toString());
		languageMap.put("instructionEndian", language.getLanguageDescription().getInstructionEndian().toString());
		languageMap.put("version", String.valueOf(language.getLanguageDescription().getVersion()));
		languageMap.put("description", String.valueOf(language.getLanguageDescription().getDescription()));
		properties.put("Language", languageMap);

		return gson.toJson(properties);
	}
}