package ghidrallmintegration.tools;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.theokanning.openai.assistants.AssistantFunction;
import com.theokanning.openai.assistants.AssistantToolsEnum;
import com.theokanning.openai.assistants.Tool;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.ToolParameters.Builder;

public abstract class LlmTool {
	protected Gson gson = new Gson();
	protected Program currentProgram;
	protected TaskMonitor monitor;

	protected LlmTool(Program currentProgram, TaskMonitor monitor) {
		this.currentProgram = currentProgram;
		this.monitor = monitor;
	}

	public abstract String execute(String parameterJson) throws Exception;

	public final Tool BuildTool() {
		return new Tool(AssistantToolsEnum.FUNCTION,
				AssistantFunction.builder()
						.name(getName())
						.description(getDescription())
						.parameters(buildToolParameters().build().toMap())
						.build());
	}

	protected String getName() {
		return this.getClass().getSimpleName();
	}

	protected abstract String getDescription();

	protected Map<String, String> getParameterMap() {
		return Map.ofEntries();
	}

	protected ToolParameters.Builder buildToolParameters() {
		Builder toolParameters = ToolParameters.builder();
		for (var parameterEntry : getParameterMap().entrySet()) {
			toolParameters.addParameter("string", parameterEntry.getKey(), parameterEntry.getValue());
		}
		return toolParameters;
	}

	public Map<String, String> parseParameterMap(String parameterJson) {
		Map<String, String> parameterMap;
		try {
			Type type = new TypeToken<Map<String, String>>() {
			}.getType();
			parameterMap = gson.fromJson(parameterJson, type);
		} catch (Exception exception) {
			Msg.error(this, "Could not parse LLM provided parameter JSON: " + exception);
			throw exception;
		}
		return parameterMap;
	}

	protected List<Function> findFunctionsByName(String name) throws Exception {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		SymbolIterator it = symbolTable.getSymbolIterator(name, true);

		List<Function> functions = new ArrayList<>();
		while (it.hasNext()) {
			Symbol symbol = it.next();
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				functions.add(currentProgram.getFunctionManager().getFunctionAt(symbol.getAddress()));
			}
		}
		if (!functions.isEmpty()) {
			return functions;
		}
		String error = "Specified function, \"" + name + "\" was not found.";
		Msg.error(this, error);
		throw new Exception(error);
	}

	protected Address addressFromString(String addressString) throws Exception {
		AddressFactory addressFactory = currentProgram.getAddressFactory();
		Address address = null;
		try {
			address = addressFactory.getAddress(addressString);
		} catch (IllegalArgumentException e) {
			String error = "Invalid address format: \"" + addressString + "\".";
			Msg.error(this, error);
			throw new Exception(error);
		}
		return address;
	}

	protected Function findFunctionContainingAddress(String addressString) throws Exception {
		Address address = addressFromString(addressString);
		if (address != null) {
			Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
			if (function != null) {
				return function;
			}
		}

		String error = "Specified function at address, \"" + addressString + "\" was not found.";
		Msg.error(this, error);
		return null;
	}

	protected Function getFunctionByEntryAddress(String addressStr) {
		Address entryAddress = currentProgram.getAddressFactory().getAddress(addressStr);
		if (entryAddress == null) {
			throw new IllegalArgumentException("Invalid address format or address not found.");
		}
		FunctionManager functionManager = currentProgram.getFunctionManager();
		return functionManager.getFunctionAt(entryAddress);
	}

	protected HighFunction getHighFunction(Function function) {
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults decompiledFunction = decompiler.decompileFunction(function, 30, monitor);
		return decompiledFunction.getHighFunction();
	}

	protected DecompileResults getFunctionDecompilation(Function function) {
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
		if (!results.decompileCompleted()) {
			Msg.info(this, "Decompilation failed.");
			return null;
		}
		return results;
	}

}
