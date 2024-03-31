package ghidrallmintegration.tools;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.theokanning.openai.assistants.AssistantFunction;
import com.theokanning.openai.assistants.AssistantToolsEnum;
import com.theokanning.openai.assistants.Tool;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.Errors;
import ghidrallmintegration.tools.ToolParameters.Builder;

/**
 * Abstract class representing a tool for integrating language model
 * functionalities into the Ghidra software reverse engineering framework. This
 * class provides a foundation for developing tools that can execute tasks based
 * on language model inputs, handling various Ghidra-specific operations.
 */
public abstract class LlmTool {
	protected Gson gson = new Gson();
	protected Program currentProgram;
	protected TaskMonitor monitor;
	protected PluginTool tool;
	protected static final int MONITOR_TIMEOUT = 30;

	/**
	 * Constructs an LLM tool instance with specified program, tool, and monitor.
	 *
	 * @param currentProgram The current Ghidra program.
	 * @param tool           The plugin tool instance.
	 * @param monitor        The task monitor.
	 */
	protected LlmTool(Program currentProgram, PluginTool tool, TaskMonitor monitor) {
		this.currentProgram = currentProgram;
		this.monitor = monitor;
		this.tool = tool;
	}

	/**
	 * Executes the tool with the given JSON parameters.
	 *
	 * @param parameterJson JSON string containing parameters for the execution.
	 * @return A string result of the execution.
	 * @throws Exception if an error occurs during execution.
	 */
	public abstract String execute(String parameterJson) throws Exception;

	/**
	 * Builds a Ghidra Tool object representing this LLM tool.
	 *
	 * @return The constructed Tool object.
	 */
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

	/**
	 * Parses a JSON string into a map of parameters.
	 *
	 * @param parameterJson The JSON string to parse.
	 * @return A map of parameters.
	 * @throws IllegalArgumentException if the JSON cannot be parsed.
	 */
	public Map<String, String> parseParameterMap(String parameterJson) {
		Map<String, String> parameterMap;
		try {
			Type type = new TypeToken<Map<String, String>>() {
			}.getType();
			parameterMap = gson.fromJson(parameterJson, type);
		} catch (Exception exception) {
			String errorString = "Could not parse LLM provided parameter JSON: " + exception;
			Msg.error(this, errorString);
			Msg.error(this, Errors.getStackTraceAsString(exception));
			throw new IllegalArgumentException(errorString);
		}
		return parameterMap;
	}

	/**
	 * Finds functions in the current program by name.
	 *
	 * @param name The name of the function(s) to find.
	 * @return A list of matching functions.
	 * @throws Exception if an error occurs during the search.
	 */
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
		return functions;
	}

	@Nullable
	protected Address addressFromString(String addressString) throws Exception {
		AddressFactory addressFactory = currentProgram.getAddressFactory();
		try {
			return addressFactory.getAddress(addressString);
		} catch (IllegalArgumentException e) {
			String error = "Invalid address format, \"" + addressString + "\".";
			Msg.error(this, error);
			Msg.error(this, Errors.getStackTraceAsString(e));
			return null;
		}
	}

	@Nullable
	protected Function findFunctionContainingAddress(String addressString) throws Exception {
		Address address = addressFromString(addressString);
		if (address == null) {
			String error = Errors.noFunctionFound(addressString);
			Msg.error(this, error);
			return null;
		}
		Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
		return function;
	}

	@Nullable
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
		DecompileResults decompiledFunction = decompiler.decompileFunction(function, MONITOR_TIMEOUT, monitor);
		return decompiledFunction.getHighFunction();
	}

	protected DecompileResults getFunctionDecompilation(Function function) {
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults results = decompiler.decompileFunction(function, MONITOR_TIMEOUT, monitor);
		if (!results.decompileCompleted()) {
			Msg.error(this, "Decompilation failed.");
			return null;
		}
		return results;
	}

	protected Address getCurrentAddress() {
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			ProgramLocation location = goToService.getDefaultNavigatable().getLocation();
			if (location != null) {
				return location.getAddress();
			}
		}
		return null;
	}

}
