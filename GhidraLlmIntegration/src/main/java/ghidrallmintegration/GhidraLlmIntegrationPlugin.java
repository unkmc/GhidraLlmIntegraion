/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidrallmintegration;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.stream.Collectors;

import com.google.gson.Gson;
import com.theokanning.openai.ListSearchParameters;
import com.theokanning.openai.assistants.Assistant;
import com.theokanning.openai.assistants.AssistantRequest;
import com.theokanning.openai.assistants.Tool;
import com.theokanning.openai.service.OpenAiService;
import com.theokanning.openai.threads.ThreadRequest;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidrallmintegration.tools.LlmTool;
import org.reflections.Reflections;
import java.util.Set;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class GhidraLlmIntegrationPlugin extends ProgramPlugin {
//	private static final String PLUGIN_NAME = "My Plugin";
//	private static final String OPTION_CATEGORY = "My Plugin Options";
//	private static final String MY_OPTION_KEY = "MyOption";
//	private String myOptionValue = "default";

	static final String EXPECTED_ASSISTANT_NAME = "Ghidra LLM Integration";
	static final String ASSISTANT_INSTRUCTIONS = "You are a master of Ghidra Software Reverse Engineering Framework."
			+ " Tools that interact with the Ghidra APIs have been provided to you."
			+ " If you find yourself lacking any tools which would help you, let the user know.";
	private TaskMonitor monitor;
	private GhidraLlmIntegraionPanelProvider provider;
	private HashMap<Program, GhidraLlmIntegrationTask> services = new HashMap<Program, GhidraLlmIntegrationTask>();
	private GhidraLlmIntegrationConfiguration config;
	private OpenAiService openAiService;
	private HashMap<String, LlmTool> toolMap;
	private final Gson gson = new Gson();

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraLlmIntegrationPlugin(PluginTool tool) {
		super(tool);
		config = new GhidraLlmIntegrationConfiguration();
		monitor = new TaskMonitorAdapter(true);
		openAiService = new OpenAiService(config.apiKey);
	}

	private String getPanelThread() {
		var threadResponse = openAiService.createThread(ThreadRequest.builder().build());
		return threadResponse.getId();
	}

	private Assistant createAssistant() {
		Msg.info(this, "There are " + toolMap.size() + " tools that the assistant needs.");
		ArrayList<Tool> functionList = toolMap.values().stream().map(llmTool -> llmTool.BuildTool())
				.collect(Collectors.toCollection(ArrayList::new));

		Msg.info(this, functionList.size() + " tools have been built.");
		var assistantBuilder = AssistantRequest.builder()
				.name(EXPECTED_ASSISTANT_NAME)
				.model(config.model)
				.instructions(ASSISTANT_INSTRUCTIONS)
				.tools(functionList);
		AssistantRequest createRequest = assistantBuilder.build();

		Msg.info(this, "Requesting assistant creation:" + gson.toJson(createRequest));
		Assistant assistant = openAiService.createAssistant(createRequest);
		return assistant;
	}

	private void buildToolMap() throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
		toolMap = new HashMap<>();
		Reflections reflections = new Reflections("ghidrallmintegration.tools.functions");
		Set<Class<? extends LlmTool>> classes = reflections.getSubTypesOf(LlmTool.class);
		for (Class<? extends LlmTool> clazz : classes) {
			LlmTool toolInstance = clazz
					.getConstructor(Program.class, TaskMonitor.class)
					.newInstance(currentProgram, monitor);
			toolMap.put(clazz.getSimpleName(), toolInstance);
		}
	}

	private String getAssistantId() throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
		var hasMore = true;
		String lastAssistantIdSeen = "";
		buildToolMap();
		while (hasMore) {
			// Make sure to request "after" the last one seen.
			var listRequestBuilder = ListSearchParameters.builder();
			if (lastAssistantIdSeen != "") {
				listRequestBuilder.after(lastAssistantIdSeen);
			}

			// Fetch the list, update hasMore
			var assistants = openAiService.listAssistants(listRequestBuilder.build());
			hasMore = assistants.hasMore;

			// Check if expected assistant is in this batch.
			for (Assistant assistant : assistants.data) {
				var assistantId = assistant.getId();
				lastAssistantIdSeen = assistantId;
				if (assistant.getName().equals(GhidraLlmIntegrationPlugin.EXPECTED_ASSISTANT_NAME)) {
					if (assistant.getTools().size() != toolMap.size()) {
						Msg.info(this,
								"Matching assistant,\"" + assistantId + "\" has " + assistant.getTools().size()
										+ " tools but " + toolMap.size()
										+ " are expected. Will delete assistant and create new.");
						openAiService.deleteAssistant(assistantId);
						break;
					}
					return assistantId;
				}
				Msg.info(this, "Found assistant \"" + assistant.getName() + "\" does not match expected \""
						+ GhidraLlmIntegrationPlugin.EXPECTED_ASSISTANT_NAME + "\"");
			}
		}

		// Fell through, expected assistant was not found.
		Msg.warn(this, "Will create new assistant...");
		try {
			Assistant assistant = createAssistant();
			Msg.warn(this, "New Assistant has been created.");
			return assistant.getId();
		} catch (Exception e) {
			Msg.error(this, "An error ocurred while trying to create the assistant: " + e);
			throw e;
		}
	}

	@Override
	public void init() {
		super.init();
		// IDK how this works
//		Options options = tool.getOptions(OPTION_CATEGORY);
//		options.registerOption(MY_OPTION_KEY, OptionType.STRING_TYPE, "Description of MyOption", null, "default");
//		myOptionValue = options.getString(MY_OPTION_KEY, "default");

		Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
			public void uncaughtException(Thread t, Throwable e) {
				// Log the exception here using your logging framework
				Msg.error(this, "Uncaught exception in thread '" + t.getName() + "': " + e.getMessage());
				Msg.error(this, Errors.getStackTraceAsString(e));
			}
		});
	}

	@Override
	protected void programActivated(Program program) {
		// Load the UI and dependencies
		String pluginName = getName();
		String threadId = getPanelThread();
		String assistantId;
		try {
			assistantId = getAssistantId();
		} catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException e) {
			// I dunno
			e.printStackTrace();
			return;
		}
		provider = new GhidraLlmIntegraionPanelProvider(this, pluginName, openAiService, threadId, assistantId,
				config.model);
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));

		GhidraLlmIntegrationTask service = new GhidraLlmIntegrationTask(program, provider, openAiService, threadId,
				toolMap);
		Msg.info(this, "Starting LLM service for " + program.getName());
		TaskBuilder.withTask(service).setCanCancel(true).setHasProgress(false).setTitle("LLM Integration")
				.launchInBackground(monitor);
		services.put(program, service);
	}

}
