package ghidrallmintegration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.theokanning.openai.ListSearchParameters;
import com.theokanning.openai.OpenAiResponse;
import com.theokanning.openai.runs.Run;
import com.theokanning.openai.runs.SubmitToolOutputsRequest;
import com.theokanning.openai.runs.ToolCallFunction;
import com.theokanning.openai.runs.SubmitToolOutputRequestItem;
import com.theokanning.openai.service.OpenAiService;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidrallmintegration.tools.LlmTool;

public class GhidraLlmIntegrationTask extends Task {
	public static final int RUN_CHECK_INTERVAL = 5; // seconds
	GhidraLlmIntegraionPanelProvider provider;
	private ScheduledExecutorService scheduler;
	private OpenAiService openAiService;
	private String threadId;
	private Map<String, LlmTool> toolMap;

	public GhidraLlmIntegrationTask(Program program, GhidraLlmIntegraionPanelProvider provider,
			OpenAiService openAiService, String threadId, Map<String, LlmTool> toolMap) {
		super("GhidraLlmIntegrationService");
		this.provider = provider;
		this.openAiService = openAiService;
		this.threadId = threadId;
		this.toolMap = toolMap;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		scheduler = Executors.newSingleThreadScheduledExecutor();
		scheduler.scheduleAtFixedRate(this::checkForFunctionRuns, 0, RUN_CHECK_INTERVAL, TimeUnit.SECONDS);
	}

	private void checkForFunctionRuns() {
//		Msg.info(this, "Polling for open runs...");
		ListSearchParameters parameters = ListSearchParameters.builder().limit(2).build();
		OpenAiResponse<Run> runResponse = openAiService.listRuns(threadId, parameters);
		if (runResponse.data != null) {
//			Msg.info(this, "Found " + runResponse.data.size() + " runs.");
		}
		List<SubmitToolOutputRequestItem> toolRequests = new ArrayList<>();
		for (var run : runResponse.data) {
//			Msg.info(this, "Found a run: " + run);
			if (run.getStatus().equals("requires_action")
					&& run.getRequiredAction().getType().equals("submit_tool_outputs")) {
				var toolCalls = run.getRequiredAction().getSubmitToolOutputs().getToolCalls();
//				Msg.info(this, "Run \"" + run.getId() + "\" needs " + toolCalls.size() + " tool calls.");
				for (var toolCall : toolCalls) {
					if (toolCall.getType().equals("function")) {
//						Msg.info(this, "Run \"" + run.getId() + "\" needs a function call.");
						ToolCallFunction function = toolCall.getFunction();
						Msg.info(this, "Run requested function, \"" + function.getName() + "\" with arguments:" + function.getArguments());
						String callResult = callFunction(function);
						Msg.info(this, "Call result was \"" + callResult + "\", adding to result list...");
						toolRequests.add(SubmitToolOutputRequestItem.builder().toolCallId(toolCall.getId())
								.output(callResult).build());
//						Msg.info(this, "Result added.");
					}
				}
				Msg.info(this, "Total of " + toolRequests.size() + " tool responses were created, sending...");
				SubmitToolOutputsRequest toolOutputRequest = SubmitToolOutputsRequest.builder()
						.toolOutputs(toolRequests).build();
				Run submitResult = openAiService.submitToolOutputs(threadId, run.getId(), toolOutputRequest);
				Msg.info(this, "Tool output submission result: " + submitResult + "\n");
			} else {
//				Msg.info(this, "Run \"" + run.getId() + "\" does not need submit_tool_outputs");
			}
		}
	}

	private String callFunction(ToolCallFunction function) {
		try {
			Msg.info(this, "Will check toolMap for function matching name \"" + function.getName() + "\"");
			if (!toolMap.containsKey(function.getName())) {
				Msg.info(this, "Matching function for name, \"" + function.getName() + "\" was not found.");
				return "NO_RESULT";
			}
		} catch (Exception exception) {
			Msg.error(this, "Unable to check toolMap for function: " + exception);
			return "INTERNAL_ERROR";
		}

		try {
//			Msg.info(this, "Execution of function " + function.getName() + " was requested.");
			String returnValue = toolMap.get(function.getName()).execute(function.getArguments());
//			Msg.info(this, "returnValue was \"" + returnValue + "\"");
			return returnValue;
		} catch (Exception exception) {
			Msg.error(this, "Tool called by LLM threw an exception: " + exception + "\n" + Errors.getStackTraceAsString(exception));
			return exception.toString();
		}
	}

}
