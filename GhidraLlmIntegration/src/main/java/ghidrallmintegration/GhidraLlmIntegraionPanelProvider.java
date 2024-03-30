package ghidrallmintegration;

import javax.swing.*;

import com.theokanning.openai.OpenAiResponse;
import com.theokanning.openai.messages.Message;
import com.theokanning.openai.messages.MessageContent;
import com.theokanning.openai.messages.MessageRequest;
import com.theokanning.openai.runs.RunCreateRequest;
import com.theokanning.openai.service.OpenAiService;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.HashSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import docking.ActionContext;
import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.Msg;
import resources.Icons;
import docking.action.DockingAction;
import docking.action.ToolBarData;

// Inside your plugin class
class GhidraLlmIntegraionPanelProvider extends ComponentProvider {
	private JPanel panel;
	private DockingAction action;
	private JTextArea outputArea; // For displaying LLM responses
	private JTextField inputField; // For user to input queries
	private JButton submitButton; // To submit queries
	private OpenAiService openAiService;
	private String threadId;
	private String assistantId;
	private String model;
	private ScheduledExecutorService scheduler;
	private final long updateInterval = 5; // Seconds

	public GhidraLlmIntegraionPanelProvider(Plugin plugin, String owner, OpenAiService openAiService, String threadId,
			String assistantId, String model) {
		super(plugin.getTool(), owner, owner);
		this.openAiService = openAiService;
		this.threadId = threadId;
		this.assistantId = assistantId;
		this.model = model;
		buildPanel();
		createActions();
	}

	private void buildPanel() {
		panel = new JPanel(new BorderLayout());

		// Output area
		outputArea = new JTextArea(5, 25);
		outputArea.setEditable(false); // Make sure users can't edit LLM responses
		outputArea.setLineWrap(true); // Enable line wrapping
		outputArea.setWrapStyleWord(true); // Wrap lines by words rather than characters for better readability
		JScrollPane scrollPane = new JScrollPane(outputArea);
		panel.add(scrollPane, BorderLayout.CENTER);

		// Input area and Submit button panel
		JPanel inputPanel = new JPanel(new BorderLayout());
		inputField = new JTextField(25);
		inputPanel.add(inputField, BorderLayout.CENTER); // Add input field to center of input panel

		submitButton = new JButton("Submit");
		inputPanel.add(submitButton, BorderLayout.EAST); // Add submit button to the east (right) of input panel

		ActionListener submitAction = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				submitQuery(inputField.getText());
				inputField.setText("");
			}
		};
		submitButton.addActionListener(submitAction);
		inputField.addActionListener(submitAction);

		// Add the input panel to the main panel, position it at the bottom
		panel.add(inputPanel, BorderLayout.SOUTH);
		setVisible(true);
		startUpdating();
	}

	private void startUpdating() {
		scheduler = Executors.newSingleThreadScheduledExecutor();
		scheduler.scheduleAtFixedRate(this::updateOutputArea, 0, updateInterval, TimeUnit.SECONDS);
	}

//	private String latestMessageId = "";
	private HashSet<String> seenMessageIds = new HashSet<>();

	private void updateOutputArea() {
		boolean hasMore = true;
		StringBuilder newMessagesBuilder = new StringBuilder();

//		Msg.info(this, "Polling thread \"" + threadId + "\" for new messages...");
		while (hasMore) {
			OpenAiResponse<Message> currentThreadState = fetchMessages();
			if (currentThreadState != null && !currentThreadState.data.isEmpty()) {
				// Process and append new messages
				List<Message> messages = currentThreadState.data;
//				Msg.info(this, "Found " + messages.size() + " messages in thread batch.");
				for (int i = messages.size() - 1; i >= 0; i--) {
					Message message = messages.get(i);
//					Msg.info(this, "Message contents:");
//					for (MessageContent content : message.getContent()) {
//						String text = content.getText().getValue();
//						Msg.info(this, "  " + text);
//					}

					if (seenMessageIds.contains(message.getId())) {
						// We already have this message
//						Msg.info(this, "Already have this one.");
						continue;
					}
					for (MessageContent content : message.getContent()) {
						String text = content.getText().getValue();
//						Msg.info(this, "Found a new message: " + text);
						newMessagesBuilder.append(text).append("\n");
						seenMessageIds.add(message.getId());
//						latestMessageId = message.getId();
					}
				}
				hasMore = currentThreadState.hasMore;
			} else {
				hasMore = false; // No more data, I guess
			}
		}

		// Now, update the outputArea with the new messages, if any
		String newMessages = newMessagesBuilder.toString();
		if (!newMessages.isEmpty()) {
			SwingUtilities.invokeLater(() -> {
				outputArea.append("\n"); // newline between separate messages, might need more later?
				outputArea.append(newMessages); 
			});

		}
	}

	private OpenAiResponse<Message> fetchMessages() {
//		if (latestMessageId.isEmpty()) {
		return openAiService.listMessages(threadId); // Initial fetch
//		}
		// Apparently I don't know how this works, because it keeps returning 1 message
		// no matter what
//		ListSearchParameters parameters = ListSearchParameters.builder().after(latestMessageId).build();
//		return openAiService.listMessages(threadId, parameters); // Paginated fetch
	}

	// TODO: Customize actions if needed
	private void createActions() {
		action = new DockingAction("My Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	private void submitQuery(String query) {
		Msg.info(this, "Sending query: " + query);
		// package message
		MessageRequest messageRequest = MessageRequest.builder().content(query).build();
		openAiService.createMessage(threadId, messageRequest);

		// build Run
		RunCreateRequest runRequest = RunCreateRequest.builder().model(model).assistantId(assistantId).build();
		openAiService.createRun(threadId, runRequest);
	}

	@Override
	public void closeComponent() {
		super.closeComponent();
		if (scheduler != null) {
			scheduler.shutdownNow(); // Stop polling for updates when the component is closed
		}
	}

}
