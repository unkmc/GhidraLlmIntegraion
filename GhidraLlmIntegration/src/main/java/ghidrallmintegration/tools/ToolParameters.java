package ghidrallmintegration.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ToolParameters {
	private final Map<String, PropertyDetail> properties;
	private final List<String> required;

	private ToolParameters(Builder builder) {
		this.properties = builder.properties;
		this.required = builder.required;
	}

	public Map<String, Object> toMap() {
		Map<String, Object> result = new HashMap<>();
		Map<String, Object> propertiesMap = new HashMap<>();
		for (var entry : properties.entrySet()) {
			Map<String, Object> detailMap = new HashMap<>();
			detailMap.put("type", entry.getValue().type());
			detailMap.put("description", entry.getValue().description());
			if (entry.getValue().enumValues() != null) {
				detailMap.put("enum", entry.getValue().enumValues());
			}
			propertiesMap.put(entry.getKey(), detailMap);
		}
		result.put("type", "object");
		result.put("properties", propertiesMap);
		result.put("required", required);
		return result;
	}

	public static class Builder {
		private final Map<String, PropertyDetail> properties = new HashMap<>();
		private final List<String> required = new ArrayList<>();

		public Builder addParameter(String type, String name, String description) {
			properties.put(name, new PropertyDetail(type, description));
			required.add(name);
			return this;
		}

		public Builder addParameter(String type, String name, String description, List<String> enumValues) {
			properties.put(name, new PropertyDetail(type, description, enumValues));
			required.add(name);
			return this;
		}

		public ToolParameters build() {
			return new ToolParameters(this);
		}
	}

	public static Builder builder() {
		return new Builder();
	}
}
