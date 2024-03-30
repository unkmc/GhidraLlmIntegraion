package ghidrallmintegration.tools;

import java.util.ArrayList;
import java.util.List;

public record PropertyDetail(String type, String description, List<String> enumValues) {
	public PropertyDetail(String type, String description) {
		this(type, description, new ArrayList<String>());
	}
}
