package ghidrallmintegration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.symbol.*;

public class Json {

	public static Map<String, Object> empty() {
		Map<String, Object> jsonMap = new HashMap<>();
		return jsonMap;
	}

	public static Map<String, Object> toJson(Reference reference) {
		var map = empty();
		Address fromAddr = reference.getFromAddress();
		map.put("from", fromAddr.toString());
		map.put("to", reference.getToAddress().toString());
		return map;
	}

	public static Map<String, Object> toJson(DataType dataType) {
		var map = empty();
		map.put("description", dataType.getDescription());
		map.put("name", dataType.getName());
		map.put("displayName", dataType.getDisplayName());
		return map;
	}

	public static Map<String, Object> toJson(Function function) {
		var map = empty();
		map.put("name", function.getName());

		FunctionSignature signature = function.getSignature();
		{
			var signatureMap = empty();
			signatureMap.put("callingConventionName", signature.getCallingConventionName());
			signatureMap.put("comment", signature.getComment());
			signatureMap.put("name", signature.getName());
			signatureMap.put("prototypeString", signature.getPrototypeString());
			signatureMap.put("returnType", toJson(signature.getReturnType()));

			var argumentsJson = new ArrayList<Map<String, Object>>();
			for (var argument : signature.getArguments()) {
				var argMap = empty();
				argMap.put("name", argument.getName());
				argMap.put("comment", argument.getComment());
				var dataType = toJson(argument.getDataType());
				argMap.put("dataType", dataType);
				argumentsJson.add(argMap);
			}
			signatureMap.put("arguments", argumentsJson);

			map.put("signature", signatureMap);
		}

		map.put("callingConvention", function.getCallingConventionName());
		map.put("entryAddress", function.getEntryPoint().toString());
		map.put("functionSize", function.getBody().getNumAddresses());

		var references = new ArrayList<Map<String, Object>>();
		ReferenceIterator referenceIterator = function.getProgram().getReferenceManager().getReferencesTo(function.getEntryPoint());
		while (referenceIterator.hasNext()) {
			Reference reference = referenceIterator.next();
			references.add(toJson(reference));
		}
		map.put("references", references);

		return map;
	}
}
