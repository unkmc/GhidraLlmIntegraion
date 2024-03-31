package ghidrallmintegration;

import java.io.PrintWriter;
import java.io.StringWriter;

public class Errors {
	public static String getStackTraceAsString(Throwable e) {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		e.printStackTrace(pw);
		return sw.toString();
	}

	public static String noFunctionFound(String address) {
		return "No function found at entryAddress \"" + address + "\"";
	}

	public static String noAddress(String address) {
		return "Invalid address format or address not found for address, \"" + address + "\"";
	}
}
