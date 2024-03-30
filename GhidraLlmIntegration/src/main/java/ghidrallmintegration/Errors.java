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
}
