package edu.memphis.cs.netlab.nacapp;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Description:
 * <p>
 * Author: lei
 */

public abstract class Utils {

	public static String nowIsoString() {
		TimeZone tz = TimeZone.getTimeZone("UTC");
//    DateFormat df = SimpleDateFormat.getDateTimeInstance();
		DateFormat df = new SimpleDateFormat("yyyyMMdd'T'HHmmss"); // Quoted "Z" to indicate UTC, no timezone offset
		df.setTimeZone(tz);
		String nowAsISO = df.format(new Date());
		return nowAsISO;
	}

	public static String nameComponent(String unchecked) {
		if (unchecked.indexOf("/") != 0) {
			unchecked = "/" + unchecked;
		}
		return unchecked;
	}
}
