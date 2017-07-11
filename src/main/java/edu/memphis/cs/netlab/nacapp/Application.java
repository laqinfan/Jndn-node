package edu.memphis.cs.netlab.nacapp;

import net.named_data.jndn.Name;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Description:
 * <p>
 * Author: lei
 * Date  : 7/7/17.
 */
public class Application {
	private static Logger logger = Global.LOGGER;

	public static void main(String[] args) {
		final Name group = new Name(Global.LOCAL_HOME + "/READ");
		TemperatureReader reader = new TemperatureReader(group);
		reader.init(new Name(Global.APP_PREFIX));

		TemperatureReader.OnDataCallback onData = new TemperatureReader.OnDataCallback() {
			@Override
			public void onData(String desc, int temperature) {
				logger.log(Level.INFO, String.format("%s: %d", desc, temperature));
			}
		};

		Runnable onRequestPermissionSuccess = new Runnable() {
			@Override
			public void run() {
				logger.info("permission granted.");
				reader.read(new Name("bedroom"), onData);
			}
		};

		Runnable onRequestPermissionFailed = new Runnable() {
			@Override
			public void run() {
				logger.warning("permission not granted.");
			}
		};

		Runnable onRegisterIdentity = new Runnable() {
			@Override
			public void run() {
				reader.requestGrantPermission(
					"bedroom", onRequestPermissionSuccess, onRequestPermissionFailed);
			}
		};

		logger.info("registerIdentity...");
		reader.registerIdentity(onRegisterIdentity);
		reader.startFaceProcessing();
	}
}
