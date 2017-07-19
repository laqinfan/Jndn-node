package edu.memphis.cs.netlab.nacapp;

import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.encrypt.Consumer;
import net.named_data.jndn.encrypt.EncryptError;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.util.Blob;

import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static edu.memphis.cs.netlab.nacapp.Global.*;

/**
 * Description:
 * <p>
 * Author: lei
 */

public class TemperatureReader extends NACNode {
	private final static String TAG = NACNode.class.getName();
	//  private static final Logger LOGGER = Logger.getLogger(TAG);

	private static final Logger LOGGER = Global.LOGGER;

	public TemperatureReader(Name group) {
		super();
		m_group = group;
	}

	public interface OnDataCallback { void onData(String desc, int temperature); }

	public void read(final Name location, final OnDataCallback callback) {
		Name servicePrefix = new Name(
			LOCAL_HOME + SAMPLE + LOCATION + location + "/temperature/" + Utils.nowIsoString());
		m_consumer.consume(servicePrefix,
			new Consumer.OnConsumeComplete() {
				@Override
				public void onConsumeComplete(Data data, Blob result) {
					int tempReading = result.buf().getInt();
					LOGGER.info("GOT temperature: " + String.valueOf(tempReading));
					callback.onData("success", tempReading);
				}
			},
			new EncryptError.OnError() {
				@Override
				public void onError(EncryptError.ErrorCode errorCode, String message) {
					LOGGER.log(Level.SEVERE,
						"Error consuming " + servicePrefix.toUri() + ": " + errorCode.name());
					LOGGER.log(Level.SEVERE, message);
					try {
						callback.onData("Error: " + errorCode.name(), 0);
					} catch (Throwable e) {
						LOGGER.log(Level.SEVERE, e.getMessage());
					}
					LOGGER.info("restart reading in 3 seconds...");
					try {
						TimeUnit.SECONDS.sleep(3);
						read(location, callback);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			});
	}

	public void requestGrantPermission(
		String location, final Runnable onSuccess, final Runnable onFail) {
		final String datatype = LOCATION + Utils.nameComponent(location);
		super.requestGrantPermission(
			m_consumerWrapper.getCertificate().getName(), datatype, onSuccess, onFail);
	}

	public void registerIdentity(final Runnable onSuccess) {
		OnRegisterIdentitySuccess callback = new OnRegisterIdentitySuccess() {
			@Override
			public void onNewCertificate(IdentityCertificate cert) {
				//				m_consumerWrapper.setCertificate(cert);
				onSuccess.run();
			}
		};

		Data cert = m_consumerWrapper.getCertificate();
		Name certName = cert.getName();
		super.registerIdentity(certName, cert, callback);
	}

	@Override
	public void init(Name appPrefix) {
		super.init(appPrefix);
		initConsumer(appPrefix);
	}

	private void initConsumer(Name appPrefix) {
		Name consumerName = new Name(appPrefix);
		consumerName.append("Consumer");
		m_consumerWrapper =
			ConsumerWrapper.make(consumerName, m_group, m_keychain, m_face, CONSUMER_DB_PATH);
		m_consumer = m_consumerWrapper.getConsumer();
	}

	public Consumer getConsumer() {
		return m_consumer;
	}

	public ConsumerWrapper getConsumerWrapper() {
		return m_consumerWrapper;
	}

	public Name getGroup() {
		return m_group;
	}

	private Consumer m_consumer;
	private ConsumerWrapper m_consumerWrapper;
	private final Name m_group;
}
