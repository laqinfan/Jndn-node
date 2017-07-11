package edu.memphis.cs.netlab.nacapp;

import net.named_data.jndn.Face;
import net.named_data.jndn.Name;
import net.named_data.jndn.encrypt.Consumer;
import net.named_data.jndn.encrypt.ConsumerDb;
import net.named_data.jndn.encrypt.Sqlite3ConsumerDb;
import net.named_data.jndn.security.KeyChain;

/**
 * Description:
 * <p>
 * Author: lei
 */

public abstract class NACConsumers {
	public static Consumer newConsumer(
		Face f, KeyChain kc, Name group, Name consumer, String dbFilePath) {
		try {
			return new Consumer(f, kc, group, consumer, new Sqlite3ConsumerDb(dbFilePath));
		} catch (ConsumerDb.Error error) {
			throw new RuntimeException(error);
		}
	}
}
