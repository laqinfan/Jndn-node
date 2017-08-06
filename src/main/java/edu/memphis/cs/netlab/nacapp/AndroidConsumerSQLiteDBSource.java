package edu.memphis.cs.netlab.nacapp;

import net.named_data.jndn.encrypt.AndroidSqlite3ConsumerDb;
import net.named_data.jndn.encrypt.ConsumerDb;
import net.named_data.jndn.encrypt.Sqlite3ConsumerDb;

import java.io.File;

/**
 * Description:
 * <p>
 * Author: lei
 * Date  : 8/6/17.
 */
public class AndroidConsumerSQLiteDBSource extends ConsumerSQLiteDBSource {
	public AndroidConsumerSQLiteDBSource(String dbPath){
		super(dbPath);
	}

	@Override
	public ConsumerDb getDB() {
		return new AndroidSqlite3ConsumerDb(dbPath);
	}

}