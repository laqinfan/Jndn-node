package edu.memphis.cs.netlab.nacapp;

import net.named_data.jndn.encrypt.ConsumerDb;
import net.named_data.jndn.encrypt.Sqlite3ConsumerDb;

import java.io.File;

/**
 * Description:
 * <p>
 * Author: lei
 * Date  : 8/6/17.
 */
public class ConsumerSQLiteDBSource implements ConsumerDBSource {
	public ConsumerSQLiteDBSource(String dbPath){
		this.dbPath = dbPath;
	}

	@Override
	public ConsumerDb getDB() {
		try {
			return new Sqlite3ConsumerDb(dbPath);
		} catch (ConsumerDb.Error error) {
			throw new RuntimeException(error);
		}
	}

	@Override
	public boolean deleteDB() {
		if (!isMemoryDB()){
			File f = new File(dbPath);
			return f.delete();
		}
		return false;
	}

	@Override
	public boolean isMemoryDB() {
		return dbPath.endsWith(":memory:");
	}

	final protected String dbPath;
}