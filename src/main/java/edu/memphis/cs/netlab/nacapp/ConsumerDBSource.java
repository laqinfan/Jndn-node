package edu.memphis.cs.netlab.nacapp;

import net.named_data.jndn.encrypt.ConsumerDb;

/**
 * Description:
 * <p>
 * Author: lei
 * Date  : 8/6/17.
 */
public interface ConsumerDBSource {

	ConsumerDb getDB();

	boolean deleteDB();

	boolean isMemoryDB();
}
