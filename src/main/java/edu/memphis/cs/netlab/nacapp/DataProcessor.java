package edu.memphis.cs.netlab.nacapp;

import net.named_data.jndn.Data;

/**
 * Description:
 * <p>
 * Author: lei
 */

public interface DataProcessor { Data process(Data d) throws Exception; }
