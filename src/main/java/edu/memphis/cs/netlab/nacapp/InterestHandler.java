package edu.memphis.cs.netlab.nacapp;

import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnRegisterSuccess;

/**
 * Description:
 * <p>
 * Author: lei
 * Date  : 7/19/17.
 */
public interface InterestHandler extends OnInterestCallback, OnRegisterSuccess {
	String path();
}