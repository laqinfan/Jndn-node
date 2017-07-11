package edu.memphis.cs.netlab.nacapp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class StringHelper {
	public static String toHex(byte[] bytes) {
		BigInteger bi = new BigInteger(1, bytes);
		return String.format("%0" + (bytes.length << 1) + "X", bi);
	}

	/*
	 * from: http://www.java2s.com/Code/Java/Data-Type/hexStringToByteArray.htm
	 */
	public static byte[] fromHex(String hex) {
		byte[] b = new byte[hex.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int index = i * 2;
			int v = Integer.parseInt(hex.substring(index, index + 2), 16);
			b[i] = (byte) v;
		}
		return b;
	}

	public static String joinStrings(String[] strs, String delimiter) {
		int n = strs.length;
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < n; i++) {
			sb.append(strs[i]);
			if (i < n - 1) {
				sb.append(delimiter);
			}
		}
		return sb.toString();
	}

	public static void randomBytes(byte[] bts) {
		//    TODO:
		//    SecureRandom random = new SecureRandom(seed);
		Random rnd = new Random(System.nanoTime());
		rnd.nextBytes(bts);
	}

	public static byte[] sha256(byte[] input) {
		try {
			MessageDigest d = MessageDigest.getInstance("SHA-256");
			return d.digest(input);
		} catch (NoSuchAlgorithmException e) {
			// should happen on android.
			throw new RuntimeException(e);
		}
	}
}
