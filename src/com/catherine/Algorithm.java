package com.catherine;

import java.util.HashMap;
import java.util.Map;

public class Algorithm {
	public final static String CHARSET = "UTF8";
	/**
	 * 在Android平台的JCE中，非对称Key的常用算法有“RSA”、“DSA”、“Diffie−Hellman”、“Elliptic Curve
	 * (EC)”等。
	 */
	public final static String KEYPAIR_ALGORITHM = "RSA";
	public final static String SINGLE_KEY_ALGORITHM = "DES";
	public final static Map<String, String> rules = new HashMap<>();;
	static {
		rules.put("DES", "DES/CBC/PKCS5Padding");
		rules.put("RSA", "RSA/ECB/PKCS1Padding");
	}
}
