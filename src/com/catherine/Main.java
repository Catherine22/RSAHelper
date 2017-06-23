package com.catherine;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {

	private final static String[] secretKeys = { "Czc0SC", "xvaw089", "ca90vj", "NCV0dk", "Xhf0i4m" };
	private static List<String> encrypedSecretKeys = new ArrayList<>();
	private static String modulus;
	private static String exponent;

	public static void main(String[] args) {
		try {
			System.out.println(
					"Copy and paste the following infomation to your android project. Paste encrypted secretKeys on C/C++ side and paste modulus and exponent on JAVA side.");
			// generate a keyPair
			PrivateKey key = generateRSAKeyPair();
			// 把打印出来的值modulus和exponent贴到应用端
			for (int i = 0; i < secretKeys.length; i++) {
				String s = encryptRSA(key, secretKeys[i]);
				encrypedSecretKeys.add(s);
				// 把打印出来的值贴到应用端
				System.out.println("secret key(" + decryptRSA(s) + "):" + s);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * 
	 * Generate a keyPair by RSA algorithm
	 * 
	 * @return PrivateKey Use this key to encrypt your content
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws ClassNotFoundException
	 */
	public static PrivateKey generateRSAKeyPair()
			throws NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException {
		KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(Algorithm.KEYPAIR_ALGORITHM);
		// 限制长度
		kpGenerator.initialize(1024);
		// 创建非对称密钥对，即KeyPair对象
		KeyPair keyPair = kpGenerator.generateKeyPair();
		// 获取密钥对中的公钥和私钥对象
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		// 打印base64编码后的公钥和私钥值，每次都不一样
		// System.out.println("==>public key: " +
		// bytesToHexString(publicKey.getEncoded()));
		// System.out.println("==>private key: " +
		// bytesToHexString(privateKey.getEncoded()));

		// SecretKeySpec没有提供类似对称密钥的方法直接从二进制数值还原
		Class clazz = Class.forName("java.security.spec.RSAPublicKeySpec");
		KeyFactory kFactory = KeyFactory.getInstance(Algorithm.KEYPAIR_ALGORITHM);
		RSAPublicKeySpec rsaPublicKeySpec = (RSAPublicKeySpec) kFactory.getKeySpec(publicKey, clazz);
		// 对RSA算法来说，只要获取modulus和exponent这两个RSA算法特定的参数就可以了

		modulus = Base64.getEncoder().encodeToString(rsaPublicKeySpec.getModulus().toByteArray());
		exponent = Base64.getEncoder().encodeToString(rsaPublicKeySpec.getPublicExponent().toByteArray());
		System.out.println("modulus:" + modulus);
		System.out.println("exponent:" + exponent);
		return privateKey;
	}

	/**
	 * You can component a publicKey by a specific pair of values - modulus and
	 * exponent.
	 * 
	 * @param modulus
	 *            When you generate a new RSA KeyPair, you'd get a PrivateKey, a
	 *            modulus and an exponent.
	 * @param exponent
	 *            When you generate a new RSA KeyPair, you'd get a PrivateKey, a
	 *            modulus and an exponent.
	 * @throws ClassNotFoundException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static Key converStringToPublicKey(BigInteger modulus, BigInteger exponent)
			throws ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] modulusByteArry = modulus.toByteArray();
		byte[] exponentByteArry = exponent.toByteArray();

		// 由接收到的参数构造RSAPublicKeySpec对象
		RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(new BigInteger(modulusByteArry),
				new BigInteger(exponentByteArry));
		// 根据RSAPublicKeySpec对象获取公钥对象
		KeyFactory kFactory = KeyFactory.getInstance(Algorithm.KEYPAIR_ALGORITHM);
		PublicKey publicKey = kFactory.generatePublic(rsaPublicKeySpec);
		// System.out.println("==>public key: " +
		// bytesToHexString(publicKey.getEncoded()));
		return publicKey;
	}

	/**
	 * Encrypt messages by RSA algorithm
	 * 
	 * @param key
	 * @param message
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encryptRSA(PrivateKey key, String message)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		byte[] msg = message.getBytes(Algorithm.CHARSET); // 待加解密的消息
		Cipher c1 = Cipher.getInstance(Algorithm.rules.get("RSA")); // 创建一个Cipher对象，注意这里用的算法需要和Key的算法匹配
		c1.init(Cipher.ENCRYPT_MODE, key);
		byte[] decryptedData = c1.doFinal(msg);
		return Base64.getEncoder().encodeToString(decryptedData);// 加密后的数据
	}

	/**
	 * Decrypt messages by RSA algorithm<br>
	 * 
	 * @param message
	 * @return Original message
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 * @throws ClassNotFoundException
	 */
	public static String decryptRSA(String message) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
			InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeySpecException {
		Cipher c2 = Cipher.getInstance(Algorithm.rules.get("RSA")); // 创建一个Cipher对象，注意这里用的算法需要和Key的算法匹配
		BigInteger m = new BigInteger(Base64.getDecoder().decode(modulus));
		BigInteger e = new BigInteger(Base64.getDecoder().decode(exponent));
		c2.init(Cipher.DECRYPT_MODE, converStringToPublicKey(m, e)); // 设置Cipher为解密工作模式，需要把Key传进去
		byte[] decryptedData = c2.doFinal(Base64.getDecoder().decode(message));
		return new String(decryptedData, Algorithm.CHARSET);
	}
}
