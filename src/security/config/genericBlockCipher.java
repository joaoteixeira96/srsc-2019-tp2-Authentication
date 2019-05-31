package security.config;


import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class genericBlockCipher {

	public static byte[] encrypt(byte[] input, byte[] ks) throws InvalidKeyException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {

		FileInputStream inputStream = new FileInputStream("ciphersuite.properties");
		Properties properties = new Properties();
		properties.load(inputStream);
		String[] ciphersuite = properties.getProperty("CIPHERSUITE").split("/");
		String method = ciphersuite[0];
		String mode = ciphersuite[1];
		String padding = ciphersuite[2];

		SecretKeySpec key = new SecretKeySpec(ks, method);
		Cipher cipher = Cipher.getInstance(method + "/" + mode + "/" + padding, "SunJCE");

		byte[] cipherText = null;
		int ctLength = 0;

		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = new byte[cipher.getOutputSize(input.length)];
		ctLength += cipher.update(input, 0, input.length, cipherText, ctLength);
		ctLength += cipher.doFinal(cipherText, ctLength);
		return cipherText;


	}

	public static byte[] decrypt(byte[] encryptedMessage, byte[] ks) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {

		FileInputStream inputStream = new FileInputStream("ciphersuite.properties");
		Properties properties = new Properties();
		properties.load(inputStream);
		String[] ciphersuite = properties.getProperty("CIPHERSUITE").split("/");
		String method = ciphersuite[0];
		String mode = ciphersuite[1];
		String padding = ciphersuite[2];

		SecretKeySpec key = new SecretKeySpec(ks, method);
		Cipher cipher = Cipher.getInstance(method + "/" + mode + "/" + padding, "SunJCE");

		cipher.init(Cipher.DECRYPT_MODE, key);

		// decryption

		byte[] buf = new byte[cipher.getOutputSize(encryptedMessage.length)];
		int ptLength = cipher.update(encryptedMessage, 0, encryptedMessage.length, buf, 0);
		ptLength += cipher.doFinal(buf, ptLength);
		return buf;
	}
}
