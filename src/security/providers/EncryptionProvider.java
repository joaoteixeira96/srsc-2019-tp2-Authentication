package security.providers;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionProvider {
	
	// key settings
	public static final int KEYCHAIN_SIZE = 5;

	// Crypto files parameters
	public static final String CRYPTO_CIPHER_TOKEN = "CIPHERSUITE";
	public static final String CRYPTO_CIPHER_KEY_SIZE_TOKEN = "KEYSIZE";
	public static final String CRYPTO_CIPHER_IV_TOKEN = "IV";
	public static final String CRYPTO_SIGNATURE_TOKEN = "SIGNATURE";
	public static final String CRYPTO_PROVIDER_TOKEN = "PROVIDER";

	// other constatns
	public static final String DEFAULT_SECURITY_PROVIDER = "SunJSSE";

	public static final String CIPHER_ECB_MODE = "ECB";
	public static final String CIPHER_CBC_MODE = "CBC";
	public static final String CIPHER_NOPADDING_MODE = "NoPadding";
	
	public static final String SIGNATURE_SPLIT = "with";

	// CRYPTO
	private Cipher cipher;
	private List<SecretKey> cipherKeys;
	private int cipherKeySize;
	private IvParameterSpec ivSpec;
	private String cipherAlgorithm, cipherMode, cipherPadding, signatureAlgorithm;
	private String signatureType;

	// PROVIDER
	private String provider;
	
	
	// KEYS
	private Map<String, PublicKey> pubKeys;
	private PrivateKey privKey;

	public EncryptionProvider(String provider) {
		// try to get user-specified provider, if it doesn't exist, default to BC
		this.provider = Security.getProvider(provider) != null ? provider : DEFAULT_SECURITY_PROVIDER;
		this.pubKeys = new HashMap<String, PublicKey>();
		this.cipherKeys = new LinkedList<SecretKey>();	
	}

	/* Setters */
	public void setCiphersuite(String ciphersuite, int keySize, byte[] ivBytes, String signature) throws Exception {

		String[] ciphersuiteParams = ciphersuite.split("/");
		if (ciphersuiteParams.length == 3) {
			// custom mode and padding
			cipherAlgorithm = ciphersuiteParams[0];
			cipherMode = ciphersuiteParams[1];
			cipherPadding = ciphersuiteParams[2];
		} else if (ciphersuiteParams.length == 1) {
			// mode and padding are set to default implementation values
			cipherAlgorithm = ciphersuite;
		} else {
			throw new Exception("Unknown ciphersuite!");
		}

		// Get corresponding cipher
		this.cipher = Cipher.getInstance(ciphersuite, provider);
		// Get key size for cipher
		this.cipherKeySize = keySize / 8;
		
		if (ivBytes != null) {
			// if the user specified IV, save it
			this.ivSpec = new IvParameterSpec(ivBytes);
		}
		
		// set signature algorithm
		this.signatureAlgorithm = signature;
		this.signatureType = signature.split(SIGNATURE_SPLIT)[1].toLowerCase();
	}
	
	public void pushKey(byte[] secret) {
		// creates a new key based on DH secret
		cipherKeys.add(new SecretKeySpec(secret, 0, cipherKeySize, cipherAlgorithm));
		// if the number of stored keys reaches a certain threshold, remove the oldest one
		// remember we iterate from last to first, the last one being the newest one
		if (cipherKeys.size() > KEYCHAIN_SIZE) {
			cipherKeys.remove(0);
		}
	}
	
	public void init(File keystoreFile, String keystorePassword, File truststoreFile, String currentUser) 
	throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		
		// load keystore
	    FileInputStream is = new FileInputStream(keystoreFile);
	    KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	    keystore.load(is, keystorePassword.toCharArray());
	    is.close();
	    
	    // load truststore
	    is = new FileInputStream(truststoreFile);
	    KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
	    truststore.load(is, keystorePassword.toCharArray());
	    is.close();
	   
	    // get user private key
	    if (signatureType != null) {
	    	String userAlias = currentUser + signatureType;
	    	privKey = (PrivateKey) keystore.getKey(userAlias, keystorePassword.toCharArray());
	    }
	    
	    // get all public keys from keystore
	    Enumeration<String> aliases = keystore.aliases();
	    while (aliases.hasMoreElements()) {
	    	String alias = aliases.nextElement();
	    	PublicKey pubKey = keystore.getCertificate(alias).getPublicKey();
	    	pubKeys.put(alias, pubKey);
	    }
	    // get all public keys from truststore
	    aliases = truststore.aliases();
	    while (aliases.hasMoreElements()) {
	    	String alias = aliases.nextElement();
	    	PublicKey pubKey = truststore.getCertificate(alias).getPublicKey();
	    	pubKeys.put(alias, pubKey);
	    }
	}

	/* Encryption/Decryption methods */
	
	public byte[] encrypt(byte[] cipherText, int ctLength) throws Exception {
		// encrypt with the most recent key
		return encrypt(cipherText, ctLength, cipherKeys.get(cipherKeys.size()-1));
	}
	
	public byte[] decrypt(byte[] cipherText, int ctLength) throws Exception {
		
		byte[] decryptedOutput = null;
		
		// try to decrypt starting with the most recent key we know of
		ListIterator<SecretKey> keychain = cipherKeys.listIterator(cipherKeys.size());
		do {
			try {
				decryptedOutput = decrypt(cipherText, ctLength, keychain.previous());
				break;
			} catch (Exception e) {
				// continue if we've got keys to try
				if (!keychain.hasPrevious()) {
					throw e;
				}
			}
		} while (keychain.hasPrevious());
		
		return decryptedOutput;
	}

	private byte[] encrypt(byte[] plainText, int ptLength, SecretKey key) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {

		// initialize the cipher and do the first step of encryption
		if (cipherMode == null || cipherMode.equals(CIPHER_ECB_MODE)) {
			cipher.init(Cipher.ENCRYPT_MODE, key);
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		}
		
		byte[] signedText = sign(plainText, ptLength);

		// processing for NoPadding ciphersuites, generates custom padding
		int rndPaddingSize = 0;
		byte[] rndPadding = null;
		
		if (cipherMode != null && cipherPadding != null) {
			if ((cipherMode.equals(CIPHER_CBC_MODE) || cipherMode.equals(CIPHER_ECB_MODE))
					&& cipherPadding.equals(CIPHER_NOPADDING_MODE)) {
	
				// calculate custom padding
				rndPaddingSize = cipher.getBlockSize() - signedText.length % cipher.getBlockSize();
	
				if (rndPaddingSize == 0)
					rndPaddingSize = cipher.getBlockSize();
	
				rndPadding = new byte[rndPaddingSize];
				new Random().nextBytes(rndPadding);
				// cast is safe, since padding size is always lower
				rndPadding[rndPaddingSize - 1] = (byte) rndPaddingSize;
			}
		}

		// allocate ciphertext byte array for SIGNATURE_SIZE || MESSAGE || SIGNATURE || OPTIONAL RND PADDING
		byte[] cipherText = new byte[cipher.getOutputSize(signedText.length + rndPaddingSize)];

		// execute last step and fully encrypt by adding the signature and rnd padding if needed
		if (rndPaddingSize > 0) {
			int ctLength = cipher.update(signedText, 0, signedText.length, cipherText, 0);
			cipher.doFinal(rndPadding, 0, rndPaddingSize, cipherText, ctLength);
		} else {
			cipher.doFinal(signedText, 0, signedText.length, cipherText, 0);
		}
		
		return cipherText;
	}

	private byte[] decrypt(byte[] cipherText, int ctLength, SecretKey key)
			throws InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException, SecurityException, NoSuchAlgorithmException, 
			NoSuchProviderException, SignatureException, IOException, KeyStoreException {

		// initialize the cipher, decrypt fully and calculate message length
		if (cipherMode == null || cipherMode.equals(CIPHER_ECB_MODE)) {
			cipher.init(Cipher.DECRYPT_MODE, key);
		} else {
			cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		}

		byte[] signedText = cipher.doFinal(cipherText, 0, ctLength);

		// processing for NoPadding ciphersuites
		int rndPaddingCount = 0;
		if (cipherMode != null && cipherPadding != null) {
			if ((cipherMode.equals(CIPHER_CBC_MODE) || cipherMode.equals(CIPHER_ECB_MODE))
					&& cipherPadding.equals(CIPHER_NOPADDING_MODE)) {
	
				rndPaddingCount = signedText[signedText.length - 1];
			}
		}

		return verify(signedText, signedText.length, rndPaddingCount, null);
	}

	

	public byte[] sign(byte[] plainText, int ptLength)
	throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {

		// start signing
		Signature sig = Signature.getInstance(signatureAlgorithm, provider);
		sig.initSign(privKey, new SecureRandom());
		sig.update(plainText);
		byte[] signature = sig.sign();

		// get signature size and put everything in a buffer
		ByteBuffer bb = ByteBuffer.allocate(Integer.BYTES + ptLength + signature.length);
		bb.putInt(signature.length);
		bb.put(plainText);
		bb.put(signature);

		return bb.array();
	}

	public byte[] verify(byte[] signedText, int stLength, int paddingSize, String username) 
	throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {

		// get the signature size
		byte[] signSzBytes = new byte[Integer.BYTES];
		for (int i = 0; i < Integer.BYTES; i++) {
			signSzBytes[i] = signedText[i];
		}
		ByteBuffer bb = ByteBuffer.wrap(signSzBytes);
		int signSz = bb.getInt();

		// calculate message offset and length
		int messageOffset = signSzBytes.length;
		int messageLength = stLength - signSzBytes.length - signSz - paddingSize;

		// parse message
		byte[] message = new byte[messageLength];
		System.arraycopy(signedText, messageOffset, message, 0, messageLength);

		// parse signature
		byte[] signature = new byte[signSz];
		System.arraycopy(signedText, messageOffset + messageLength, signature, 0, signSz);

		if (username == null) {
			// extract the user who's messaging us and get his public key
			DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(message));
			inputStream.skip(Long.BYTES * 2 + Integer.BYTES); // discard nonce, chat
																// magic number and
																// message type
			username = inputStream.readUTF();
			inputStream.close();
		}

		// retrieve sender public key
		PublicKey publicKey = pubKeys.get(username + signatureType);

		// verify signature
		Signature sig = Signature.getInstance(signatureAlgorithm, provider);
		sig.initVerify(publicKey);
		sig.update(message);
		if (!sig.verify(signature))
			throw new SecurityException("Message digital signature is invalid!");
			
		return message;

	}
}
