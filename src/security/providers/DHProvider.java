package security.providers;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class DHProvider {


	private static BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
			+ "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b" + "410b7a0f12ca1cb9a428cc", 16);

	private static BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
			+ "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b" + "f0573bf047a3aca98cdf3b", 16);

	private KeyAgreement keyAgree;
	private KeyPair keyPair;
	
	public DHProvider() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		DHParameterSpec dhParamSpec = new DHParameterSpec(p512, g512);
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
		keyPairGen.initialize(dhParamSpec, new SecureRandom());
		keyPair = keyPairGen.generateKeyPair();
	}
	
	public byte[] getPublicNumber() {
		
		return ((DHPublicKey) keyPair.getPublic()).getY().toByteArray();
	}

	public byte[] generatePublicNumber() throws NoSuchAlgorithmException, InvalidKeyException {

		keyAgree = KeyAgreement.getInstance("DiffieHellman");
		keyAgree.init(keyPair.getPrivate());

		BigInteger pubKeyBI = ((DHPublicKey) keyPair.getPublic()).getY();
		byte[] pubKeyBytes = pubKeyBI.toByteArray();

		return pubKeyBytes;

	}
	
	public DHPublicKey getPublicKey() {
		return (DHPublicKey) keyPair.getPublic();
	}
	
	public DHPrivateKey getPrivateKey() {
		// !!! handle with care
		return (DHPrivateKey) keyPair.getPrivate();
	}

	public byte[] computeSharedSecret(byte[] pubKeyBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalStateException {

		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		BigInteger pubKeyBI = new BigInteger(1, pubKeyBytes);

		PublicKey pubKey = keyFactory.generatePublic(new DHPublicKeySpec(pubKeyBI, p512, g512));
		keyAgree.doPhase(pubKey, true);
		byte[] sharedKeyBytes = keyAgree.generateSecret();

		return sharedKeyBytes;
	}


}
