package security.providers;


import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class DHProvider {


	private  BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
			+ "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b" + "410b7a0f12ca1cb9a428cc", 16);

	private  BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
			+ "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b" + "f0573bf047a3aca98cdf3b", 16);

	private KeyPair      keyPair;
	private KeyPairGenerator keyGen;
	private DHParameterSpec dhParams;
	public DHProvider() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		dhParams = new DHParameterSpec(p512, g512); 
		keyGen = KeyPairGenerator.getInstance("DH", "BC");
	        keyGen.initialize(dhParams);
	        keyPair = keyGen.generateKeyPair();
	}
	public  byte[] getSharedKey(byte[] pubKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {
		
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
       
        aKeyAgree.init(keyPair.getPrivate());
        
        PublicKey publicKeyb = 
        	   KeyFactory.getInstance("DiffieHellman", "BC").generatePublic(new X509EncodedKeySpec(pubKey));
        aKeyAgree.doPhase(publicKeyb, true);
        MessageDigest	hash = MessageDigest.getInstance("SHA256", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        return aShared;
	}
	public  byte[] getPublicKey() {
		return keyPair.getPublic().getEncoded();
	}
}
