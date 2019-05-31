package server.Authentication;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.omg.PortableInterceptor.DISCARDING;

import Utils.UtilsBase;
import security.config.SHA256;
import security.config.genericBlockCipher;
import security.providers.DHProvider;

public class AuthenticationAPI {

	private static final String DIVIDER = " ";
	private static final String NOT_AUTHENTICATED = "Not Authenticated";
	private static final String AUTHENTICATED = "Authenticated";
	private static final String filePath = "src/server/Authentication/authentication";
	private static String nonceA= Integer.toString(Integer.MIN_VALUE);
	Dictionary<String, User> usersDictionary = new Hashtable<>();
	private static DHProvider hdprovider;
	private static String currentUser;

	public static boolean login(String username, String password, Dictionary<String, User> users) { // TODO: take Static
		return users.get(username).verifyUser(password);
	}
	
	public boolean  checkUsername (String username) throws Exception
	{
			if(getUsername(username)!=null ) {
				currentUser = username;
				return true;
			}
			return false ;
	}

	public String sendChallenge() throws Exception {
		
	  nonceA = Integer.toString(new SecureRandom().nextInt());
	  //Will be unique for each client
	  hdprovider = new DHProvider();
	  String pubKeyA = Base64.getEncoder().encodeToString((hdprovider.getPublicKey()));
	  
	  System.out.println("sendChallenge method: " + " nonceA: " + nonceA + " pubKeyA: "+ pubKeyA);
	  return nonceA+DIVIDER+pubKeyA;
	}
	public String challangeResponse(String message) throws Exception {
		Encoder encoder = Base64.getEncoder();
		Decoder decoder = Base64.getDecoder();
		
		String[] messageArgs = message.split(DIVIDER);
		String encryptedPWDNonceA = messageArgs[0]; 
		String nonceC= messageArgs[1];
		String pubKeyC = messageArgs[2];
		// DH returns shared of 1024 bitskey and a AES only supports 256 bits so we make a SHA to output 256 bits
		byte[] pubKeyCBytes = decoder.decode(pubKeyC);
		byte[] sharedKey= hdprovider.getSharedKey(pubKeyCBytes);
		String sharedKeyToString = encoder.encodeToString(sharedKey);
		byte[] ks = SHA256.generateHash(sharedKeyToString); 
		byte[] encryptedMessage = decoder.decode(encryptedPWDNonceA);//ate aqui esta bem
		System.out.println(encryptedMessage);
		byte[] decryptMessage = genericBlockCipher.decrypt(encryptedMessage, ks);
		String [] decryptedPWDNonceA = new String(decryptMessage).split(DIVIDER);
		System.out.println("Password form client:" +decryptedPWDNonceA[0]);
		String password = decryptedPWDNonceA[0];
		String nonceA = decryptedPWDNonceA[1]; //TODO : check this nonceA > old nonceA
		
		System.out.println("challangeResponse method : "+ " encryptedPWDNonceA: " + encryptedPWDNonceA + 
				" nonceC: " + nonceC + " pubKeyC: " + pubKeyC + " ks: " + ks + " password: " +password + " nonceA: "+ nonceA);
		if(passwordMatch(getUsername(currentUser)[1], password)) {
			return AUTHENTICATED;
		} 
		return NOT_AUTHENTICATED;
	}
	
	private static boolean passwordMatch(String filePassword, String receivedPassword) {
		return filePassword.equals(receivedPassword);	
	}
	//Get username and his password
	private static String[] getUsername(String username) throws Exception {
		File file = new File(filePath);
		Scanner sc = new Scanner(file);
		try {
			while (sc.hasNextLine()) {
				String[] line = sc.nextLine().split(DIVIDER);
				if (username.equals(line[0])) {
					sc.close();
					return line;
				}
			}
		} catch (Exception e) {
			System.err.println(AuthenticationAPI.class + " user not found");
		}
		return null;
	}

	public static void main(String args[]) throws Exception {
		Dictionary<String, User> users = new Hashtable<>();

		users.put("Deus", new User("Deus", "aaa"));
		users.put("Hitler", new User("Deus", "bbb"));
		users.put("Conan Osiris", new User("Deus", "cc"));
		users.put("Batista", new User("Deus", "ddd"));
		users.put("Julio", new User("Deus", "eee"));
		System.out.println(login("Deus", "aaa", users));
		System.out.println(login("Deus", "bbb", users));

		String testUser = "Deus";
		String testUserPassword = "aaa";

//		System.out.println("User: " + testUser + " with password: " + testUserPassword + " authenticated?: "
//				+ login(testUser, testUserPassword));
	}
}
