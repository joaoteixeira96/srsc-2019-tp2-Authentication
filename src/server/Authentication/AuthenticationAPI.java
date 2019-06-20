package server.Authentication;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Scanner;

import security.providers.DHProvider;
import security.providers.PKCS1Signature;
import security.providers.RetrieveInfoFromKeystore;
import security.providers.SHA256;
import security.providers.Token1024;
import security.providers.genericBlockCipher;

public class AuthenticationAPI {

	private static final Encoder ENCODER = Base64.getEncoder();
	private static final Decoder DECODER = Base64.getDecoder();
	private static final String TTL = "50";
	private static final String UTF_8 = "UTF-8";
	private static final String IDENTIFIER = "AuthenticationServer";
	private static final String DIVIDER = " ";
	private static final String NOT_AUTHENTICATED = "Not Authenticated";
	private static final String filePath = "authentication";
	private String currentNonceA;
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
			System.out.println("User not in Authentication DB");
			return false ;
	}

	public String sendChallenge() throws Exception {
		
	  currentNonceA = Integer.toString(new SecureRandom().nextInt());
	  //Will be unique for each client
	  hdprovider = new DHProvider();
	  String pubKeyA = ENCODER.encodeToString((hdprovider.getPublicKey()));
	  
	  System.out.println("sendChallenge method: " + " nonceA: " + currentNonceA + " pubKeyA: "+ pubKeyA);
	  return currentNonceA+DIVIDER+pubKeyA;
	}
	public String challangeResponse(String message) throws Exception {
		
		String[] messageArgs = message.split(DIVIDER);
		String encryptedPWDNonceA = messageArgs[0]; 
		String nonceC= messageArgs[1];
		String pubKeyC = messageArgs[2];
		
		byte[] pubKeyCBytes = DECODER.decode(pubKeyC);
		byte[] sharedKey= hdprovider.getSharedKey(pubKeyCBytes);
		String sharedKeyToString = ENCODER.encodeToString(sharedKey);
		// DH returns shared key of 1024 bits and a AES only supports 256 bits so we make a SHA of the shared key to output 256 bits
		byte[] ks = SHA256.generateHash(sharedKeyToString); 
		byte[] encryptedMessage = DECODER.decode(encryptedPWDNonceA);
		System.out.println(encryptedMessage);
		byte[] decryptMessage = genericBlockCipher.decrypt(encryptedMessage, ks);
		String [] decryptedPWDNonceA = new String(decryptMessage).split(DIVIDER);
		System.out.println("Password from client:" +decryptedPWDNonceA[0]);
		String password = decryptedPWDNonceA[0];
		String nonceA = decryptedPWDNonceA[1].trim();
		int nonceAInt = Integer.valueOf(nonceA);
		int currentNonceAInt = Integer.valueOf(currentNonceA);
		if(!(nonceAInt > currentNonceAInt)) return NOT_AUTHENTICATED;
		currentNonceA = nonceA;
		System.out.println("challangeResponse method : "+ " encryptedPWDNonceA: " + encryptedPWDNonceA + 
				" nonceC: " + nonceC + " pubKeyC: " + pubKeyC + " ks: " + ks + " password: " +password + " nonceA: "+ nonceA);
		if(passwordMatch(getUsername(currentUser)[1], password)) {
			return challangeFeedback(nonceC,ks);
		} 
		return NOT_AUTHENTICATED;
	}
	
	private String challangeFeedback(String nonce,byte[] ks) throws Exception {
		
			String A = IDENTIFIER;
			String token = Token1024.generateToken();
			String ttl = TTL;
			String signature = A +DIVIDER+ token+ DIVIDER+ ttl;
			String nonceC = Integer.toString(Integer.valueOf(nonce)+1);
			byte[] digitalSignature = Base64.getEncoder().encode(PKCS1Signature.getDigitalSignature(RetrieveInfoFromKeystore.getKeystorePrivateKey(), signature.getBytes(UTF_8)));			
			
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write( digitalSignature);
			outputStream.write( (DIVIDER+nonceC).getBytes(UTF_8));
			outputStream.write( (DIVIDER+ signature).getBytes(UTF_8));
			byte messageToEncrypt[] = outputStream.toByteArray();
			
			byte [] encryptedMessage = genericBlockCipher.encrypt(messageToEncrypt,ks);
			
			return ENCODER.encodeToString(encryptedMessage);
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

}
