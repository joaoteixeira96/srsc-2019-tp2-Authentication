package security.providers;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class SHA256 {

	public static byte[] generateHash(String password) throws InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md   = MessageDigest.getInstance("sha-256"); //make sure it exists, there are other algorithms, but I prefer SHA for simple and relatively quick hashing
		md.update(password.getBytes("UTF-8")); //I'd rather specify the encoding. It's platform dependent otherwise. 
		byte[] digestBuff = md.digest();
		return digestBuff;
	}

}
