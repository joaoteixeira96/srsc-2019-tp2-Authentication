package security.providers;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;

import Utils.UtilsBase;

public class RetrieveInfoFromKeystore {
    private static final String ENTRY = "authentication";
	private static final String AUTHENTICATION_JKS = "authentication.jks";
	private static final char[] PASSWORD = "password".toCharArray();
	public static PrivateKey getKeystorePrivateKey () throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, UnrecoverableKeyException {
		// Ficheiro da keystore
        FileInputStream is = new FileInputStream(AUTHENTICATION_JKS); 

	    // Passar a password
	
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, PASSWORD);
	
	    // Passar o identificador (alias) da entry da keystore
	
		String alias = ENTRY;
	    // Obter chave privada
	
		Key key = keystore.getKey(alias, PASSWORD);
		KeyPair kp = null;
		if (key instanceof PrivateKey) {

		    // Retornar certificado da chave publica da entry
		    Certificate cert = keystore.getCertificate(alias);

		    // Obter chave Publica da entry
		    PublicKey publicKey = cert.getPublicKey();

		    // Retornar o par de chaves da entry
		    kp = new KeyPair(publicKey, (PrivateKey) key);

		}
		else System.out.println("Not instance of Private Key ...");
		return kp.getPrivate();
	}
	public static PublicKey getKeystorePublicKey () throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, UnrecoverableKeyException {
		// Ficheiro da keystore
        FileInputStream is = new FileInputStream(AUTHENTICATION_JKS); 

	    // Passar a password
	
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, PASSWORD);
	
	    // Passar o identificador (alias) da entry da keystore
	
		String alias = ENTRY;
	    // Obter chave privada
	
		Key key = keystore.getKey(alias, PASSWORD);
		KeyPair kp = null;
		PublicKey publicKey = null;
		if (key instanceof PrivateKey) {

		    // Retornar certificado da chave publica da entry
		    Certificate cert = keystore.getCertificate(alias);

		    // Obter chave Publica da entry
		    publicKey = cert.getPublicKey();

		    // Retornar o par de chaves da entry
		    kp = new KeyPair(publicKey, (PrivateKey) key);

		}
		else System.out.println("Not instance of Private Key ...");
		return publicKey;
	}
	
}