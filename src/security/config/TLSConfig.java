package security.config;

import java.io.File;

public class TLSConfig {
	
	// TLS files parameters
	public static final String TLS_TLS_TOKEN = "TLS";
	public static final String TLS_AUT_TOKEN = "AUT";
	public static final String TLS_ENABLED_CIPHERSUITES_TOKEN = "CIPHERSUITES";
	public static final String TLS_PRIVKEYSTORE_TOKEN = "PRIVKEYSTORE";
	public static final String TLS_TRUSTSTORE_TOKEN = "TRUSTSTORE";
	
	public static final String TLS_AUT_CLIENT_ONLY = "CLIENTE";
	public static final String TLS_AUT_SERVER_ONLY = "SERVIDOR";
	public static final String TLS_AUT_MUTUAL = "CLIENTE-SERVIDOR";
	
	private String tls, aut;
	private String[] ciphersuites;
	private File privKeyStore, trustStore;
	
	public TLSConfig(String version, String auth, String[] ciphersuite, String privateKeyStorePath, String trustKeyStorePath) {
		this.tls = version;
		this.aut = auth;
		this.ciphersuites = ciphersuite;
		this.privKeyStore = new File(privateKeyStorePath);
		this.trustStore = new File(trustKeyStorePath);
	}
	
	public String getVersion() {
		return tls;
	}

	public String getAuth() {
		return aut;
	}
	
	public String[] getEnabledCiphersuites() {
		return ciphersuites;
	}
	
	public File getPrivateKeyStore() {
		return privKeyStore;
	}
	
	public File getTrustStore() {
		return trustStore;
	}

}