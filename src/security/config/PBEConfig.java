package security.config;

public class PBEConfig {
	
	// PBE files parameters
	public static final String PBE_CIPHER_TOKEN = "PBE";
	public static final String PBE_SALT_TOKEN = "SALT";
	public static final String PBE_CTR_TOKEN = "CTR";
	
	private String ciphersuite;
	private byte[] salt;
	private int ctr;
	
	public PBEConfig(String ciphersuite, byte[] salt, int ctr)
	{
		this.ciphersuite = ciphersuite;
		this.salt = salt;
		this.ctr = ctr;
	}

	public String getCiphersuite() {
		return ciphersuite;
	}

	public byte[] getSalt() {
		return salt;
	}

	public int getCtr() {
		return ctr;
	}

}
