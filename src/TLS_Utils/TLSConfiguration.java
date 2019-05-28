package TLS_Utils;
import java.io.File;

public class TLSConfiguration {

    public static final String TLS_TOKEN = "TLS";
    public static final String AUT_TOKEN = "AUT";
    public static final String CIPHERSUITES_TOKEN = "CIPHERSUITES";
    public static final String KEYSTORE_TOKEN = "PRIVKEYSTORE";
    public static final String TRUSTSTORE_TOKEN = "TRUSTSTORE";
    public static final String AUT_CLIENT_ONLY = "CLIENT";
    public static final String AUT_SERVER_ONLY = "SERVER";
    public static final String AUT_MUTUAL = "MUTUAL";


    private String tls,auth;
    private String[] ciphersuites;
    private File keyStore, trustStore;

    public TLSConfiguration(String tls, String auth, String[] ciphersuites, String keyStorePath, String trustStorePath) {
        this.tls = tls;
        this.auth = auth;
        this.ciphersuites = ciphersuites;
        this.keyStore = new File(keyStorePath);
        this.trustStore = new File(trustStorePath);
    }

    public String getTls() {
        return tls;
    }

    public String getAuth() {
        return auth;
    }

    public String[] getCiphersuites() {
        return ciphersuites;
    }

    public File getKeyStore() {
        return keyStore;
    }

    public File getTrustStore() {
        return trustStore;
    }
}
