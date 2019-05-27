package security.providers;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.naming.ConfigurationException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import Utils.ConversionUtils;
import security.config.PBEConfig;
import security.config.TLSConfig;

public class AuthProvider {

	public static final String AUTH_SERVER_HOST = "127.0.0.1";
	public static final int AUTH_SERVER_PORT = 4443;
	public static final String TLS_CONFIG_FILENAME = "tls.config";
	public static final String KEYSTORE_PASSWORD = "password";
	public static final String AUTH_PASSWORD_HASH = "SHA-256";

	public static final String AUTH_MSG_RESULT_SUCCESS = "[OK]";
	public static final String AUTH_MSG_RESULT_FAILURE = "[ERROR]";
	public static final String AUTH_MSG_TERMINATOR = "[END]";

	private File configFolder, tlsConfigFile;
	private Map<String, PBEConfig> pbeSchemes;

	public static byte[] TOKEN;

	public AuthProvider(String configFolderPath) {
		configFolder = new File(configFolderPath);
		tlsConfigFile = new File(configFolderPath + '/' + TLS_CONFIG_FILENAME);
	}

	public void init() throws ConfigurationException {
		if (configFolder.exists()) {
			pbeSchemes = new HashMap<String, PBEConfig>();

			File[] pbeFiles = configFolder.listFiles(new FilenameFilter() {
				public boolean accept(File dir, String filename) {
					return filename.endsWith(".pbe");
				}
			});

			for (File pbe : pbeFiles) {
				String pbeNameStrippedExt = pbe.getName().substring(0, pbe.getName().lastIndexOf("."));
				pbeSchemes.put(pbeNameStrippedExt, loadPBEFile(pbe));
			}
		}
	}

	public EncryptionProvider requestChatroomConfig(String ipAddress, String username, char[] password)
			throws Exception {

		if (ipAddress == null || ipAddress.isEmpty())
			return null;

		if (!pbeSchemes.containsKey(ipAddress))
			throw new FileNotFoundException("PBE file for chat at " + ipAddress + " does not exist.");

		// get pbe scheme
		PBEConfig pbe = pbeSchemes.get(ipAddress);

		// get password secret for server to compare
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password, pbe.getSalt(), pbe.getCtr());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(pbe.getCiphersuite(), "BC");
		Key key = secretKeyFactory.generateSecret(pbeKeySpec);
		byte[] secretBytes = key.getEncoded();

		// hash the secret
		MessageDigest md = MessageDigest.getInstance(AUTH_PASSWORD_HASH);
		md.update(secretBytes);
		byte[] passwordHash = md.digest();

		// load tls config and create ssl socket accordingly
		TLSConfig tlsConfig = loadTLSFile(tlsConfigFile);

		try {
			// setup ssl socket and start tls handshake
			SSLSocket sslSocket = createSSLSocket(tlsConfig, KEYSTORE_PASSWORD.toCharArray(), AUTH_SERVER_PORT,
					AUTH_SERVER_HOST);

			// setup payload to request auth
			String request = ipAddress + "//" + username + "//" + ConversionUtils.bytesToHexString(passwordHash);

			// send payload through sslsocket
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream()));
			writer.write(request, 0, request.length());
			writer.newLine();
			writer.flush();

			// wait for data to be returned
			BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));

			StringBuilder sb = new StringBuilder();
			boolean success = false;
			String line = null;
			while ((line = reader.readLine()) != null) {

				// check header (should be either OK or ERROR)
				if (line.equals(AUTH_MSG_RESULT_SUCCESS) || line.equals(AUTH_MSG_RESULT_FAILURE)) {
					if (line.equals(AUTH_MSG_RESULT_SUCCESS))
						success = true;
					continue;
				}

				// check terminator that signals end of msg
				if (line.equals(AUTH_MSG_TERMINATOR))
					break;

				// if it's content, append it
				if (sb.length() > 0) {
					sb.append("\n" + line);
				} else {
					sb.append(line);
				}

			}

			// dispose of socket and io tools
			writer.close();
			reader.close();
			sslSocket.close();

			// if there's any error, show the user an error msg and exit the
			// chat application
			if (!success) {
				int errorCode = Integer.valueOf(sb.toString());

				String errorMsg = "Authentication error: ";
				switch (errorCode) {
				case 401:
					errorMsg += "Wrong password.";
					break;
				case 404:
					errorMsg += "Unknown username '" + username + "'.";
					break;
				case 422:
					errorMsg += "Unknown chatroom '" + ipAddress + "'.";
					break;
				case 424:
					errorMsg += "You don't have permissions to access this chatroom.";
					break;
				default:
					errorMsg += "Unexpected error!";
				}
				System.err.println(errorMsg);
				System.exit(1);
			}

			// getting this far means success
			String[] serverData = sb.toString().split("\n"); // split obtained server data

			// get server token
			TOKEN = Base64.getDecoder().decode(serverData[1]);

			// get crypto config
			byte[] decodedConfigBytes = Base64.getDecoder().decode(serverData[0]);
			String[] decodedConfig = new String(decodedConfigBytes).split("\n");

			// parse read content into a chat room config
			EncryptionProvider scheme = parseChatroomConfig(decodedConfig);

			// init our encryption scheme (it will read the keystore)
			scheme.init(tlsConfig.getPrivateKeyStore(), KEYSTORE_PASSWORD, tlsConfig.getTrustStore(), username);
			return scheme;

		} catch (IOException e) {
			System.err.println(e.toString());
		}

		return null;
	}

	private TLSConfig loadTLSFile(File tlsFile) throws ConfigurationException {
		try {

			FileReader freader = new FileReader(tlsFile);
			BufferedReader breader = new BufferedReader(freader);

			String tls = null;
			String aut = null;
			String[] ciphersuites = null;
			String privKeyStore = null;
			String trustStore = null;

			String line = null;
			while ((line = breader.readLine()) != null) {

				if (line.trim().length() == 0 || line.startsWith("#"))
					continue;

				if (line.contains(":")) {
					String[] tokens = line.split(":");
					String paramKey = tokens[0].trim();
					String paramValue = tokens[1].indexOf("#") > 0
							? tokens[1].substring(0, tokens[1].indexOf("#")).trim()
							: tokens[1].trim(); // removes
												// inline
												// comments
					switch (paramKey) {

					case TLSConfig.TLS_TLS_TOKEN:
						tls = paramValue;
						break;
					case TLSConfig.TLS_AUT_TOKEN:
						aut = paramValue;
						break;
					case TLSConfig.TLS_ENABLED_CIPHERSUITES_TOKEN:
						ciphersuites = paramValue.split(" ");
						break;
					case TLSConfig.TLS_PRIVKEYSTORE_TOKEN:
						privKeyStore = paramValue;
						break;
					case TLSConfig.TLS_TRUSTSTORE_TOKEN:
						trustStore = paramValue;
						break;
					default:
						continue;
					}

				}
			}
			breader.close();

			if (tls != null && ciphersuites != null && aut != null && privKeyStore != null && trustStore != null) {
				return new TLSConfig(tls, aut, ciphersuites, privKeyStore, trustStore);
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private PBEConfig loadPBEFile(File pbeFile) throws ConfigurationException {
		try {

			FileReader freader = new FileReader(pbeFile);
			BufferedReader breader = new BufferedReader(freader);

			String pbeCipher = null;
			byte[] pbeSaltBytes = null;
			int pbeCtr = -1;

			String line = null;
			while ((line = breader.readLine()) != null) {

				if (line.trim().length() == 0 || line.startsWith("#"))
					continue;

				if (line.contains(":")) {

					String[] tokens = line.split(":");
					String paramKey = tokens[0].trim();
					String paramValue = tokens[1].indexOf("#") > 0
							? tokens[1].substring(0, tokens[1].indexOf("#")).trim()
							: tokens[1].trim(); // removes

					switch (paramKey) {

					case PBEConfig.PBE_CIPHER_TOKEN:
						pbeCipher = paramValue;
						break;
					case PBEConfig.PBE_SALT_TOKEN:
						pbeSaltBytes = ConversionUtils.hexStringToBytes(paramValue);
						break;
					case PBEConfig.PBE_CTR_TOKEN:
						pbeCtr = Integer.parseInt(paramValue);
						break;
					default:
						continue;
					}

				}

			}
			breader.close();

			if (pbeCipher != null && pbeSaltBytes != null && pbeCtr != -1) {
				return new PBEConfig(pbeCipher, pbeSaltBytes, pbeCtr);
			}

			throw new ConfigurationException("PBE file is misconfigurated! Check if there's any field missing.");

		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	private EncryptionProvider parseChatroomConfig(String[] configStrings) throws Exception {

		EncryptionProvider scheme = null;
		String cryptoCipher = null, provider = null, signature = null;
		byte[] ivBytes = null;
		int cryptoKeySize = -1;

		for (String line : configStrings) {

			if (line.trim().length() == 0 || line.startsWith("#"))
				continue;

			if (line.contains(":")) {

				String[] tokens = line.split(":");
				String paramKey = tokens[0].trim();
				String paramValue = tokens[1].indexOf("#") > 0 ? tokens[1].substring(0, tokens[1].indexOf("#")).trim()
						: tokens[1].trim(); // removes inline comments

				switch (paramKey) {

				case EncryptionProvider.CRYPTO_CIPHER_TOKEN:
					cryptoCipher = paramValue;
					break;
				case EncryptionProvider.CRYPTO_CIPHER_KEY_SIZE_TOKEN:
					cryptoKeySize = Integer.parseInt(paramValue);
					break;
				case EncryptionProvider.CRYPTO_CIPHER_IV_TOKEN:
					ivBytes = ConversionUtils.hexStringToBytes(paramValue);
					break;
				case EncryptionProvider.CRYPTO_SIGNATURE_TOKEN:
					signature = paramValue;
					break;
				case EncryptionProvider.CRYPTO_PROVIDER_TOKEN:
					provider = paramValue;
					break;
				default:
					continue;
				}

			}

		}

		try {
			scheme = new EncryptionProvider(provider);
			scheme.setCiphersuite(cryptoCipher, cryptoKeySize, ivBytes, signature);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return scheme;
	}

	private static SSLSocket createSSLSocket(TLSConfig conf, char[] password, int port, String host)
			throws UnknownHostException, IOException, CertificateExpiredException, CertificateNotYetValidException {

		SSLSocketFactory factory = null;
		SSLSocket socket;
		if (conf.getAuth().equals(TLSConfig.TLS_AUT_CLIENT_ONLY) || conf.getAuth().equals(TLSConfig.TLS_AUT_MUTUAL)) {
			try {

				SSLContext ctx = SSLContext.getInstance(conf.getVersion());
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");

				KeyStore ks = KeyStore.getInstance("JKS");
				ks.load(new FileInputStream(conf.getPrivateKeyStore()), password);
				KeyStore ts = KeyStore.getInstance("JKS");
				ts.load(new FileInputStream(conf.getTrustStore()), password);

				kmf.init(ks, password);
				tmf.init(ts);
				ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

				factory = ctx.getSocketFactory();
				socket = (SSLSocket) factory.createSocket(host, port);

				String[] enabledProtocols = { conf.getVersion() };
				socket.setEnabledProtocols(enabledProtocols);
				socket.setEnabledCipherSuites(conf.getEnabledCiphersuites());

				if (conf.getAuth().equals(TLSConfig.TLS_AUT_CLIENT_ONLY))
					socket.setUseClientMode(false);

			} catch (Exception e) {
				throw new IOException(e.getMessage());
			}
		} else {
			factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			socket = (SSLSocket) factory.createSocket(host, port);
		}

		// start tls handshake
		socket.startHandshake();

		// validate peer certificates!
		Certificate[] crts = socket.getSession().getPeerCertificates();
		for (Certificate crt : crts) {
			X509Certificate x509crt = (X509Certificate) crt;
			x509crt.checkValidity();
		}

		return socket;
	}

}
