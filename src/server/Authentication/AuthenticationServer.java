package server.Authentication;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class AuthenticationServer {

	private static final int PORT = 8081;

	private MainDispatcherHandler handler;

	public AuthenticationServer() {
		this.handler = new MainDispatcherHandler();
	}

	public static void main(String[] args) throws Exception {

		System.setProperty("javax.net.ssl.trustStore", "serverTruststore.jks");
		System.setProperty("javax.net.ssl.trustStorePassword", "password");

		char[] passphrase = "password".toCharArray();
		KeyStore keystore = KeyStore.getInstance("JKS");
		keystore.load(new FileInputStream("server.jks"), passphrase);
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keystore, passphrase);
		SSLContext context = SSLContext.getInstance("TLS");
		KeyManager[] keyManagers = kmf.getKeyManagers();

		context.init(keyManagers, null, null);

		SSLServerSocketFactory ssf = context.getServerSocketFactory();
		ServerSocket ss = ssf.createServerSocket(PORT);

		// SSLSocketwith mutual authentication
		((SSLServerSocket) ss).setNeedClientAuth(true);

		SSLSocket s = (SSLSocket) ss.accept();

		BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
		String line = "";
		while (((line = in.readLine()) != null)) {
			System.out.println(line);
		}
		in.close();
		s.close();
	}
}
