package server.MainDispatcher;

		import TLS_Utils.TLSConfiguration;
		import TLS_Utils.TLSServerCreate;

		import java.io.BufferedReader;
		import java.io.FileInputStream;
		import java.io.IOException;
		import java.io.InputStreamReader;
		import java.util.Properties;

		import javax.net.ssl.SSLSocket;

public class AuthenticationServer {

	private static final int PORT = 8081;

	public static void main(String[] args) throws Exception {


		SSLSocket socket = (SSLSocket) TLSServerCreate.createSSLServer(getConfiguration(),"password".toCharArray(),PORT).accept();
		receiveCommunication(socket);

		socket.close();
	}

	private static TLSConfiguration getConfiguration() throws IOException {
		FileInputStream inputStream = new FileInputStream("servertls.conf");
		Properties properties = new Properties();
		properties.load(inputStream);
		return new TLSConfiguration(properties.getProperty("TLS-PROT-ENF"),properties.getProperty("TLS-AUTH"),properties.getProperty("CIPHERSUITES").split(";"),"server.jks","serverTruststore.jks");
	}

	private static void receiveCommunication(SSLSocket socket) throws IOException {
		BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		String line;
		while (((line = in.readLine()) != null)) {
			System.out.println(line);
		}
		in.close();
	}


}
