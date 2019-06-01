package server.Authentication;

import TLS_Utils.TLSConfiguration;
import TLS_Utils.TLSServerCreate;

import java.io.*;
import java.util.Properties;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

public class AuthenticationServer {

	private static final int PORT = 8083;

	public static void main(String[] args) throws Exception {
		SSLServerSocket serverSocket = TLSServerCreate.createSSLServer(getConfiguration(),"password".toCharArray(),PORT);
		while(true) 
			try {
			mainFlow((SSLSocket) serverSocket.accept());
			} catch (Exception e) {
				System.out.println("Connection Crashed");
			}
	}
	
	private static void mainFlow(SSLSocket socket) throws Exception{
		(new  MainDispatcherHandler(socket)).login();
	}

	private static TLSConfiguration getConfiguration() throws IOException {
		FileInputStream inputStream = new FileInputStream("servertls.conf");
		Properties properties = new Properties();
		properties.load(inputStream);
		return new TLSConfiguration(properties.getProperty("TLS-PROT-ENF"),properties.getProperty("TLS-AUTH"),properties.getProperty("CIPHERSUITES").split(";"),"authentication.jks","authenticationTruststore.jks");
	}
	
    

}
