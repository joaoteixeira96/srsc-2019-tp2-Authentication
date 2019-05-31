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
		PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
		BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		sendMessage(MainDispatcherHandler.login(receiveCommunication(in)), out);
	}

	private static TLSConfiguration getConfiguration() throws IOException {
		FileInputStream inputStream = new FileInputStream("servertls.conf");
		Properties properties = new Properties();
		properties.load(inputStream);
		return new TLSConfiguration(properties.getProperty("TLS-PROT-ENF"),properties.getProperty("TLS-AUTH"),properties.getProperty("CIPHERSUITES").split(";"),"authentication.jks","authenticationTruststore.jks");
	}
	
    private static void sendMessage(String message, PrintWriter out) throws IOException {
    	System.out.println("Message sent :" + message);
        out.println(message);
        out.flush();
    }
    
	private static String receiveCommunication(BufferedReader in) throws Exception {
		String message = in.readLine();
		System.out.println("Received message :" +message);
		return message;
		
	}

}
