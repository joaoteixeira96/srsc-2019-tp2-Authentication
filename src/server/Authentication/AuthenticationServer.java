package server.Authentication;

import TLS_Utils.TLSConfiguration;
import TLS_Utils.TLSServerCreate;

import java.io.*;
import java.util.Properties;

import javax.net.ssl.SSLSocket;

public class AuthenticationServer {

	private static final int PORT = 8083;

	public static void main(String[] args) throws Exception {
		SSLSocket socket = (SSLSocket) TLSServerCreate.createSSLServer(getConfiguration(),"password".toCharArray(),PORT).accept();
		
		mainCycle(socket);
	}
	
	private static void mainCycle(SSLSocket socket) throws Exception{
		PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
		BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		while(true)
			receiveCommunication(socket,in,out);
	}

	private static TLSConfiguration getConfiguration() throws IOException {
		FileInputStream inputStream = new FileInputStream("servertls.conf");
		Properties properties = new Properties();
		properties.load(inputStream);
		return new TLSConfiguration(properties.getProperty("TLS-PROT-ENF"),properties.getProperty("TLS-AUTH"),properties.getProperty("CIPHERSUITES").split(";"),"authentication.jks","authenticationTruststore.jks");
	}
	
    private static void sendMessage(String message, SSLSocket socket, PrintWriter out) throws IOException {
    	System.out.println("Message sent :" + message);
        out.println(message);
        out.flush();
    }
    
	private static void receiveCommunication(SSLSocket socket, BufferedReader in, PrintWriter out) throws Exception {
		String message = in.readLine();
		System.out.println("Received message :" +message);
		sendMessage(MainDispatcherHandler.login(message), socket,out);
	}

}
