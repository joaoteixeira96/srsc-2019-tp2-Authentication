package server.Authentication;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import javax.net.ssl.SSLSocket;

public class MainDispatcherHandler {

	private static final String DIVIDER = " ";
    private static PrintWriter out;
    private static BufferedReader in;
	private static final String NOT_AUTHENTICATED = "Not Authenticated";
	private static final String AUTHENTICATED = "Authenticated";
    
    public MainDispatcherHandler(SSLSocket socket) throws IOException{
        out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    public void close() throws Exception {
    	out.close();
    	in.close();
    }
  //TODO : do this
    public  void login() throws Exception {
    	AuthenticationAPI authenticationAPI = new AuthenticationAPI();
    	String username = receiveCommunication();
    	if(!authenticationAPI.checkUsername(username)) {sendMessage(NOT_AUTHENTICATED);}
    	sendMessage(authenticationAPI.sendChallenge());
    	sendMessage(authenticationAPI.challangeResponse(receiveCommunication()));
    }
    private static void sendMessage(String message) throws IOException {
    	System.out.println("Message sent :" + message);
        out.println(message.trim());
        out.flush();
    }
    
	private static String receiveCommunication() throws Exception {
		String message = in.readLine().trim();
		System.out.println("Received message :" +message);
		return message;
		
	}
}
