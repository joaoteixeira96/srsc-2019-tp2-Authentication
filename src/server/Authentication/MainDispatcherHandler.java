package server.Authentication;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import javax.net.ssl.SSLSocket;

public class MainDispatcherHandler {

    private static final String DIVIDER = " ";
    private  SSLSocket socket;

    public MainDispatcherHandler(SSLSocket socket){
        this.socket = socket;
        try{
        	sendMessage(login(receiveMessage()));
        }
        catch (Exception e){
            System.out.println("Falhou");
        }
    }
    private void sendMessage(String message) throws IOException {
        PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
        out.println(message);
        out.println();
        out.flush();
        out.close();
    }

    private  String receiveMessage() throws IOException {
		BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		String message = in.readLine();
		in.close();
		return message;
	}
    private String login(String message) throws FileNotFoundException {
    	String [] messageArgs = message.split(DIVIDER);
		return AuthenticationAPI.login(messageArgs[0], messageArgs[1]);
    	
    }
}
