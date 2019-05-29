package server.Authentication;

public class MainDispatcherHandler {

    private static final String DIVIDER = " ";

    public MainDispatcherHandler(){
    }
    
    public static String login(String message) throws Exception {
    	String [] messageArgs = message.trim().split(DIVIDER);
		return AuthenticationAPI.login(messageArgs[0], messageArgs[1]);
    	
    }
}
