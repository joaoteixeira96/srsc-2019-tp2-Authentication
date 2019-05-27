package server.Authentication;

public class User {
    private String username;
    private String password;


    User(String username, String password){
        this.password = password;
        this.username = username;
    }

    public boolean verifyUser(String password){
        return this.password.equals(password);
    }

}
