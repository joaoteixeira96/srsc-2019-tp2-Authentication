package server.Authentication;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Scanner;

public class AuthenticationAPI {

	private static final String NOT_AUTHENTICATED = "Not Authenticated";
	private static final String AUTHENTICATED = "Authenticated";
	private static final String filePath = "src/server/Authentication/authentication";
	Dictionary<String, User> usersDictionary = new Hashtable<>();

	public static boolean login(String username, String password, Dictionary<String, User> users) { // TODO: take Static
		return users.get(username).verifyUser(password);
	}

	// Search user in local file and verify if he can login
	public static String login(String username, String password) throws FileNotFoundException {
		File file = new File(filePath);
		Scanner sc = new Scanner(file);
		try {
			while (sc.hasNextLine()) {
				String[] readLine = sc.nextLine().split(" ");
				if (readLine[0].equals(username) && readLine[1].equals(password)) {
					sc.close();
					return AUTHENTICATED;
				}
			}
		} catch (Exception e) {
			System.out.println(AuthenticationAPI.class + " user not found");
		}
		sc.close();
		return NOT_AUTHENTICATED;

	}

	public static void main(String args[]) throws Exception {
		Dictionary<String, User> users = new Hashtable<>();

		users.put("Deus", new User("Deus", "aaa"));
		users.put("Hitler", new User("Deus", "bbb"));
		users.put("Conan Osiris", new User("Deus", "cc"));
		users.put("Batista", new User("Deus", "ddd"));
		users.put("Julio", new User("Deus", "eee"));
		System.out.println(login("Deus", "aaa", users));
		System.out.println(login("Deus", "bbb", users));

		String testUser = "Deus";
		String testUserPassword = "aaa";

		System.out.println("User: " + testUser + " with password: " + testUserPassword + " authenticated?: "
				+ login(testUser, testUserPassword));
	}
}
