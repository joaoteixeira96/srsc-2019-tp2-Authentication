package security.providers;

import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

//Sample method to construct a JWT
public class Token1024{
	private static final String DD_MM_YYYY = "dd/MM/yyyy";
	private static final String EXPIRE_DATE = "31/08/2020";
	private static final String DIVIDER = " ";
	//Sample method to construct a JWT
	protected static SecureRandom random = new SecureRandom();
    public static String generateToken( ) throws ParseException {
            long longToken = Math.abs( random.nextLong() );
            String random = Long.toString( longToken, 16 );
            DateFormat dateFormat = new SimpleDateFormat(DD_MM_YYYY);
        	Date current = new Date();
        	Date expires = dateFormat.parse(EXPIRE_DATE);
        	
            return  dateFormat.format(current) +DIVIDER+ dateFormat.format(expires);
    }
}