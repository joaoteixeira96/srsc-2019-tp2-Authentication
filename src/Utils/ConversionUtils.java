package Utils;

/**
 * Classe auxiliar
 */
public class ConversionUtils
{

	public static byte[] hexStringToBytes(String dataString) {
		String[] hexStrs = dataString.replaceAll("0x", "").split(" ");
		byte[] output = new byte[hexStrs.length];
		for (int i = 0; i < hexStrs.length; i++) {
			output[i] = (byte) (Integer.parseInt(hexStrs[i], 16) & 0xff);
		}
		return output;
	}
	
	public static String bytesToHexStringPrettyPrint(byte[] dataBytes) {
	    final StringBuilder builder = new StringBuilder();
	    for(byte b : dataBytes) {
	        builder.append(" 0x" + String.format("%02x", b));
	    }
	    return builder.toString().trim();
	}
	
	public static String bytesToHexString(byte[] dataBytes) {
	    final StringBuilder builder = new StringBuilder();
	    for(byte b : dataBytes) {
	        builder.append(String.format("%02x", b));
	    }
	    return builder.toString().trim();
	}
	
}
