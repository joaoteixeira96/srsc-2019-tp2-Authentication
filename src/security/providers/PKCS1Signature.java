package security.providers;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;


/**
 * Geracao de uma assinatura de uma mensagem com RSA
 * no esquema PKCS1 
 * Este esquema usa uma assinatura de uma sintese SHA512 da mensagem que
 * se pretende assinar
 * Atencao ao controlo do tamanho das chaves face a sintese parametrizada
 * para a assinatura
 */
public class PKCS1Signature
{
    public static byte[] getDigitalSignature(PrivateKey privKey, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    	Signature  signature = Signature.getInstance("SHA512withRSA");
    	signature.initSign(privKey);
    	signature.update(message);
        byte[]  sigBytes = signature.sign();
		return sigBytes;
    }
    public static boolean verifySignature(PublicKey pubKey,byte[] sigBytes,byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
    	Signature  signature = Signature.getInstance("SHA512withRSA");
    	signature.initVerify(pubKey);
        signature.update(message);

        return signature.verify(sigBytes);   
        }
}
