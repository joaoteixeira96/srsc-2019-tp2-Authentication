package TLS_Utils;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;


public class TLSServerCreate {

    private static KeyManagerFactory getKeyManagerFactory(char[] password, TLSConfiguration configuration) throws NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, CertificateException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(configuration.getKeyStore()), password);
        kmf.init(ks, password);
        return kmf;
    }

    private static TrustManagerFactory getTrustManagerFactory(char[] password, TLSConfiguration configuration) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(new FileInputStream(configuration.getTrustStore()), password);
        tmf.init(ts);
        return tmf;
    }

    private static SSLContext getSSLContext(char[] password, TLSConfiguration configuration) throws NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, KeyStoreException, IOException, KeyManagementException {
        SSLContext ctx = SSLContext.getInstance(configuration.getTls());
        ctx.init(getKeyManagerFactory(password, configuration).getKeyManagers(), getTrustManagerFactory(password, configuration).getTrustManagers(), null);
        return ctx;
    }


    private static boolean  clientAuthenticationIsNeeded(TLSConfiguration configuration){
        return configuration.getAuth().equals(TLSConfiguration.AUT_MUTUAL);
    }

    private static SSLServerSocket getSocketForTLSCommunication(SSLServerSocket socket, TLSConfiguration configuration){
        if (clientAuthenticationIsNeeded(configuration))
            socket.setNeedClientAuth(true);
        String[] enabledProtocols = { configuration.getTls() };
        socket.setEnabledProtocols(enabledProtocols);
        //socket.setEnabledCipherSuites(configuration.getCiphersuites());
        return socket;
    }


    public static SSLServerSocket createSSLServer(TLSConfiguration conf, char[] password, int port) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        try {

            SSLServerSocket s = getSocketForTLSCommunication(
                    (SSLServerSocket) getSSLContext(password, conf).getServerSocketFactory().createServerSocket(port), conf);
            printServerSocketInfo(s);
            return s;
        } catch (Exception e) {
            System.err.println(e.toString());
        }
        return null;
    }

    private static void printServerSocketInfo(SSLServerSocket s) {
        System.out.println("Server socket class: " + s.getClass());
        System.out.println("   Socket address = " + s.getInetAddress().toString());
        System.out.println("   Socket port = " + s.getLocalPort());
        System.out.println("   Need client authentication = " + s.getNeedClientAuth());
        System.out.println("   Want client authentication = " + s.getWantClientAuth());
        System.out.println("   Use client mode = " + s.getUseClientMode());
    }

}
