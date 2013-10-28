package de.rub.nds.tinytlssocket;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.log4j.Logger;

public class GoodTLSServer extends Thread{

    private volatile boolean running;
    
    private final InetAddress serverAddr;
    private final int serverPort;
    private SSLServerSocket serverSocket;
    
    private Thread thread;
    
    public final String keyStoreName;
    public final char[] passphrase;
    
    public final SecureRandom rng;
    public KeyStore keyStore;
    
    public GoodTLSServer(InetAddress sA, int sP, String serverKeyStoreName, String serverPasswd){
        serverAddr = sA;
        serverPort = sP;
        keyStoreName = serverKeyStoreName;
        passphrase = serverPasswd.toCharArray();
        rng = new SecureRandom();
        int junk = rng.nextInt();
        
        start();
    }
    
    @Override
    public void run() {
        thread =  Thread.currentThread();
        KeyManagerFactory kmf;
        SSLContext sslContext;

        TrustManager[] tms = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {}
                @Override
                public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {}
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        };

        try{
            sslContext = SSLContext.getInstance("TLS");
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(keyStoreName), passphrase);
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, passphrase);
            sslContext.init(kmf.getKeyManagers(), tms, rng);
        }catch(GeneralSecurityException e){
            e.printStackTrace();
            return;
        }catch(IOException e){
            e.printStackTrace();
            return;
        }
            
        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        try{
            serverSocket = (SSLServerSocket)ssf.createServerSocket(serverPort);
            serverSocket.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA"});
            serverSocket.setReuseAddress(true);
            //serverSocket.bind(new InetSocketAddress(serverAddr, serverPort), 128);
        }catch(IOException e){
            e.printStackTrace();
            try{
                serverSocket.close();
            }catch(Throwable t){
            }
        }
        try{
            handleConnections();
        }catch(InterruptedException e){
            e.printStackTrace();
        }
    }
    
    private void handleConnections() throws InterruptedException{        
        Logger logger = Logger.getRootLogger();
        logger.debug("Server ready. Waiting for connections.");
        byte[] buffer = new byte[512];
        running = true;
        Socket socket = null;
        while(running){
            try{                
                socket = serverSocket.accept();
                logger.debug("Connection active.");
                int count = socket.getInputStream().read(buffer, 0, buffer.length);
                socket.getOutputStream().write(buffer, 0, count);
            }catch(InterruptedIOException e){
                running = false;
                interrupt();
            }catch(IOException e){
                e.printStackTrace();
            }
        }
    }

    @Override
    public void interrupt() {
        super.interrupt();
        try{
            serverSocket.close();
        }catch(IOException e){
            e.printStackTrace();
        }
    }
    
    public void close(){
        running = false;
        if(thread != null && thread.isAlive()){
            Thread cThread = Thread.currentThread();
            if(thread != cThread){
                thread.interrupt();;
                try{
                    thread.join(1000);
                }catch(InterruptedException e){
                    e.printStackTrace();
                }
            }
        }
    }
    
    public Thread getThread(){
        return thread;
    }
    
    public boolean isRunning(){
        return running;
    }
    
    public InetAddress getServerAddress(){
        return serverAddr;
    }
    
    public int getServerPort(){
        return serverPort;
    }
    
    public SSLServerSocket getServerSocket(){
        return serverSocket;
    }

}
