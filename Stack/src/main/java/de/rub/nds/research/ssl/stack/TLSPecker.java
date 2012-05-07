package de.rub.nds.research.ssl.stack;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Stack;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.research.ssl.stack.protocols.handshake.EMessageType;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.*;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ASN1Certificate;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ClientDHPublic;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;

/**
 * HTTPS penetration suite - main entry point
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 9, 2011
 */
public class TLSPecker {

    /**
     * Default port for HTTPS
     */
    private static final int DEFAULT_HTTPS_PORT = 443;
    /**
     * Default timeout for connection attempts
     */
    private static final int DEFAULT_CONNECTION_TIMEOUT = 10000; // 10 seconds
    /**
     * Array of enabled ECipherSuite
     */
    private ECipherSuite[] enabledCipherSuites = null;
    /**
     * Protocol version
     */
    private EProtocolVersion protocolVersion = EProtocolVersion.TLS_1_0;
    /** 
     * Content type
     */
    private EContentType contentType = EContentType.HANDSHAKE;
    /**
     * Message Type
     */
    private EMessageType messageType = EMessageType.CLIENT_HELLO;
    /**
     * Log file object in which the log outputs are written
     */
    private File logFile;
    /**
     * Writer object for the log file
     */
    private FileWriter logFileWriter;
    /**
     * Stack for the hosts to check
     */
    private Stack<String> hosts = new Stack<String>();

    /**
     * Creates an instance of the TLSPecker.
     * The TLSPecker is a penetration tool to check for potential 
     * vulnerabilities of TLS/SSL implementations.
     * 
     * @param targetsFilePath Path to a file containing the targets. The form
     * is as follows: www.example.com<br>www.example.com<br>.....
     * @param logFilePath Path to the log file for the tools' output.
     * @throws IOException Exception thrown in case of I/O troubles.
     */
    public TLSPecker(final String targetsFilePath, final String logFilePath)
            throws IOException {
        // initialize logging
        this(logFilePath);
        // load targets list
        loadList(targetsFilePath);
    }

    /**
     * Creates an instance of the TLSPecker.
     * The TLSPecker is a penetration tool to check for potential 
     * vulnerabilities of TLS/SSL implementations.
     * 
     * @param logFilePath Path to the log file for the tools' output.
     * @throws IOException Exception thrown in case of I/O troubles.
     */
    public TLSPecker(final String logFilePath) throws IOException {
        // initialize logging
        logFile = new File(logFilePath);
        logFileWriter = new FileWriter(logFile);

        if (!logFile.canWrite()) {
            throw new IOException("Log file not writebale.");
        }
    }

    /**
     * Specify the protocol version that should be used.
     * @param version Desired protocol version
     */
    public void setProtocolVersion(EProtocolVersion version) {
        if(protocolVersion == null) {
            throw new IllegalArgumentException("Protocol version must not be null!");
        }
        
        this.protocolVersion = version;
    }
    
    public void setContentType(EContentType type) {
        if(type == null) {
            throw new IllegalArgumentException("Content type must not be null!");
        }
        
        this.contentType = type;
    }
    /**
     * Specify the message type that should be used.
     * @param type Desired messageType
     */
    public void setMessageType(EMessageType type) {
        if(messageType == null) {
            throw new IllegalArgumentException("Message type must not be null!");
        }
        
        this.messageType = type;
    }
    
    /**
     * Lets knock on wood...
     * Which server on the loaded targets list supports SSL/TLS?
     */
    public void checkTLSSupport() {
        while (!hosts.empty()) {
           checkTLSSupport(hosts.pop(), DEFAULT_HTTPS_PORT);
        }
    }

    /**
     * Checks if a host supports SSL/TLS
     * @param host Host to check
     * @param port SSL/TLS port
     */
    public void checkTLSSupport(String host, int port) {
        SocketAddress socketAddress = null;
        Socket socket = null;
        OutputStream outputStream = null;
        InputStream inputStream = null;
        
        try {
            // connection attempt - will timeout
            socketAddress = new InetSocketAddress(host, port);
            socket = new Socket();
            socket.connect(socketAddress, DEFAULT_CONNECTION_TIMEOUT);
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            
            ClientHello clientHelloMessage = new ClientHello(protocolVersion);
            CipherSuites cipherSuites = new CipherSuites();
            cipherSuites.setSuites(new ECipherSuite[]{
                        ECipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                        ECipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                        ECipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                        ECipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
                        ECipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                        ECipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                        ECipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                        ECipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
                        ECipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
            });
            clientHelloMessage.setCipherSuites(cipherSuites);
            byte[] messageBytes = clientHelloMessage.encode(true);

            // ready to go, output the message!
            outputStream.write(messageBytes);
            outputStream.flush();
            
            byte[] recordHeader = new byte[5];
            int readBytes = inputStream.read(recordHeader);
            int recordPayloadLength = ((((recordHeader[3]& 0xff)<<8) ) | (recordHeader[4] & 0xff));
            byte[] recordPayload = new byte[recordPayloadLength];
            
            byte[] record = new byte[recordHeader.length + recordPayload.length];
            System.arraycopy(recordHeader, 0, record, 0, recordHeader.length);
            
            for(int i = 0; i < recordPayloadLength; i++) {
                record[recordHeader.length + i] = (byte) inputStream.read();
            }
            System.out.println(Utility.byteToHex(record));
            HandshakeEnumeration hE = new HandshakeEnumeration(record, true);
            for(AHandshakeRecord tmp : hE.getMessages()) {
                if(tmp instanceof Certificate) {
                    Certificate a = (Certificate) tmp;
                    ASN1Certificate[] certs =  a.getCertificates().getCertificates();
                    for(ASN1Certificate cert : certs) {
                        
                    }
                }
                System.out.println("Message: " + tmp.toString());
            }

            
            ClientKeyExchange clientKeyExchangeMessage = new ClientKeyExchange(
                    protocolVersion, EKeyExchangeAlgorithm.DIFFIE_HELLMAN);
            ClientDHPublic clientDHPublic = new ClientDHPublic();
            clientDHPublic.setDhyc(new byte[]{0xc,0x0,0xf,0xf,0xe});
            clientKeyExchangeMessage.setExchangeKeys(clientDHPublic);
            
            messageBytes = clientKeyExchangeMessage.encode(true);
            
            // ready to go, output the message!
            outputStream.write(messageBytes);
            outputStream.flush();
        } catch (UnknownHostException e) {
            System.out.println("|-> unknown host " + e.getMessage());
        } catch (SocketTimeoutException e) {
            System.out.println("|-> timeout " + e.getMessage());
        } catch (IOException e) {
            System.out.println("|-> io error " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("|-> invalid argument " + e.getMessage());
//            e.printStackTrace();
        }
        finally {
            // we're done, let's clean up
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ex) {
                    // silently ignore the noise.....
                }
            }
        }
    }

    /**
     * Loads a list of targets to check.
     * @param targetsFilePath Path to a file containing the targets. The form
     * is as follows: www.example.com<br>www.example.com<br>.....
     * @throws IOException Exception thrown in case of I/O troubles.
     */
    public final void loadList(final String targetsFilePath)
            throws IOException {
        BufferedReader targetReader = null;
        final File targetsFile = new File(targetsFilePath);
        if (!targetsFile.exists() || !targetsFile.canRead()) {
            throw new IOException("Targets file not readable.");
        }

        // extract targets
        try {
            targetReader = new BufferedReader(
                    new FileReader(targetsFile));
            String tmp;
            do {
                tmp = targetReader.readLine();
                if(tmp != null && !tmp.startsWith("#")) {
                    hosts.push(tmp);
                }
            } while (tmp != null);
        } finally {
            if (targetReader != null) {
                targetReader.close();
            }
        }
    }
}
