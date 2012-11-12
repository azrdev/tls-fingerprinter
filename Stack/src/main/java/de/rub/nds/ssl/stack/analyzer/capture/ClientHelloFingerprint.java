package de.rub.nds.ssl.stack.analyzer.capture;

import java.util.Arrays;
import java.util.List;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.Extension;

public class ClientHelloFingerprint {
    private EProtocolVersion msgProtocolVersion;
    private ECipherSuite[] cipherSuites;
    private byte[] compressionMethod;
    private List<Extension> extensionList;
    
    public ClientHelloFingerprint(ClientHello hello) {
    	this.msgProtocolVersion = hello.getMessageProtocolVersion();
    	this.cipherSuites = hello.getCipherSuites();
    	this.compressionMethod = hello.getCompressionMethod();
    	this.extensionList = hello.getExtensionList().getExtensions();
    }
    
    
    
    public boolean equals(Object o) {
    	if (o instanceof ClientHelloFingerprint) {
    		ClientHelloFingerprint f = (ClientHelloFingerprint) o;
    		return
        			(f.msgProtocolVersion.equals(msgProtocolVersion)) &&
        			(Arrays.equals(f.cipherSuites, cipherSuites)) &&
        			(Arrays.equals(f.compressionMethod, compressionMethod)) &&
        			(f.extensionList.equals(extensionList));
    	} else {
    		return super.equals(o);
    	}
    	
    }

    public String toString() {
    	StringBuffer sb = new StringBuffer();
    	sb.append("Fingerprint for ClientHello:\n");
    	sb.append("  ProtocolVersion = " + this.msgProtocolVersion.toString() + "\n");
    	sb.append("  CipherSuites = " + Arrays.toString(this.cipherSuites) + "\n");
    	sb.append("  CompressionMethods = " + Arrays.toString(this.compressionMethod) + "\n");
    	sb.append("  Extensions = " + this.extensionList.toString());
    	
    	return new String(sb);
    }
    
    public int hashCode() {
    	return this.toString().hashCode();
    }
    

}
