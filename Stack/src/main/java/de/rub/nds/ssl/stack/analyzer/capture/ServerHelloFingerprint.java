package de.rub.nds.ssl.stack.analyzer.capture;

import java.util.Arrays;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ExtensionList;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;

public class ServerHelloFingerprint {
	
    private EProtocolVersion msgProtocolVersion;
    private ECipherSuite cipherSuite;
    private int sessionIDlen;
    private byte[] compressionMethod;
    private ExtensionList extensionList;
	
	public ServerHelloFingerprint(ServerHello sh) {
		this.msgProtocolVersion = sh.getMessageProtocolVersion();
		this.cipherSuite = sh.getCipherSuite();
		this.sessionIDlen = sh.getSessionID().getId().length;
		this.compressionMethod = sh.getCompressionMethod();
		this.extensionList = sh.getExtensionList();
		
	}
	
	
	

    @Override
	public int hashCode() {
		// FIXME: This can be done better.
		return this.toString().hashCode();
	}




	@Override
	public boolean equals(Object obj) {
		// FIXME: This can be done better.
		return this.toString().equals(obj.toString());
	}




	public String toString() {
    	StringBuffer sb = new StringBuffer();
    	sb.append("Fingerprint for ServerHello:\n");
    	sb.append("  ProtocolVersion = " + this.msgProtocolVersion.toString() + "\n");
    	sb.append("  CipherSuite = " + this.cipherSuite + "\n");
    	sb.append("  CompressionMethod = " + Arrays.toString(this.compressionMethod) + "\n");
    	sb.append("  Length of SessionID = " + this.sessionIDlen + "\n");
    	sb.append("  Extensions = " + this.extensionList.toString());
    	
    	return new String(sb);
    }

}
