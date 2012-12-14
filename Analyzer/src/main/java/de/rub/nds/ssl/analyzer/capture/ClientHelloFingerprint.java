package de.rub.nds.ssl.analyzer.capture;

import java.util.Arrays;
import java.util.List;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.Extension;
import de.rub.nds.ssl.stack.protocols.handshake.ExtensionList;
import de.rub.nds.ssl.stack.protocols.handshake.ServerNameExtension;

public class ClientHelloFingerprint {
    private EProtocolVersion msgProtocolVersion;
    private ECipherSuite[] cipherSuites;
    private byte[] compressionMethod;
    private List<Extension> extensionList;
    
    public ClientHelloFingerprint(ClientHello hello) {
    	this.msgProtocolVersion = hello.getMessageProtocolVersion();
    	this.cipherSuites = hello.getCipherSuites();
    	this.compressionMethod = hello.getCompressionMethod();
    	ExtensionList el = hello.getExtensionList();
    	if (el != null) {
    		this.extensionList = el.getExtensions();
    	}
    }
    
    
    
//    public boolean equals(Object o) {
//    	if (o instanceof ClientHelloFingerprint) {
//    		ClientHelloFingerprint f = (ClientHelloFingerprint) o;
//    		return
//        			(f.msgProtocolVersion.equals(msgProtocolVersion)) &&
//        			(Arrays.equals(f.cipherSuites, cipherSuites)) &&
//        			(Arrays.equals(f.compressionMethod, compressionMethod)) &&
//        			(f.extensionList.equals(extensionList));
//    	} else {
//    		return super.equals(o);
//    	}
//    	
//    }

    @Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(cipherSuites);
		result = prime * result + Arrays.hashCode(compressionMethod);
		result = prime * result
				+ ((extensionList == null) ? 0 : extensionList.hashCode());
		result = prime
				* result
				+ ((msgProtocolVersion == null) ? 0 : msgProtocolVersion
						.hashCode());
		return result;
	}



	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ClientHelloFingerprint other = (ClientHelloFingerprint) obj;
		if (!Arrays.equals(cipherSuites, other.cipherSuites))
			return false;
		if (!Arrays.equals(compressionMethod, other.compressionMethod))
			return false;
		if (extensionList == null) {
			if (other.extensionList != null)
				return false;
		} else if (!extensionList.equals(other.extensionList))
			return false;
		if (msgProtocolVersion != other.msgProtocolVersion)
			return false;
		return true;
	}



	public String toString() {
    	StringBuffer sb = new StringBuffer();
    	sb.append("Fingerprint for ClientHello:\n");
    	sb.append("  ProtocolVersion = " + this.msgProtocolVersion.toString() + "\n");
    	sb.append("  CipherSuites = " + Arrays.toString(this.cipherSuites) + "\n");
    	sb.append("  CompressionMethods = " + Arrays.toString(this.compressionMethod) + "\n");
    	sb.append("  Extensions = " + this.extensionList);
    	
    	return new String(sb);
    }
    
	public String getHostName() {
		if (extensionList != null) {
			for (Extension e : extensionList) {
				if (e instanceof ServerNameExtension) {
					ServerNameExtension sne = (ServerNameExtension)e;
					return sne.getServerNames().get(0);
				}
			}
		}
		return null;
	}

    

}
