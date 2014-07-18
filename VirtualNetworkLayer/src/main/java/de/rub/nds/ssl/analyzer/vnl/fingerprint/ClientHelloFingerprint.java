package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;

import java.util.Arrays;

public class ClientHelloFingerprint {

    private EProtocolVersion msgProtocolVersion;
    private ECipherSuite[] cipherSuites;
    private byte[] compressionMethod;
    private AExtension[] extensions;
    private boolean sessionIdEmpty;

    public ClientHelloFingerprint(ClientHello hello) {
        this.msgProtocolVersion = hello.getMessageProtocolVersion();

	    //TODO: make fuzzy ?
        this.cipherSuites = hello.getCipherSuites();
        this.compressionMethod = hello.getCompressionMethod();

	    //FIXME
	    this.extensions = hello.getExtensions().getExtensions();

	    //TODO: integrate into hashCode etc.
        this.sessionIdEmpty = hello.getSessionID().isEmpty();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(cipherSuites);
        result = prime * result + Arrays.hashCode(compressionMethod);
        result = prime * result + ((extensions == null) ? 0 : 
                extensions.hashCode());
        result = prime * result + ((msgProtocolVersion == null) ? 0 : 
                msgProtocolVersion.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ClientHelloFingerprint other = (ClientHelloFingerprint) obj;
        if (!Arrays.equals(cipherSuites, other.cipherSuites)) {
            return false;
        }
        if (!Arrays.equals(compressionMethod, other.compressionMethod)) {
            return false;
        }
        if (extensions == null) {
            if (other.extensions != null) {
                return false;
            }
        } else if (!extensions.equals(other.extensions)) {
            return false;
        }
        if (msgProtocolVersion != other.msgProtocolVersion) {
            return false;
        }
        return true;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("Fingerprint for ClientHello:\n");
        sb.append("  ProtocolVersion = " + this.msgProtocolVersion.toString() 
                + "\n");
        sb.append("  CipherSuites = " + Arrays.toString(this.cipherSuites) 
                + "\n");
        sb.append("  CompressionMethods = " + Arrays.toString(
                this.compressionMethod) + "\n");
        sb.append("  Extensions = " + this.extensions);

        return new String(sb);
    }

//    public String getHostName() {
//        if (extensions != null) {
//            for (EExtension e : extensions) {
//                if (e instanceof ServerNameExtension) {
//                    ServerNameExtension sne = (ServerNameExtension) e;
//                    return sne.getServerNames().get(0);
//                }
//            }
//        }
//        return null;
//    }
}