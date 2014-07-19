package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.ServerNameList;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.Arrays;

public class ClientHelloFingerprint {

    private EProtocolVersion msgProtocolVersion;
    private ECipherSuite[] cipherSuites;
    private byte[] compressionMethod;
    private Extensions extensions;
    private boolean sessionIdEmpty;

    public ClientHelloFingerprint(ClientHello hello) {
        this.msgProtocolVersion = hello.getMessageProtocolVersion();

	    //TODO: make fuzzy ?
        this.cipherSuites = hello.getCipherSuites();
        this.compressionMethod = hello.getCompressionMethod();

	    //FIXME
	    this.extensions = hello.getExtensions();

	    //TODO: integrate into hashCode etc.
        this.sessionIdEmpty = hello.getSessionID().isEmpty();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(cipherSuites);
        result = prime * result + Arrays.hashCode(compressionMethod);
        result = prime * result +
                ((extensions == null) ? 0 : extensions.hashCode());
        result = prime * result +
                ((msgProtocolVersion == null) ? 0 : msgProtocolVersion.hashCode());
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
        } else if (extensions.equals(extensions)) {
            return false;
        }
        if (msgProtocolVersion != other.msgProtocolVersion) {
            return false;
        }
        return true;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("Fingerprint for ClientHello: {");
        sb.append("\n  ProtocolVersion = ").append(this.msgProtocolVersion.toString());
        sb.append("\n  CipherSuites = ").append(Arrays.toString(this.cipherSuites));
        sb.append("\n  CompressionMethods = ")
          .append(Utility.bytesToHex(compressionMethod));
        sb.append("\n  Extensions = ").append(extensions);
        sb.append("\n}");

        return new String(sb);
    }

    public String getHostName() {
        if (extensions != null) {
            for (AExtension e : extensions.getExtensions()) {
                if (e.getExtensionType() == EExtensionType.SERVER_NAME) {
                    ServerNameList sne = (ServerNameList) e;
                    return sne.getServerNames().get(0).toString();
                }
            }
        }
        return null;
    }
}
