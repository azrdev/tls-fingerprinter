package de.rub.nds.ssl.analyzer.vnl.gui;

import com.google.common.base.Joiner;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import javax.annotation.Nonnull;
import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Factory for instances of {@link JTree} model instances representing
 * {@link SessionIdentifier}s and {@link TLSFingerprint}s.
 *
 * @author jBiegert azrdev@qrdn.de
 * @see DefaultMutableTreeNode
 * @see DefaultTreeModel
 */
public class FingerprintTreeModel {
    private static final Joiner commaJoiner = Joiner.on(", ").skipNulls();

    /**
     * @return A {@link DefaultMutableTreeNode} hierarchy representing the
     * sessionIdentifier, including a sub-node for the {@link ClientHelloFingerprint}
     * (if present).
     */
    static DefaultMutableTreeNode createNode(
            @Nonnull SessionIdentifier sessionIdentifier) {
        DefaultMutableTreeNode sesIdNode = new SessionIdentifierTreeNode(sessionIdentifier);
        final ClientHelloFingerprint chs = sessionIdentifier.getClientHelloSignature();
        if(chs != null)
            sesIdNode.add(createNode(chs.getSigns(), "Client Hello"));
        return sesIdNode;
    }

    /**
     * @return A {@link DefaultMutableTreeNode} (hierarchy) representing the fingerprint
     */
    static DefaultMutableTreeNode createNode(@Nonnull TLSFingerprint tlsFingerprint) {
        DefaultMutableTreeNode fpNode = new TlsFingerprintTreeNode(tlsFingerprint);

        if(tlsFingerprint.getServerHelloSignature() != null)
            fpNode.add(createNode(
                tlsFingerprint.getServerHelloSignature().getSigns(), "Server Hello"));
        if(tlsFingerprint.getHandshakeSignature() != null)
            fpNode.add(createNode(
                tlsFingerprint.getHandshakeSignature().getSigns(), "Handshake"));
        if(tlsFingerprint.getServerTcpSignature() != null)
            fpNode.add(createNode(
                tlsFingerprint.getServerTcpSignature().getSigns(), "Server TCP"));
        if(tlsFingerprint.getServerMtuSignature() != null)
            fpNode.add(createNode(
                tlsFingerprint.getServerMtuSignature().getSigns(), "Server MTU"));

        return fpNode;
    }

    /**
     * @return A {@link DefaultMutableTreeNode} hierarchy representing the fingerprint
     * (with the given description) and its signs.
     */
    private static DefaultMutableTreeNode createNode(@Nonnull Map<String, Object> signs,
                                                     @Nonnull String description) {
        DefaultMutableTreeNode signsNode = new SignatureTreeNode(description, signs);
        for (Map.Entry<String, Object> entry : signs.entrySet()) {
            signsNode.add(createSignNode(entry.getKey(), entry.getValue()));
        }
        return signsNode;
    }

    private static DefaultMutableTreeNode createSignNode(@Nonnull String name,
                                                         Object sign) {
        final DefaultMutableTreeNode signNode =
                new DefaultMutableTreeNode(name + ": " + sign);
        if(sign instanceof List) {
            final List<Object> list = (List<Object>) sign;
            for(Object o: list) {
                signNode.add(new DefaultMutableTreeNode(o, false));
            }
        } else
            signNode.setAllowsChildren(false);
        return signNode;
    }

    private static class SessionIdentifierTreeNode extends DefaultMutableTreeNode {
        public SessionIdentifierTreeNode(@Nonnull SessionIdentifier sessionIdentifier) {
            super(sessionIdentifier);
        }

        @Override
        public String toString() {
            final SessionIdentifier sessionIdentifier = (SessionIdentifier) userObject;
            final ClientHelloFingerprint chs = sessionIdentifier.getClientHelloSignature();
            if (chs == null)
                return sessionIdentifier.getServerHostName();
            else
                return sessionIdentifier.getServerHostName() +
                        " + ClientHello (0x" + Integer.toHexString(chs.hashCode()) + ") ...";
        }
    }

    private static class TlsFingerprintTreeNode extends DefaultMutableTreeNode {
        public TlsFingerprintTreeNode(@Nonnull TLSFingerprint fingerprint) {
            super(fingerprint);
        }

        @Override
        public String toString() {
            TLSFingerprint tlsFingerprint = (TLSFingerprint) userObject;
            List<String> fpNodeDescription = new LinkedList<>();
            if(tlsFingerprint.getServerHelloSignature() != null)
                fpNodeDescription.add("ServerHello");
            if(tlsFingerprint.getHandshakeSignature() != null)
                fpNodeDescription.add("Handshake");
            if(tlsFingerprint.getServerTcpSignature() != null)
                fpNodeDescription.add("Server TCP");
            if(tlsFingerprint.getServerMtuSignature() != null)
                fpNodeDescription.add("Server MTU");
            return "(0x" + Integer.toHexString(tlsFingerprint.hashCode()) + "): " +
                    commaJoiner.join(fpNodeDescription);
        }
    }

    private static class SignatureTreeNode extends DefaultMutableTreeNode {
        private String description;
        public SignatureTreeNode(String description, Map<String, Object> signs) {
            super(signs);
            this.description = description;
        }

        @Override
        public String toString() {
            Map<String, Object> signs = (Map<String, Object>) userObject;
            return description + ": " + commaJoiner.join(signs.keySet());
        }
    }
}
