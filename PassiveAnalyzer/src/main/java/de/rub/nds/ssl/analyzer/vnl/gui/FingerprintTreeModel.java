package de.rub.nds.ssl.analyzer.vnl.gui;

import com.google.common.base.Joiner;
import com.google.common.collect.Multimap;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.Fingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;

import javax.annotation.Nonnull;
import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature;

/**
 * Provides means for displaying {@link SessionIdentifier}s and {@link TLSFingerprint}s
 * in a {@link JTree}
 *
 * @author jBiegert azrdev@qrdn.de
 * @see DefaultMutableTreeNode
 * @see DefaultTreeModel
 */
//TODO: split SessionIdentifierTreeNode into Hostname node and ClientHello children
public abstract class FingerprintTreeModel {
    private static final Joiner commaJoiner = Joiner.on(", ").skipNulls();

    /**
     * A {@link DefaultMutableTreeNode} representing some Fingerprint [component] for
     * display in a {@link JTree}.
     * <p>
     * Most subclasses define "named constructor" static methods create() and createLazy()
     * The latter allows for the nodes children to be loaded only when needed, by calling
     * {@link #loadChildren(boolean)}. If you use lazy created nodes, you must set
     * <code>asksAllowsChildren = true</code> on the wrapping {@link DefaultTreeModel}.
     */
    public abstract static class FingerprintTreeNode extends DefaultMutableTreeNode {
        protected boolean loaded = false;

        protected FingerprintTreeNode(Object userObject) {
            super(userObject);
        }

        /**
         * add {@link FingerprintTreeNode}s as children, each corresponding to a child
         * in the data backend
         * @param childrenCreateLazy If children should also load their children, or
         *                           wait until themselves are called this method
         * @return If the children were changed, thus the model should be notified
         */
        public final boolean loadChildren(boolean childrenCreateLazy) {
            if(loaded)
                return false;
            load(childrenCreateLazy);
            loaded = true;
            return true;
        }

        /**
         * Override in subclass to actually load children
         * @see #loadChildren(boolean)
         */
        protected abstract void load(boolean childrenCreateLazy);
    }

    /**
     * A hidden root {@link FingerprintTreeNode} (corresponding to the whole
     * fingerprint <code>Multimap< SessionIdentifier, TLSFingerprint ></code>
     */
    public static class RootFingerprintTreeNode extends FingerprintTreeNode {
        private RootFingerprintTreeNode(Multimap<SessionIdentifier, TLSFingerprint> fingerprints) {
            super(fingerprints);
        }

        private Multimap<SessionIdentifier, TLSFingerprint> getBackend() {
            return (Multimap<SessionIdentifier, TLSFingerprint>) userObject;
        }

        @Override
        protected void load(boolean childrenCreateLazy) {
            final Multimap<SessionIdentifier, TLSFingerprint> fingerprints = getBackend();

            for (SessionIdentifier sessionIdentifier : fingerprints.keySet()) {
                final SessionIdentifierTreeNode sesIdNode;
                if(childrenCreateLazy)
                    sesIdNode = SessionIdentifierTreeNode.createLazy(sessionIdentifier);
                else
                    sesIdNode = SessionIdentifierTreeNode.create(sessionIdentifier, false);

                for (TLSFingerprint fingerprint : fingerprints.get(sessionIdentifier)) {
                    if(childrenCreateLazy)
                        sesIdNode.add(TlsFingerprintTreeNode.createLazy(fingerprint));
                    else
                        sesIdNode.add(TlsFingerprintTreeNode.create(fingerprint, false));
                }

                add(sesIdNode);
            }
        }

        public static RootFingerprintTreeNode create(
                @Nonnull Multimap<SessionIdentifier, TLSFingerprint> fingerprints,
                boolean childrenCreateLazy) {
            final RootFingerprintTreeNode node = new RootFingerprintTreeNode(fingerprints);
            node.loadChildren(childrenCreateLazy);
            return node;
        }
    }

    /**
     * A {@link FingerprintTreeNode} representing a {@link SessionIdentifier}
     */
    public static class SessionIdentifierTreeNode extends FingerprintTreeNode {
        private static String DESCRIPTION = "Client Hello";
        private SessionIdentifierTreeNode(@Nonnull SessionIdentifier sessionIdentifier) {
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

        @Override
        protected void load(boolean childrenCreateLazy) {
            final SessionIdentifier sessionIdentifier = (SessionIdentifier) userObject;
            final ClientHelloFingerprint chs = sessionIdentifier.getClientHelloSignature();
            if(chs != null) {
                if(childrenCreateLazy)
                    insert(SignatureTreeNode.createLazy(chs.getSigns(), DESCRIPTION), 0);
                else
                    insert(SignatureTreeNode.create(chs.getSigns(), DESCRIPTION, false), 0);
            }
        }

        public static SessionIdentifierTreeNode create(
                @Nonnull SessionIdentifier sessionIdentifier,
                boolean childrenCreateLazy) {
            final SessionIdentifierTreeNode sesIdNode = createLazy(sessionIdentifier);
            sesIdNode.loadChildren(childrenCreateLazy);
            return sesIdNode;
        }

        public static SessionIdentifierTreeNode createLazy(
                @Nonnull SessionIdentifier sessionIdentifier) {
            return new SessionIdentifierTreeNode(sessionIdentifier);
        }
    }

    /**
     * A {@link FingerprintTreeNode} representing a {@link TLSFingerprint}
     */
    public static class TlsFingerprintTreeNode extends FingerprintTreeNode {
        private static String SERVER_HELLO_DESCRIPTION = "Server Hello";
        private static String HANDSHAKE_DESCRIPTION = "Handshake";
        private static String SERVER_TCP_DESCRIPTION = "Server TCP";
        private static String SERVER_MTU_DESCRIPTION = "Server MTU";

        private TlsFingerprintTreeNode(@Nonnull TLSFingerprint fingerprint) {
            super(fingerprint);
        }

        @Override
        public String toString() {
            final TLSFingerprint tlsFingerprint = (TLSFingerprint) userObject;
            final List<String> fpNodeDescription = new LinkedList<>();
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

        @Override
        protected void load(boolean childrenCreateLazy) {
            final TLSFingerprint tlsFingerprint = (TLSFingerprint) userObject;

            if (tlsFingerprint.getServerHelloSignature() != null) {
                final Map<String, Object> signs = tlsFingerprint.getServerHelloSignature().getSigns();
                if(childrenCreateLazy)
                    add(SignatureTreeNode.createLazy(signs, SERVER_HELLO_DESCRIPTION));
                else
                    add(SignatureTreeNode.create(signs, SERVER_HELLO_DESCRIPTION, false));
            }
            if (tlsFingerprint.getHandshakeSignature() != null) {
                final Map<String, Object> signs = tlsFingerprint.getHandshakeSignature().getSigns();
                if(childrenCreateLazy)
                    add(SignatureTreeNode.createLazy(signs, HANDSHAKE_DESCRIPTION));
                else
                    add(SignatureTreeNode.create(signs, HANDSHAKE_DESCRIPTION, false));
            }
            if (tlsFingerprint.getServerTcpSignature() != null) {
                final Map<String, Object> signs = tlsFingerprint.getServerTcpSignature().getSigns();
                if(childrenCreateLazy)
                    add(SignatureTreeNode.createLazy(signs, SERVER_TCP_DESCRIPTION));
                else
                    add(SignatureTreeNode.create(signs, SERVER_TCP_DESCRIPTION, false));
            }
            if (tlsFingerprint.getServerMtuSignature() != null) {
                final Map<String, Object> signs = tlsFingerprint.getServerMtuSignature().getSigns();
                if(childrenCreateLazy)
                    add(SignatureTreeNode.createLazy(signs, SERVER_MTU_DESCRIPTION));
                else
                    add(SignatureTreeNode.create(signs, SERVER_MTU_DESCRIPTION, false));
            }
        }

        public static TlsFingerprintTreeNode create(
                @Nonnull TLSFingerprint tlsFingerprint,
                boolean childrenCreateLazy) {
            final TlsFingerprintTreeNode fpNode = createLazy(tlsFingerprint);
            fpNode.loadChildren(childrenCreateLazy);
            return fpNode;
        }

        public static TlsFingerprintTreeNode createLazy(
                @Nonnull TLSFingerprint tlsFingerprint) {
            return new TlsFingerprintTreeNode(tlsFingerprint);
        }
    }

    /**
     * A {@link FingerprintTreeNode} representing a {@link Signature} or {@link Fingerprint}
     */
    public static class SignatureTreeNode extends FingerprintTreeNode {
        private String description;
        private SignatureTreeNode(Map<String, Object> signs, String description) {
            super(signs);
            this.description = description;
        }

        private Map<String, Object> getBackend() {
            return (Map<String, Object>) userObject;
        }

        @Override
        public String toString() {
            Map<String, Object> signs = getBackend();
            return description + ": " + commaJoiner.join(signs.keySet());
        }

        @Override
        protected void load(boolean childrenCreateLazy) {
            Map<String, Object> signs = getBackend();

            for (Map.Entry<String, Object> entry : signs.entrySet()) {
                if(childrenCreateLazy)
                    add(SignTreeNode.createLazy(entry));
                else
                    add(SignTreeNode.create(entry));
            }
        }

        public static SignatureTreeNode create(@Nonnull Map<String, Object> signs,
                                               @Nonnull String description,
                                               boolean childrenCreateLazy) {
            final SignatureTreeNode signsNode = createLazy(signs, description);
            signsNode.loadChildren(childrenCreateLazy);
            return signsNode;
        }

        public static SignatureTreeNode createLazy(@Nonnull Map<String, Object> signs,
                                                   @Nonnull String description) {
             return new SignatureTreeNode(signs, description);
        }
    }

    /**
     * A {@link FingerprintTreeNode} representing a single sign
     */
    public static class SignTreeNode extends FingerprintTreeNode {
        public SignTreeNode(Map.Entry<String, Object> signEntry) {
            super(signEntry);
        }

        private Map.Entry<String, Object> getBackend() {
            return (Map.Entry<String, Object>) userObject;
        }

        @Override
        public String toString() {
            Map.Entry<String, Object> signEntry = getBackend();
            return signEntry.getKey() + ": " + signEntry.getValue();
        }

        /**
         * {@inheritDoc}
         * @param childrenCreateLazy <b>Ignored</b>
         */
        @Override
        protected void load(boolean childrenCreateLazy) {
            Map.Entry<String, Object> signEntry = getBackend();

            if (signEntry.getValue() instanceof List) {
                final List<Object> list = (List<Object>) signEntry.getValue();
                for (Object o : list) {
                    add(new DefaultMutableTreeNode(o, false));
                }
            } else {
                setAllowsChildren(false);
            }
        }

        public static SignTreeNode create(Map.Entry<String, Object> signEntry) {
            final SignTreeNode signNode = createLazy(signEntry);
            signNode.loadChildren(/* actually ignored*/ true);
            return signNode;
        }

        public static SignTreeNode createLazy(Map.Entry<String, Object> signEntry) {
            return new SignTreeNode(signEntry);
        }
    }
}
