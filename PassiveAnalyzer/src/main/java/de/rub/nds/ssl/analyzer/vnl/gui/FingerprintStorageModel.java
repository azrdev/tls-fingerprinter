package de.rub.nds.ssl.analyzer.vnl.gui;

import com.google.common.collect.ImmutableSetMultimap;
import de.rub.nds.ssl.analyzer.vnl.FingerprintListener;
import de.rub.nds.ssl.analyzer.vnl.FingerprintReporter;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import org.apache.log4j.Logger;

import javax.annotation.Nonnull;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Factory for  Adapter instances for JTree to display
 * {@link FingerprintListener#fingerprints}. Uses {@link FingerprintTreeModel}.
 *
 * @author jBiegert azrdev@qrdn.de
 * @see DefaultTreeModel
 * @see DefaultMutableTreeNode
 */
public class FingerprintStorageModel {
    private static final Logger logger = Logger.getLogger(FingerprintStorageModel.class);

    public static TreeModel getModel(FingerprintListener backend) {
        final DefaultMutableTreeNode root = new DefaultMutableTreeNode("root");

        final DefaultTreeModel model = new DefaultTreeModel(root);

        //FIXME: this calls the model, but not from the event-dispatching thread
        backend.addFingerprintReporter(new FingerprintReporter() {
            @Override
            public void reportChange(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint, Set<TLSFingerprint> previousFingerprints) {
                addNode(model, sessionIdentifier, fingerprint, true);
            }

            @Override
            public void reportUpdate(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
            }

            @Override
            public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
                addNode(model, sessionIdentifier, tlsFingerprint, false);
            }

            @Override
            public void reportArtificial(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
                addNode(model, sessionIdentifier, fingerprint, true);
            }
        });

        //TODO: asynchronous load
        final ImmutableSetMultimap<SessionIdentifier, TLSFingerprint> fingerprints =
                backend.getFingerprints();
        for (SessionIdentifier sesId : fingerprints.keys()) {
            addNode(model, sesId, fingerprints.get(sesId).asList(), true);
        }

        return model;
    }

    /**
     * single-fingerprint overload for {@link #addNode(DefaultTreeModel, SessionIdentifier, List, boolean)}
     */
    private static void addNode(
            final @Nonnull DefaultTreeModel model,
            final @Nonnull SessionIdentifier sesId,
            final @Nonnull TLSFingerprint fingerprint,
            boolean sessionIdMightExist) {
        addNode(model, sesId, Arrays.asList(fingerprint), sessionIdMightExist);
    }

    /**
     * Add nodes for sesId (if not already existing) and fingerprints, to model
     * @param sessionIdMightExist  If false,
     */
    private static void addNode(
            final @Nonnull DefaultTreeModel model,
            final @Nonnull SessionIdentifier sesId,
            final @Nonnull List<TLSFingerprint> fingerprints,
            boolean sessionIdMightExist) {
        synchronized (Objects.requireNonNull(model)) {
            final DefaultMutableTreeNode root = (DefaultMutableTreeNode) model.getRoot();
            if (sessionIdMightExist) {
                DefaultMutableTreeNode parent = findNodeByUserObject(root, sesId);
                if (parent == null) {
                    logger.debug("Could not find tree node for sessionId " + sesId);
                    parent = FingerprintTreeModel.createNode(sesId);
                    model.insertNodeInto(parent, root, root.getChildCount());
                }
                for (TLSFingerprint fingerprint : fingerprints) {
                    model.insertNodeInto(FingerprintTreeModel.createNode(fingerprint),
                            parent, parent.getChildCount());
                }
            } else {
                final DefaultMutableTreeNode node = FingerprintTreeModel.createNode(sesId);
                for (TLSFingerprint fingerprint : fingerprints) {
                    node.add(FingerprintTreeModel.createNode(fingerprint));
                }
                model.insertNodeInto(node, root, root.getChildCount());
            }
            //TODO: make insertNodeInto() display the new nodes, then remove this reload() call
            model.reload();
        }
    }

    private static DefaultMutableTreeNode findNodeByUserObject(
            @Nonnull DefaultMutableTreeNode root, Object userObject) {
        DefaultMutableTreeNode node = null;
        Enumeration<DefaultMutableTreeNode> e;
        for (e = root.breadthFirstEnumeration();
             e.hasMoreElements();
             node = e.nextElement()) {
            if (node != null && Objects.equals(userObject, node.getUserObject()))
                return node;
        }
        return null;
    }

}
