package de.rub.nds.ssl.analyzer.vnl.gui;

import de.rub.nds.ssl.analyzer.vnl.FingerprintListener;
import de.rub.nds.ssl.analyzer.vnl.FingerprintReporter.FingerprintReporterAdapter;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import de.rub.nds.ssl.analyzer.vnl.gui.FingerprintTreeModel.*;
import org.apache.log4j.Logger;

import javax.annotation.Nonnull;
import javax.swing.*;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeWillExpandListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.ExpandVetoException;
import java.util.Enumeration;
import java.util.Objects;
import java.util.Set;

/**
 * Adapter for JTree to display {@link FingerprintListener#fingerprints}. Uses {@link
 * FingerprintTreeModel}.
 *
 * @author jBiegert azrdev@qrdn.de
 * @see DefaultTreeModel
 * @see FingerprintTreeModel
 */
public class FingerprintStorageModel
        extends FingerprintReporterAdapter
        implements TreeWillExpandListener {
    private static final Logger logger = Logger.getLogger(FingerprintStorageModel.class);

    private final DefaultMutableTreeNode root;
    private final DefaultTreeModel treeModel;

    public DefaultTreeModel getTreeModel() {
        return treeModel;
    }

    // creation and loading

    public static FingerprintStorageModel create(FingerprintListener backend) {
        return new FingerprintStorageModel(backend);
    }

    private FingerprintStorageModel(FingerprintListener backend) {
        backend.addFingerprintReporter(this);
        root = RootFingerprintTreeNode.create(backend.getFingerprints(), true);
        treeModel = new DefaultTreeModel(root, true);
        treeModel.reload(); //TODO: necessary ?
    }

    /**
     * Add node for new sesId to root, or for new fingerprint to sesId
     */
    private void addNode(final @Nonnull SessionIdentifier sesId,
                         final @Nonnull TLSFingerprint fingerprint,
                         final boolean sesIdMightBeNew) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                DefaultMutableTreeNode sesIdNode =
                        findNodeByUserObject(sesId, SessionIdentifier.class);
                if (sesIdNode == null) {
                    if (!sesIdMightBeNew) {
                        logger.warn("TreeNode should exist but not found, " +
                                "for SessionId: " + sesId);
                    }
                    // prefer adding doubles over hiding sth
                    sesIdNode = SessionIdentifierTreeNode.createLazy(sesId);
                    treeModel.insertNodeInto(sesIdNode, root, root.getChildCount());
                }
                treeModel.insertNodeInto(TlsFingerprintTreeNode.createLazy(fingerprint),
                        sesIdNode, sesIdNode.getChildCount());
            }
        });
    }

    /**
     * Does a breadth first search for a node by its userObject.
     * @param requireClass <code>return null</code> if any node is iterated whose
     *                     userObject is not an instance of [a subclass of] requireClass.
     *                     Might be <code>null</code> to disable that condition.
     * @return The node that has the given userObject
     */
    private DefaultMutableTreeNode findNodeByUserObject(@Nonnull Object userObject,
                                                        Class requireClass) {
        DefaultMutableTreeNode node = null;
        Enumeration<DefaultMutableTreeNode> e = root.breadthFirstEnumeration();
        for (e.nextElement() /* skip the root node */;
             e.hasMoreElements();
             node = e.nextElement()) {
            if (node != null) {
                if (Objects.equals(userObject, node.getUserObject()))
                    return node;
                if(requireClass != null && !requireClass.isInstance(node.getUserObject()))
                    return null;
            }
        }
        return null;
    }

    // TreeWillExpandListener

    @Override
    public void treeWillExpand(TreeExpansionEvent treeExpansionEvent) throws ExpandVetoException {
        final Object _node = treeExpansionEvent.getPath().getLastPathComponent();
        if(_node instanceof FingerprintTreeNode) {
            FingerprintTreeNode node = (FingerprintTreeNode) _node;

            // change parameter childrenCreateLazy=false to load all children recursively
            if(node.loadChildren(true))
                treeModel.nodeStructureChanged(node);
        }
    }

    @Override
    public void treeWillCollapse(TreeExpansionEvent treeExpansionEvent) throws ExpandVetoException {
        // nothing
    }

    // FingerprintReporter

    @Override
    public void reportChange(SessionIdentifier sessionIdentifier,
                             TLSFingerprint fingerprint,
                             Set<TLSFingerprint> previousFingerprints) {
        addNode(sessionIdentifier, fingerprint, false);
    }

    @Override
    public void reportNew(SessionIdentifier sessionIdentifier,
                          TLSFingerprint tlsFingerprint) {
        addNode(sessionIdentifier, tlsFingerprint, true);
    }

    @Override
    public void reportArtificial(SessionIdentifier sessionIdentifier,
                                 TLSFingerprint fingerprint) {
        addNode(sessionIdentifier, fingerprint, true);
    }
}
