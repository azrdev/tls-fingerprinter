package de.rub.nds.ssl.analyzer.vnl.gui;

import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import de.rub.nds.ssl.analyzer.vnl.gui.components.ToolTippingTable;
import de.rub.nds.ssl.analyzer.vnl.gui.components.TooltippingTreeRenderer;
import org.apache.log4j.Logger;

import javax.annotation.Nonnull;
import javax.swing.*;
import javax.swing.tree.DefaultTreeModel;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.LinkedList;
import java.util.List;

import static de.rub.nds.ssl.analyzer.vnl.gui.FingerprintTreeModel.*;

/**
 * Window displaying a single fingerprint report (i.e. New/Changed/Updated/Artificial
 * fingerprint).
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class FingerprintReportWindow extends JFrame {
    private static final Logger logger = Logger.getLogger(FingerprintReportWindow.class);

    private JTabbedPane tabPane;

    private JPanel showEndpoint;
    /**
     * view for the {@link SessionIdentifier}. Uses {@link FingerprintTreeModel}.
     */
    private JTree endpointTree;

    private JPanel showFingerprint;
    /**
     * view for the {@link TLSFingerprint}. Uses {@link FingerprintTreeModel}.
     */
    private JTree fingerprintTree;

    private JPanel showPreviousPanel;
    private JComboBox<Integer> previousFingerprintSelectShowComboBox;
    /**
     * view for the selected previous {@link TLSFingerprint}. Uses {@link FingerprintTreeModel}.
     */
    private JTree previousFingerprintTree;

    private JPanel diffPreviousPanel;
    private JComboBox<Integer> previousFingerprintSelectDiffComboBox;
    /**
     * view for the difference to the selected previous {@link TLSFingerprint}. Uses
     * {@link FingerprintDiffTableModel}.
     */
    private ToolTippingTable previousFingerprintDiffTable;

    public FingerprintReportWindow(FingerprintReportModel.Report report) {
        super(String.format("Fingerprint details for %s (%s) %s%s(%s)",
                report.sessionIdentifier.getServerHostName(),
                report.type(),
                report.tlsFingerprint.hasIpFragmentation()? "IPv4-Fragmented " : "",
                report.tlsFingerprint.hasRetransmissions()? "TCP-Retransmissions " : "",
                report.dateTime));
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setContentPane(tabPane);
        setPreferredSize(new Dimension(800, 640));

        // setup endpoint view
        endpointTree.setModel(new DefaultTreeModel(
                SessionIdentifierTreeNode.create(report.sessionIdentifier, false)));
        endpointTree.setCellRenderer(new TooltippingTreeRenderer());
        ToolTipManager.sharedInstance().registerComponent(endpointTree);
        unfoldTree(endpointTree);
        // setup fingerprint view
        fingerprintTree.setModel(new DefaultTreeModel(
                TlsFingerprintTreeNode.create(report.tlsFingerprint, false)));
        ToolTipManager.sharedInstance().registerComponent(fingerprintTree);
        fingerprintTree.setCellRenderer(new TooltippingTreeRenderer());
        unfoldTree(fingerprintTree);

        if(!(report instanceof FingerprintReportModel.ChangedReport)) {
            tabPane.setEnabledAt(tabPane.indexOfComponent(showPreviousPanel), false);
            tabPane.setEnabledAt(tabPane.indexOfComponent(diffPreviousPanel), false);

            tabPane.setSelectedComponent(showFingerprint);
        } else {
            final List<TLSFingerprint> previousFingerprints =
                    ((FingerprintReportModel.ChangedReport) report).previousFingerprints.asList();

            final DefaultComboBoxModel<Integer> previousFingerprintModel =
                    new DefaultComboBoxModel<>(rangeArray(0, previousFingerprints.size()));

            // setup previousFingerprint* views
            previousFingerprintTree.setModel(null);
            final FingerprintDiffTableModel fingerprintDiffTableModel =
                    new FingerprintDiffTableModel(report.tlsFingerprint);
            previousFingerprintTree.setCellRenderer(new TooltippingTreeRenderer());
            ToolTipManager.sharedInstance().registerComponent(previousFingerprintTree);
            previousFingerprintDiffTable.setModel(fingerprintDiffTableModel);
            previousFingerprintDiffTable.getColumnModel().getColumn(0).setPreferredWidth(200);
            previousFingerprintDiffTable.getColumnModel().getColumn(1).setPreferredWidth(500);
            previousFingerprintDiffTable.getColumnModel().getColumn(2).setPreferredWidth(500);
            final ItemListener comboBoxListener = new ItemListener() {
                @Override
                public void itemStateChanged(ItemEvent itemEvent) {
                    if(itemEvent.getStateChange() != ItemEvent.SELECTED)
                        return;
                    int fpIndex = (Integer) previousFingerprintModel.getSelectedItem();
                    final TLSFingerprint fingerprint = previousFingerprints.get(fpIndex);

                    // display the fingerprint in the "show" tree
                    previousFingerprintTree.setModel(new DefaultTreeModel(
                            TlsFingerprintTreeNode.create(fingerprint, false)));
                    unfoldTree(previousFingerprintTree);

                    // display the fingerprint in the "diff" view
                    fingerprintDiffTableModel.setDiffTarget(fingerprint);
                }
            };

            // setup previousFingerprintSelect* ComboBoxes
            // sync selection of previous fingerprint in  show & diff
            previousFingerprintSelectDiffComboBox.setModel(previousFingerprintModel);
            previousFingerprintSelectShowComboBox.setModel(previousFingerprintModel);
            previousFingerprintSelectShowComboBox.addItemListener(comboBoxListener);
            previousFingerprintSelectDiffComboBox.addItemListener(comboBoxListener);
            // display more than plain previous-index
            final DefaultListCellRenderer comboBoxRenderer = new DefaultListCellRenderer() {
                @Override
                public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                    return super.getListCellRendererComponent(list,
                            (value instanceof Integer) ? "Previous #" + value : value,
                            index, isSelected, cellHasFocus);
                }
            };
            previousFingerprintSelectShowComboBox.setRenderer(comboBoxRenderer);
            previousFingerprintSelectDiffComboBox.setRenderer(comboBoxRenderer);

            // un-set selection first, or itemStateChanged() will not be called
            previousFingerprintModel.setSelectedItem(null);
            previousFingerprintModel.setSelectedItem(previousFingerprintModel.getElementAt(0));

            tabPane.setSelectedComponent(diffPreviousPanel);
        }

        pack();
        setVisible(true);
    }

    private static void unfoldTree(@Nonnull JTree tree) {
        for(int i = tree.getRowCount() -1; i > 0; --i)
            tree.expandRow(i);
    }

    /**
     * @return <code>Integer[]</code> containing the interval [min, max)
     */
    private static @Nonnull Integer[] rangeArray(final int min, final int max) {
        List<Integer> list = new LinkedList<>();
        for(int i = min; i < max; ++i)
            list.add(i);
        return list.toArray(new Integer[list.size()]);
    }
}
