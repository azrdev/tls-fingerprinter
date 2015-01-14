package de.rub.nds.ssl.analyzer.vnl.gui;

import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import org.apache.log4j.Logger;

import javax.annotation.Nonnull;
import javax.swing.*;
import javax.swing.tree.DefaultTreeModel;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Window displaying a single fingerprint report (i.e. New/Changed/Updated/Artificial
 * fingerprint).
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class FingerprintReportWindow extends JFrame {
    private static final Logger logger = Logger.getLogger(FingerprintReportWindow.class);

    private JTabbedPane tabPane;

    /**
     * view for the {@link SessionIdentifier}. Uses {@link FingerprintTreeModel}.
     */
    private JTree endpointTree;
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
    private JTable previousFingerprintDiffTable;

    public FingerprintReportWindow(FingerprintReportModel.Report report) {
        super(String.format("Fingerprint details for %s (%s)(%s)",
                report.sessionIdentifier.getServerHostName(),
                report.typeString(),
                report.dateTime));
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setContentPane(tabPane);

        // setup endpoint view
        endpointTree.setModel(new DefaultTreeModel(
                FingerprintTreeModel.createNode(report.sessionIdentifier)));
        unfoldTree(endpointTree);
        // setup fingerprint view
        fingerprintTree.setModel(new DefaultTreeModel(
                FingerprintTreeModel.createNode(report.tlsFingerprint)));
        unfoldTree(fingerprintTree);

        if(!(report instanceof FingerprintReportModel.ChangedReport)) {
            tabPane.setEnabledAt(tabPane.indexOfComponent(showPreviousPanel), false);
            tabPane.setEnabledAt(tabPane.indexOfComponent(diffPreviousPanel), false);
        } else {
            final List<TLSFingerprint> previousFingerprints =
                    ((FingerprintReportModel.ChangedReport) report).previousFingerprints.asList();

            final DefaultComboBoxModel<Integer> previousFingerprintModel =
                    new DefaultComboBoxModel<>(rangeArray(0, previousFingerprints.size()));

            // setup previousFingerprint* views
            previousFingerprintTree.setModel(null);
            final FingerprintDiffTableModel fingerprintDiffTableModel =
                    new FingerprintDiffTableModel(report.tlsFingerprint);
            previousFingerprintDiffTable.setModel(fingerprintDiffTableModel);
            final ItemListener comboBoxListener = new ItemListener() {
                @Override
                public void itemStateChanged(ItemEvent itemEvent) {
                    if(itemEvent.getStateChange() != ItemEvent.SELECTED)
                        return;
                    int fpIndex = (Integer) previousFingerprintModel.getSelectedItem();
                    final TLSFingerprint fingerprint = previousFingerprints.get(fpIndex);

                    // display the fingerprint in the "show" tree
                    previousFingerprintTree.setModel(new DefaultTreeModel(
                            FingerprintTreeModel.createNode(fingerprint)));
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
