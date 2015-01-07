package de.rub.nds.ssl.analyzer.vnl.gui;

import de.rub.nds.ssl.analyzer.vnl.FingerprintListener;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

import javax.swing.*;
import javax.swing.event.MouseInputAdapter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseEvent;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;

import static org.apache.log4j.Level.*;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class MainWindow extends JFrame {
    private MessageListModel messageListModel;

    // ui elements
    private JTabbedPane tabPane;

    private JCheckBox showFingerprintUpdatesCheckBox;
    private JCheckBox showNewFingerprintsCheckBox;
    private JCheckBox showGuessedFingerprintsCheckBox;
    private JButton flushReportsButton;
    private JTable fingerprintReportsTable;

    private JTree storedFingerprintTree;

    private JComboBox<Level> logLevelCB;
    private JTable logView;

    public MainWindow(FingerprintListener listener) {
        super();
        // setup JFrame
        setTitle("TLS Fingerprinter");
        setContentPane(tabPane);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // setup fingerprint Reports View
        final FingerprintReportModel fingerprintReportsModel =
                FingerprintReportModel.getModel(listener);
        fingerprintReportsTable.setModel(fingerprintReportsModel);
        fingerprintReportsTable.getColumnModel().getColumn(0).setPreferredWidth(120);
        fingerprintReportsTable.getColumnModel().getColumn(1).setPreferredWidth(30);
        fingerprintReportsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        fingerprintReportsTable.setDefaultRenderer(Date.class,
                new DefaultTableCellRenderer() {
                    final DateFormat format = new SimpleDateFormat("");
                    @Override
                    protected void setValue(Object value) {
                        setText((value instanceof Date)?
                            format.format((Date) value) : Objects.toString(value));

                    }
                });
        fingerprintReportsTable.addMouseListener(new MouseInputAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(e.getClickCount() > 1)
                    fingerprintReportsModel.showReportItem(
                            fingerprintReportsTable.getSelectedRow());
            }
        });
        // setup fingerprint Reports Components
        showFingerprintUpdatesCheckBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent itemEvent) {
                fingerprintReportsModel.setShowUpdates(
                        itemEvent.getStateChange() == ItemEvent.SELECTED);
            }
        });
        showFingerprintUpdatesCheckBox.setSelected(fingerprintReportsModel.getShowUpdates());
        showNewFingerprintsCheckBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent itemEvent) {
                fingerprintReportsModel.setShowNew(
                        itemEvent.getStateChange() == ItemEvent.SELECTED);
            }
        });
        showNewFingerprintsCheckBox.setSelected(fingerprintReportsModel.getShowNew());
        showGuessedFingerprintsCheckBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent itemEvent) {
                fingerprintReportsModel.setShowArtificial(
                        itemEvent.getStateChange() == ItemEvent.SELECTED);
            }
        });
        showGuessedFingerprintsCheckBox.setSelected(fingerprintReportsModel.getShowArtificial());
        flushReportsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                fingerprintReportsModel.flushReports();
            }
        });

        // setup storedFingerprintTree
        storedFingerprintTree.setModel(FingerprintStorageModel.getModel(listener));
        storedFingerprintTree.setRootVisible(false);
        storedFingerprintTree.setShowsRootHandles(true);
        storedFingerprintTree.setEditable(false);

        // setup logView
        messageListModel = new MessageListModel();
        logView.setModel(messageListModel);
        logView.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        logView.getColumnModel().getColumn(0).setPreferredWidth(120);
        logView.getColumnModel().getColumn(1).setPreferredWidth(50);
        logView.getColumnModel().getColumn(2).setPreferredWidth(80);
        logView.getColumnModel().getColumn(3).setPreferredWidth(400);
        Logger.getRootLogger().addAppender(messageListModel.getAppender());
        // setup logLevel
        logLevelCB.setSelectedItem(messageListModel.getAppender().getThreshold());
        logLevelCB.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                Level level = (Level) ((JComboBox) actionEvent.getSource()).getSelectedItem();
                messageListModel.getAppender().setThreshold(level);
            }
        });

        pack();
        setVisible(true);
    }

    private void createUIComponents() {
        logLevelCB = new JComboBox<>(new Level[]{ALL, TRACE, DEBUG, INFO, WARN, FATAL});
    }
}
