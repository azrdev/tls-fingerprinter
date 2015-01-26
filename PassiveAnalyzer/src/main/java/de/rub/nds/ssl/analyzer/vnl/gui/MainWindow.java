package de.rub.nds.ssl.analyzer.vnl.gui;

import com.google.common.base.Joiner;
import de.rub.nds.ssl.analyzer.vnl.FingerprintListener;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import javax.swing.*;
import javax.swing.event.MouseInputAdapter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseEvent;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.apache.log4j.Level.*;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class MainWindow extends JFrame {
    private final MessageListModel messageListModel = new MessageListModel();
    private final FingerprintReportModel fingerprintReportsModel;
    private final TableRowSorter<FingerprintReportModel> fingerprintReportsRowSorter;
    private final TableRowSorter<MessageListModel> logViewRowSorter;

    // ui elements
    private JTabbedPane tabPane;

    private JCheckBox showFingerprintUpdatesCheckBox;
    private JCheckBox showNewFingerprintsCheckBox;
    private JCheckBox showGuessedFingerprintsCheckBox;
    private JButton flushReportsButton;
    private ToolTippingTable fingerprintReportsTable;

    private JTree storedFingerprintTree;

    private JComboBox<Level> logLevelCB;
    private ToolTippingTable logView;
    private JButton flushLogButton;

    public MainWindow(FingerprintListener listener) {
        super();
        // setup JFrame
        setTitle("TLS Fingerprinter");
        setContentPane(tabPane);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        //// setup fingerprint Reports View
        fingerprintReportsModel = FingerprintReportModel.getModel(listener);
        fingerprintReportsTable.setModel(fingerprintReportsModel);
        // column sizes
        fingerprintReportsTable.getColumnModel().getColumn(0).setPreferredWidth(100);
        fingerprintReportsTable.getColumnModel().getColumn(1).setPreferredWidth(50);
        fingerprintReportsTable.getColumnModel().getColumn(2).setPreferredWidth(225);
        fingerprintReportsTable.getColumnModel().getColumn(3).setPreferredWidth(1000);
        // display date + time
        fingerprintReportsTable.setDefaultRenderer(Date.class,
                new DefaultTableCellRenderer() {
                    private final DateFormat format = new SimpleDateFormat();
                    @Override
                    protected void setValue(Object value) {
                        setText(format.format((Date) value));
                    }
                });
        // row sorting & filtering
        fingerprintReportsRowSorter = new TableRowSorter<>(fingerprintReportsModel);
        fingerprintReportsTable.setRowSorter(fingerprintReportsRowSorter);
        fingerprintReportsRowSorter.setSortsOnUpdates(true);
        // show report details on user action
        fingerprintReportsTable.getInputMap().put(KeyStroke.getKeyStroke("ENTER"), "show-report");
        fingerprintReportsTable.getActionMap().put("show-report", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                final int modelIndex = fingerprintReportsTable.convertRowIndexToModel(
                        fingerprintReportsTable.getSelectedRow());
                showReportItem(modelIndex);
            }
        });
        fingerprintReportsTable.addMouseListener(new MouseInputAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() > 1) {
                    final int modelIndex = fingerprintReportsTable.convertRowIndexToModel(
                            fingerprintReportsTable.rowAtPoint(e.getPoint()));
                    showReportItem(modelIndex);
                }
            }
        });
        // setup fingerprint Reports Components
        final ItemListener fingerprintCheckBoxListener = new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent itemEvent) {
                updateFingerprintReportsFilter();
            }
        };
        showFingerprintUpdatesCheckBox.addItemListener(fingerprintCheckBoxListener);
        showNewFingerprintsCheckBox.addItemListener(fingerprintCheckBoxListener);
        showGuessedFingerprintsCheckBox.addItemListener(fingerprintCheckBoxListener);
        updateFingerprintReportsFilter();
        flushReportsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                fingerprintReportsModel.flushReports();
            }
        });

        //// setup storedFingerprintTree
        storedFingerprintTree.setModel(FingerprintStorageModel.getModel(listener));
        storedFingerprintTree.setRootVisible(false);
        storedFingerprintTree.setShowsRootHandles(true);
        storedFingerprintTree.setEditable(false);
        storedFingerprintTree.setCellRenderer(new TooltippingTreeRenderer());
        ToolTipManager.sharedInstance().registerComponent(storedFingerprintTree);

        //// setup logView
        Logger.getRootLogger().addAppender(messageListModel.getAppender());
        logView.setModel(messageListModel);
        logView.getColumnModel().getColumn(0).setPreferredWidth(160);
        logView.getColumnModel().getColumn(1).setPreferredWidth(60);
        logView.getColumnModel().getColumn(2).setPreferredWidth(400);
        logView.getColumnModel().getColumn(3).setPreferredWidth(700);
        logView.setDefaultRenderer(Date.class, new DefaultTableCellRenderer() {
            private final DateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
            @Override
            protected void setValue(Object value) {
                setText(f.format((Date) value));
            }
        });
        // sorting & filtering
        logViewRowSorter = new TableRowSorter<>(messageListModel);
        logView.setRowSorter(logViewRowSorter);
        // setup logLevel ComboBox
        logLevelCB.setSelectedItem(messageListModel.getAppender().getThreshold());
        logLevelCB.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                final JComboBox source = (JComboBox) actionEvent.getSource();
                final Level level = (Level) source.getSelectedItem();
                messageListModel.getAppender().setThreshold(level);
                logViewRowSorter.setRowFilter(new RowFilter<MessageListModel, Integer>() {
                    final int levelColumnIndex = messageListModel.findColumn("LogLevel");
                    @Override
                    public boolean include(Entry<? extends MessageListModel, ? extends Integer> entry) {
                        final Level entryLevel = (Level) entry.getValue(levelColumnIndex);
                        return entryLevel.isGreaterOrEqual(level);
                    }
                });
            }
        });
        flushLogButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                messageListModel.clear();
            }
        });

        pack();
        setVisible(true);
    }

    /**
     * set a filter on {@link #fingerprintReportsRowSorter} according to the state of
     * the associated CheckBoxes.
     * @see TableRowSorter#setRowFilter(RowFilter)
     */
    private void updateFingerprintReportsFilter() {
        final String regex = '^' + Joiner.on('|').skipNulls().join("Change",
                (showNewFingerprintsCheckBox.isSelected()? "New" : null),
                (showFingerprintUpdatesCheckBox.isSelected()? "Update" : null),
                (showGuessedFingerprintsCheckBox.isSelected()? "Guess" : null)) + '$';
        fingerprintReportsRowSorter.setRowFilter(RowFilter.regexFilter(regex,
                fingerprintReportsModel.findColumn("Type")));
    }

    /**
     * @see FingerprintReportModel#showReportItem(int)
     */
    private void showReportItem(int indexInModel) {
        fingerprintReportsModel.showReportItem(indexInModel);
    }

    private void createUIComponents() {
        logLevelCB = new JComboBox<>(new Level[]{ALL, TRACE, DEBUG, INFO, WARN, Level.ERROR, FATAL});
    }
}
