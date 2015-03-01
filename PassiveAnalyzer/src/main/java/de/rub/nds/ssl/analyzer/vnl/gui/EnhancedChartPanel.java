package de.rub.nds.ssl.analyzer.vnl.gui;

import org.jfree.chart.ChartPanel;

import java.awt.*;

/**
 * A convenience class for instantiatint {@link ChartPanel}s
 * @see StatisticsModel
 * @author jBiegert azrdev@qrdn.de
 */
public class EnhancedChartPanel extends ChartPanel {
    public EnhancedChartPanel() {
        super(null);
        setMouseWheelEnabled(true);
        setMinimumSize(new Dimension(0, 0)); // allow hiding via SplitPane
    }
}
