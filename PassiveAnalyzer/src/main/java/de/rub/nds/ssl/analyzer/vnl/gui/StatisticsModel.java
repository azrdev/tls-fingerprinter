package de.rub.nds.ssl.analyzer.vnl.gui;

import com.google.common.collect.Multiset;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.FingerprintStatistics;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.StandardChartTheme;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.labels.StandardCategoryItemLabelGenerator;
import org.jfree.chart.labels.StandardXYItemLabelGenerator;
import org.jfree.chart.labels.XYItemLabelGenerator;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.renderer.xy.XYItemRenderer;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DatasetUtilities;
import org.jfree.data.xy.XYBarDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import java.awt.*;
import java.util.*;
import java.util.List;

import static de.rub.nds.ssl.analyzer.vnl.fingerprint.FingerprintStatistics.ReportType.*;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class StatisticsModel implements Observer {
    private static final Color changeColor = Color.red;

    private final FingerprintStatistics statistics;

    // dataset instances
    private final DefaultCategoryDataset reportsDataset = new DefaultCategoryDataset();
    private final XYSeries previousCountSeries =
            new XYSeries("Previous Fingerprints", true, false);

    public StatisticsModel(FingerprintStatistics statistics) {
        this.statistics = statistics;
        statistics.addObserver(this);

        ChartFactory.setChartTheme(StandardChartTheme.createLegacyTheme());

        reportsDataset.addValue(null, "Count", "New");
        reportsDataset.addValue(null, "Count", "Update");
        reportsDataset.addValue(null, "Count", "Guess");
        reportsDataset.addValue(null, "Count", "Changed");
    }

    public JFreeChart getReportsChart() {
        final JFreeChart chart = ChartFactory.createBarChart(null, "Reports", "Count", reportsDataset,
                PlotOrientation.VERTICAL, false, true, false);
        chart.getCategoryPlot().setRenderer(new BarRenderer() {
            {
                setBaseItemLabelGenerator(new StandardCategoryItemLabelGenerator());
                setBaseItemLabelsVisible(true);
            }

            @Override
            public Paint getItemPaint(int row, int column) {
                final List<Color> colors = Arrays.asList(
                        Color.green, Color.blue.brighter(), Color.yellow, changeColor);
                return colors.get( column % colors.size() );
            }
        });
        return chart;
    }

    public JFreeChart getPreviousCountChart() {
        final JFreeChart chart = ChartFactory.createXYBarChart(
                null, "# Previous fingerprints", false, "Changed Report Count",
                new XYBarDataset(new XYSeriesCollection(previousCountSeries), 1),
                PlotOrientation.VERTICAL, false, true, false);
        XYPlot plot = (XYPlot) chart.getPlot();
        NumberAxis domainAxis = (NumberAxis) plot.getDomainAxis();
        domainAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        XYItemRenderer renderer = plot.getRenderer();
        renderer.setBaseItemLabelsVisible(true);
        renderer.setBaseItemLabelGenerator(new StandardXYItemLabelGenerator());
        renderer.setBasePaint(changeColor); // this is probably overwritten by seriesPaint
        return chart;
    }

    // Observer implementation

    @Override
    public void update(Observable observable, Object o) {
        reportsDataset.setValue(statistics.getReportCount(New), "Count", "New");
        reportsDataset.setValue(statistics.getReportCount(Update), "Count", "Update");
        reportsDataset.setValue(statistics.getReportCount(Generated), "Count", "Guess");
        reportsDataset.setValue(statistics.getReportCount(Change), "Count", "Changed");

        if(! Objects.equals(o, "Change"))
            return;

        for (Multiset.Entry<Integer> entry :
                statistics.getDiffsToPreviousDistribution().entrySet()) {
            previousCountSeries.addOrUpdate((Number) entry.getElement(), entry.getCount());
        }
    }
}
