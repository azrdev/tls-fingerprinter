package de.rub.nds.ssl.analyzer.vnl.gui;

import com.google.common.collect.Multiset;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.FingerprintStatistics;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.StandardChartTheme;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.labels.ItemLabelAnchor;
import org.jfree.chart.labels.ItemLabelPosition;
import org.jfree.chart.labels.StandardCategoryItemLabelGenerator;
import org.jfree.chart.labels.StandardXYItemLabelGenerator;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.ValueMarker;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.renderer.xy.XYItemRenderer;
import org.jfree.data.DataUtilities;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DatasetUtilities;
import org.jfree.data.xy.XYBarDataset;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.ui.RectangleAnchor;
import org.jfree.ui.TextAnchor;

import java.awt.*;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.*;
import java.util.List;

import static de.rub.nds.ssl.analyzer.vnl.fingerprint.FingerprintStatistics.ReportType.*;

/**
 * @author jBiegert azrdev@qrdn.de
 */
//TODO: "total" insets
public class StatisticsModel implements Observer {
    private final FingerprintStatistics statistics;

    // dataset instances
    private final DefaultCategoryDataset reportsDataset = new DefaultCategoryDataset();
    private final XYSeries previousCountSeries =
            new XYSeries("Previous Fingerprints", true, false);
    private final ValueMarker previousCountAverageMarker = new AverageMarker(0);
    private final XYSeries diffSizeSeries =
            new XYSeries("Previous Fingerprints", true, false);
    private final ValueMarker diffSizeAverageMarker = new AverageMarker(0);
    private DefaultCategoryDataset signsCountDataset = new DefaultCategoryDataset();

    public StatisticsModel(FingerprintStatistics statistics) {
        this.statistics = statistics;
        statistics.addObserver(this);

        ChartFactory.setChartTheme(StandardChartTheme.createLegacyTheme());
    }

    public JFreeChart getReportsChart() {
        final JFreeChart chart = ChartFactory.createBarChart(
                "All Fingerprint Reports", "Reports", "Count", reportsDataset,
                PlotOrientation.VERTICAL, false, true, false);
        chart.getCategoryPlot().setRenderer(new SimpleBarChartRenderer(
                Arrays.asList(newColor, updateColor, guessColor, changeColor)));
        return chart;
    }

    public JFreeChart getPreviousCountChart() {
        final JFreeChart chart = ChartFactory.createXYBarChart(
                "Previous fingerprints per change report", "# Previous fingerprints",
                false, "Changed Report Count",
                new XYBarDataset(new XYSeriesCollection(previousCountSeries), 1),
                PlotOrientation.VERTICAL, false, true, false);
        XYPlot plot = chart.getXYPlot();
        plot.addDomainMarker(previousCountAverageMarker);
        plot.getDomainAxis().setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        XYItemRenderer renderer = plot.getRenderer();
        renderer.setBaseItemLabelsVisible(true);
        renderer.setBaseItemLabelGenerator(new PercentageXYLabelGenerator());
        renderer.setBasePositiveItemLabelPosition(innerItemLabel);
        renderer.setBasePaint(changeColor); // this is probably overwritten by seriesPaint
        return chart;
    }

    public JFreeChart getChangedSignsCountChart() {
        final JFreeChart chart = ChartFactory.createXYBarChart(
                "Diff sizes", "# of signs in diff", false,
                "Count of previous fingerprints",
                new XYBarDataset(new XYSeriesCollection(diffSizeSeries), 1),
                PlotOrientation.VERTICAL, false, true, false);
        final XYPlot plot = chart.getXYPlot();
        plot.addDomainMarker(diffSizeAverageMarker);
        plot.getDomainAxis().setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        XYItemRenderer renderer = plot.getRenderer();
        renderer.setBaseItemLabelsVisible(true);
        renderer.setBaseItemLabelGenerator(new PercentageXYLabelGenerator());
        renderer.setBasePositiveItemLabelPosition(innerItemLabel);
        renderer.setBasePaint(changeColor); // this is probably overwritten by seriesPaint
        return chart;
    }

    public JFreeChart getSignsCountChart() {
        final JFreeChart chart = ChartFactory.createBarChart(
                "Signs in all changed reports", null, "Count", signsCountDataset,
                PlotOrientation.HORIZONTAL, false, true, false);
        final BarRenderer renderer = (BarRenderer) chart.getCategoryPlot().getRenderer();
        renderer.setBaseItemLabelGenerator(new PercentageBarLabelGenerator());
        renderer.setBaseItemLabelsVisible(true);
        renderer.setBasePositiveItemLabelPosition(innerItemLabel);
        renderer.setPositiveItemLabelPositionFallback(innerItemLabel);
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

        for (final Multiset.Entry<Integer> entry :
                statistics.getDiffsToPreviousDistribution().entrySet()) {
            previousCountSeries.addOrUpdate((Number) entry.getElement(), entry.getCount());
        }
        previousCountAverageMarker.setValue(statistics.getDiffsToPreviousAverage());

        for (final Multiset.Entry<Integer> entry :
                statistics.getDiffSizeDistribution().entrySet()) {
            diffSizeSeries.addOrUpdate((Number) entry.getElement(), entry.getCount());
        }
        diffSizeAverageMarker.setValue(statistics.getChangedSignsAverage());

        // clear the dataset beforehand, there is no other way to do sorting by value
        signsCountDataset.clear();
        for (final Multiset.Entry<FingerprintStatistics.SignIdentifier> entry :
                statistics.getMostCommonChangedSigns(Integer.MAX_VALUE).entrySet()) {
            signsCountDataset.setValue(entry.getCount(), "Count", entry.getElement().toString());
        }
    }

    // Chart helper(s)
    private static final Color newColor = new Color(0x55, 0xFF, 0x55);
    private static final Color updateColor = new Color(0x55, 0x55, 0xFF);
    private static final Color guessColor = new Color(0xFF, 0xFF, 0x55);
    private static final Color changeColor = new Color(0xFF, 0x55, 0x55);

    private static final ItemLabelPosition innerItemLabel =
            new ItemLabelPosition(ItemLabelAnchor.CENTER, TextAnchor.CENTER);

    /**
     * A {@link BarRenderer} for bar charts with only one series (i.e., row in the
     * table). Sets different colors for each category (i.e. column).
     */
    private static class SimpleBarChartRenderer extends BarRenderer {
        private final List<Color> colors;

        public SimpleBarChartRenderer(final List<Color> colors) {
            this.colors = colors;

            setBaseItemLabelGenerator(new PercentageBarLabelGenerator());
            setBaseItemLabelsVisible(true);
            setBasePositiveItemLabelPosition(innerItemLabel);
            setPositiveItemLabelPositionFallback(innerItemLabel);
        }

        @Override
        public Paint getItemPaint(int row, int column) {
            return colors.get( column % colors.size() );
        }
    }

    /**
     * A {@link ValueMarker} for displaying the average
     */
    private static class AverageMarker extends ValueMarker {
        final DecimalFormat df = new DecimalFormat("Average: #");
        public AverageMarker(double value) {
            super(value);
            setLabelAnchor(RectangleAnchor.TOP_RIGHT);
            setLabelTextAnchor(TextAnchor.TOP_LEFT);
            df.setMaximumFractionDigits(2);
        }

        @Override
        public String getLabel() {
            return df.format(getValue());
        }
    }

    /**
     * Generator for Item Labels of a bar graph, which include the value and a
     * percentage relative to the series total.
     */
    private static class PercentageBarLabelGenerator
            extends StandardCategoryItemLabelGenerator {
        private static final NumberFormat numberFormat = NumberFormat.getInstance();
        private static final NumberFormat percentFormat = NumberFormat.getPercentInstance();

        @Override
        public String generateLabel(CategoryDataset dataset, int row, int column) {
            final double base = DataUtilities.calculateRowTotal(dataset, row);
            final Number value = dataset.getValue(row, column);
            if(value != null) {
                return numberFormat.format(value) + " (" +
                        percentFormat.format(value.doubleValue() / base) + ")";
            }
            return "-";
        }
    }

    /**
     * Generator for Item Labels of a XY graph, which include the y value and a
     * percentage relative to the series y total.
     */
    private static class PercentageXYLabelGenerator
            extends StandardXYItemLabelGenerator {
        private static final NumberFormat yFormat = NumberFormat.getInstance();
        private static final NumberFormat percentFormat = NumberFormat.getPercentInstance();

        @Override
        public String generateLabel(XYDataset dataset, int series, int item) {
            final double base = calculateSeriesYTotal(dataset, series);
            final Number value = dataset.getY(series, item);
            if(value != null) {
                return yFormat.format(value) + " (" +
                        percentFormat.format(value.doubleValue() / base) + ")";
            }
            return "-";
        }
    }

    /** @return The sum of all Y values in the series of the dataset */
    private static double calculateSeriesYTotal(XYDataset dataset, int series) {
        final int count = dataset.getItemCount(series);
        double sum = 0;
        for(int i = 0; i < count; ++i) {
            final Number y = dataset.getY(series, i);
            if(y != null)
                sum += y.doubleValue();
        }
        return sum;
    }
}
