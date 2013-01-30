package de.rub.nds.ssl.analyzer.executor;

import de.rub.nds.ssl.analyzer.AnalyzerResult;
import de.rub.nds.ssl.analyzer.fingerprinter.ETLSImplementation;
import de.rub.nds.ssl.analyzer.fingerprinter.ScoreCounter;
import java.text.DecimalFormat;
import org.apache.log4j.Logger;

/**
 * <DESCRIPTION> @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 30, 2013
 */
public final class Reporter {

    private Reporter() {
    }

    private static ScoreCounter compress(final AnalyzerResult[] results) {
        ScoreCounter result = new ScoreCounter();

        // sum up the results
        ScoreCounter tmpSC;
        for (AnalyzerResult tmpResult : results) {
            tmpSC = tmpResult.getScoreCounter();
            if (tmpSC != null) {
                for (ETLSImplementation impl : ETLSImplementation.values()) {
                    result.countResult(impl, tmpSC.getScore(impl));
                }
            }
        }

        return result;
    }

    public static void generateReport(final AnalyzerResult[] results,
            final Logger logger) {

        logger.info("########################################################"
                + "################");
        logger.info("Final analyzer Results");
        logger.info("########################################################"
                + "################");
        // sum up the results
        ScoreCounter scoreCounter = compress(results);
        int totalScore = scoreCounter.getTotalCounter();

        // output results
        int tmpScore = 0;
        DecimalFormat twoDForm = new DecimalFormat("###.##");
        for (ETLSImplementation impl : ETLSImplementation.values()) {
            tmpScore = scoreCounter.getScore(impl);
            logger.info(impl.name() + ": " + tmpScore
                    + " - " + Double.valueOf(twoDForm.format(
                    (double) tmpScore / (double) totalScore * 100)
                    ) + "% Probability");
        }

        tmpScore = scoreCounter.getNoHitCounter();
        logger.info("No hit" + ": " + tmpScore
                + " - " + Double.valueOf(twoDForm.format(
                (double) tmpScore / (double) totalScore * 100))
                + "% Probability");
    }
}
