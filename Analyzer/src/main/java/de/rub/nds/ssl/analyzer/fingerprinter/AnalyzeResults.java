package de.rub.nds.ssl.analyzer.fingerprinter;

import org.apache.log4j.Logger;

/**
 * Assign a fingerprint score for a specific implementation.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 21, 2012
 */
public class AnalyzeResults {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();

    /**
     * Generate the analyzer report.
     */
    public void generateReport() {
        ScoreCounter counter = ScoreCounter.getInstance();

        int total = counter.getTotalCounter();
        int score = counter.getNoHitCounter();
        float result = this.computeProbability(score, total);
        logger.info("NoHit: " + score);
        logger.info("No hit in DB: " + result);
        for (ETLSImplementation impl : ETLSImplementation.values()) {
            //output the score for each implementation
            score = counter.getScore(impl);
            logger.info(impl.name() + " Points: " + score);
            //compute probability
            result = this.computeProbability(score, total);
            logger.info("  Probability: " + result);
        }
    }

    /**
     * Compute the probability for a specific implementation.
     *
     * @param impl Implementation score
     * @param total Maximum reachable score
     * @return Probability for the implementation
     */
    private float computeProbability(final int impl, final int total) {
        float result;
        result = ((float) impl / (float) total) * 100;
        return result;
    }
}
