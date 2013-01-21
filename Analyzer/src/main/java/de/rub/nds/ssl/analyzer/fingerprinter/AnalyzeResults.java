package de.rub.nds.ssl.analyzer.fingerprinter;

import org.apache.log4j.Logger;

/**
 * Assign a fingerprint score for a specific implementation.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Jun 21, 2012
 */
public class AnalyzeResults {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    
    public void generateReport() {
        ScoreCounter counter = ScoreCounter.getInstance();
        int jsse = counter.getJSSEStandardScore();
        int openssl = counter.getOpenSSLScore();
        int gnutls = counter.getGNUtlsScore();
        int total = counter.getTotalCounter();
        int noHit = counter.getNoHitCounter();
        float result;
        //output the score for each implementation
        logger.info("JSSE Points: " + jsse);
        logger.info("GNUtls Points: " + gnutls);
        logger.info("OpenSSL Points: " + openssl);
        logger.info("NoHit: " + noHit);
        //compute probability
        result = this.computeProbability(jsse, total);
        logger.info("Probability for JSSE: " + result);
        result = this.computeProbability(gnutls, total);
        logger.info("Probability for GNUtls: " + result);
        result = this.computeProbability(openssl, total);
        logger.info("Probability for OpenSSL: " + result);
        result = this.computeProbability(noHit, total);
        logger.info("No hit in DB: " + result);

    }
    
    /**
     * Compute the probability for a specific implementation.
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
