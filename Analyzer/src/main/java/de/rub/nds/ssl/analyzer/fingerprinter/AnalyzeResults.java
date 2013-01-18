package de.rub.nds.ssl.analyzer.fingerprinter;

/**
 * Assign a fingerprint score for a specific implementation.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Jun 21, 2012
 */
public class AnalyzeResults {

    public void generateReport() {
        ScoreCounter counter = ScoreCounter.getInstance();
        int jsse = counter.getJSSEStandardScore();
        int openssl = counter.getOpenSSLScore();
        int gnutls = counter.getGNUtlsScore();
        int total = counter.getTotalCounter();
        int noHit = counter.getNoHitCounter();
        float result;
        //output the score for each implementation
        System.out.println("JSSE Points: " + jsse);
        System.out.println("GNUtls Points: " + gnutls);
        System.out.println("OpenSSL Points: " + openssl);
        System.out.println("NoHit: " + noHit);
        //compute probability
        result = this.computeProbability(jsse, total);
        System.out.println("Probability for JSSE: " + result);
        result = this.computeProbability(gnutls, total);
        System.out.println("Probability for GNUtls: " + result);
        result = this.computeProbability(openssl, total);
        System.out.println("Probability for OpenSSL: " + result);
        result = this.computeProbability(noHit, total);
        System.out.println("No hit in DB: " + result);

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
