package de.rub.nds.ssl.analyzer.fingerprinter;

/**
 * Counts the points of the fingerprint analyzers,
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 24, 2012
 */
public class ScoreCounter {

	/**
	 * Score counter instance.
	 */
    private static volatile ScoreCounter counter;
    /**
     * OpenSSL score.
     */
    private int openSSLScore = 0;
    /**
     * JSSE score.
     */
    private int jsseStandardScore = 0;
    /**
     * GnuTLS score.
     */
    private int gnutlsScore = 0;
    /**
     * Total score.
     */
    private int totalCounter = 0;
    /**
     * Score for no hits.
     */
    private int noHit = 0;

    /**
     * Empty constructor.
     */
    private ScoreCounter() {
    }

    /**
     * Get an instance of ScoreCounter.
     * @return Instance of ScoreCounter
     */
    public static ScoreCounter getInstance() {
        if (counter == null) {
            counter = new ScoreCounter();
        }
        return counter;
    }

    /**
     * Count the score for different implementations
     *
     * @param impl TLS implementation
     * @param score Score
     */
    public void countResult(final ETLSImplementation impl, final int score) {
    	//always add the score to compute the total reachable points
        this.totalCounter += score;
        //assign the score for a specific implementation
        switch (impl) {
            case OPENSSL:
                this.openSSLScore += score;
                break;
            case JSSE_STANDARD:
                this.jsseStandardScore += score;
                break;
            case GNUTLS:
                this.gnutlsScore += score;
                break;
            default:
                break;
        }

    }

    /**
     * Assign a score if DB search leads to no hit.
     * @param score Score
     */
    public void countNoHit(final int score) {
        this.noHit = this.noHit + score;
    }

    /**
     * Get the score for OpenSSL.
     * @return OpenSSL score
     */
    public int getOpenSSLScore() {
        return this.openSSLScore;
    }

    /**
     * Get the score for JSSE.
     * @return JSSE score.
     */
    public int getJSSEStandardScore() {
        return this.jsseStandardScore;
    }

    /**
     * Get the score for GnuTLS.
     * @return GnuTLS score
     */
    public int getGNUtlsScore() {
        return this.gnutlsScore;
    }

    /**
     * Get the total reachable points of the fingerprint analysis.
     * @return Total score
     */
    public int getTotalCounter() {
        return this.totalCounter + this.noHit;
    }

    /**
     * Get the points for no DB hits.
     * @return No hit score
     */
    public int getNoHitCounter() {
        return this.noHit;
    }
}
