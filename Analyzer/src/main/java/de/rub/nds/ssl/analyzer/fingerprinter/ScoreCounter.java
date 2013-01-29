package de.rub.nds.ssl.analyzer.fingerprinter;

import java.util.EnumMap;

/**
 * Counts the points of the fingerprint analyzers.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 24, 2012
 */
public final class ScoreCounter {

    /**
     * Score counter instance.
     */
    private static volatile ScoreCounter instance;
    /**
     * Total score.
     */
    private int totalCounter = 0;
    /**
     * Score for no hits.
     */
    private int noHit = 0;
    /**
     * Map of counters for each implementation.
     */
    private EnumMap<ETLSImplementation, Integer> counter;

    /**
     * Empty constructor.
     */
    private ScoreCounter() {
        counter = new EnumMap<ETLSImplementation, Integer>(
                ETLSImplementation.class);
    }

    /**
     * Get an instance of ScoreCounter.
     *
     * @return Instance of ScoreCounter
     */
    public static ScoreCounter getInstance() {
        if (instance == null) {
            instance = new ScoreCounter();
        }
        return instance;
    }

    /**
     * Count the score for different implementations.
     *
     * @param impl TLS implementation
     * @param score Score
     */
    public void countResult(final ETLSImplementation impl, final int score) {
        //always add the score to compute the total reachable points
        this.totalCounter += score;
        //assign the score for a specific implementation
        Integer newValue = counter.get(impl);
        if (newValue == null) {
            newValue = score;
        } else {
            newValue += score;
        }
        counter.put(impl, newValue);

    }

    /**
     * Assign a score if DB search leads to no hit.
     *
     * @param score Score
     */
    public void countNoHit(final int score) {
        this.noHit += score;
    }

    /**
     * Get the score for a given implementation.
     *
     * @param impl Implementation for which to receive the scoring
     * @return Score of the passed implementation
     */
    public int getScore(final ETLSImplementation impl) {
        int result;
        try {
            result = counter.get(impl);
        } catch (NullPointerException e) {
            result = 0;
        }

        return result;
    }

    /**
     * Get the total reachable points of the fingerprint analysis.
     *
     * @return Total score
     */
    public int getTotalCounter() {
        return this.totalCounter + this.noHit;
    }

    /**
     * Get the points for no DB hits.
     *
     * @return No hit score
     */
    public int getNoHitCounter() {
        return this.noHit;
    }
}
