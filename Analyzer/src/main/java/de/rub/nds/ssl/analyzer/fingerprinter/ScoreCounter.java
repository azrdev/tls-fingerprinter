package de.rub.nds.ssl.analyzer.fingerprinter;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;

/**
 * Counts the points of the fingerprint analyzers.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 24, 2012
 */
public final class ScoreCounter {

    private List<String> alreadyScored = new ArrayList<String>(50);
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
     * Public constructor.
     */
    public ScoreCounter() {
        counter = new EnumMap<ETLSImplementation, Integer>(
                ETLSImplementation.class);
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
     * Count the score for different implementations. This counter only
     * increments the total counter if the identifier was not encountered
     * anytime before.
     *
     * @param impl TLS implementation
     * @param score Score
     * @param identifier Identifier of this score call
     */
    public void countResult(final ETLSImplementation impl, final int score,
            final String identifier) {
        if (!alreadyScored.contains(identifier)) {
            this.totalCounter += score;
            alreadyScored.add(identifier);
        }
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
