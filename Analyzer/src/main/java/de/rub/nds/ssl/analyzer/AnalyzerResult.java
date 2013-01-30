package de.rub.nds.ssl.analyzer;

import de.rub.nds.ssl.analyzer.fingerprinter.ScoreCounter;

/**
 * Results of test analyzers.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 30, 2013
 */
public class AnalyzerResult {

    private ScoreCounter scoreCounter;

    /**
     * Public constructor. 
     * Don't forget to set the parameters!
     */
    public AnalyzerResult() {
    }

    /**
     * Getter for the Score counter. Be carful! No deep copying!
     *
     * @return Score counter
     */
    public ScoreCounter getScoreCounter() {
        return scoreCounter;
    }

    /**
     * Setter for the Score Counter. Be carful! No deep copying!
     *
     * @param scoreCounter Score counter to set
     */
    public void setScoreCounter(final ScoreCounter scoreCounter) {
        this.scoreCounter = scoreCounter;
    }
}
