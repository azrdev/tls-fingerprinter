package de.rub.nds.research.ssl.stack.tests.analyzer.counter;

import de.rub.nds.research.ssl.stack.tests.analyzer.common.ETLSImplementation;

/**
 * Counts the points of the fingerprint analyzers,
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * May 24, 2012
 */
public class ScoreCounter {
	
	private static volatile ScoreCounter counter;
	
	private int openSSLScore = 0;
	private int jsseStandardScore = 0;
	private int jsseBouncyScore = 0;
	private int microsoftScore = 0;
	private int totalCounter = 0;
	
	/**Empty constructor.*/
	private ScoreCounter() {
	}
	
	public static ScoreCounter getInstance() {
		if (counter == null) {
			counter = new ScoreCounter ();
		}
		return counter;
	}
	
	/**
	 * Count the score for different implementations
	 * @param impl TLS implementation
	 * @param score Score
	 */
	public void countResult(ETLSImplementation impl, int score) {
		this.totalCounter += score;
		switch (impl) {
		case OPENSSL: this.openSSLScore += score;
		break;
		case JSSE_STANDARD: this.jsseStandardScore += score;
		break;
		case JSSE_BOUNCY: this.jsseBouncyScore += score;
		break;
		case MICROSOFT: this.microsoftScore += score;
		break;
		default: break;
		}
		
	}
	
	public int getOpenSSLScore() {
		return this.openSSLScore;
	}
	
	public int getJSSEStandardScore() {
		return this.jsseStandardScore;
	}
	
	public int getJSSEBouncyScore() {
		return this.jsseBouncyScore;
	}
	
	public int getMicrosoftScore() {
		return this.microsoftScore;
	}
	
	public int getTotalCounter() {
		return this.totalCounter;
	}
	

}
