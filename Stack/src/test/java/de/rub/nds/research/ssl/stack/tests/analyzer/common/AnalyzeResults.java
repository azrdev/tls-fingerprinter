package de.rub.nds.research.ssl.stack.tests.analyzer.common;

import java.util.List;

import org.testng.IInvokedMethod;
import org.testng.IReporter;
import org.testng.ISuite;
import org.testng.xml.XmlSuite;

import de.rub.nds.research.ssl.stack.tests.analyzer.counter.ScoreCounter;

public class AnalyzeResults implements IReporter {

	@Override
	public void generateReport(List<XmlSuite> suite, List<ISuite> mySuite,
			String outputDirectory) {
		ScoreCounter counter = ScoreCounter.getInstance();
		int jsse = counter.getJSSEStandardScore();
		int openssl = counter.getOpenSSLScore();
		int gnutls = counter.getGNUtlsScore();
		int total = counter.getTotalCounter();
		int noHit = counter.getNoHitCounter();
		float result;
		System.out.println("JSSE Points: " + jsse);
		System.out.println("GNUtls Points: " + gnutls);
		System.out.println("OpenSSL Points: " + openssl);
		System.out.println("NoHit: " + noHit);
		//compute Probability
		result = this.computeProbability(jsse, total);
		System.out.println("Probability for JSSE: " + result);
		result = this.computeProbability(gnutls, total);
		System.out.println("Probability for GNUtls: " + result);
		result = this.computeProbability(openssl, total);
		System.out.println("Probability for OpenSSL: " + result);
		result = this.computeProbability(noHit, total);
		System.out.println("No hit in DB: " + result);
		
	}
	
	private float computeProbability(int impl, int total) {
		float result;
		result = ((float)impl / (float)total)*100;
		return result;
	}
	

}
