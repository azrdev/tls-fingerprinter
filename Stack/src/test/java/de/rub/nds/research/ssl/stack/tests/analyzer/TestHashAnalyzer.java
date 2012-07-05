package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.testng.Reporter;

import de.rub.nds.research.ssl.stack.protocols.alert.Alert;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.ETLSImplementation;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.ScoreCounter;
import de.rub.nds.research.ssl.stack.tests.analyzer.db.Database;
import de.rub.nds.research.ssl.stack.tests.analyzer.parameters.AParameters;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;
import de.rub.nds.research.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;

/**
 * Fingerprint analysis where the hash value of test parameters is
 * mapped to a specific behavior of an implementation 
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Jun 05, 2012
 */
public class TestHashAnalyzer extends AFingerprintAnalyzer {
	
	/**
	 * Hash value of the test parameters.
	 */
	private String hashValue;
	
	/**
	 * Log4j logger initialization.
	 */
	static Logger logger = Logger.getRootLogger();
	
	/**
	 * Initialize the analyzer and compute the hash value.
	 * @param parameters Test parameters
	 */
	public TestHashAnalyzer(AParameters parameters){
		//compute the hash value of the test parameters
		this.hashValue = parameters.computeHash();
		logger.debug("Hash value: " + this.hashValue);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void analyze(ArrayList<Trace> traceList) {
		boolean dbHit = false;
		Trace lastTrace = traceList.get(traceList.size()-1);
		String lastState = lastTrace.getState().name();
		String alertDesc = null;
		for (int i=0; i<traceList.size(); i++) {
			Trace currentTrace = traceList.get(i);
			if (currentTrace.getState() == EStates.ALERT) {
				Alert alert = (Alert) currentTrace.getCurrentRecord();
				alertDesc = alert.getAlertDescription().name();
			}
		}
		ScoreCounter counter = ScoreCounter.getInstance();
		Database db = Database.getInstance();
		ResultSet result = db.findHashInDB(this.hashValue);
		try {
			while (result.next()) {
				if (result.getString("LAST_STATE").equalsIgnoreCase("ALERT")) {
					if (result.getString("ALERT").equalsIgnoreCase(alertDesc)) {
						dbHit=true;
						counter.countResult(ETLSImplementation.valueOf(result.getString("TLS_IMPL")),
								result.getInt("POINTS"));
						Reporter.log("Found fingerprint hit for " + result.getString("TLS_IMPL"));
					}
				}
				else if (result.getString("LAST_STATE").equalsIgnoreCase(lastState)) {
					dbHit=true;
					counter.countResult(ETLSImplementation.valueOf(result.getString("TLS_IMPL")),
							result.getInt("POINTS"));
					Reporter.log("Found fingerprint hit for " + result.getString("TLS_IMPL"));
				}	
			}
			if (dbHit == false) {
				counter.countNoHit(2);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

}
