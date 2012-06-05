package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.testng.Reporter;

import de.rub.nds.research.ssl.stack.protocols.alert.Alert;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.AFingerprintAnalyzer;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.AParameters;
import de.rub.nds.research.ssl.stack.tests.analyzer.common.ETLSImplementation;
import de.rub.nds.research.ssl.stack.tests.analyzer.counter.ScoreCounter;
import de.rub.nds.research.ssl.stack.tests.analyzer.db.Database;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;

public class TestHashAnalyzer extends AFingerprintAnalyzer {
	
	private String hashValue;
	
	static Logger logger = Logger.getRootLogger();
	
	public TestHashAnalyzer(AParameters parameters){
		this.hashValue = parameters.computeHash();
		logger.debug("Hash value: " + this.hashValue);
	}

	@Override
	public void analyze(ArrayList<Trace> traceList) {
		boolean dbHit = false;
		Trace lastTrace = traceList.get(traceList.size()-1);
		String lastState = lastTrace.getState().name();
		String alertDesc = null;
		String stateBeforeAlert = null;
		if (lastState.equals("ALERT")) {
			Alert alert = (Alert) lastTrace.getCurrentRecord();
			alertDesc = alert.getAlertDescription().name();
			Trace previousTrace = traceList.get(traceList.size()-2);
			stateBeforeAlert = previousTrace.getState().name();
		}
		ScoreCounter counter = ScoreCounter.getInstance();
		Database db = Database.getInstance();
		ResultSet result = db.findHashInDB(this.hashValue);
		try {
			while (result.next()) {
				if (result.getString("LAST_STATE").equalsIgnoreCase("ALERT")) {
					if (result.getString("STATE_BEFORE_ALERT").equalsIgnoreCase(stateBeforeAlert) &&
							result.getString("ALERT").equalsIgnoreCase(alertDesc)) {
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
