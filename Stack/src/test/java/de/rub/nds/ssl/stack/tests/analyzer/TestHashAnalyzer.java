package de.rub.nds.ssl.stack.tests.analyzer;

import de.rub.nds.ssl.stack.tests.analyzer.common.AnalyzeTraceList;
import de.rub.nds.ssl.stack.tests.analyzer.common.ETLSImplementation;
import de.rub.nds.ssl.stack.tests.analyzer.common.ScoreCounter;
import de.rub.nds.ssl.stack.tests.analyzer.db.Database;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageTrace;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import org.apache.log4j.Logger;
import org.testng.Reporter;

/**
 * Fingerprint analysis where the hash value of test parameters is mapped to a
 * specific behavior of an implementation.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 05, 2012
 */
public class TestHashAnalyzer extends AFingerprintAnalyzer {

    /**
     * Hash value of the test parameters.
     */
    private String hashValue;
    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();

    /**
     * Initialize the analyzer and compute the hash value.
     *
     * @param parameters Test parameters
     */
    public TestHashAnalyzer(final AParameters parameters) {
        //compute the hash value of the test parameters
        this.hashValue = parameters.computeHash();
        logger.debug("Hash value: " + this.hashValue);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void analyze(final ArrayList<MessageTrace> traceList) {
        boolean dbHit = false;
        String lastState = null;
        String alertDesc = null;
        AnalyzeTraceList analyzeList = new AnalyzeTraceList();
        //set the alert description
        alertDesc = analyzeList.getAlertFromTraceList(traceList);
        //set the last state of the trace list
        if (alertDesc != null) {
            lastState = EStates.ALERT.name();
        }
        else {
        	MessageTrace lastTrace = analyzeList.getLastTrace(traceList);
        	lastState = lastTrace.getState().name();
        }
        ScoreCounter counter = ScoreCounter.getInstance();
        Database db = Database.getInstance();
        //search for the parameter hash in the database
        ResultSet result = db.findHashInDB(this.hashValue);
        try {
        	/*iterate through the database results and assign an 
        	 * implementation and a score.
        	 */
            while (result.next()) {
                if (result.getString("LAST_STATE").equalsIgnoreCase("ALERT")) {
                    if (result.getString("ALERT").equalsIgnoreCase(alertDesc)) {
                        dbHit = true;
                        counter.countResult(ETLSImplementation.valueOf(result.
                                getString("TLS_IMPL")),
                                result.getInt("POINTS"));
                        Reporter.log("Found fingerprint hit for " + result.
                                getString("TLS_IMPL"));
                    }
                } else if (result.getString("LAST_STATE").equalsIgnoreCase(
                        lastState)) {
                    dbHit = true;
                    counter.countResult(ETLSImplementation.valueOf(result.
                            getString("TLS_IMPL")),
                            result.getInt("POINTS"));
                    Reporter.log("Found fingerprint hit for " + result.getString(
                            "TLS_IMPL"));
                }
            }
            //assign 2 points for "no hit" if there is no hit in the database
            if (!dbHit) {
                counter.countNoHit(2);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
