package de.rub.nds.ssl.analyzer.fingerprinter;

import de.rub.nds.ssl.analyzer.AnalyzerResult;
import de.rub.nds.ssl.analyzer.db.Database;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import org.apache.log4j.Logger;

/**
 * Fingerprint analysis where the hash value of test parameters is mapped to a
 * specific behavior of an implementation.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 05, 2012
 */
public final class TestHashAnalyzer implements IFingerprinter {

    /**
     * Hash value of the test parameters.
     */
    private String hashValue;
    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();

    /**
     * Standard constructor.
     */
    public TestHashAnalyzer() {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(final AParameters parameters) {
        //compute the hash value of the test parameters
        this.hashValue = parameters.computeHash();
        logger.debug("Hash value: " + this.hashValue);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AnalyzerResult analyze(final List<MessageContainer> traceList) {
        AnalyzerResult result = new AnalyzerResult();
        boolean dbHit = false;
        String lastState;
        String alertDesc;

        //set the alert description
        alertDesc = TraceListAnalyzerUtility.getAlertFromTraceList(traceList);
        //set the last state of the trace list
        if (alertDesc != null) {
            lastState = EStates.ALERT.name();
        } else {
            MessageContainer lastTrace = TraceListAnalyzerUtility.getLastTrace(
                    traceList);
            lastState = lastTrace.getState().name();
        }
        ScoreCounter counter = new ScoreCounter();
        Database db = Database.getInstance();
        //search for the parameter hash in the database
        PreparedStatement statement = db.prepapreFindHashInDB(this.hashValue);
        try {
            ResultSet queryResult = statement.executeQuery();
            int score = 2;
            if (queryResult != null && !queryResult.wasNull()) {
                // determine #results
                queryResult.last();
                if (queryResult.getRow() > 1) {
                    score = 1;
                }
                queryResult.beforeFirst();
                /*
                 * Iterate through the database results and assign an 
                 * implementation and a score.
                 */
                while (queryResult.next()) {
                    if (queryResult.getString("LAST_STATE").equalsIgnoreCase(
                            "ALERT")) {
                        if (queryResult.getString("ALERT").
                                equalsIgnoreCase(alertDesc)) {
                            dbHit = true;
                            counter.countResult(ETLSImplementation.valueOf(
                                    queryResult.getString("TLS_IMPL")),
                                    score, this.hashValue);
                        }
                    } else if (queryResult.getString("LAST_STATE").
                            equalsIgnoreCase(lastState)) {
                        dbHit = true;
                        counter.countResult(ETLSImplementation.valueOf(
                                queryResult.getString("TLS_IMPL")),
                                score, this.hashValue);
                    }
                }
                //assign 2 points for "no hit" if there is no hit in the database
//                if (!dbHit) {
//                    counter.countNoHit(2);
//                }
            };
        } catch (SQLException e) {
            logger.error("Database error.", e);
        } finally {
            if (statement != null) {
                db.closeStatementAndConnection(statement);
            }
        }

        result.setScoreCounter(counter);
        return result;
    }
}
