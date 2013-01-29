package de.rub.nds.ssl.analyzer.fingerprinter;

import de.rub.nds.ssl.analyzer.db.Database;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DecimalFormat;
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
    public void analyze(final List<MessageContainer> traceList) {
        boolean dbHit = false;
        String lastState;
        String alertDesc;
        AnalyzeTraceList analyzeList = new AnalyzeTraceList();
        //set the alert description
        alertDesc = analyzeList.getAlertFromTraceList(traceList);
        //set the last state of the trace list
        if (alertDesc != null) {
            lastState = EStates.ALERT.name();
        } else {
            MessageContainer lastTrace = analyzeList.getLastTrace(traceList);
            lastState = lastTrace.getState().name();
        }
        ScoreCounter counter = ScoreCounter.getInstance();
        Database db = Database.getInstance();
        //search for the parameter hash in the database
        PreparedStatement statement = db.prepapreFindHashInDB(this.hashValue);
        try {
            ResultSet result = statement.executeQuery();
            int score = 2;
            if (result != null && !result.wasNull()) {
                // determine #results
                result.last();
                if (result.getRow() > 1) {
                    score = 1;
                }
                result.beforeFirst();
                /*
                 * Iterate through the database results and assign an 
                 * implementation and a score.
                 */
                while (result.next()) {
                    if (result.getString("LAST_STATE").equalsIgnoreCase("ALERT")) {
                        if (result.getString("ALERT").
                                equalsIgnoreCase(alertDesc)) {
                            dbHit = true;
                            counter.countResult(ETLSImplementation.valueOf(
                                    result.getString("TLS_IMPL")), score);
                            logger.info("Found fingerprint hit for "
                                    + result.getString("TLS_IMPL"));
                        }
                    } else if (result.getString("LAST_STATE").equalsIgnoreCase(
                            lastState)) {
                        dbHit = true;
                        counter.countResult(ETLSImplementation.valueOf(
                                result.getString("TLS_IMPL")), score);
                        logger.info("Found fingerprint hit for "
                                + result.getString("TLS_IMPL"));
                    }
                }
                //assign 2 points for "no hit" if there is no hit in the database
                if (!dbHit) {
                    counter.countNoHit(2);
                    logger.info("No fingerprint hit.");
                }
            };
        } catch (SQLException e) {
            logger.error("Database error.", e);
        } finally {
            if (statement != null) {
                db.closeStatementAndConnection(statement);
            }
        }

        logger.info("########################################################"
                + "################");
        logger.info("Final analyzer Results");
        logger.info("########################################################"
                + "################");
        int score;
        int toalScore = counter.getTotalCounter();
        DecimalFormat twoDForm = new DecimalFormat("###.##");
        for (ETLSImplementation impl : ETLSImplementation.values()) {
            score = counter.getScore(impl);
            logger.info(impl.name() + ":" + counter.getScore(impl) 
                    + " - " + Double.valueOf(
                    twoDForm.format(((double)((double)score/(double)toalScore))*100))
                    +"% Probability");
        }
        score= counter.getNoHitCounter();
        logger.info("No hit" + ":" + score
                    + " - " + Double.valueOf(
                    twoDForm.format(((double)((double)score/(double)toalScore))*100))
                    +"% Probability");
    }
}
