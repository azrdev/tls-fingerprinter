package de.rub.nds.ssl.analyzer.db;

import de.rub.nds.ssl.analyzer.fingerprinter.AnalyzeTraceList;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import org.apache.log4j.Logger;

/**
 * Example how to add a fingerprint to the database.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 16, 2012
 */
public final class FillBehaviourDB {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Database.
     */
    private Database db;

    /**
     * Get database instance.
     */
    public FillBehaviourDB() {
        db = Database.getInstance();
    }

    /**
     * Insert an entry to the fingerprint database.
     *
     * @param parameters Test parameters
     * @param traceList Trace list of the handshake
     * @param testcase Test Case description
     * @param implementation TLS implementation
     * @throws SQLException
     */
    public void insertFingerprint(final AParameters parameters,
            final List<MessageContainer> traceList, final String testcase,
            final String implementation) {
        PreparedStatement prepared = null;
        String lastState;
        String alertDesc;
        MessageContainer lastTrace;
        AnalyzeTraceList analyzeList;

        try {
            //prepared insert statement
            prepared = db.prepareStatement("insert into tls_fuzzer_fingerprint "
                    + "values (default,?,?,?,?,?,?)");

            // hash
            String fingerprint = parameters.computeHash();
            prepared.setString(1, fingerprint);

            // state && alert description
            analyzeList = new AnalyzeTraceList();
            //assign the alert description and last state
            alertDesc = analyzeList.getAlertFromTraceList(traceList);
            if (alertDesc != null) {
                lastState = EStates.ALERT.name();
            } else {
                lastTrace = analyzeList.getLastTrace(traceList);
                lastState = lastTrace.getState().name();
            }
            prepared.setString(2, lastState);
            prepared.setString(3, alertDesc);

            // implementation
            prepared.setString(4, implementation);

            // testcase name
            String tmpDesc = parameters.getDescription();
            String desc = testcase;
            if (tmpDesc != null && !tmpDesc.isEmpty()) {
                desc += " | " + tmpDesc;
            }
            prepared.setString(5, desc);
            StringBuilder sb = new StringBuilder("");
            for (MessageContainer msg: traceList) {
            	sb.append(msg.getState().name());
            	sb.append(" | ");
            }
            prepared.setString(6, sb.toString());

            logger.info("####################################################"
                    + "####################");
            logger.info("Description: " + desc);
            logger.info("Message Trace: " + sb.toString());
            logger.info("Chosen implementation: " + implementation);
            logger.info("Alert description: " + alertDesc);
            logger.info("Last state: " + lastState);
            logger.info("Fingerprint: " + fingerprint);
            logger.info("####################################################"
                    + "####################");

            prepared.executeUpdate();
        } catch (SQLException e) {
            logger.error("Database problems.", e);
        } 
//        finally {
//            db.closeStatementAndConnection(prepared);
//        }
    }
}
