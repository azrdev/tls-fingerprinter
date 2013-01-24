package de.rub.nds.ssl.analyzer.db;

import de.rub.nds.ssl.analyzer.fingerprinter.AnalyzeTraceList;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import org.apache.log4j.Logger;

/**
 * Example how to add a fingerprint to the database.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 16, 2012
 */
public class FillBehaviourDB {

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
     * @param impl TLS implementation
     * @throws Exception
     */
    public void insertFingerprint(AParameters parameters,
            List<MessageContainer> traceList, String testcase,
            String implementation) throws SQLException {
        Connection conn = db.getConnection();
        //prepared insert statement
        java.sql.PreparedStatement prepared = conn.
                prepareStatement("insert into tls_fuzzer_fingerprint"
                + " values (default,?,?,?,?,?)");
        String lastState = null;
        String alertDesc = null;
        AnalyzeTraceList analyzeList = new AnalyzeTraceList();
        //assign the alert description and last state
        alertDesc = analyzeList.getAlertFromTraceList(traceList);
        if (alertDesc != null) {
            lastState = EStates.ALERT.name();
        } else {
            MessageContainer lastTrace = analyzeList.getLastTrace(traceList);
            lastState = lastTrace.getState().name();
        }
        String fingerprint = parameters.computeHash();
        // hash
        prepared.setString(1, fingerprint);
        // state
        prepared.setString(2, lastState);
        // alert description
        prepared.setString(3, alertDesc);
        // implementation
        prepared.setString(4, implementation);
        // testcase name
        String tmpDesc = parameters.getDescription();
        String desc = testcase;
        if (tmpDesc != null && !tmpDesc.isEmpty()) {
            desc += " | " + parameters.getDescription();
        }
        prepared.setString(5, desc);

        logger.info("########################################################"
                + "################");
        logger.info("Description: " + desc);
        logger.info("Chosen implementation: " + implementation);
        logger.info("Alert description: " + alertDesc);
        logger.info("Last state: " + lastState);
        logger.info("Fingerprint: " + fingerprint);
        logger.info("########################################################"
                + "################");
        

        prepared.executeUpdate();

    }
}
