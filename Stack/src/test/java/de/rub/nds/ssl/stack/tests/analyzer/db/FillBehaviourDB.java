package de.rub.nds.ssl.stack.tests.analyzer.db;

import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.tests.analyzer.common.AnalyzeResults;
import de.rub.nds.ssl.stack.tests.analyzer.common.AnalyzeTraceList;
import de.rub.nds.ssl.stack.tests.analyzer.common.ETLSImplementation;
import de.rub.nds.ssl.stack.tests.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.tests.trace.Trace;
import de.rub.nds.ssl.stack.tests.workflows.SSLHandshakeWorkflow.EStates;

import java.sql.Connection;
import java.util.ArrayList;

public class FillBehaviourDB {
	
	private Database db;
    
    public FillBehaviourDB(){
    	db = Database.getInstance();
    }


    public void insertBehaviour(AParameters parameters, ArrayList<Trace> traceList,
    		ETLSImplementation impl) throws Exception {
        Connection conn = db.getConnection();
        java.sql.PreparedStatement prepared = conn.prepareStatement("insert into tls_fingerprint_hash"
                + " values (default,?,?,?,?,?,?)");
        String implementation = impl.name();
        String lastState = null;
        String alertDesc = null;
        AnalyzeTraceList analyzeList = new AnalyzeTraceList();
        alertDesc = analyzeList.getAlertFromTraceList(traceList);
        if (alertDesc != null) {
        	lastState = EStates.ALERT.name();
        }
        else {
        	Trace lastTrace = analyzeList.getLastTrace(traceList);
        	lastState = lastTrace.getState().name();
        }
        String fingerprint = parameters.computeHash();
        prepared.setString(1, fingerprint);
        prepared.setString(2, lastState);
        prepared.setString(3, alertDesc);
        prepared.setString(4, implementation);
        prepared.setInt(5, 2);
        prepared.setInt(6, 26);
        prepared.executeUpdate();
    }
    
    
    
}
