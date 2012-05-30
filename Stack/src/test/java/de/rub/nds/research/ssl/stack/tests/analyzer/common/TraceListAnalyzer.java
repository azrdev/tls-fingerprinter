package de.rub.nds.research.ssl.stack.tests.analyzer.common;

import java.util.ArrayList;
import org.testng.Reporter;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.alert.Alert;
import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.handshake.Certificate;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerHelloDone;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.research.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;

public class TraceListAnalyzer {
	
	
	public TraceListAnalyzer() {
		
	}

	public void logOutput(ArrayList<Trace> traceList) {
		for (Trace trace : traceList) {
			 ARecordFrame currentRecord = trace.getCurrentRecord();
			 if (currentRecord instanceof ClientHello) {
				 Reporter.log("--Client Hello send--");
				 ClientHello clientHello = (ClientHello) currentRecord; 
				 ECipherSuite [] ciphers = clientHello.getCipherSuites();
				 Reporter.log("Cipher suites:");
				 for (ECipherSuite cipher : ciphers) {
					 Reporter.log(cipher.name() + ",");
				 }
				 Reporter.log("Protocol version: "
						 + clientHello.getMessageProtocolVersion());
				 Reporter.log("Random value: "
						 + Utility.byteToHex(clientHello.getRandom().getValue()));
			 }
			 if (currentRecord instanceof ServerHello) {
				 Reporter.log("--Server Hello received--");
				 ServerHello serverHello = (ServerHello) currentRecord;
				 Reporter.log("Chosen cipher suite: " +
				 serverHello.getCipherSuite().name());
				 Reporter.log("Protocol version: "
						 + serverHello.getProtocolVersion());
				 Reporter.log("Random value: "
						 + Utility.byteToHex(serverHello.getRandom().getValue()));
			 }
			 if (currentRecord instanceof Certificate) {
				 Reporter.log("--Certificate received--");
				 Certificate certificate = (Certificate) currentRecord;
			 }
			 if (currentRecord instanceof ServerKeyExchange) {
				 Reporter.log("--Server Key Exchange received--");
				 ServerKeyExchange ske = (ServerKeyExchange) currentRecord;
			 }
			 if (currentRecord instanceof ServerHelloDone) {
				 Reporter.log("--Server Hello Done received--");
				 ServerHelloDone shd = (ServerHelloDone) currentRecord;
			 }
			 if (currentRecord instanceof ClientKeyExchange) {
				 Reporter.log("--Client Key Exchange send--");
				 ClientKeyExchange cke = (ClientKeyExchange) currentRecord;
			 }
			 if (currentRecord instanceof ChangeCipherSpec) {
				 Reporter.log("--Change Cipher Spec--");
				 ChangeCipherSpec ccs = (ChangeCipherSpec) currentRecord;
			 }
			 if (currentRecord instanceof TLSCiphertext) {
				 Reporter.log("--Encrypted Handshake message--");
				 TLSCiphertext tlsCipher = (TLSCiphertext) currentRecord;
			 }
			 if (currentRecord instanceof Alert) {
				 Alert alert = (Alert) currentRecord;
				 Reporter.log("Handshake ends with Alert: "
				 + alert.getAlertLevel() + "- " + alert.getAlertDescription());
			 }
		 }
	}

}
