package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.util.ArrayList;

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
	
	public void analyzeList(ArrayList<Trace> traceList) {
		for (int i=0; i<traceList.size(); i++) {
			if (traceList.get(i).getOldRecord() != null) {
			}
		}
	}
	
	public void logOutput(ArrayList<Trace> traceList) {
		for (Trace trace : traceList) {
			 ARecordFrame currentRecord = trace.getCurrentRecord();
			 if (currentRecord instanceof ClientHello) {
				 System.out.println("--Client Hello send--");
				 ClientHello clientHello = (ClientHello) currentRecord; 
				 ECipherSuite [] ciphers = clientHello.getCipherSuites();
				 System.out.println("Cipher suites:");
				 for (ECipherSuite cipher : ciphers) {
					 System.out.print(cipher.name() + ",");
				 }
				 System.out.println();
				 System.out.println("Protocol version: "
						 + clientHello.getMessageProtocolVersion());
				 System.out.println("Random value: "
						 + Utility.byteToHex(clientHello.getRandom().getValue()));
			 }
			 if (currentRecord instanceof ServerHello) {
				 System.out.println("--Server Hello received--");
				 ServerHello serverHello = (ServerHello) currentRecord;
				 System.out.println("Chosen cipher suite: " +
				 serverHello.getCipherSuite().name());
				 System.out.println("Protocol version: "
						 + serverHello.getProtocolVersion());
				 System.out.println("Random value: "
						 + Utility.byteToHex(serverHello.getRandom().getValue()));
			 }
			 if (currentRecord instanceof Certificate) {
				 System.out.println("--Certificate received--");
				 Certificate certificate = (Certificate) currentRecord;
			 }
			 if (currentRecord instanceof ServerKeyExchange) {
				 System.out.println("--Server Key Exchange received--");
				 ServerKeyExchange ske = (ServerKeyExchange) currentRecord;
			 }
			 if (currentRecord instanceof ServerHelloDone) {
				 System.out.println("--Server Hello Done received--");
				 ServerHelloDone shd = (ServerHelloDone) currentRecord;
			 }
			 if (currentRecord instanceof ClientKeyExchange) {
				 System.out.println("--Client Key Exchange send--");
				 ClientKeyExchange cke = (ClientKeyExchange) currentRecord;
			 }
			 if (currentRecord instanceof ChangeCipherSpec) {
				 System.out.println("--Change Cipher Spec--");
				 ChangeCipherSpec ccs = (ChangeCipherSpec) currentRecord;
			 }
			 if (currentRecord instanceof TLSCiphertext) {
				 System.out.println("--Encrypted Handshake message--");
				 TLSCiphertext tlsCipher = (TLSCiphertext) currentRecord;
			 }
			 if (currentRecord instanceof Alert) {
				 Alert alert = (Alert) currentRecord;
				 System.out.println("Handshake ends with Alert: "
				 + alert.getAlertLevel() + "- " + alert.getAlertDescription());
			 }
		 }
	}

}
