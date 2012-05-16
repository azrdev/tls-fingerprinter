package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.sql.ResultSet;
import java.util.ArrayList;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.tests.analyzer.db.Database;
import de.rub.nds.research.ssl.stack.tests.trace.Trace;

public class SSLAnalyzer {

	/**
	 * @param args
	 */
	@SuppressWarnings("unchecked")
	public static void main(String[] args) {
//		InputStream fileInStream = null;
//		TraceListAnalyzer listAnalyzer = new TraceListAnalyzer();
//		try {
//			fileInStream = new FileInputStream("eugenTest.ser");
//			ObjectInputStream oInput = new ObjectInputStream(fileInStream);
//			ArrayList<Trace> traceList = (ArrayList<Trace>) oInput.readObject();
//			listAnalyzer.analyzeList(traceList);
//			fileInStream.close();
//		} catch (FileNotFoundException e) {
//			e.printStackTrace();
//		} catch (IOException e) {
//			e.printStackTrace();
//		} catch (ClassNotFoundException e) {
//			e.printStackTrace();
//		}
		Database db = new Database();
		ResultSet result = null;
		try {
			result = db.readValue();
			do {
				result.next();
				System.out.println(Utility.byteToHex(result.getBytes("status")));
			}
			while (!(result.isLast()));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
