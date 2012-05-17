package de.rub.nds.research.ssl.stack.tests.analyzer;

import java.sql.ResultSet;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.tests.analyzer.db.Database;

public class SSLAnalyzer {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Database db = new Database();
		ResultSet result = null;
		try {
			result = db.readValue();
			do {
				result.next();
				System.out.println(Utility.byteToHex(result.getBytes("value")));
			}
			while (!(result.next()));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

}
