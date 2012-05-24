package de.rub.nds.research.ssl.stack.tests.analyzer.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

import de.rub.nds.research.ssl.stack.protocols.commons.SecurityParameters;

public class Database {
	
	/**Instance of Database.*/
    private static volatile Database db;
	private Connection conn;

	public Database() {
		try {
			this.connectDB();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**Singleton instance creation.
     * @return Database instance
     */
    public static Database getInstance() {
        if (db == null) {
            db = new Database();
        }
        return db;
    }
	
	public void connectDB() throws Exception {
//		Class.forName("org.apache.derby.jdbc.ClientDriver");
//		conn = DriverManager.getConnection("jdbc:derby://localhost:1527//home/regit/svn/SSL/Stack/Fingerprint;create=false;user=tester;password=ssltest");
		Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
		conn = DriverManager.getConnection("jdbc:derby:Fingerprint;create=false;user=tester;password=ssltest");
	}
	
	public ResultSet checkFingerprintInDB(String hash) {
		Connection conn = db.getConnection();
		ResultSet result = null;
		try {
			PreparedStatement prepared = conn.prepareStatement("select tls_impl, last_state, alert, state_before_alert, points" +
					" from tls_fingerprint_hash where signature = ?");
			prepared.setString(1, hash);
			result = prepared.executeQuery();
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}
	
	
	public void writeToDB(String signature, Timestamp timestamp, String test_name,
			String test_desc) throws Exception {
		java.sql.PreparedStatement prepared = conn.prepareStatement("insert into app.tls_testrun"
				+ " values (default,?,?,?,?)");
		prepared.setString(1, signature);
		prepared.setTimestamp(2, timestamp);
		prepared.setString(3, test_name);
		prepared.setString(4, test_desc);
		prepared.executeUpdate();
	}
	
	public void closeDB() throws Exception {
		conn.close();
	}
	
	public Connection getConnection() {
		return conn;
	}

	public void setConnection(Connection conn) {
		this.conn = conn;
	}

}
