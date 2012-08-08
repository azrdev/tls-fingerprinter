package de.rub.nds.ssl.stack.tests.analyzer.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

import de.rub.nds.ssl.stack.protocols.commons.SecurityParameters;

/**
 * Establish a connection to the fingerprint database and execute
 * SQL queries.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * May 16, 2012
 */
public class Database {

    /**
     * Instance of Database.
     */
    private static volatile Database db;
    /**
     * Database connection.
     */
    private Connection conn;

    /**
     * Connect to database.
     */
    public Database() {
        try {
            this.connectDB();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Singleton instance creation.
     *
     * @return Database instance
     */
    public static Database getInstance() {
        if (db == null) {
            db = new Database();
        }
        return db;
    }

    /**
     * Connect to database.
     * @throws Exception
     */
    public final void connectDB() throws Exception {
    	/*Use the embedded driver to connect. Only one
    	 * connection can be established at the same time.
    	 */
        Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
        conn = DriverManager.getConnection(
                "jdbc:derby:Fingerprint;create=false;user=tester;password=ssltest");
    }

    /**
     * Find a hash value in the database.
     * @param hash Hash value
     * @return Database result set
     */
    public final ResultSet findHashInDB(final String hash) {
        Connection conn = db.getConnection();
        ResultSet result = null;
        try {
        	/*
        	 * search for a hash value in the tls_fingerprint_hash table
        	 */
            PreparedStatement prepared = conn.prepareStatement(
            		"select tls_impl, last_state, alert, points"
                    + " from tls_fingerprint_hash where hash = ?");
            prepared.setString(1, hash);
            result = prepared.executeQuery();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Close the database connection.
     * @throws Exception
     */
    public final void closeDB() throws Exception {
        conn.close();
    }

    /**
     * Get the database connection.
     * @return Database connection.
     */
    public final Connection getConnection() {
        return conn;
    }

    /**
     * Set the database connection.
     * @param conn Database connection
     */
    public final void setConnection(final Connection conn) {
        this.conn = conn;
    }
}
