package de.rub.nds.ssl.analyzer.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.apache.log4j.Logger;

/**
 * Establish a connection to the fingerprint database and execute SQL queries.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 16, 2012
 */
public final class Database {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Instance of Database.
     */
    private static volatile Database db;

    /**
     * Connect to database.
     */
    private Database() {
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
     *
     * @return Connection object to the DB
     */
    private Connection openConnection() {
        Connection conn = null;
        /*
         * Use the embedded driver to connect. Only one
         * connection can be established at the same time.
         */
        try {
            Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
            conn = DriverManager.getConnection("jdbc:derby:Fingerprint;"
                    + "create=false;user=tester;password=ssltest");
        } catch (ClassNotFoundException e) {
            logger.error("DB driver instantiation failed.", e);
        } catch (SQLException e) {
            logger.error("Database error.", e);
        }

        return conn;
    }

    /**
     * Find a hash value in the database.
     *
     * @param hash Hash value
     * @return Database result set
     */
    public ResultSet findHashInDB(final String hash) {
        ResultSet result = null;
        PreparedStatement prepared = null;
        try {
            /*
             * search for a hash value in the tls_fingerprint_hash table
             */
            prepared = prepareStatement("select tls_impl, last_state, alert, "
                    + "points from tls_fingerprint_hash where hash = ?");
            prepared.setString(1, hash);
            result = prepared.executeQuery();
        } catch (SQLException e) {
            logger.error("Database error.", e);
        } catch (Exception e) {
            logger.error("Unspecified Error.", e);
        } finally {
            if(prepared != null) {
                closeStatementAndConnection(prepared);
            }
        }
        return result;
    }

    /**
     * Prepares a SQL statement for the given String.
     * @param statement SQL Statement
     * @return Executable statement
     * @throws SQLException 
     */
    public PreparedStatement prepareStatement(final String statement) throws
            SQLException {
        Connection conn = openConnection();
        return conn.prepareStatement(statement);
    }

    /**
     * Closes the passed statement and the connection.
     * @param prepared Statement to close
     */
    public void closeStatementAndConnection(final PreparedStatement prepared) {
        try {
            prepared.closeOnCompletion();
            closeConnection(prepared.getConnection());
        } catch (SQLException e) {
            logger.error("Database error.", e);
        }
    }

    /**
     * Closes a given connection.
     * @param connection  Connection to close
     */
    private void closeConnection(final Connection connection) {
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException ex) {
                // never mind
                logger.error("Database could not be closed.", ex);
            }
        }
    }
}
