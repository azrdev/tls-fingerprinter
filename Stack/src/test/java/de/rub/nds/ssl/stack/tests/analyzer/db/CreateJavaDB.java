package de.rub.nds.ssl.stack.tests.analyzer.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

/**
 * Create a fresh Database.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 17, 2012
 */
public class CreateJavaDB {

    public static void main(String args[]) {
        Connection conn = null;
        Properties props = new Properties();
        props.put("user", "tester");
        props.put("password", "ssltest");
        try {
            Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        try {
            conn = DriverManager.getConnection(
                    "jdbc:derby:Fingerprint;create=true",
                    props);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
