package de.rub.nds.ssl.analyzer.db;

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

    public static void main(String args[]) throws SQLException {
//        args = new String[]{"YesIWouldLikeToDropAllData!"};
        // foot shot protection :-D
        if ("YesIWouldLikeToDropAllData!".equals(args[0])) {
            Properties props = new Properties();
            props.put("user", "tester");
            props.put("password", "ssltest");
            Connection conn = null;
            try {
                Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
                conn = DriverManager.getConnection(
                        "jdbc:derby:Fingerprint;create=true", props);
            } catch (SQLException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            } finally {
                if(conn != null) {
                    conn.close();
                }
            }
        }
    }
}
