package de.rub.nds.ssl.stack.tests.analyzer.db;

import de.rub.nds.ssl.stack.tests.analyzer.parameters.HeaderParameters;
import de.rub.nds.ssl.stack.tests.fingerprint.FingerprintCKERecordHeader;
import java.sql.Connection;

public class FillBehaviourDB {

    private static Database db = new Database();

    public static void main(String args[]) {
        try {
            insertBehaviour();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    static byte[] sessionID = new byte[]{(byte) 0xff, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
        (byte) 0x0f
    };

    public static void insertBehaviour() throws Exception {
        Connection conn = db.getConnection();
        java.sql.PreparedStatement prepared = conn.prepareStatement("insert into tls_fingerprint_hash"
                + " values (default,?,?,?,?,?,?)");
        HeaderParameters parameters = new HeaderParameters();
        parameters.setTestClassName(FingerprintCKERecordHeader.class.getName());
        parameters.setMsgType(null);
        parameters.setProtocolVersion(null);
        parameters.setRecordLength(new byte[]{(byte) 0xff, (byte) 0xff});
        parameters.setDescription("Invalid length 0xff,0xff");
        String fingerprint = parameters.computeHash();
        prepared.setString(1, fingerprint);
        prepared.setString(2, "ALERT");
        prepared.setString(3, "BAD_RECORD_MAC");
        prepared.setString(4, "OPENSSL");
        prepared.setInt(5, 2);
        prepared.setInt(6, 26);
        prepared.executeUpdate();
    }
}
