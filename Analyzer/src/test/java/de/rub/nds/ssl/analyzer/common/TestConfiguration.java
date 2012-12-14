package de.rub.nds.ssl.analyzer.common;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class TestConfiguration {

    /**
     * Instance of TestConfiguration.
     */
    private static volatile TestConfiguration conf;
    /**
     * Test host.
     */
    public static String HOST = "";
    /**
     * Test port.
     */
    public static int PORT = 0;
    /**
     * Use test server.
     */
    public static boolean useTestServer = true;

    /**
     * Initialize the properties.
     */
    public TestConfiguration() {
        Properties properties = new Properties();
        FileInputStream fis;
        try {
            fis = new FileInputStream("test.properties");
            properties.load(fis);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String host = properties.getProperty("ssl.test.host");
        String port = properties.getProperty("ssl.test.port");
        String useServer = properties.getProperty("ssl.test.useTestServer");
        if (host != null) {
            HOST = host;
        }
        if (port != null) {
            PORT = Integer.parseInt(port);
        }
        if (useServer != null) {
            useTestServer = Boolean.parseBoolean(useServer);
        }
    }

    /**
     * Singleton instance creation.
     *
     * @return StackProperties instance
     */
    public static TestConfiguration getInstance() {
        if (conf == null) {
            conf = new TestConfiguration();
        }
        return conf;
    }
}
