/*
 * 
 */
package de.rub.nds.ecdhattack.ciphersuites;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class GetServerCiphersuites {

    private static final String HOST = "134.147.198.51";
    private static final int PORT = 9090;

    public static void main(String[] args) throws Exception {
        String host;
        int port;
        if(args.length == 2) {
            host = args[0];
            port = Integer.parseInt(args[1]);
            System.out.println("Using defined server: " + host + ":" + port);
        } else {
            host = HOST;
            port = PORT;
            System.out.println("Using default server: " + HOST + ":" + PORT);
        }
        
        CiphersuiteChecker connector = new CiphersuiteChecker(host, port);
        List<ECipherSuite> acceptedCiphersuites = new LinkedList<ECipherSuite>();
        for(ECipherSuite suite : ECipherSuite.values()) {
            boolean accepted = false;
            try {
                accepted = connector.isCiphersuiteAccepted(suite);
            } catch(Exception e) {
                e.printStackTrace();
                accepted = connector.isAccepted();
            }
            System.out.println("Tested: " + suite);
            System.out.println("Result: " + accepted);
            if(accepted) {
                acceptedCiphersuites.add(suite);
            }
        }
        System.out.println("List of all accepted cipher suites: ");
        for(ECipherSuite s : acceptedCiphersuites) {
            System.out.println(s);
        }
    }
}
