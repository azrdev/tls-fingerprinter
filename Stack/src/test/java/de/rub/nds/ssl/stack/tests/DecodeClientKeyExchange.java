package de.rub.nds.ssl.stack.tests;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ClientECDHPublic;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;
import java.security.InvalidKeyException;
import java.security.Security;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECFieldElement;

/**
 * <DESCRIPTION> @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Aug 1, 2013
 */
public class DecodeClientKeyExchange {

    private static byte[] message = new byte[]{
//        (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x42, 
        (byte) 0x41,
        (byte) 0x04, (byte) 0x85, (byte) 0x62, (byte) 0xb1, (byte) 0xb7,
        (byte) 0x0d, (byte) 0x5a, (byte) 0xfe, (byte) 0x4e, (byte) 0xef,
        (byte) 0xd1, (byte) 0xe1, (byte) 0x0c, (byte) 0xea, (byte) 0x0f,
        (byte) 0xcb, (byte) 0x7a, (byte) 0x93, (byte) 0x57, (byte) 0x5a,
        (byte) 0x19, (byte) 0x57, (byte) 0x4e, (byte) 0x70, (byte) 0x91,
        (byte) 0x97, (byte) 0xef, (byte) 0x9e, (byte) 0x30, (byte) 0xae,
        (byte) 0x9d, (byte) 0xf3, (byte) 0xf1, (byte) 0x98, (byte) 0x96,
        (byte) 0x8a, (byte) 0xd8, (byte) 0x9e, (byte) 0xe1, (byte) 0x99,
        (byte) 0x96, (byte) 0xe3, (byte) 0x6a, (byte) 0xb9, (byte) 0x20,
        (byte) 0xc7, (byte) 0xd9, (byte) 0xa2, (byte) 0x69, (byte) 0x91,
        (byte) 0xa4, (byte) 0x1e, (byte) 0xb1, (byte) 0xb5, (byte) 0x01,
        (byte) 0xa8, (byte) 0x1a, (byte) 0xe3, (byte) 0xb8, (byte) 0x78,
        (byte) 0xc9, (byte) 0x6f, (byte) 0xa7, (byte) 0xcb, (byte) 0xdd};
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws InvalidKeyException {
        ClientKeyExchange cke = new ClientKeyExchange(message,
                EKeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, false);
        ClientECDHPublic params = (ClientECDHPublic) cke.getExchangeKeys();
        ECPoint publicPoint = params.getECDHYc();
        System.out.println(params.isExplicitPublicValueEncoding());
        System.out.println(Utility.bytesToHex(publicPoint.getPoint()));

        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters x9 = NISTNamedCurves.getByName("P-256");
        org.bouncycastle.math.ec.ECPoint g = x9.getG();

        org.bouncycastle.math.ec.ECCurve curve = x9.getCurve();
        byte[] publicPointBytes = publicPoint.getPoint();

        org.bouncycastle.math.ec.ECPoint point =
                curve.decodePoint(publicPointBytes);
        System.out.println("Point compression enabled: " + point.isCompressed());
        ECFieldElement x = point.getX();

        ECFieldElement y = point.getY();
        ECFieldElement a = curve.getA();
        ECFieldElement b = curve.getB();
        ECFieldElement lhs = y.multiply(y);
        ECFieldElement rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b);

        // y^2 = x^3 + ax + b
        boolean pointIsOnCurve = lhs.equals(rhs);
        System.out.println("Point on curve? " + pointIsOnCurve);
    }
}
