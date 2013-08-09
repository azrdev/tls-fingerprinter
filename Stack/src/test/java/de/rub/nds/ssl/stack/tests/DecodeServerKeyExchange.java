package de.rub.nds.ssl.stack.tests;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.handshake.ServerKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ServerECDHParams;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECParameters;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Security;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECFieldElement;

/**
 * <DESCRIPTION>
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1

 * Aug 1, 2013
 */
public class DecodeServerKeyExchange {

    private static byte[] message = new byte[]{
//    (byte) 0x0c, (byte) 0x00, (byte) 0x00, (byte) 0xc7, 
    (byte) 0x03, 
    (byte) 0x00, (byte) 0x17, (byte) 0x41, (byte) 0x04, (byte) 0xe6, 
    (byte) 0xc6, (byte) 0xdf, (byte) 0x91, (byte) 0xd7, (byte) 0xac, 
    (byte) 0x19, (byte) 0x0d, (byte) 0x04, (byte) 0x8d, (byte) 0x3c, 
    (byte) 0x71, (byte) 0x02, (byte) 0x3f, (byte) 0x47, (byte) 0xbc, 
    (byte) 0x7f, (byte) 0x58, (byte) 0xaf, (byte) 0xb1, (byte) 0xe2, 
    (byte) 0x68, (byte) 0xf4, (byte) 0x7f, (byte) 0x4a, (byte) 0x21, 
    (byte) 0x1a, (byte) 0x48, (byte) 0xfe, (byte) 0x5a, (byte) 0x31, 
    (byte) 0xce, (byte) 0xa4, (byte) 0x64, (byte) 0x90, (byte) 0x6a, 
    (byte) 0x75, (byte) 0x72, (byte) 0x46, (byte) 0x39, (byte) 0xca, 
    (byte) 0x8b, (byte) 0xec, (byte) 0x68, (byte) 0x4c, (byte) 0x65, 
    (byte) 0xbb, (byte) 0x00, (byte) 0x10, (byte) 0x5c, (byte) 0x9d, 
    (byte) 0xb4, (byte) 0xe7, (byte) 0xa9, (byte) 0x29, (byte) 0xba, 
    (byte) 0xfd, (byte) 0x2f, (byte) 0x6c, (byte) 0x0a, (byte) 0xe0, 
    (byte) 0x99, (byte) 0x51, (byte) 0xd6, (byte) 0x00, (byte) 0x80, 
    (byte) 0x6d, (byte) 0xad, (byte) 0xa3, (byte) 0x43, (byte) 0xec, 
    (byte) 0x04, (byte) 0x0a, (byte) 0xcc, (byte) 0x73, (byte) 0x0f, 
    (byte) 0x1a, (byte) 0x33, (byte) 0x68, (byte) 0x59, (byte) 0x92, 
    (byte) 0x81, (byte) 0x2c, (byte) 0xdb, (byte) 0x34, (byte) 0xac, 
    (byte) 0x67, (byte) 0x81, (byte) 0xf3, (byte) 0xc6, (byte) 0x9a, 
    (byte) 0x5d, (byte) 0xdd, (byte) 0x2e, (byte) 0xf4, (byte) 0xf7, 
    (byte) 0x16, (byte) 0x1b, (byte) 0x8b, (byte) 0x06, (byte) 0x99, 
    (byte) 0xd7, (byte) 0x33, (byte) 0xe1, (byte) 0x27, (byte) 0x29, 
    (byte) 0x0f, (byte) 0xef, (byte) 0x08, (byte) 0xdb, (byte) 0x71, 
    (byte) 0xa3, (byte) 0xb1, (byte) 0x8b, (byte) 0xeb, (byte) 0x6f, 
    (byte) 0x08, (byte) 0xa7, (byte) 0x8f, (byte) 0xd9, (byte) 0x12, 
    (byte) 0x84, (byte) 0x21, (byte) 0xf2, (byte) 0xba, (byte) 0x86, 
    (byte) 0xa5, (byte) 0x55, (byte) 0x85, (byte) 0x26, (byte) 0x59, 
    (byte) 0xd6, (byte) 0x5e, (byte) 0xbd, (byte) 0xf8, (byte) 0xb0, 
    (byte) 0x72, (byte) 0xc0, (byte) 0x59, (byte) 0x01, (byte) 0x6b, 
    (byte) 0xd0, (byte) 0xf8, (byte) 0x2a, (byte) 0xd4, (byte) 0xf1, 
    (byte) 0x67, (byte) 0x56, (byte) 0xa3, (byte) 0xff, (byte) 0xfc, 
    (byte) 0x13, (byte) 0xa0, (byte) 0xa4, (byte) 0x35, (byte) 0x68, 
    (byte) 0xbd, (byte) 0x85, (byte) 0xde, (byte) 0xfa, (byte) 0x85, 
    (byte) 0xc4, (byte) 0x1f, (byte) 0x72, (byte) 0x89, (byte) 0x65, 
    (byte) 0xae, (byte) 0x8f, (byte) 0x61, (byte) 0xee, (byte) 0xa2, 
    (byte) 0x04, (byte) 0x35, (byte) 0x61, (byte) 0xac, (byte) 0xf2, 
    (byte) 0x8d, (byte) 0x66, (byte) 0xc1, (byte) 0x2d, (byte) 0x28, 
    (byte) 0xb3, (byte) 0xca, (byte) 0xb0, (byte) 0x91, (byte) 0xc4, 
    (byte) 0x3b, (byte) 0x6c, (byte) 0xa7, (byte) 0x0a, (byte) 0xa6, 
    (byte) 0xa0, (byte) 0x91, (byte) 0x49};

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws InvalidKeyException {
        ServerKeyExchange ske = new ServerKeyExchange(message,
                EKeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, false);
        ServerECDHParams params = (ServerECDHParams) ske.getExchangeKeys();
        ECParameters ecParams = params.getCurveParameters();
        ECPoint publicPoint = params.getPublicKey();
        System.out.println(ecParams.getCurveType().name());
        System.out.println(ecParams.getNamedCurve().name());
        System.out.println(ecParams.getNamedCurve().name());
        System.out.println(Utility.bytesToHex(publicPoint.getPoint()));
        
        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters x9 = NISTNamedCurves.getByName("P-256");
        org.bouncycastle.math.ec.ECPoint g = x9.getG();
        BigInteger n = x9.getN();
        int nBitLength = n.bitLength();
        
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
