package de.rub.nds.ssl.stack.tests;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.testng.annotations.Test;

/**
 * Encodes a given Point according to ANSI X9.62.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1

 * Aug 1, 2013
 */
public class ANSIX962PointEncoding {

    private static final BigInteger x = new BigInteger("32910910923616822470882795766002892358092379688431322448625892480452235335600");
    private static final BigInteger y = new BigInteger("64354991328235689453813615382084131294339853420594271997976840393194210591700");
    

    private static final String CURVE_NAME = "P-256";
    
    @Test(enabled = true)
    public static void test() throws InvalidKeyException {
        X9ECParameters x9 = NISTNamedCurves.getByName("P-256");
        
        ECCurve.Fp curve = (ECCurve.Fp) x9.getCurve();
        ECFieldElement xElement = new ECFieldElement.Fp(curve.getQ(), x);
        ECFieldElement yElement = new ECFieldElement.Fp(curve.getQ(), y);
        
        ECPoint g = x9.getG();
        ECPoint point = new ECPoint.Fp(curve,xElement,yElement);
System.out.println(bytesToHex(point.getEncoded()));
    }

    
    
    private final static char[] HEXCHARS = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    
    /**
     * Converts a byte array into its hex string representation.
     *
     * @param bytes Bytes to convert
     * @return Hex string of delivered byte array
     */
    public static String bytesToHex(final byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; i++) {
            builder.append("(byte) 0x");
            // unsigned right shift of the MSBs
            builder.append(HEXCHARS[(bytes[i] & 0xff) >>> 4]);
            // handling the LSBs
            builder.append(HEXCHARS[bytes[i] & 0xf]);
            builder.append(", ");
        }

        return builder.toString();
    }
}
