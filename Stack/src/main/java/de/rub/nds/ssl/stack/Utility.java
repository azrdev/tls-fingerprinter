package de.rub.nds.ssl.stack;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import sun.security.x509.*;

/**
 * Helper routines for common use
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 *
 * Dec 20, 2011
 */
public abstract class Utility {
    /**
     * Bits in byte.
     */
    public static final int BITS_IN_BYTE = 8;
    
    /**
     * Valid Hex Chars.
     */
    private final static char[] HEXCHARS = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    /**
     * Private constructor - Utility class only.
     */
    private Utility() {
    }

    /**
     * Converts a byte array into its hex string representation.
     *
     * @param bytes Bytes to convert
     * @return Hex string of delivered byte array
     */
    public static String bytesToHex(final byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; i++) {
            // unsigned right shift of the MSBs
            builder.append(HEXCHARS[(bytes[i] & 0xff) >>> 4]);
            // handling the LSBs
            builder.append(HEXCHARS[bytes[i] & 0xf]);
            builder.append(' ');
        }

        return builder.toString();
    }

//    public static String bytesToHex(byte[] array) {
//        StringBuilder sb = new StringBuilder(200);
//        int bytecon = 0;
//        for (int i = 0; i < array.length; i++) {
//            bytecon = array[i] & 0xFF;
//
//            // byte-wise AND converts signed byte to unsigned.
//            if (bytecon < 16) {
//                sb.append("0x0" + Integer.toHexString(bytecon).toUpperCase() + ", ");
//            } // pad on left if single hex digit.
//            else {
//                sb.append("0x" + Integer.toHexString(bytecon).toUpperCase() + ", ");
//            }
//            // pad on left if single hex digit.
//        }
//        return sb.toString();
//    }
    /**
     * Computes the Greatest Common Divisor of two integers.
     *
     * @param a First Integer
     * @param b Second Integer
     * @return Greatest Common Divisor of both integers
     */
    public static int findGCD(int a, int b) {
        if (b == 0) {
            return a;
        }
        return findGCD(b, a % b);
    }

    /**
     * Computes the Greatest Common Divisor of two BigIntegers.
     *
     * @param a First BigInteger
     * @param b Second BigInteger
     * @return Greatest Common Divisor of both BigIntegers
     */
    public static BigInteger findGCD(BigInteger a, BigInteger b) {
        if (b.compareTo(BigInteger.ZERO) == 0) {
            return a;
        }
        return findGCD(b, a.mod(b));
    }

    /**
     * Computes the Least Common Multiple of two integers.
     *
     * @param a First Integer
     * @param b Second Integer
     * @return Least Common Multiple of both integers
     */
    public static int findLCM(int a, int b) {
        int result = 0;
        int num1, num2;
        if (a > b) {
            num1 = a;
            num2 = b;
        } else {
            num1 = b;
            num2 = a;
        }
        for (int i = 1; i <= num2; i++) {
            if ((num1 * i) % num2 == 0) {
                result = i * num1;
            }
        }

        return result;
    }

    /**
     * Computes the Least Common Multiple of two BigIntegers.
     *
     * @param ba First BigInteger
     * @param bb Second BigInteger
     * @return Least Common Multiple of both BigIntegers
     */
    public static BigInteger findLCM(BigInteger ba, BigInteger bb) {
        BigInteger result = BigInteger.ZERO;
        long a = ba.longValue();
        long b = bb.longValue();
        long num1, num2;
        if (a > b) {
            num1 = a;
            num2 = b;
        } else {
            num1 = b;
            num2 = a;
        }
        for (int i = 1; i <= num2; i++) {
            if ((num1 * i) % num2 == 0) {
                result = BigInteger.valueOf(i * num1);
            }
        }

        return result;
    }

    /**
     * Computes the Least Common Multiple of a list of BigIntegers.
     *
     * @param numbers List of BigIntegers
     * @return Least Common Multiple of all BigIntegers contained in the list
     */
    public static BigInteger findLCM(List<BigInteger> numbers) {
        BigInteger result = numbers.get(0);
        for (int i = 1; i < numbers.size(); i++) {
            result = findLCM(result, numbers.get(i));
        }
        return result;
    }

    /**
     * Corrects the length of a byte array to a multiple of a passed blockSize.
     *
     * @param array Array which size should be corrected
     * @param blockSize Blocksize - the resulting array length will be a
     * multiple of it
     * @param removeSignByte If set to TRUE leading sign bytes will be removed
     * @return Size corrected array (maybe padded or stripped the sign byte)
     */
    public static byte[] correctSize(final byte[] array, int blockSize,
            boolean removeSignByte) {
        int remainder = array.length % blockSize;
        byte[] result = array;
        byte[] tmp;

        if (removeSignByte && remainder > 0 && result[0] == 0x0) {
            // extract signing byte if present
            tmp = new byte[result.length - 1];
            System.arraycopy(result, 1, tmp, 0, tmp.length);
            result = tmp;
            remainder = tmp.length % blockSize;
        }

        if (remainder > 0) {
            // add zeros to fit size
            tmp = new byte[result.length + blockSize - remainder];
            System.arraycopy(result, 0, tmp, blockSize - remainder,
                    result.length);
            result = tmp;
        }

        return result;
    }

    /**
     * Create a self-signed X.509 Certificate
     *
     * @param keyPair Public/Private key pair
     * @param algorithm Signature alogrithm
     * @param distinguishedNameSubject X.509 Distinguished Name of the subject
     * @param distinguishedNameIssuer X.509 Distinguished Name of the issuer
     * @param validFrom Valid strating from this date
     * @param validUntil Valid until this date
     * @param serialNumber Serial number
     */
    public static X509Certificate generateX509v3Cert(KeyPair keyPair,
            String algorithm, String distinguishedNameSubject,
            String distinguishedNameIssuer, Date validFrom, Date validUntil,
            BigInteger serialNumber)
            throws GeneralSecurityException, IOException {
        // prepare necessary infos
        X500Name subject = new X500Name(distinguishedNameSubject);
        X500Name issuer = new X500Name(distinguishedNameIssuer);
        CertificateValidity validtyPeriod = new CertificateValidity(validFrom,
                validUntil);
        AlgorithmId algorithmId = AlgorithmId.get(algorithm);

        // put the pieces together
        X509CertInfo certificateInfo = new X509CertInfo();
        certificateInfo.set(X509CertInfo.VERSION,
                new CertificateVersion(CertificateVersion.V3));
        certificateInfo.set(X509CertInfo.SUBJECT,
                new CertificateSubjectName(subject));
        certificateInfo.set(X509CertInfo.ISSUER,
                new CertificateIssuerName(issuer));
        certificateInfo.set(X509CertInfo.VALIDITY, validtyPeriod);
        certificateInfo.set(X509CertInfo.SERIAL_NUMBER,
                new CertificateSerialNumber(serialNumber));
        certificateInfo.set(X509CertInfo.ALGORITHM_ID,
                new CertificateAlgorithmId(algorithmId));
        certificateInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.
                getPublic()));

        // Sign the certificate
        X509CertImpl cert = new X509CertImpl(certificateInfo);
        cert.sign(keyPair.getPrivate(), algorithm);

        return cert;
    }
    
    /**
     * Converts a byte[] to int.
     *
     * @param bytes 4 bytes array to be converted
     * @return Integer representation of the byte[]
     */
    public static int bytesToInt(byte... bytes) {
        return (int) ((0xFF & bytes[0]) << Utility.BITS_IN_BYTE*3
                | (0xFF & bytes[1]) << Utility.BITS_IN_BYTE*2
                | (0xFF & bytes[2]) << Utility.BITS_IN_BYTE
                | (0xFF & bytes[3]));
    }
}
