package de.rub.nds.research.ssl.stack.protocols.msgs.datatypes;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * Utility class for RSA Operations.
 * 
 * @author Erik Tews <erik@datenzone.de>
 *
 */
public class RsaUtil {

	/*
	public static byte[] pubOp(byte[] msg, RSAPublicKey k) {
		try {
			byte[] m1 = RSACore.rsa(msg, k);
			byte[] m2 = myPubOp(msg, k);
			System.err.println(Arrays.toString(m1));
			System.err.println(Arrays.toString(m2));
			return m1;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
	}
	*/
	
	/**
	 * Perform the RSA public key operation. Please be aware that this code
	 * doesn't do anything against (timing) based side channel attacks.
	 * 
	 * @param msg
	 *            The RSA encrypted message, or the signature to verify.
	 * @param k
	 *            The RSA public key.
	 * @return msg^(k.e) mod k.n.
	 */
	public static byte[] pubOp(byte[] msg, RSAPublicKey k) {
		BigInteger e = k.getPublicExponent();
		BigInteger n = k.getModulus();
		BigInteger m = new BigInteger(1, msg);
		BigInteger r = m.modPow(e, n);
		byte[] t = r.toByteArray();
		/*
		 * BigInteger uses a leading sign-bit, so that also negative integers
		 * can be represented as a byte-array. This can result in an (unwanted)
		 * leading zero byte in the result. Remove that zero byte.
		 */
		if (t[0] == 0) {
			byte[] result = new byte[t.length - 1];
			System.arraycopy(t, 1, result, 0, t.length - 1);
			return result;
		} else {
			return t;
		}
	}
}
