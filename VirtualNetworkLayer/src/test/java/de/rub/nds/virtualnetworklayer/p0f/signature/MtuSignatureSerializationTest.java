package de.rub.nds.virtualnetworklayer.p0f.signature;

import org.junit.Test;

import static de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature;
import static org.junit.Assert.assertEquals;

/**
 * Test [de]serialization of MTU signatures to the p0f format.
 *
 * @see MTUSignature#MTUSignature(String)
 * @see MTUSignature#writeToString(Signature)
 */
public class MtuSignatureSerializationTest {

    // examples from p0f.fp resource
    public static final String empty = "";
    public static final String ethernet = "1500";
    public static final String loopback = "65535";

    // simple deserialization + plausibility check

    @Test
    public void deserialize_empty() {
        Signature sig = new MTUSignature(empty);
        assertEquals(0, sig.getSigns().size());
        assertEquals(0, sig.getQuirks().size());
    }

    @Test
    public void deserialize_signCount1() {
        Signature sig = new MTUSignature(ethernet);
        assertEquals(1, sig.getSigns().size());
        assertEquals(0, sig.getQuirks().size());
    }

    @Test
    public void deserialize_signCount2() {
        Signature sig = new MTUSignature(loopback);
        assertEquals(1, sig.getSigns().size());
        assertEquals(0, sig.getQuirks().size());
    }

    // round-trip examples

    @Test
    public void both_complete1() {
        Signature sig = new MTUSignature(ethernet);
        assertEquals(ethernet, MTUSignature.writeToString(sig));
    }

    @Test
    public void both_complete2() {
        Signature sig = new MTUSignature(loopback);
        assertEquals(loopback, MTUSignature.writeToString(sig));
    }

    @Test
    public void both_empty() {
        Signature sig = new MTUSignature(empty);
        assertEquals(empty, MTUSignature.writeToString(sig));
    }
}
