package de.rub.nds.virtualnetworklayer.p0f.signature;

import org.junit.Test;

import static de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature;
import static org.junit.Assert.assertEquals;

/**
 * Test [de]serialization of TCP signatures to the p0f format.
 *
 * @see TCPSignature#TCPSignature(String)
 * @see TCPSignature#writeToString(Signature)
 */
public class TcpSignatureSerializationTest {

    // examples from p0f.fp resource
    public static final String emptyOptionsLayout = "4:109:0:0:mss*20,42::df,id+,ecn:0";
    public static final String linux3x = "*:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0";
    public static final String openVMS = "4:64:0:1460:3993,0:mss::0";
    public static final String tru64 = "4:64:0:1460:mss*25,0:mss:df,id+:0";

    // simple deserialization + plausibility check

    @Test
    public void deserialize_signCount() {
        Signature sig = new TCPSignature(tru64);
        assertEquals(8, sig.getSigns().size());
        assertEquals(2, sig.getQuirks().size());
    }

    @Test
    public void deserialize_signCountNoQuirks() {
        Signature sig = new TCPSignature(openVMS);
        assertEquals(8, sig.getSigns().size());
        assertEquals(0, sig.getQuirks().size());
    }

    @Test
    public void deserialize_wildcards() {
        Signature sig = new TCPSignature(linux3x);
        assertEquals(6, sig.getSigns().size());
        assertEquals(2, sig.getQuirks().size());
    }

    // round-trip examples

    @Test
    public void both_complete() {
        Signature sig = new TCPSignature(tru64);
        assertEquals(tru64, TCPSignature.writeToString(sig));
    }

    @Test
    public void both_noQuirks() {
        Signature sig = new TCPSignature(openVMS);
        assertEquals(openVMS, TCPSignature.writeToString(sig));
    }

    @Test
    public void both_wildcards() {
        Signature sig = new TCPSignature(linux3x);
        assertEquals(linux3x, TCPSignature.writeToString(sig));
    }

    @Test
    public void both_emptyOptionsLayout() {
        Signature sig = new TCPSignature(emptyOptionsLayout);
        assertEquals(emptyOptionsLayout, TCPSignature.writeToString(sig));
    }
}