package de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.Fingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerHelloFingerprint;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class SerializerTest {

    /**
     * Check for hardcoded things in Serializer not to break silently if changed
     */
    @Test
    public void testInvariants() {
        assertEquals(",", Serializer.LIST_DELIMITER);
    }

    @Test
    public void deserializeList() {
        List<Id> list;

        list = Serializer.deserializeList("");
        assertNull(list);

        list = Serializer.deserializeList("12");
        assertEquals(Arrays.asList(new Id((byte) 0x12)), list);

        list = Serializer.deserializeList("ab,cd");
        assertEquals(Arrays.asList(new Id((byte) 0xab), new Id((byte) 0xcd)), list);
    }

    @Test(expected = IllegalArgumentException.class)
    public void deserializeListInvalidId() {
        List<Id> list = Serializer.deserializeList("XH");
    }

    // test ClientHelloFingerprint

    @Test(expected = IllegalArgumentException.class)
    public void clientHelloFingerprintEmpty() {
        Fingerprint chf = ClientHelloFingerprint.deserializeFingerprint("");
    }

    private static final String ch_TLS1_complete = "0301:00:c02b,c02f,009e,c00a,c009,c013,c014,c007,c011,0033,0032,0039,009c,002f,0035,000a,0005,0004:0000,ff01,000a,000b,0023,3374,0010,7550,0005,0012,000d:00:0017,0018,0019";
    private static final String ch_ssl3 = "0300:00:00ff,009e,0033,0032,0039,009c,002f,0035,000a,0005,0004:::";

    @Test
    public void clientHelloFingerprintTLS1_1() {
        final Fingerprint chf = ClientHelloFingerprint.deserializeFingerprint(ch_TLS1_complete);
        assertEquals(6, chf.getSigns().size());

        final String serialized = chf.serialize();
        assertEquals(ch_TLS1_complete, serialized);
        assertEquals(chf, ClientHelloFingerprint.deserializeFingerprint(serialized));
    }

    @Test
    public void clientHelloFingerprintSSL3() {
        final Fingerprint chf = ClientHelloFingerprint.deserializeFingerprint(ch_ssl3);
        assertEquals(3, chf.getSigns().size());

        final String serialized = chf.serialize();
        assertEquals(ch_ssl3, serialized);
        assertEquals(chf, ClientHelloFingerprint.deserializeFingerprint(serialized));
    }

    // test ServerHelloFingerprint

    @Test(expected = IllegalArgumentException.class)
    public void serverHelloFingerprintEmpty() {
        final Fingerprint shf = ServerHelloFingerprint.deserializeFingerprint("");
    }

    private static final String sh_TLS1_2_complete = "0303:c02f:00:true:0000,ff01,000b,0023,0005,0010:00,01,02";
    private static final String sh_TLS1_1_emptyExt = "0302:0005:00:false:,:";
    private static final String sh_TLS1_0_noExt = "0301:0004:00:false::";
    private static final String sh_SSL3 = "0300:0033:00:false:ff01:";

    @Test
    public void serverHelloFingerprintTLS1_2_complete() {
        ServerHelloFingerprint shf = ServerHelloFingerprint.deserializeFingerprint(sh_TLS1_2_complete);
        assertEquals(6, shf.getSigns().size());

        assertTrue(shf.getSign("extensions-layout") instanceof List);
        List<Id> extensionsLayout = shf.getSign("extensions-layout");
        assertEquals(6, extensionsLayout.size());

        String serialized = shf.serialize();
        assertEquals(sh_TLS1_2_complete, serialized);
        assertEquals(shf, ServerHelloFingerprint.deserializeFingerprint(serialized));
    }

    @Test
    public void serverHelloFingerprintTLS1_1_emptyExt() {
        final ServerHelloFingerprint shf = ServerHelloFingerprint.deserializeFingerprint(sh_TLS1_1_emptyExt);
        assertEquals(5, shf.getSigns().size());

        assertTrue(shf.getSign("extensions-layout") instanceof List);
        final List<Id> extensionsLayout = shf.getSign("extensions-layout");
        assertEquals(0, extensionsLayout.size());

        final String serialized = shf.serialize();
        assertEquals(sh_TLS1_1_emptyExt, serialized);
        assertEquals(shf, ServerHelloFingerprint.deserializeFingerprint(serialized));
    }

    @Test
    public void serverHelloFingerprintTLS1_0_noExt() {
        final Fingerprint shf = ServerHelloFingerprint.deserializeFingerprint(sh_TLS1_0_noExt);
        assertEquals(4, shf.getSigns().size());

        assertNull(shf.getSign("extensions-layout"));

        final String serialized = shf.serialize();
        assertEquals(sh_TLS1_0_noExt, serialized);
        assertEquals(shf, ServerHelloFingerprint.deserializeFingerprint(serialized));
    }

    @Test
    public void serverHelloFingerprintSSL3() {
        final ServerHelloFingerprint shf = ServerHelloFingerprint.deserializeFingerprint(sh_SSL3);
        assertEquals(5, shf.getSigns().size());

        assertTrue(shf.getSign("extensions-layout") instanceof List);
        final List<Id> extensionsLayout = shf.getSign("extensions-layout");
        assertEquals(1, extensionsLayout.size());

        final String serialized = shf.serialize();
        assertEquals(sh_SSL3, serialized);
        assertEquals(shf, ServerHelloFingerprint.deserializeFingerprint(serialized));
    }
}