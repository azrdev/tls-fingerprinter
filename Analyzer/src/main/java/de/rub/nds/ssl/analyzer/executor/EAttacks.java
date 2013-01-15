package de.rub.nds.ssl.analyzer.executor;

import de.rub.nds.ssl.analyzer.tests.fingerprint.CCS;
import de.rub.nds.ssl.analyzer.tests.fingerprint.CCSRecordHeader;
import de.rub.nds.ssl.analyzer.tests.fingerprint.CH;
import de.rub.nds.ssl.analyzer.tests.fingerprint.CHHandshakeHeader;
import de.rub.nds.ssl.analyzer.tests.fingerprint.CHRecordHeader;
import de.rub.nds.ssl.analyzer.tests.fingerprint.CKE;
import de.rub.nds.ssl.analyzer.tests.fingerprint.CKEHandshakeHeader;
import de.rub.nds.ssl.analyzer.tests.fingerprint.CKERecordHeader;
import de.rub.nds.ssl.analyzer.tests.fingerprint.FIN;
import de.rub.nds.ssl.analyzer.tests.fingerprint.FINHandshakeHeader;
import de.rub.nds.ssl.analyzer.tests.fingerprint.FINRecordHeader;

/**
 * Listing of all available attacks.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 15, 2013
 */
public enum EAttacks {

    CCS("ChangeCipherSpec Message Test", CCS.class),
    CCS_RH("ChangeCiperSpec Message Record Header Test", CCSRecordHeader.class),
    CH("ClientHello Message Test", CH.class),
    CH_HH("ClientHello Message Handshake Header Test", CHHandshakeHeader.class),
    CH_RH("ClientHello Message Record Header Test", CHRecordHeader.class),
    CKE("ClientKeyExchange Message Test", CKE.class),
    CKE_HH("ClientKeyExchange Message Handshake Header Test",
    CKEHandshakeHeader.class),
    CKE_RH("ClientKeyExchange Message Record Header Test", CKERecordHeader.class),
    FIN("Finished Message Test", FIN.class),
    FIN_HH("Finished Message Handshake Header Test", FINHandshakeHeader.class),
    FIN_RH("Finished Message Record Header Test", FINRecordHeader.class);
    
    /**
     * Fingerprint Test description.
     */
    private String description;
    /**
     * Test implementor.
     */
    private Class implementor;

    /**
     * Prepare Fingerprint Test listing,
     * 
     * @param description Test description
     * @param implementor Test implementor
     */
    private EAttacks(final String description, final Class implementor) {
        this.description = description;
        this.implementor = implementor;
    }
}
