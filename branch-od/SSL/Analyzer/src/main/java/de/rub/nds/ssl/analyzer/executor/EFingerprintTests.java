package de.rub.nds.ssl.analyzer.executor;

import de.rub.nds.ssl.analyzer.AAnalyzerComponent;
import de.rub.nds.ssl.analyzer.fingerprinter.IFingerprinter;
import de.rub.nds.ssl.analyzer.fingerprinter.TestHashAnalyzer;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.BleichenbacherPossible;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CCS;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CCSRecordHeader;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CH;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CHHandshakeHeader;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CHRecordHeader;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CKE;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CKEHandshakeHeader;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CKERecordHeader;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CheckEnumeration;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.CheckExtensions;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.FIN;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.FINHandshakeHeader;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.FINRecordHeader;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.GoodCase;
import de.rub.nds.ssl.analyzer.fingerprinter.tests.Renegotiation;

/**
 * Listing of all available Fingerprinting tests.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 13, 2013
 */
public enum EFingerprintTests {

    CCS("ChangeCipherSpec Message Test",
    CCS.class, TestHashAnalyzer.class),
    CCS_RH("ChangeCiperSpec Message Record Header Test",
    CCSRecordHeader.class, TestHashAnalyzer.class),
    CH("ClientHello Message Test",
    CH.class, TestHashAnalyzer.class),
    CH_HH("ClientHello Message Handshake Header Test",
    CHHandshakeHeader.class, TestHashAnalyzer.class),
    CH_RH("ClientHello Message Record Header Test",
    CHRecordHeader.class, TestHashAnalyzer.class),
    CKE("ClientKeyExchange Message Test",
    CKE.class, TestHashAnalyzer.class),
    CKE_HH("ClientKeyExchange Message Handshake Header Test",
    CKEHandshakeHeader.class, TestHashAnalyzer.class),
    CKE_RH("ClientKeyExchange Message Record Header Test",
    CKERecordHeader.class, TestHashAnalyzer.class),
    FIN("Finished Message Test",
    FIN.class, TestHashAnalyzer.class),
    FIN_HH("Finished Message Handshake Header Test",
    FINHandshakeHeader.class, TestHashAnalyzer.class),
    FIN_RH("Finished Message Record Header Test",
    FINRecordHeader.class, TestHashAnalyzer.class),
    GOOD("Good Case - Clean Run Test",
    GoodCase.class, TestHashAnalyzer.class),
    HANDSHAKE_ENUM("Handshake Enumeration Test",
    CheckEnumeration.class, TestHashAnalyzer.class),
    BLEICHENBACHER_POSSIBLE("Bleichenbacher Vulnerability Test",
    BleichenbacherPossible.class, TestHashAnalyzer.class),
    TLS_RENEGOTIATION("TLS Renegotiation Test",
    Renegotiation.class, TestHashAnalyzer.class);
//    EXTENSIONS("Supported extensions test",
//    CheckExtensions.class, TestHashAnalyzer.class);
    /**
     * Fingerprint Test description.
     */
    private String description;
    /**
     * Test implementer.
     */
    private Class<AAnalyzerComponent> implementer;
    /**
     * Analyzer implementer.
     */
    private Class<IFingerprinter> analyzer;

    /**
     * Prepare Fingerprint Test listing.
     *
     * @param description Test description
     * @param implementer Test implementer
     * @param analyzer Test analyzer
     */
    private EFingerprintTests(final String description,
            final Class implementer,
            final Class analyzer) {
        this.description = description;
        this.implementer = implementer;
        this.analyzer = analyzer;
    }

    /**
     * Getter for Fingerprint Test description.
     *
     * @return Fingerprint Test description
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Getter for Fingerprint Test implementer.
     *
     * @return Fingerprint Test implementer
     */
    public Class<AAnalyzerComponent> getImplementer() {
        return this.implementer;
    }

    /**
     * Getter for Fingerprint Test analyzer.
     *
     * @return Fingerprint Test analyzer
     */
    public Class<IFingerprinter> getAnalyzer() {
        return this.analyzer;
    }
}
