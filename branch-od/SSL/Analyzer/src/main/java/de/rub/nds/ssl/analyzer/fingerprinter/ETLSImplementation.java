package de.rub.nds.ssl.analyzer.fingerprinter;

/**
 * TLS implementations which are fingerprinted.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 May 24, 2012
 */
public enum ETLSImplementation {

    /**
     * OpenSSL Version 0.9.8
     */
    OPENSSL_0_9_8,
    /**
     * OpenSSL Version 1.0.1
     */
    OPENSSL_1_0_1,
    /**
     * JSSE of OpenJDK Version 6.24
     */
    OPENJDK_6_24,
    /**
     * JSSE of OpenJDK Version 7.07
     */
    OPENJDK_7_07,
    /**
     * JSSE of Oracle JDK Version 4.19
     */
    JDK_4_19,
    /**
     * JSSE of Oracle JDK Version 5.22
     */
    JDK_5_22,
    /**
     * JSSE of Oracle JDK Version 6.35
     */
    JDK_6_35,
    /**
     * JSSE of Oracle JDK Version 7.07
     */
    JDK_7_07,
    /**
     * GnuTLS Version 3.1.8
     */
    GNUTLS_3_1_8,
    /**
     * Microsoft SChannel as shipped with IIS 6.0
     */
    IIS_6_0,
    /**
     * Microsoft SChannel as shipped with IIS 7.5
     */
    IIS_7_5,
    /**
     * BigIP 8950 - BIG-IP 11.3.0 Build 3022.0 Hotfix HF3
     */
    BigIp_8950_11_3_0,
    /**
     * BigIP 8950 - BIG-IP 11.1.0 Build 2268.0 Hotfix HF5
     */
    BigIp_8950_11_1_0;
}
