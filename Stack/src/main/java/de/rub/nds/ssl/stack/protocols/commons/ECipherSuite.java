package de.rub.nds.ssl.stack.protocols.commons;

import de.rub.nds.ssl.stack.Utility;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.rub.nds.ssl.stack.exceptions.UnknownCipherSuiteException;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;

/**
 * Cipher Suites for SSL/TLS.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1 Nov 11, 2011
 */
public enum ECipherSuite {
    //TODO: handle cipher suites as short instead of byte[]

    TLS_NULL_WITH_NULL_NULL(new byte[]{(byte) 0x00, (byte) 0x00}),
    TLS_RSA_WITH_NULL_MD5(new byte[]{(byte) 0x00, (byte) 0x01}),
    TLS_RSA_WITH_NULL_SHA(new byte[]{(byte) 0x00, (byte) 0x02}),
    TLS_RSA_EXPORT_WITH_RC4_40_MD5(new byte[]{(byte) 0x00, (byte) 0x03}),
    TLS_RSA_WITH_RC4_128_MD5(new byte[]{(byte) 0x00, (byte) 0x04}),
    TLS_RSA_WITH_RC4_128_SHA(new byte[]{(byte) 0x00, (byte) 0x05}),
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5(new byte[]{(byte) 0x00, (byte) 0x06}),
    TLS_RSA_WITH_IDEA_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x07}),
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x08}),
    TLS_RSA_WITH_DES_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x09}),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x0A}),
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x0B}),
    TLS_DH_DSS_WITH_DES_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x0C}),
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x0D}),
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x0E}),
    TLS_DH_RSA_WITH_DES_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x0F}),
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x10}),
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x11}),
    TLS_DHE_DSS_WITH_DES_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x12}),
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x13}),
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x14}),
    TLS_DHE_RSA_WITH_DES_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x15}),
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x16}),
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5(new byte[]{(byte) 0x00, (byte) 0x17}),
    TLS_DH_anon_WITH_RC4_128_MD5(new byte[]{(byte) 0x00, (byte) 0x18}),
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x19}),
    TLS_DH_anon_WITH_DES_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x1A}),
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x1B}),
    TLS_KRB5_WITH_DES_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x1E}),
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x1F}),
    TLS_KRB5_WITH_RC4_128_SHA(new byte[]{(byte) 0x00, (byte) 0x20}),
    TLS_KRB5_WITH_IDEA_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x21}),
    TLS_KRB5_WITH_DES_CBC_MD5(new byte[]{(byte) 0x00, (byte) 0x22}),
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5(new byte[]{(byte) 0x00, (byte) 0x23}),
    TLS_KRB5_WITH_RC4_128_MD5(new byte[]{(byte) 0x00, (byte) 0x24}),
    TLS_KRB5_WITH_IDEA_CBC_MD5(new byte[]{(byte) 0x00, (byte) 0x25}),
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA(new byte[]{(byte) 0x00, (byte) 0x26}),
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA(new byte[]{(byte) 0x00, (byte) 0x27}),
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA(new byte[]{(byte) 0x00, (byte) 0x28}),
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5(new byte[]{(byte) 0x00, (byte) 0x29}),
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5(new byte[]{(byte) 0x00, (byte) 0x2A}),
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5(new byte[]{(byte) 0x00, (byte) 0x2B}),
    TLS_PSK_WITH_NULL_SHA(new byte[]{(byte) 0x00, (byte) 0x2C}),
    TLS_DHE_PSK_WITH_NULL_SHA(new byte[]{(byte) 0x00, (byte) 0x2D}),
    TLS_RSA_PSK_WITH_NULL_SHA(new byte[]{(byte) 0x00, (byte) 0x2E}),
    TLS_RSA_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x2F}),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x30}),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x31}),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x32}),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x33}),
    TLS_DH_anon_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x34}),
    TLS_RSA_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x35}),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x36}),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x37}),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x38}),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x39}),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0x40}),
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x41}),
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x42}),
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x43}),
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x44}),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x45}),
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x46}),
    TLS_DHE_DSS_WITH_RC4_128_SHA(new byte[]{(byte) 0x00, (byte) 0x66}),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0x67}),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0x68}),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0x69}),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0x6A}),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0x6B}),
    TLS_DH_anon_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0x6C}),
    TLS_DH_anon_WITH_AES_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0x6D}),
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x84}),
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x85}),
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x86}),
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x87}),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x88}),
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x89}),
    TLS_PSK_WITH_RC4_128_SHA(new byte[]{(byte) 0x00, (byte) 0x8A}),
    TLS_PSK_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x8B}),
    TLS_PSK_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x8C}),
    TLS_PSK_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x8D}),
    TLS_DHE_PSK_WITH_RC4_128_SHA(new byte[]{(byte) 0x00, (byte) 0x8E}),
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x8F}),
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x90}),
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x91}),
    TLS_RSA_PSK_WITH_RC4_128_SHA(new byte[]{(byte) 0x00, (byte) 0x92}),
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x93}),
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x94}),
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x95}),
    TLS_RSA_WITH_SEED_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x96}),
    TLS_DH_DSS_WITH_SEED_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x97}),
    TLS_DH_RSA_WITH_SEED_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x98}),
    TLS_DHE_DSS_WITH_SEED_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x99}),
    TLS_DHE_RSA_WITH_SEED_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x9A}),
    TLS_DH_anon_WITH_SEED_CBC_SHA(new byte[]{(byte) 0x00, (byte) 0x9B}),
    TLS_RSA_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0x00, (byte) 0x9C}),
    TLS_RSA_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0x00, (byte) 0x9D}),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0x00, (byte) 0x9E}),
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0x00, (byte) 0x9F}),
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0x00, (byte) 0xA0}),
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0x00, (byte) 0xA1}),
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0x00, (byte) 0xA2}),
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0x00, (byte) 0xA3}),
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0x00, (byte) 0xA4}),
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0x00, (byte) 0xA5}),
    TLS_DH_anon_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0x00, (byte) 0xA6}),
    TLS_DH_anon_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0x00, (byte) 0xA7}),
    TLS_PSK_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0x00, (byte) 0xA8}),
    TLS_PSK_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0x00, (byte) 0xA9}),
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0x00, (byte) 0xAA}),
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0x00, (byte) 0xAB}),
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0x00, (byte) 0xAC}),
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0x00, (byte) 0xAD}),
    TLS_PSK_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xAE}),
    TLS_PSK_WITH_AES_256_CBC_SHA384(new byte[]{(byte) 0x00, (byte) 0xAF}),
    TLS_PSK_WITH_NULL_SHA256(new byte[]{(byte) 0x00, (byte) 0xB0}),
    TLS_PSK_WITH_NULL_SHA384(new byte[]{(byte) 0x00, (byte) 0xB1}),
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xB2}),
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384(new byte[]{(byte) 0x00, (byte) 0xB3}),
    TLS_DHE_PSK_WITH_NULL_SHA256(new byte[]{(byte) 0x00, (byte) 0xB4}),
    TLS_DHE_PSK_WITH_NULL_SHA384(new byte[]{(byte) 0x00, (byte) 0xB5}),
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xB6}),
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384(new byte[]{(byte) 0x00, (byte) 0xB7}),
    TLS_RSA_PSK_WITH_NULL_SHA256(new byte[]{(byte) 0x00, (byte) 0xB8}),
    TLS_RSA_PSK_WITH_NULL_SHA384(new byte[]{(byte) 0x00, (byte) 0xB9}),
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xBA}),
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xBB}),
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xBC}),
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xBD}),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xBE}),
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xBF}),
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xC0}),
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xC1}),
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xC2}),
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xC3}),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xC4}),
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256(new byte[]{(byte) 0x00, (byte) 0xC5}),
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV(new byte[]{(byte) 0x00, (byte) 0xFF}),
    TLS_ECDH_ECDSA_WITH_NULL_SHA(new byte[]{(byte) 0xC0, (byte) 0x01}),
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA(new byte[]{(byte) 0xC0, (byte) 0x02}),
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x03}),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x04}),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x05}),
    TLS_ECDHE_ECDSA_WITH_NULL_SHA(new byte[]{(byte) 0xC0, (byte) 0x06}),
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(new byte[]{(byte) 0xC0, (byte) 0x07}),
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x08}),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x09}),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x0A}),
    TLS_ECDH_RSA_WITH_NULL_SHA(new byte[]{(byte) 0xC0, (byte) 0x0B}),
    TLS_ECDH_RSA_WITH_RC4_128_SHA(new byte[]{(byte) 0xC0, (byte) 0x0C}),
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x0D}),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x0E}),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x0F}),
    TLS_ECDHE_RSA_WITH_NULL_SHA(new byte[]{(byte) 0xC0, (byte) 0x10}),
    TLS_ECDHE_RSA_WITH_RC4_128_SHA(new byte[]{(byte) 0xC0, (byte) 0x11}),
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x12}),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x13}),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x14}),
    TLS_ECDH_anon_WITH_NULL_SHA(new byte[]{(byte) 0xC0, (byte) 0x15}),
    TLS_ECDH_anon_WITH_RC4_128_SHA(new byte[]{(byte) 0xC0, (byte) 0x16}),
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x17}),
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x18}),
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x19}),
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x1A}),
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x1B}),
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x1C}),
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x1D}),
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x1E}),
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x1F}),
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x20}),
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x21}),
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x22}),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x23}),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x24}),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x25}),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x26}),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x27}),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x28}),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x29}),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x2A}),
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x2B}),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x2C}),
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x2D}),
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x2E}),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x2F}),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x30}),
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x31}),
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x32}),
    TLS_ECDHE_PSK_WITH_RC4_128_SHA(new byte[]{(byte) 0xC0, (byte) 0x33}),
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x34}),
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x35}),
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA(new byte[]{(byte) 0xC0, (byte) 0x36}),
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x37}),
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x38}),
    TLS_ECDHE_PSK_WITH_NULL_SHA(new byte[]{(byte) 0xC0, (byte) 0x39}),
    TLS_ECDHE_PSK_WITH_NULL_SHA256(new byte[]{(byte) 0xC0, (byte) 0x3A}),
    TLS_ECDHE_PSK_WITH_NULL_SHA384(new byte[]{(byte) 0xC0, (byte) 0x3B}),
    TLS_RSA_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x3C}),
    TLS_RSA_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x3D}),
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x3E}),
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x3F}),
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x40}),
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x41}),
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x42}),
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x43}),
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x44}),
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x45}),
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x46}),
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x47}),
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x48}),
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x49}),
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x4A}),
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x4B}),
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x4C}),
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x4D}),
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x4E}),
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x4F}),
    TLS_RSA_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x50}),
    TLS_RSA_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x51}),
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x52}),
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x53}),
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x54}),
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x55}),
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x56}),
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x57}),
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x58}),
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x59}),
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x5A}),
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x5B}),
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x5C}),
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x5D}),
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x5E}),
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x5F}),
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x60}),
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x61}),
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x62}),
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x63}),
    TLS_PSK_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x64}),
    TLS_PSK_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x65}),
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x66}),
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x67}),
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x68}),
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x69}),
    TLS_PSK_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x6A}),
    TLS_PSK_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x6B}),
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x6C}),
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x6D}),
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x6E}),
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x6F}),
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x70}),
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x71}),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x72}),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x73}),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x74}),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x75}),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x76}),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x77}),
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x78}),
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x79}),
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x7A}),
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x7B}),
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x7C}),
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x7D}),
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x7E}),
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x7F}),
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x80}),
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x81}),
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x82}),
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x83}),
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x84}),
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x85}),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x86}),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x87}),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x88}),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x89}),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x8A}),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x8B}),
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x8C}),
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x8D}),
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x8E}),
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x8F}),
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x90}),
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x91}),
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256(new byte[]{(byte) 0xC0, (byte) 0x92}),
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384(new byte[]{(byte) 0xC0, (byte) 0x93}),
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x94}),
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x95}),
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x96}),
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x97}),
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x98}),
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x99}),
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(new byte[]{(byte) 0xC0, (byte) 0x9A}),
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(new byte[]{(byte) 0xC0, (byte) 0x9B}),
    SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA(new byte[]{(byte) 0xfe, (byte) 0xff}),;

    /**
     * * Length of the cipher suite id: 2 Bytes.
     */
    final public static int LENGTH_ENCODED = 2;
    final private static Map<Integer, ECipherSuite> ID_MAP =
            new HashMap<>(values().length);
    final private byte[] id;

    static {
        byte[] id;
        for (ECipherSuite tmp : ECipherSuite.values()) {
            id = tmp.getId();
            ID_MAP.put((id[0] & 0xff) << 8 | (id[1] & 0xff), tmp);
        }
    }

    /**
     * Construct a cipher suite with the given id.
     *
     * @param idBytes Id of this cipher suite
     */
    private ECipherSuite(final byte[] idBytes) {
        id = idBytes;
    }

    /**
     * Get the Id of this cipher suite.
     *
     * @return Id as byte array
     */
    public byte[] getId() {
        byte[] tmp = new byte[id.length];
        // deep copy
        System.arraycopy(id, (byte) 0, tmp, (byte) 0, tmp.length);

        return tmp;
    }

    public EKeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        if (this.isRsa()) {
            return EKeyExchangeAlgorithm.RSA;
        } else if (this.isDhe()) {
            return EKeyExchangeAlgorithm.DIFFIE_HELLMAN;
        } else if (this.isEcdhe()) {
            return EKeyExchangeAlgorithm.EC_DIFFIE_HELLMAN;
        } else {
            throw new IllegalArgumentException(
                    "sorry, key exchange type is not supported: " + this);
        }
    }

	private static String NAME_PREFIX_REGEX = "\\A(SSL|TLS)_";

    /**
     * Is this cipher suite a ECDHE suite?
     *
     * @return True if it is, false otherwise.
     */
    public boolean isEcdhe() {
        return this.name().matches(NAME_PREFIX_REGEX + "ECDHE.*");
    }

    /**
     * Is this cipher suite an RSA suite?
     *
     * @return True if it is, false otherwise.
     */
    public boolean isRsa() {
        return this.name().matches(NAME_PREFIX_REGEX + "RSA.*");
    }

    /**
     * Is this cipher suite a DHE suite?
     *
     * @return True if it is, false otherwise.
     */
    public boolean isDhe() {
        return this.name().matches(NAME_PREFIX_REGEX + "DHE.*");
    }

    /**
     * Get the cipher suite for a given id.
     *
     * @param id ID of the desired cipher suite
     * @return Associated cipher suite
     */
    public static ECipherSuite getCipherSuite(final byte[] id)
		    throws UnknownCipherSuiteException {
        final int cipherSuite;

        if (id == null || id.length != LENGTH_ENCODED) {
            throw new IllegalArgumentException(
                    "ID must not be null and have a length of exactly "
                    + LENGTH_ENCODED + " bytes.");
        }
        cipherSuite = ((id[0] & 0xff) << Utility.BITS_IN_BYTE) | (id[1] & 0xff);

        if (!ID_MAP.containsKey(cipherSuite)) {
            throw new UnknownCipherSuiteException(cipherSuite);
        }

        return ID_MAP.get(cipherSuite);
    }
}
