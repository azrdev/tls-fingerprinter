package de.rub.nds.ssl.stack.workflows.commons;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.*;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.ssl.stack.protocols.handshake.ApplicationRecord;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.*;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ClientECDHPublic;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECParameters;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.protocols.msgs.TLSPlaintext;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.GenericBlockCipher;
import de.rub.nds.ssl.stack.protocols.msgs.datatypes.GenericStreamCipher;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.log4j.Logger;

/**
 * Builder for SSL handshake messages.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Christopher Meyer - christopher.meyer@ruhr-uni-bochum.de
 *
 * @version 0.1 Apr 04, 2012
 */
public class MessageBuilder {

    /**
     * Log4j logger.
     */
    private static Logger logger = Logger.getRootLogger();

    /**
     * Empty public constructor.
     */
    public MessageBuilder() {
    }

    /**
     * Builds a ClientHello message on the byte layer
     *
     * @param protocolVersion SSL/TLS protocol version
     * @param random Random value
     * @param cipherSuites Cipher suites
     * @param compMethod Compression method
     * @return ClientHello message
     */
    public final ClientHello createClientHello(byte[] id,
            byte[] random, byte[] cipherSuites, byte[] compMethod) {
        EProtocolVersion protocolVersion = EProtocolVersion.getProtocolVersion(
                id);
        ClientHello clientHello = new ClientHello(protocolVersion);
        clientHello.setRandom(random);
        clientHello.setCompressionMethod(compMethod);
        clientHello.setCipherSuites(cipherSuites);
        return clientHello;
    }

    /**
     * Create simple ClientHello containing one cipher suite
     *
     * @param protocolVersion Protocol version in this message
     * @return ClientHello message
     */
    public final ClientHello createClientHello(
            final EProtocolVersion protocolVersion) {
        //create ClientHello message
        ClientHello clientHello = new ClientHello(protocolVersion);

        //set the cipher suites
        CipherSuites suites = new CipherSuites();
        suites.setSuites(new ECipherSuite[]{
            ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA});
        clientHello.setCipherSuites(suites);
        clientHello.encode(true);
        return clientHello;
    }

    /**
     * Create simple ClientKeyExchange message depending on the key exchange
     * algorithm.
     *
     * @param protocolVersion
     * @return
     */
    public final ClientKeyExchange createClientKeyExchange(
            final EProtocolVersion protocolVersion,
            final TLS10HandshakeWorkflow workflow) {
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        EKeyExchangeAlgorithm exchangeAlgorithm = keyParams.
                getKeyExchangeAlgorithm();
        PublicKey pk = keyParams.getPublicKey();
        ClientKeyExchange cke = new ClientKeyExchange(protocolVersion,
                exchangeAlgorithm);
        PreMasterSecret pms;
        SecureRandom random = new SecureRandom();
        byte[] privateValue;
        BigInteger priv;

        switch (exchangeAlgorithm) {
            case RSA:
                pms = new PreMasterSecret(protocolVersion);
                //create encoded PMS
                byte[] encodedPMS = pms.encode(false);
                //encrypted PreMasterSecret
                EncPreMasterSecret encPMS = new EncPreMasterSecret(
                        encodedPMS, pk);
                workflow.setPreMasterSecret(pms);
                cke.setExchangeKeys(encPMS);
                break;
            case DIFFIE_HELLMAN:
                ClientDHPublic clientDHPublic = new ClientDHPublic();
                byte[] generator = keyParams.getDHGenerator();
                byte[] primeModulus = keyParams.getDHPrime();
                byte[] clientPublic;

                BigInteger gen = new BigInteger(1, generator);
                BigInteger primeMod = new BigInteger(1, primeModulus);

                // generate a random private value
                privateValue = new byte[primeModulus.length];
                random.nextBytes(privateValue);
                priv = new BigInteger(1, privateValue);
                // TODO check that priv != 1
                // 2 <= priv <= q-2
                priv = priv.mod(primeMod.subtract(BigInteger.valueOf(2)));

                /*
                 * compute clients DH public value g^x mod p
                 */
                clientPublic = gen.modPow(priv, primeMod).toByteArray();

                byte[] tmp = new byte[primeModulus.length];

                if (clientPublic.length > primeModulus.length) {
                    System.arraycopy(clientPublic, 1, tmp, 0,
                            primeModulus.length);
                    clientPublic = tmp;
                }
                clientDHPublic.setDhyc(clientPublic);
                cke.setExchangeKeys(clientDHPublic);
                pms = new PreMasterSecret(privateValue, keyParams.
                        getDhPublic(), primeModulus);
                workflow.setPreMasterSecret(pms);
                break;
            case EC_DIFFIE_HELLMAN:
                ClientECDHPublic clientECDHPublic = new ClientECDHPublic();
                clientECDHPublic.setExplicitPublicValueEncoding(true);
                ECParameters ecParameters = keyParams.getECDHParameters();
//                BigInteger order = new BigInteger(1, ecParameters.getOrder());
//                ECPoint genPoint = ecParameters.getBase();
//                
//                // generate a random private value
//                privateValue = new byte[ecParameters.getPrimeP().length];
//                random.nextBytes(privateValue);
//                priv = new BigInteger(1, privateValue);
//                // 1 <= priv <= n-1
//                priv = priv.mod(order.subtract(BigInteger.ONE));
//                
// TODO         priv*genPoint
//                clientECDHPublic.setECDHYc(null);
                break;
        }

        return cke;
    }

    /**
     * Create Finished message
     *
     * @param protocolVersion Protocol version
     * @param endpoint Client/Server side
     * @param handshakeHash Hash of the handshake messages so far
     * @param masterSec Master secret
     * @return Finished message
     */
    public final Finished createFinished(final EProtocolVersion protocolVersion,
            EConnectionEnd endpoint, byte[] handshakeHash,
            MasterSecret masterSec) {
        Finished finished = new Finished(protocolVersion, endpoint);
        try {
            finished.createVerifyData(masterSec, handshakeHash);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        finished.encode(true);

        return finished;
    }
    /**
     * Create Application message
     *
     * @return Application message
     */
    public final ApplicationRecord createApplication(EProtocolVersion protocol, final byte[] message){
        return new ApplicationRecord(protocol, message);
    }

    /**
     * Encrypt a record frame depend on the cipher
     *
     * @param protocolVersion Protocol version
     * @param record Record frame
     * @return Encrypted record
     */
    public final TLSCiphertext encryptRecord(
            final EProtocolVersion protocolVersion,
            final ARecordFrame record,
            final EContentType contentType) {
        SecurityParameters param = SecurityParameters.getInstance();
        //create the key material
        KeyMaterial keyMat = new KeyMaterial();
        //encrypt message
        String cipherName = param.getBulkCipherAlgorithm().toString();
        String macName = param.getMacAlgorithm().toString();
        SecretKey macKey = new SecretKeySpec(keyMat.getClientMACSecret(),
                macName);
        SecretKey symmKey = new SecretKeySpec(keyMat.getClientKey(), cipherName);
        TLSCiphertext rec = new TLSCiphertext(protocolVersion,
                contentType);
        if (param.getCipherType() == ECipherType.BLOCK) {
            GenericBlockCipher blockCipher = new GenericBlockCipher(record);
            blockCipher.computePayloadMAC(macKey, macName);
            blockCipher.encryptData(symmKey, cipherName, keyMat.getClientIV());
            rec.setGenericCipher(blockCipher);
        } else if (param.getCipherType() == ECipherType.STREAM) {
            GenericStreamCipher streamCipher = new GenericStreamCipher(record);
            streamCipher.computePayloadMAC(macKey, macName);
            streamCipher.encryptData(symmKey, cipherName);
            rec.setGenericCipher(streamCipher);
        }

        return rec;
    }

    public final TLSPlaintext decryptRecord(
            final ARecordFrame record) {
        SecurityParameters param = SecurityParameters.getInstance();
        //create the key material
        KeyMaterial keyMat = new KeyMaterial();
        //decrypt message
        String cipherName = param.getBulkCipherAlgorithm().toString();
        String macName = param.getMacAlgorithm().toString();
        SecretKey macKey = new SecretKeySpec(keyMat.getServerMACSecret(),
                macName);
        SecretKey symmKey = new SecretKeySpec(keyMat.getServerKey(), cipherName);
        byte[] plainBytes;
        TLSPlaintext rec = null;
        if (param.getCipherType() == ECipherType.BLOCK) {
            GenericBlockCipher blockCipher =
                    new GenericBlockCipher(record.getPayload());
            plainBytes = blockCipher.decryptData(symmKey, cipherName,
                    keyMat.getServerIV());

            // check padding (padding = padding bytes + padding length)
            int paddingLength = plainBytes[plainBytes.length - 1];;
            for (int i = 0; i < paddingLength + 1; i++) {
                if (plainBytes[plainBytes.length - 1 - i] != paddingLength) {
                    // TODO Communicate padding error 
                    byte[] padding = new byte[paddingLength];
                    System.arraycopy(plainBytes,
                            plainBytes.length - 1 - paddingLength, padding, 0,
                            padding.length);
                    logger.info("Invalid padding detected: "
                            + Utility.bytesToHex(padding));
                }
            }

            // TODO add MAC check
//            blockCipher.computePayloadMAC(macKey, macName);

            // remove padding
            byte[] tmp = new byte[plainBytes.length - paddingLength - 1];
            System.arraycopy(plainBytes, 0, tmp, 0, tmp.length);
            plainBytes = tmp;

            // remove MAC
            int macLength = 0;
            switch (param.getMacAlgorithm()) {
                case MD5:
                    macLength = 16;
                    break;
                case SHA1:
                    macLength = 20;
                    break;
            }
            tmp = new byte[plainBytes.length - macLength];
            System.arraycopy(plainBytes, 0, tmp, 0, tmp.length);
            plainBytes = tmp;

            rec = new TLSPlaintext(plainBytes, false);
        } else if (param.getCipherType() == ECipherType.STREAM) {
            GenericStreamCipher streamCipher = new GenericStreamCipher(record);
            streamCipher.computePayloadMAC(macKey, macName);
            // TODO add stream cipher decryption
//            plainBytes = streamCipher.decryptData(symmKey, cipherName, 
//                    keyMat.getClientIV());
//            
//            rec = new TLSPlaintext(plainBytes, true);
        }

        return rec;
    }

    /**
     * Create master secret part.
     *
     * @param workflow Handshake workflow
     * @return Computed MasterSecret
     */
    public MasterSecret createMasterSecret(final TLS10HandshakeWorkflow workflow) {
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        PreMasterSecret pms = workflow.getPreMasterSecret();
        //set pre_master_secret
        byte[] pre_master_secret = new byte[46];
        switch (keyParams.getKeyExchangeAlgorithm()) {
            case RSA:
                pre_master_secret = pms.encode(false);
                break;
            case DIFFIE_HELLMAN:
                pre_master_secret = pms.getDHKey();
                break;
            case EC_DIFFIE_HELLMAN:
// TODO compute pre master secret correctly                
                
                break;
            default:
                break;
        }

        SecurityParameters param = SecurityParameters.getInstance();
        MasterSecret masterSec = null;
        try {
            masterSec = new MasterSecret(param.getClientRandom(), param.
                    getServerRandom(), pre_master_secret);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        param.setMasterSecret(masterSec);
        return masterSec;
    }
}
