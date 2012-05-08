package de.rub.nds.research.ssl.stack.tests.common;

import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.research.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ClientDHPublic;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.EncryptedPreMasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Builder for SSL handshake messages.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 04, 2012
 */
public class MessageBuilder {

    /**
     * Empty public constructor.
     */
    public MessageBuilder() {
    }

    /**
     * Builds a ClientHello message on the byte layer
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
     * @param protocolVersion Protocol version in this message
     * @return ClientHello message
     */
    public final ClientHello createClientHello(final EProtocolVersion protocolVersion) {
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
     * Create simple ClientKeyExchange message depending on the 
     * key exchange algorithm.
     * @param protocolVersion
     * @return
     */
    public final ClientKeyExchange createClientKeyExchange(final EProtocolVersion protocolVersion,
    		final SSLHandshakeWorkflow workflow) {
    	KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
    	EKeyExchangeAlgorithm exchangeAlgorithm = keyParams.getKeyExchangeAlgorithm();
    	PublicKey pk = keyParams.getPublicKey();
    	ClientKeyExchange cke = new ClientKeyExchange(protocolVersion, exchangeAlgorithm);
        if (exchangeAlgorithm == EKeyExchangeAlgorithm.RSA) {
            PreMasterSecret pms = new PreMasterSecret(protocolVersion);
            //create encoded PMS
            byte[] encodedPMS = pms.encode(false);
            //encrypted PreMasterSecret
            EncryptedPreMasterSecret encPMS = new EncryptedPreMasterSecret(
                    encodedPMS, pk);
            workflow.setPreMasterSecret(pms);
            cke.setExchangeKeys(encPMS);
        } else {
            ClientDHPublic clientDHPublic = new ClientDHPublic();
            byte[] generator = keyParams.getDHGenerator();
            byte[] primeModulus = keyParams.getDHPrime();
            byte[] privateValue = new byte[20];
            byte[] clientPublic = new byte[primeModulus.length];
            /*
             * generate a random private value
             */
            SecureRandom random = new SecureRandom();
            random.nextBytes(privateValue);

            BigInteger gen = new BigInteger(1, generator);
            BigInteger primeMod = new BigInteger(1, primeModulus);
            BigInteger priv = new BigInteger(1, privateValue);

            /*
             * compute clients DH public value g^x mod p
             */
            clientPublic = gen.modPow(priv, primeMod).toByteArray();

            byte[] tmp = new byte[primeModulus.length];

            if (clientPublic.length > primeModulus.length) {
                System.arraycopy(clientPublic, 1, tmp, 0, primeModulus.length);
                clientPublic = tmp;
            }
            clientDHPublic.setDhyc(clientPublic);
            cke.setExchangeKeys(clientDHPublic);
            PreMasterSecret pms = new PreMasterSecret(privateValue, keyParams.getDhPublic(),
                    primeModulus);
            workflow.setPreMasterSecret(pms);
        }
    	return cke;
    }

    /**
     * Create Finished message
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
}
