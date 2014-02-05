package de.rub.nds.ssl.stack.workflows.commons;

import de.rub.nds.ssl.stack.protocols.commons.EBulkCipherAlgorithm;
import de.rub.nds.ssl.stack.protocols.commons.PseudoRandomFunction;
import de.rub.nds.ssl.stack.protocols.commons.SecurityParameters;
import org.apache.log4j.Logger;
import java.security.InvalidKeyException;

/**
 * Creation of the key material for message security.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Oliver Domke - oliver.domke@ruhr-uni-bochum.de
 * @version 0.2
 * 
 * Feb 05, 2014
 */
public class KeyMaterial {
    
    private static Logger logger = Logger.getRootLogger();

    /**
     * Client-side MAC secret.
     */
    private byte[] clientMACSecret = null;
    /**
     * Server-side MAC secret.
     */
    private byte[] serverMACSecret = null;
    /**
     * Symmetric encryption key of the client.
     */
    private byte[] clientKey = null;
    /**
     * Symmetric encryption key of the server.
     */
    private byte[] serverKey = null;
    /**
     * Initialization vector of the client.
     */
    private byte[] clientIV = null;
    /**
     * Initialization vector of the server.
     */
    private byte[] serverIV = null;
    /**
     * AES Initialization vectpr length.
     */
    private static final int IV_LENGTH_AES = 16;
    /**
     * Initialization vector standard length.
     */
    private static final int IV_LENGTH = 8;

    /**
     * Public constructor to create the key material.
     *
     * @param param Security parameters of the SSL session
     */
    public KeyMaterial() {
        SecurityParameters param = SecurityParameters.getInstance();
        clientMACSecret = new byte[param.getHashSize()];
        serverMACSecret = new byte[param.getHashSize()];
        clientKey = new byte[param.getKeySize()];
        serverKey = new byte[param.getKeySize()];
        if (param.getBulkCipherAlgorithm() == EBulkCipherAlgorithm.AES) {
            clientIV = new byte[IV_LENGTH_AES];
            serverIV = new byte[IV_LENGTH_AES];
        } else {
            clientIV = new byte[IV_LENGTH];
            serverIV = new byte[IV_LENGTH];
        }
        try {
            createKeyMaterial();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /**
     * Computation of the key material.
     *
     * @param param Security parameters of the SSL session
     * @throws InvalidKeyException
     */
    public void createKeyMaterial() throws InvalidKeyException {
        SecurityParameters param = SecurityParameters.getInstance();
        byte[] clientRandom = param.getClientRandom();
        byte[] serverRandom = param.getServerRandom();
        byte[] keyBlock = new byte[param.getKeyMaterialLength()];
        int keySize = param.getKeySize();
        int hashSize = param.getHashSize();
        PseudoRandomFunction prf =
                new PseudoRandomFunction(keyBlock.length);
        //create the seed for the pseudo random function
        byte[] seed =
                new byte[param.getServerRandom().length + param.getClientRandom().length];
        int pointer = 0;
        System.arraycopy(serverRandom, 0, seed, pointer, serverRandom.length);
        pointer += serverRandom.length;
        System.arraycopy(clientRandom, 0, seed, pointer, clientRandom.length);

        //generate the key block using the pseudo random function
        keyBlock = prf.generatePseudoRandomValue(param.getMasterSecret().
                getMasterSecret(), "key expansion", seed);

        //assign the key block parts to the appropriate parameters
        pointer = 0;
        System.arraycopy(keyBlock, pointer, clientMACSecret, 0, hashSize);
        pointer += hashSize;
        System.arraycopy(keyBlock, pointer, serverMACSecret, 0, hashSize);
        pointer += hashSize;
        System.arraycopy(keyBlock, pointer, clientKey, 0, keySize);
        pointer += keySize;
        System.arraycopy(keyBlock, pointer, serverKey, 0, keySize);
        pointer += keySize;
        System.arraycopy(keyBlock, pointer, clientIV, 0, clientIV.length);
        pointer += clientIV.length;
        System.arraycopy(keyBlock, pointer, serverIV, 0, serverIV.length);
    }

    /**
     * Get the MAC secret of the client.
     *
     * @return MAC secret bytes
     */
    public final byte[] getClientMACSecret() {
        return clientMACSecret;
    }

    /**
     * Get the MAC secret of the server.
     *
     * @return MAC secret bytes
     */
    public final byte[] getServerMACSecret() {
        return serverMACSecret;
    }

    /**
     * Get symmetric encryption key of the client.
     *
     * @return Encryption key bytes
     */
    public final byte[] getClientKey() {
        return clientKey;
    }

    /**
     * Get symmetric encryption key of the server.
     *
     * @return Encryption key bytes
     */
    public final byte[] getServerKey() {
        return serverKey;
    }

    /**
     * Get initialization vector of the client.
     *
     * @return Initialization vector bytes
     */
    public final byte[] getClientIV() {
        return clientIV;
    }

    /**
     * Get initialization vector of the server.
     *
     * @return Initialization vector bytes
     */
    public final byte[] getServerIV() {
        return serverIV;
    }
}
