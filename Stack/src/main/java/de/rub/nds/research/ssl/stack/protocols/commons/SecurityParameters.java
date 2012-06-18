package de.rub.nds.research.ssl.stack.protocols.commons;

import de.rub.nds.research.ssl.stack.protocols.handshake.
datatypes.CompressionMethod;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.MasterSecret;

/**
 * Security parameters as defined in Chapter 6.1 of RFC2246.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1 Mar 09, 2012
 */
public final class SecurityParameters {

    /**Instance of SecurityParameters.*/
    private static volatile SecurityParameters param;
    /**Endpoint of the connection.*/
    private EConnectionEnd entity;
    /**Cipher used for encryption/decryption.*/
    private EBulkCipherAlgorithm bulkCipher;
    /**Cipher type - block/stream.*/
    private ECipherType cipherType;
    /**Key size of the cipher.*/
    private int keySize;
    /**Length of the key material.*/
    private int keyMatLength;
    /**Flag which defines if cipher suite is exportable.*/
    private boolean isExportable;
    /**MAC algorithm.*/
    private EMACAlgorithm macAlg;
    /**Size of the hash value.*/
    private int hashSize;
    /**Compression method used in the handshake.*/
    private CompressionMethod compMethod;
    /**Master secret.*/
    private MasterSecret masterSecret;
    /**Random value length.*/
    private static final int RANDOM_LENGTH = 32;
    /**Client random of the ClientHello message.*/
    private byte[] clientRandom = new byte[RANDOM_LENGTH];
    /**Server random of the ServerHello message.*/
    private byte[] serverRandom = new byte[RANDOM_LENGTH];
    /**Mode of operation used for the block cipher.*/
    private EModeOfOperation modeOfOp;

    /**Empty constructor.*/
    private SecurityParameters() {
    }

    /**Singleton instance creation.
     * @return SecurityParameters instance
     */
    public static SecurityParameters getInstance() {
        if (param == null) {
            param = new SecurityParameters();
        }
        return param;
    }

    /**
     * Get the connection end - client/server - of the message.
     * @return Connection end
     */
    public synchronized EConnectionEnd getConnectionEnd() {
        return entity;
    }

    /**
     * Set the connection end - client/server - of the message.
     * @param connEnd Connection end
     */
    public synchronized void setConnectionEnd(final EConnectionEnd connEnd) {
        this.entity = EConnectionEnd.valueOf(connEnd.name());
    }

    /**
     * Get the bulk cipher defined in the chosen cipher suite.
     * @return Bulk cipher used for encryption / decryption
     */
    public synchronized EBulkCipherAlgorithm getBulkCipherAlgorithm() {
        return bulkCipher;
    }

    /**
     * Set the bulk cipher defined in the chosen cipher suite.
     * @param algorithm Bulk cipher used for encryption/decryption
     */
    public synchronized void setBulkCipherAlgorithm(final EBulkCipherAlgorithm algorithm) {
        this.bulkCipher = EBulkCipherAlgorithm.valueOf(algorithm.name());
    }

    /**
     * Get the cipher type of the block cipher.
     * @return Cipher type - block/stream
     */
    public synchronized ECipherType getCipherType() {
        return cipherType;
    }

    /**
     * Set the cipher type of the block cipher.
     * @param type Cipher type - block/stream
     */
    public synchronized void setCipherType(final ECipherType type) {
        this.cipherType = ECipherType.valueOf(type.name());
    }

    /**
     * Get the key size of the bulk cipher.
     * @return Key size
     */
    public synchronized int getKeySize() {
        return keySize;
    }

    /**
     * Set the key size of the bulk cipher.
     * @param size Key size
     */
    public synchronized void setKeySize(final int size) {
        this.keySize = size;
    }

    /**
     * Get the Key material length. The key material is
     * computed applying the PseudoRandomFunction.
     * @return Key material length
     */
    public synchronized int getKeyMaterialLength() {
        return keyMatLength;
    }

    /**
     * Set the Key material length. The key material is
     * computed applying the PseudoRandomFunction.
     * @param length Key material length
     */
    public synchronized void setKeyMaterialLength(final int length) {
        this.keyMatLength = length;
    }

    /**
     * Signalizes if an "EXPORT" cipher suite is used.
     * @return True if cipher suite is exportable
     */
    public synchronized boolean isExportable() {
        return isExportable;
    }

    /**
     * Set the exportable flag for a cipher suite.
     * @param export True if cipher suite is exportable
     */
    public synchronized void setExportable(final boolean export) {
        this.isExportable = export;
    }

    /**
     * Get MAC algorithm used for MAC computation in the handshake.
     * @return MAC algorithm
     */
    public synchronized EMACAlgorithm getMacAlgorithm() {
        return macAlg;
    }

    /**
     * Set MAC algorithm used for MAC computation in the handshake.
     * @param mac MAC algorithm
     */
    public synchronized void setMacAlgorithm(final EMACAlgorithm mac) {
        this.macAlg = EMACAlgorithm.valueOf(mac.name());
    }

    /**
     * Get the compression method of the handshake.
     * @return Compression method
     */
    public synchronized CompressionMethod getCompressionMethod() {
        return compMethod;
    }

    /**
     * Set the compression method of the handshake.
     * @param comp Compression method
     */
    public synchronized void setCompressionMethod(final CompressionMethod comp) {
        this.compMethod = new CompressionMethod(comp.encode(
                false));
    }

    /**
     * Get the hash value size.
     * @return Hash size
     */
    public synchronized int getHashSize() {
        return hashSize;
    }

    /**
     * Set the hash value size.
     * @param size Hash size
     */
    public synchronized void setHashSize(final int size) {
        this.hashSize = size;
    }

    /**
     * Get the master secret which is computed from the
     * pre_master_secret applying the PseudoRandomFunction.
     * @return Master secret
     */
    public synchronized MasterSecret getMasterSecret() {
        return masterSecret;
    }

    /**
     * Set the master secret which is computed from the
     * pre_master_secret applying the PseudoRandomFunction.
     * @param masterSec Master secret
     */
    public synchronized void setMasterSecret(final MasterSecret masterSec) {
        this.masterSecret = masterSec;
    }

    /**
     * Get the client random of the ClientHello message.
     * @return Client random value
     */
    public synchronized byte[] getClientRandom() {
        return clientRandom.clone();
    }

    /**
     * Set the client random of the ClientHello message.
     * @param clientRand Client random value
     */
    public synchronized void setClientRandom(final byte[] clientRand) {
        this.clientRandom = clientRand.clone();
    }

    /**
     * Get the server random of the ServerHello message.
     * @return Server random value
     */
    public synchronized byte[] getServerRandom() {
        return serverRandom.clone();
    }

    /**
     * Set the server random of the ServerHello message.
     * @param serverRand Client random value
     */
    public synchronized void setServerRandom(final byte[] serverRand) {
        this.serverRandom = serverRand.clone();
    }

    /**
     * Get the mode operation used for the block cipher.
     * @return Mode of operation
     */
    public synchronized EModeOfOperation getModeOfOperation() {
        return modeOfOp;
    }

    /**
     * Set the mode operation used for the block cipher.
     * @param mode Mode of operation
     */
    public synchronized void setModeOfOperation(final EModeOfOperation mode) {
        this.modeOfOp = EModeOfOperation.valueOf(mode.name());
    }
}
