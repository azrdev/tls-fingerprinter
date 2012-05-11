package de.rub.nds.research.ssl.stack.protocols.commons;

import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CompressionMethod;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.MasterSecret;

/**
 * Security parameters as defined in Chapter 6.1 of RFC2246
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1 Mar 09, 2012
 */
public class SecurityParameters {

    private static volatile SecurityParameters param;
    private EConnectionEnd entity;
    private EBulkCipherAlgorithm bulkCipher;
    private ECipherType cipherType;
    private int keySize;
    private int keyMatLength;
    private boolean isExportable;
    private EMACAlgorithm macAlg;
    private int hashSize;
    private CompressionMethod compMethod;
    private MasterSecret masterSecret;
    private byte[] clientRandom = new byte[32];
    private byte[] serverRandom = new byte[32];
    private EModeOfOperation modeOfOp;

    private SecurityParameters() {
    }

    public static SecurityParameters getInstance() {
        if (param == null) {
            param = new SecurityParameters();
        }
        return param;
    }

    public EConnectionEnd getConnectionEnd() {
        return entity;
    }

    public void setConnectionEnd(final EConnectionEnd entity) {
        this.entity = EConnectionEnd.valueOf(entity.name());
    }

    public EBulkCipherAlgorithm getBulkCipherAlgorithm() {
        return bulkCipher;
    }

    public void setBulkCipherAlgorithm(final EBulkCipherAlgorithm bulkCipher) {
        this.bulkCipher = EBulkCipherAlgorithm.valueOf(bulkCipher.name());
    }

    public ECipherType getCipherType() {
        return cipherType;
    }

    public void setCipherType(final ECipherType cipherType) {
        this.cipherType = ECipherType.valueOf(cipherType.name());
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(final int keySize) {
        this.keySize = keySize;
    }

    public int getKeyMaterialLength() {
        return keyMatLength;
    }

    public void setKeyMaterialLength(final int keyMatLength) {
        this.keyMatLength = keyMatLength;
    }

    public boolean isExportable() {
        return isExportable;
    }

    public void setExportable(final boolean isExportable) {
        this.isExportable = isExportable;
    }

    public EMACAlgorithm getMacAlgorithm() {
        return macAlg;
    }

    public void setMacAlgorithm(final EMACAlgorithm macAlg) {
        this.macAlg = EMACAlgorithm.valueOf(macAlg.name());
    }

    public CompressionMethod getCompressionMethod() {
        return compMethod;
    }

    public void setCompressionMethod(final CompressionMethod compMethod) {
        this.compMethod = new CompressionMethod(compMethod.encode(
                false));
    }

    public int getHashSize() {
        return hashSize;
    }

    public void setHashSize(final int hashSize) {
        this.hashSize = hashSize;
    }

    public MasterSecret getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(final MasterSecret masterSecret) {
        this.masterSecret = masterSecret;
    }

    public byte[] getClientRandom() {
        return clientRandom.clone();
    }

    public void setClientRandom(final byte[] clientRandom) {
        this.clientRandom = clientRandom.clone();
    }

    public byte[] getServerRandom() {
        return serverRandom.clone();
    }

    public void setServerRandom(final byte[] serverRandom) {
        this.serverRandom = serverRandom.clone();
    }

    public EModeOfOperation getModeOfOperation() {
        return modeOfOp;
    }

    public void setModeOfOperation(final EModeOfOperation modeOfOp) {
        this.modeOfOp = EModeOfOperation.valueOf(modeOfOp.name());
    }
}
