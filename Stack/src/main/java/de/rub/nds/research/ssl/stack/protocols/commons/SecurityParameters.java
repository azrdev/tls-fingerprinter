package de.rub.nds.research.ssl.stack.protocols.commons;

import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CompressionMethod;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;

/**
 * Security parameters as defined in Chapter 6.1 of RFC2246
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1
 * Mar 09, 2012
 */
public class SecurityParameters {
	
	private static SecurityParameters param;
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
	private byte[] clientRandom = new byte [32];
	private byte[] serverRandom = new byte [32];
	private EModeOfOperation modeOfOp;
	
	private SecurityParameters(){
	}
	
	public static SecurityParameters getInstance(){
		if(param == null){
			param = new SecurityParameters();
		}
		return param;
	}
	
	public EConnectionEnd getConnectionEnd() {
		return entity;
	}
	
	public void setConnectionEnd(EConnectionEnd entity) {
		this.entity = entity;
	}
	
	public EBulkCipherAlgorithm getBulkCipherAlgorithm() {
		return bulkCipher;
	}
	
	public void setBulkCipherAlgorithm(EBulkCipherAlgorithm bulkCipher) {
		this.bulkCipher = bulkCipher;
	}
	
	public ECipherType getCipherType() {
		return cipherType;
	}
	
	public void setCipherType(ECipherType cipherType) {
		this.cipherType = cipherType;
	}
	
	public int getKeySize() {
		return keySize;
	}
	
	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}
	
	public int getKeyMaterialLength() {
		return keyMatLength;
	}
	
	public void setKeyMaterialLength(int keyMatLength) {
		this.keyMatLength = keyMatLength;
	}
	
	public boolean isExportable() {
		return isExportable;
	}
	
	public void setExportable(boolean isExportable) {
		this.isExportable = isExportable;
	}
	
	public EMACAlgorithm getMacAlgorithm() {
		return macAlg;
	}
	
	public void setMacAlgorithm(EMACAlgorithm macAlg) {
		this.macAlg = macAlg;
	}
	
	public CompressionMethod getCompressionMethod() {
		return compMethod;
	}
	
	public void setCompressionMethod(CompressionMethod compMethod) {
		this.compMethod = compMethod;
	}
	
	public int getHashSize() {
		return hashSize;
	}
	
	public void setHashSize(int hashSize) {
		this.hashSize = hashSize;
	}
	
	public MasterSecret getMasterSecret() {
		return masterSecret;
	}
	
	public void setMasterSecret(MasterSecret masterSecret) {
		this.masterSecret = masterSecret;
	}
	
	public byte [] getClientRandom() {
		return clientRandom;
	}
	
	public void setClientRandom(byte [] clientRandom) {
		this.clientRandom = clientRandom;
	}
	
	public byte [] getServerRandom() {
		return serverRandom;
	}
	
	public void setServerRandom(byte [] serverRandom) {
		this.serverRandom = serverRandom;
	}

	public EModeOfOperation getModeOfOperation() {
		return modeOfOp;
	}

	public void setModeOfOperation(EModeOfOperation modeOfOp) {
		this.modeOfOp = modeOfOp;
	}
	
	
	

}
