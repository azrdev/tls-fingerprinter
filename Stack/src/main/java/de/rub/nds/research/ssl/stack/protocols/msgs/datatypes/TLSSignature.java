package de.rub.nds.research.ssl.stack.protocols.msgs.datatypes;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ESignatureAlgorithm;

public class TLSSignature {
	
	public ESignatureAlgorithm sigAlgorithm;
	private Signature signature;
	
	public TLSSignature(ESignatureAlgorithm sigAlgorithm) {
		this.sigAlgorithm=sigAlgorithm;
		try {
			signature = Signature.getInstance(sigAlgorithm.name());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
	}
	
	public boolean checkSignature(byte [] signature) {
		KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
		try {
			this.signature.initVerify(keyParams.getPublicKey());
			this.signature.verify(signature);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

}
