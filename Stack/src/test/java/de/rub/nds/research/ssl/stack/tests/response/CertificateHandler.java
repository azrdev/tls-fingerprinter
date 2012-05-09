package de.rub.nds.research.ssl.stack.tests.response;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import de.rub.nds.research.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.research.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.research.ssl.stack.protocols.handshake.Certificate;
import de.rub.nds.research.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.ASN1Certificate;

public class CertificateHandler implements IHandshakeStates {
	
	Certificate certificate;
	
	public CertificateHandler() {
	}

	@Override
	public void handleResponse(AHandshakeRecord handRecord) {
		certificate = (Certificate) handRecord;
		this.extractPublicKey();
	}
	
	/**Extracts the public key from the Certificate.
	 * @return Public key of the server certificate
	 */
	public void extractPublicKey() {
		PublicKey pk = null;
		KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
		for (ASN1Certificate certs : certificate.getCertificates().getCertificates()) {
			ByteArrayInputStream inCert = new ByteArrayInputStream(certs.getCertificate());
    		try {
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				java.security.cert.Certificate cert = cf.generateCertificate(inCert);
				pk = cert.getPublicKey();
				keyParams.setPublicKey(pk);
				return;
			} catch (CertificateException e) {
				e.printStackTrace();
			}
		}
	}

}
