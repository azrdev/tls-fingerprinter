package de.rub.nds.research.ssl.stack.tests.common;

import java.security.InvalidKeyException;

import de.rub.nds.research.ssl.stack.protocols.commons.EConnectionEnd;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.Finished;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.MasterSecret;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.RandomValue;

/**Builder for SSL handshake messages.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Apr 04, 2012
 */
public class MessageBuilder {

	/**Empty public constructor.*/
	public MessageBuilder() {
	}

	/**Builds a ClientHello message.
	 * @param protocolVersion SSL/TLS protocol version
	 * @param random Random value
	 * @param cipherSuites Cipher suites
	 * @param compMethod Compression method
	 * @return ClientHello message
	 */
	public final ClientHello createClientHello(byte [] id, 
			byte [] random, byte [] cipherSuites, byte [] compMethod) {
		EProtocolVersion protocolVersion = EProtocolVersion.getProtocolVersion(id);
		ClientHello clientHello = new ClientHello(protocolVersion);
		clientHello.setRandom(random);
    	clientHello.setCompressionMethod(compMethod);
		clientHello.setCipherSuites(cipherSuites);
		return clientHello;
	}
	
	public final Finished createFinished(final EProtocolVersion protocolVersion, EConnectionEnd endpoint, byte [] handshakeHash, MasterSecret masterSec){
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
