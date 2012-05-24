package de.rub.nds.research.ssl.stack.tests.analyzer.common;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.research.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.research.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.research.ssl.stack.tests.common.SSLHandshakeWorkflow.EStates;

public class AnalyzeUtils {

	public AnalyzeUtils() {
	}
	
	public byte [] integerToByteArray(int number) {
		byte [] array = null;
		int count = 0;
		int tmp = number;
		if (number == 0) {
			return new byte[]{0x00};
		}
		else {
			while (tmp > 0) {
				tmp /= 256; 
				count++;
			}
			array = new byte [count];
			for (int i = count-1; i >= 0; i--) {
				array[i] = (byte) (number & 0xff);
				number = number >> 8;
			}
			return array;
		}
	}
	
	

}
