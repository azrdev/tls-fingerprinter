package de.rub.nds.research.ssl.stack.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import de.rub.nds.research.ssl.stack.Utility;
import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;

/**
 * MAC computation of the record payloads
 * @author Eugen Weiss
 * 
 * Mar 22, 2012
 */
public class MACComputation extends ARecordFrame {
	
	private Mac mac=null;
	private byte [] seqNum = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	
	public MACComputation(SecretKey key, String macName){
		try {
			mac = Mac.getInstance("Hmac" + macName);
			mac.init(key);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Compute MAC as described in Chapter 6.2.3.1 in RFC 2246
	 * @param key
	 * @param macName
	 */
	public byte [] computeMAC(byte[] protocolVersion, byte contentType, byte [] payloadLength, byte [] payload){
		//concatenate sequence number, content type, protocol version, length and payload
		byte [] data = new byte [seqNum.length+1+protocolVersion.length+payloadLength.length+payload.length];
		int pointer = 0;
		
		//add sequence number
		System.arraycopy(seqNum, 0, data, pointer, seqNum.length);
		pointer += seqNum.length;
		System.out.println("Sequence-Number: " + Utility.byteToHex(seqNum));
		
		//add content type
		data[pointer]=contentType;
		pointer += 1;
		System.out.println("Content-Type: " + contentType);
		
		//add protocol version
		System.arraycopy(protocolVersion, 0, data, pointer, protocolVersion.length);
		pointer += protocolVersion.length;
		System.out.println("ProtocolVersion: " + Utility.byteToHex(protocolVersion));
		
		//add length bytes
		System.arraycopy(payloadLength, 0, data, pointer, payloadLength.length);
		pointer += payloadLength.length;
		System.out.println("PayloadLength: " + Utility.byteToHex(payloadLength));

		//add record payload
		System.arraycopy(payload, 0, data, pointer, payload.length);
		System.out.println("Payload: " + Utility.byteToHex(payload));
		System.out.println("Complete: " + Utility.byteToHex(data));

		//compute the MAC of the message
		return mac.doFinal(data);
	}
	
//	private void incrementSeqNum(){
//		byte num = 0x01;
//		for (int i=0; i<seqNum.length; i++){
//			
//		}
//	}

}
