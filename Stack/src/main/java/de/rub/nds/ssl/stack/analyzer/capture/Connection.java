package de.rub.nds.ssl.stack.analyzer.capture;

import java.util.ArrayList;
import java.util.List;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.Extension;
import de.rub.nds.ssl.stack.protocols.handshake.ExtensionList;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.ServerNameExtension;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.p0f.Label;
import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.Packet.Direction;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;

public class Connection {
	private PcapTrace trace;
	private List<MessageContainer> fl;
	private List<Label> labels;
	
	public Connection(PcapTrace trace, List<Label> labels) {
		this.trace = trace;
		this.labels = labels;
		this.fl = this.decodeTrace();
	}
	
	public boolean isCompleted() {
		return this.fl != null;
	}

	public ServerHelloFingerprint getServerHelloFingerprint() {
		for (MessageContainer mc : fl) {
			ARecordFrame rf = mc.getCurrentRecord();
			if (rf instanceof ServerHello) {
				ServerHello sh = (ServerHello) rf;
				return new ServerHelloFingerprint(sh);
			}
		}
		// No Server Hello?
		throw new RuntimeException("Could not find a ServerHello");
	}
	
	public ClientHelloFingerprint getClientHelloFingerprint() {
		MessageContainer clientHelloMC = fl.get(0);
		ClientHello ch = (ClientHello) clientHelloMC.getCurrentRecord();
		return new ClientHelloFingerprint(ch);
	}
	
	public String getServerHostName() {
		MessageContainer clientHelloMC = fl.get(0);
		ClientHello ch = (ClientHello) clientHelloMC.getCurrentRecord();
		ExtensionList el = ch.getExtensionList();
		List<Extension> extensions = el.getExtensions();
		for (Extension ex : extensions) {
			if (ex instanceof ServerNameExtension) {
				ServerNameExtension sne = (ServerNameExtension)ex;
				return sne.getServerNames().get(0);
			}
		}
		return null;
	}
	
	public List<Label> getLabels() {
		return labels;
	}
	
	public NetworkFingerprint getNetworkFingerprint() {
		return new NetworkFingerprint(this.getLabels().get(1), this.getServerTTL());
	}
	
	public int getServerTTL() {
		for (PcapPacket packet : trace) {
			if (packet.getDirection() == Direction.Response) {
				Ip4Header h = packet.getHeader(Headers.Ip4.getId());
				return h.getTimeToLive();
			}
			
		}
		throw new RuntimeException("Header not found");
	}
	
	public void printReport() {
		if (fl != null) {
			System.out.println("###########################################################################");
			System.out.println("Full report");
			for (MessageContainer aRecordFrame : fl) {
				System.out.println(aRecordFrame.getCurrentRecord());
			}
			System.out.println("end of trace");
			System.out.println("###########################################################################");
			
		}
	}

	private List<MessageContainer> decodeTrace() {
		List<MessageContainer> frameList = new ArrayList<MessageContainer>();
		EKeyExchangeAlgorithm keyExchangeAlgorithm = null;
	
		boolean clientCompleted = false;
		boolean serverCompleted = false;
	
		// Now, iterate over all packets and find TLS record layer frames
		for (PcapPacket packet : trace) {
			/*
			 * System.out.println(packet + " " + packet.getHeaders());
			 * System.out.println("direction " + packet.getDirection());
			 */
			for (Header header : packet.getHeaders()) {
				if (header instanceof TlsHeader) {
					if ((packet.getDirection() == Direction.Request && !clientCompleted)
							|| (packet.getDirection() == Direction.Response && !serverCompleted)) {
						// Get the raw bytes of the frame, including the header
						byte[] content = header.getHeaderAndPayload();
	
						// Decode these bytes
						ARecordFrame[] frames = ACaptureConverter
								.decodeRecordFrames(content,
										keyExchangeAlgorithm);
	
						// Convert all Frames to MessageContainer and add them
						// to the list
						for (int i = 0; i < frames.length; i++) {
							if (frames[i] == null) {
								// Something went wrong
								System.out
										.println("failed to parse something: "
												+ packet + " "
												+ packet.getHeaders());
							}
							frameList.add(new MessageContainer(frames[i],
									packet));
							/*
							 * Does this complete the unencrypted part of the handshake?
							 */
							if (frames[i] instanceof ChangeCipherSpec) {
								if (packet.getDirection() == Direction.Request) {
									clientCompleted = true;
								} else {
									serverCompleted = true;
								}
								if (clientCompleted && serverCompleted) {
									// Both have send a ChangeCipherSpec message
									return frameList;
								}
							}
							if (frames[i] instanceof ServerHello) {
								/*
								 * We need to set the key exchange algorithm here.
								 */
								ServerHello sh = (ServerHello) frames[i];
								keyExchangeAlgorithm = sh.getCipherSuite()
										.getKeyExchangeAlgorithm();
							}
						}
	
					}
				}
			}
		}
		return null;
	}

}
