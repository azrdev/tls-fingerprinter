package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.NetworkFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerHelloFingerprint;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.ServerNameList;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.Packet.Direction;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.application.TlsHeader;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip4Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;

import java.util.LinkedList;
import java.util.List;

public class Connection {
	private PcapTrace trace;
	private List<MessageContainer> fl;
	private List<Fingerprint.Signature> fingerprints;
	private NetworkFingerprint networkFingerprint;
    private SessionIdentifier sessionIdentifier = new SessionIdentifier();
    private EKeyExchangeAlgorithm keyExchangeAlgorithm;

    public Connection(PcapConnection pcapConnection) {
		this.trace = pcapConnection.getTrace();
		this.fingerprints = pcapConnection.getSignatures(Direction.Response);
		this.fl = this.decodeTrace();
		this.networkFingerprint = new NetworkFingerprint(this.fingerprints);
//		if ((this.fingerprints.size() != 2) || (this.fingerprints.get(0) == null)) {
//			System.err.println("Sorry, incorrect fingerprints!");
//		}
		
	}
	
	public boolean isCompleted() {
		return this.fl != null;
	}

    public ServerHello getServerHello() {
        for (MessageContainer mc : fl) {
            ARecordFrame rf = mc.getCurrentRecord();
            if (rf instanceof ServerHello) {
                return (ServerHello) rf;
            }
        }
        // No Server Hello?
        throw new RuntimeException("Could not find a ServerHello");
    }
	
	public ClientHello getClientHello() {
		// the first message is always the ClientHello
		MessageContainer clientHelloMC = fl.get(0);
		return (ClientHello) clientHelloMC.getCurrentRecord();
	}

  	public String getServerHostName() {
        ClientHello ch = getClientHello();
        if(ch == null)
            return null;

        return ch.getHostName();
  	}

	public NetworkFingerprint getNetworkFingerprint() {
		return this.networkFingerprint;
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
        //TODO: why not merge MessageContainer and ARecordFrame ?
		List<MessageContainer> frameList = new LinkedList<>();

        boolean clientCompleted = false;
		boolean serverCompleted = false;
	
		// Now, iterate over all packets and find TLS record layer frames
		for (PcapPacket packet : trace) {
			/*
			 * System.out.println(packet + " " + packet.getHeaders());
			 * System.out.println("direction " + packet.getDirection());
			 */
			for (Header header : packet.getHeaders()) {
				if(header instanceof  TlsHeader) {
				//XXX: if (header.getId() == TlsHeader.Id) {
					if ((packet.getDirection() == Direction.Request && !clientCompleted)
							|| (packet.getDirection() == Direction.Response && !serverCompleted)) {
						// Get the raw bytes of the frame, including the header
						byte[] content = header.getHeaderAndPayload();
	
						// Decode these bytes
						ARecordFrame[] frames = ACaptureConverter
								.decodeRecordFrames(content,
                                        keyExchangeAlgorithm);
	
						// Convert all Frames to MessageContainer and add them to the list
                        for (ARecordFrame frame : frames) {
                            if (frame == null) {
                                // Something went wrong
                                System.out.println("failed to parse something: "
                                        + packet + " "
                                        + packet.getHeaders());
                            }
                            frameList.add(new MessageContainer(frame, packet));
                            /*
							 * Does this complete the unencrypted part of the handshake?
							 */
                            if (frame instanceof ChangeCipherSpec) {
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
                            if (frame instanceof ClientHello) {
                                /*
                                 * a ClientHello will always be part of a connection, and
                                 * contains all information we need for SessionIdentifier
                                 */
                                Ip ipHeader = packet.getHeader(Headers.Ip4);
                                if (ipHeader == null)
                                    ipHeader = packet.getHeader(Headers.Ip6);
                                if (ipHeader == null)
                                    sessionIdentifier.setServerIPAddress(null);
                                else
                                    sessionIdentifier.setServerIPAddress(ipHeader.getDestinationAddress());

                                TcpHeader tcpHeader = packet.getHeader(Headers.Tcp);
                                //sessionIdentifier.setClientTcpPort(tcpHeader.getSourcePort());
                                sessionIdentifier.setServerTcpPort(tcpHeader.getDestinationPort());

                                ClientHello ch = (ClientHello) frame;
                                sessionIdentifier.setServerHostName(ch.getHostName());
                            }
                            if (frame instanceof ServerHello) {
								/*
								 * We need to set the key exchange algorithm here.
								 */
                                ServerHello sh = (ServerHello) frame;
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

    public SessionIdentifier getSessionIdentifier() {
        return sessionIdentifier;
    }
}
