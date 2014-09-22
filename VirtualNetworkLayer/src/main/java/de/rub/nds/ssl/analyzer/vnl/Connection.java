package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprints;
import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.Packet.Direction;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import org.apache.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public class Connection {

    private Logger logger = Logger.getLogger(getClass());

	private PcapTrace trace;
	private List<MessageContainer> fl;

    private Fingerprint.Signature serverTcpSignature;
    private Fingerprint.Signature serverMtuSignature;
    private SessionIdentifier sessionIdentifier = new SessionIdentifier();
    private EKeyExchangeAlgorithm keyExchangeAlgorithm;

    public Connection(PcapConnection pcapConnection) {
		this.trace = pcapConnection.getTrace();
        //TODO: Direction.Request  if we serve TLS
		this.serverTcpSignature = pcapConnection.getSignature(Direction.Response, Fingerprints.Tcp);
		this.serverMtuSignature = pcapConnection.getSignature(Direction.Response, Fingerprints.Mtu);
		this.fl = this.decodeTrace();
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

    public Fingerprint.Signature getServerTcpSignature() {
        return serverTcpSignature;
    }

    public Fingerprint.Signature getServerMtuSignature() {
        return serverMtuSignature;
    }

	public void printReport() {
		if (fl != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("Full connection report: begin trace\n");
			for (MessageContainer aRecordFrame : fl) {
				sb.append(aRecordFrame.getCurrentRecord()).append("\n");
			}
			sb.append("end of trace");
            logger.info(sb.toString());
		}
	}

    public SessionIdentifier getSessionIdentifier() {
        return sessionIdentifier;
    }

	private List<MessageContainer> decodeTrace() {
		List<MessageContainer> frameList = new LinkedList<>();

        boolean clientCompleted = false;
		boolean serverCompleted = false;
	
		// Now, iterate over all packets and find TLS record layer frames
		for (PcapPacket packet : trace) {
			/*
			 * logger.debug(packet + " " + packet.getHeaders());
			 * logger.debug("direction " + packet.getDirection());
			 */
			for (Header header : packet.getHeaders(Headers.Tls)) {
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
                            logger.warn("failed to parse something: "
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
		return null;
	}
}
