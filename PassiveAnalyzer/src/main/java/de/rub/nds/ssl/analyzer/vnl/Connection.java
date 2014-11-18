package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapConnection;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.connection.pcap.ReassembledPacket;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprints;
import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.Packet.Direction;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.internet.Ip;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import org.apache.log4j.Logger;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class Connection {
    private static Logger logger = Logger.getLogger(Connection.class);

	private PcapTrace trace;
    private List<MessageContainer> frameList;

    private Fingerprint.Signature serverTcpSignature;
    private Fingerprint.Signature serverMtuSignature;
    private SessionIdentifier sessionIdentifier = new SessionIdentifier();
    private EKeyExchangeAlgorithm keyExchangeAlgorithm;

    public Connection(PcapConnection pcapConnection) {
		this.trace = pcapConnection.getTrace();
        //TODO: Direction.Request  if we serve TLS
		this.serverTcpSignature = pcapConnection.getSignature(Direction.Response, Fingerprints.Tcp);
		this.serverMtuSignature = pcapConnection.getSignature(Direction.Response, Fingerprints.Mtu);
		this.frameList = this.decodeTrace();
	}
	
	public boolean isCompleted() {
		return this.frameList != null;
	}

    public List<MessageContainer> getFrameList() {
        return frameList;
    }

    public ServerHello getServerHello() {
        for (MessageContainer mc : frameList) {
            ARecordFrame rf = mc.getCurrentRecord();
            if (rf instanceof ServerHello) {
                return (ServerHello) rf;
            }
        }
        throw new RuntimeException("Could not find a ServerHello");
    }
	
	public ClientHello getClientHello() {
        // should be the first message, but who knows about hello_request
        for (MessageContainer mc : frameList) {
            ARecordFrame rf = mc.getCurrentRecord();
            if (rf instanceof ClientHello) {
                return (ClientHello) rf;
            }
        }
        throw new RuntimeException("Could not find a ClientHello");
	}

    public Fingerprint.Signature getServerTcpSignature() {
        return serverTcpSignature;
    }

    public Fingerprint.Signature getServerMtuSignature() {
        return serverMtuSignature;
    }

	public void printReport() {
		if (frameList != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("Full connection report: begin trace\n");
			for (MessageContainer aRecordFrame : frameList) {
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

        // whether we have seen a ChangeCipherSpec message
        boolean clientCompleted = false;
		boolean serverCompleted = false;

        // index of the current TLSPlaintext record (different from frame, because of fragmentation
        int clientRecordIndex = 0;
        int serverRecordIndex = 0;
        List<Integer> segmentIndices = Arrays.asList(-1);
	
		// Now, iterate over all packets
		for (PcapPacket packet : trace) {
            final boolean request = packet.getDirection() == Direction.Request;

            // get tcp segment indices
            Integer lastSegmentIndex = Collections.max(segmentIndices);
            segmentIndices = new LinkedList<>();
            if(packet instanceof ReassembledPacket) {
                for (PcapPacket op : ((ReassembledPacket) packet).getFragmentSequence().getPackets()) {
                    segmentIndices.add(++lastSegmentIndex);
                }
            } else {
                segmentIndices = Arrays.asList(++lastSegmentIndex);
            }

            // ... and find TLS record layer frames
			for (Header header : packet.getHeaders(Headers.Tls)) {

                // we're not interested in any messages after we've seen ChangeCipherSpec
                if(request && clientCompleted)
                    continue;
                if(!request && serverCompleted)
                    continue;

                // Decode the raw bytes of (TLS)-header and -payload
                final List<ARecordFrame> frames = ACaptureConverter.decodeRecordFrames(
                        header.getHeaderAndPayload(),
                        keyExchangeAlgorithm);

                // Convert all Frames to MessageContainer and add them to the list
                for (ARecordFrame frame : frames) {
                    if (frame == null) {
                        logger.warn("failed to parse something: "
                                + packet + " " + packet.getHeaders());
                    }

                    final MessageContainer messageContainer =
                            new MessageContainer(frame, packet);

                    //TODO: we cannot distinguish between TLS record and frame, see ARecordFrame
                    // set index of TCP segment holding TLSPlaintext record
                    messageContainer.setRecordSourceSegments(segmentIndices);

                    // set index of TLSPlaintext record holding frame
                    messageContainer.addFragmentSourceRecord(
                            request? clientRecordIndex : serverRecordIndex);

                    frameList.add(messageContainer);

                    /*
                     * Does this complete the unencrypted part of the handshake?
                     */
                    if (frame instanceof ChangeCipherSpec) {
                        if (request) {
                            clientCompleted = true;
                        } else {
                            serverCompleted = true;
                        }
                        if (clientCompleted && serverCompleted) {
                            // Both have sent a ChangeCipherSpec message -> Finalize
                            return frameList;
                        }
                    }

                    if (frame instanceof ClientHello) {
                        /*
                         * a ClientHello will always be part of a connection, and
                         * contains all information we need for SessionIdentifier
                         */
                        sessionIdentifier =
                                extractSessionIdentifier((ClientHello) frame, packet);
                    }

                    /*
                     * ServerHello contains keyExchangeAlgorithm needed to decode
                     * KeyExchange messages
                     */
                    if (frame instanceof ServerHello) {
                        ServerHello sh = (ServerHello) frame;
                        keyExchangeAlgorithm =
                                sh.getCipherSuite().getKeyExchangeAlgorithm();
                    }
                }

                if(request)
                    ++clientRecordIndex;
                else
                    ++serverRecordIndex;
			}
		}
		return null;
	}

    private SessionIdentifier extractSessionIdentifier(ClientHello clientHello,
                                                       PcapPacket packet) {
        SessionIdentifier sid = new SessionIdentifier();
        sid.setServerHostName(clientHello.getHostName());
        sid.setClientHelloSignature(new ClientHelloFingerprint(clientHello));
        return sid;
    }
}
