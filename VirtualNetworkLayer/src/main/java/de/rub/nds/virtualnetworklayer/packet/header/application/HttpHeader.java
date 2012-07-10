package de.rub.nds.virtualnetworklayer.packet.header.application;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.header.EncodedHeader;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.nio.charset.Charset;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Hypertext Transfer Protocol
 * <p/>
 * For binding to default port 80 only, use {@code new HttpHeader(true)}.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Application)
public class HttpHeader extends EncodedHeader {
    private final static Logger logger = Logger.getLogger(HttpHeader.class.getName());
    private final static Pattern Delimiter = Pattern.compile("\r\n\r\n");

    public final static int Id = Headers.Http.getId();
    public final static Set<String> Requests;

    static {
        Requests = new HashSet<String>();
        Requests.add("GET");
        Requests.add("HEAD");
        Requests.add("POST");
        Requests.add("PUT");
        Requests.add("DELETE");
        Requests.add("TRACE");
        Requests.add("OPTIONS");
        Requests.add("CONNECT");
    }

    public static enum Status {
        Information(1),
        Success(2),
        Redirection(3),
        ClientError(4),
        ServerError(5);

        private String startsWith;

        private Status(int startsWith) {
            this.startsWith = String.valueOf(startsWith);
        }

        public static Status valueOf(int code) {
            for (Status status : values()) {
                if (String.valueOf(code).startsWith(status.startsWith)) {
                    return status;
                }
            }

            return null;
        }
    }

    private boolean bindToDefaultPorts;
    private int length = -1;
    private Map<String, String> headers;


    public HttpHeader(boolean bindToDefaultPorts) {
        this.bindToDefaultPorts = bindToDefaultPorts;
    }

    public HttpHeader() {
        this(true);
    }

    public String getVersion() {
        return getString(5, 3);
    }

    public Status getStatus() {
        return Status.valueOf(getStatusCode());
    }

    public int getStatusCode() {
        return Integer.parseInt(getString(9, 3));
    }

    public Map<String, String> getHeaders() {
        if (headers == null) {
            headers = new HashMap<String, String>();

            for (StringTokenizer tokenizer = new StringTokenizer(getString(0, getLength()), "\r\n"); tokenizer.hasMoreElements(); ) {
                String[] parts = tokenizer.nextToken().split(": ");
                if (parts.length == 2) {
                    headers.put(parts[0].trim(), parts[1].trim());
                }
            }
        }

        return headers;
    }

    @Override
    public int getLength() {
        if (length == -1) {
            Matcher matcher = getMatcher(Delimiter);
            if (matcher.find()) {
                length = matcher.end();
            } else {
                length = 0;
            }
        }

        return length;
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public int getPayloadLength() {
        Map<String, String> headers = getHeaders();

        if (headers.containsKey("Content-Length")) {
            return Integer.parseInt(headers.get("Content-Length"));
        }

        if (headers.containsKey("Transfer-Encoding")) {
            logger.warning("not implemented " + headers.get("Transfer-Encoding"));
        }

        if (getDirection() == Packet.Direction.Response) {
            return Integer.MAX_VALUE;
        } else {
            return 0;
        }
    }

    public Packet.Direction getDirection() {
        if (getString(0, 4).equals("HTTP")) {
            return Packet.Direction.Response;
        }

        for (String request : Requests) {
            if (getString(0, request.length()).equals(request)) {
                return Packet.Direction.Request;
            }
        }

        return null;
    }

    @Override
    protected Charset getCharset() {
        return Charset.forName("ISO-8859-1");
    }

    @Override
    public Header clone() {
        HttpHeader header = (HttpHeader) super.clone();
        header.headers = null;
        header.length = -1;

        return header;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof TcpHeader) {
            TcpHeader header = (TcpHeader) previousHeaders.getLast();

            if (bindToDefaultPorts && !(header.getDestinationPort() == 80 || header.getSourcePort() == 80)) {
                return false;
            }

            return getDirection() != null;
        }

        return false;
    }
}

