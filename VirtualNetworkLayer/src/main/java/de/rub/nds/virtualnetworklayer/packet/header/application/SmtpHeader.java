package de.rub.nds.virtualnetworklayer.packet.header.application;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.header.EncodedHeader;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.nio.charset.Charset;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Simple Mail Transfer Protocol
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Application)
public class SmtpHeader extends EncodedHeader {
    public final static int Id = Headers.Smtp.getId();
    public final static Set<String> Commands;

    private final static Pattern Delimiter = Pattern.compile("\r\n");

    public static class Command {
        private int statusCode;
        private String action;
        private Packet.Direction direction;

        public Command(String line) {
            direction = readDirection(line);
        }

        private Packet.Direction readDirection(String line) {
            statusCode = readStatusCode(line);

            if (statusCode >= 100 && statusCode < 600) {
                return Packet.Direction.Response;
            }

            for (String command : Commands) {
                if (line.length() >= command.length() && line.substring(0, command.length()).equals(command)) {
                    action = line.substring(0, command.length());

                    return Packet.Direction.Request;
                }
            }

            return null;
        }

        public int readStatusCode(String line) {
            if (line.length() < 3) {
                return 0;
            }

            try {
                return Integer.parseInt(line.substring(0, 3));
            } catch (NumberFormatException e) {
                return 0;
            }
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getAction() {
            return action;
        }

        public Packet.Direction getDirection() {
            return direction;
        }

        @Override
        public String toString() {
            if (getDirection() == Packet.Direction.Response) {
                return String.valueOf(getStatusCode());
            } else {
                return action;
            }
        }
    }

    static {
        Commands = new HashSet<String>();
        Commands.add("HELO");
        Commands.add("EHLO");
        Commands.add("MAIL");
        Commands.add("RCPT");
        Commands.add("DATA");
        Commands.add("RSET");
        Commands.add("SEND");
        Commands.add("SOML");
        Commands.add("SAML");
        Commands.add("VRFY");
        Commands.add("EXPN");
        Commands.add("HELP");
        Commands.add("NOOP");
        Commands.add("QUIT");
        Commands.add("TURN");
        Commands.add("AUTH");
        Commands.add("STARTTLS");
    }

    private boolean bindToDefaultPorts;

    public SmtpHeader(boolean bindToDefaultPorts) {
        this.bindToDefaultPorts = bindToDefaultPorts;
    }

    public SmtpHeader() {
        this(true);
    }

    @Override
    public int getLength() {
        Matcher matcher = getMatcher(Delimiter);
        if (matcher.find()) {
            return matcher.end();
        } else {
            return 0;
        }
    }

    public LinkedList<Command> getCommands() {
        LinkedList<Command> commands = new LinkedList<Command>();

        Matcher matcher = getMatcher(Delimiter);
        int start = 0;

        while (matcher.find()) {
            int length = matcher.start() - start;
            commands.add(new Command(getString(start, length)));

            start = matcher.end();
        }

        return commands;
    }

    @Override
    protected Charset getCharset() {
        return Charset.forName("US-ASCII");
    }

    @Override
    public int getId() {
        return Id;
    }


    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof TcpHeader) {
            TcpHeader header = (TcpHeader) previousHeaders.getLast();


            if (bindToDefaultPorts && !((header.getDestinationPort() == 587 || header.getDestinationPort() == 25) ||
                    (header.getSourcePort() == 587 || header.getSourcePort() == 25))) {
                return false;
            }

            Command firstCommand = new Command(getString(0, getLength()));
            return firstCommand.getDirection() != null;
        }

        return false;
    }
}
