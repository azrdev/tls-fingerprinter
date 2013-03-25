package de.rub.nds.tinytlssocket;

/**
 * Server launcher.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Mar 25, 2013
 */
public class Launcher {

    /**
     * TinyTLSServer launcher
     *
     * @param args key store path, password, protocol version, port
     */
    public static void main(String[] args) throws Exception {
        final TLSServer serverThread;
        if (args.length != 5) {
            System.out.println("Invalid number of arguments!\n"
                    + "Usage: java -jar TinyTLSServer.jar "
                    + " Key store path, Password, Protocol version, Port, "
                    + " Debug mode enabled");
        } else {
            int port = Integer.parseInt(args[3]);
            boolean debug = Boolean.getBoolean(args[4]);
            serverThread = new TLSServer(args[0], args[1], args[2], port, debug);
            serverThread.start();

            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    if (serverThread != null) {
                        serverThread.shutdown();
                    }
                }
            });
        }
    }
}
