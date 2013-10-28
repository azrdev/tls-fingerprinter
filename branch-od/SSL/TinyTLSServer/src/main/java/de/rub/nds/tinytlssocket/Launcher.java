package de.rub.nds.tinytlssocket;

import java.net.InetAddress;

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
        //final TLSServer serverThread;
        final GoodTLSServer serverThread;
        //if (args.length != 5) {
        if(args.length != 0){
            System.out.println("Invalid number of arguments!\n"
                    + "Usage: java -jar TinyTLSServer.jar "
                    + " Key store path, Password, Protocol version, Port, "
                    + " Debug mode enabled");
        } else {
            /*
            int port = Integer.parseInt(args[3]);
            boolean debug = Boolean.parseBoolean(args[4]);
            if(debug) {
                System.out.println("Debuggin enabled!");
            }
            serverThread = new TLSServer(args[0], args[1], args[2], port, debug);
            */
            serverThread = new GoodTLSServer(InetAddress.getLocalHost(), 8000, "keystore.jks", "server");
            //serverThread.start();

            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    if (serverThread != null) {
                        //serverThread.shutdown();
                        serverThread.interrupt();
                    }
                }
            });
        }
    }
}
