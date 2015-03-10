Filters traffic (using pcap) for SSL/TLS connections, and fingerprints the other sides (server) implementation, reporting especially fingerprint *changes* which might indicate MITM attacks.

Call for parameter description:

    java -jar PassiveAnalyzer....jar --help

# TODO

- A session resumption whose clienthello has no SNI cannot be matched to the (previous) normal handshake. Such has been observed, even though it should not happen according to http://tools.ietf.org/html/rfc5246#section-7.4.1.4 .
- ssl fragmentation is only partially supported: when multiple handshake messages are put into one record layer frame. all cases of split messages are not implemented in the SSL Stack

