# TLS Fingerprinter

Filters traffic (using pcap) for SSL/TLS connections, and fingerprints the other
sides (i.e. server) implementation, reporting especially fingerprint *changes*
which might indicate MITM attacks.

For parameter description, call:

    java -jar PassiveAnalyzer.jar --help

## General workings

The application opens the specified *capture sources* (see `--help`) one after
another. It processes all traffic, looking for TLS handshakes. The found ones
are fingerprinted, and the resulting fingerprint(s) are then reported.

## GUI manual

On Windows, you can use `PassiveAnalyzer-GUI.cmd` to start the GUI and a live
capture, without having to use the command line.

### Fingerprint reports
- Enter or double-click on report to open detail window
- click on column heads to sort

### Stored Fingerprints
type ahead to search

### Statistics
- use right-click/popup menu to interact with charts: zooming, export as image, ...
- select chart areas with left mouse to zoom, left click + move left to unzoom
- resizing hooks between chart panels

### Log
- click on column heads to sort
- The full log will always be written to $PWD/log/



## TODO

- A session resumption whose clienthello has no SNI cannot be matched to the
  (previous) normal handshake. Such has been observed, even though it should
  not happen according to <http://tools.ietf.org/html/rfc5246#section-7.4.1.4>.
- ssl fragmentation is only partially supported: when multiple handshake
  messages are put into one record layer frame. all cases of split messages are
  not implemented in the SSL Stack

