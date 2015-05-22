# hacking TLS Fingerprinter
If you have any questions, please contact me at <azrdev@qrdn.de>.
Read my thesis "Non-certificate-based TLS Fingerprinting and MITM detection" which describes the fingerprinting application.

The first thing to do when extending the fingerprinter probably is to re-think the matching of fingerprints: If the new requirements can be implemented with the current `equals()` based method, or need to use a true distance measure, and how it should be defined.

# project structure
TLS Fingerprinter == project PassiveAnalyzer

## VirtualNetworkLayer (VNL)
`package de.rub.nds.virtualnetworklayer`
* libpcap interface via bridj in class `de.rub.nds.virtualnetworklayer.pcap.Pcap`
* implements `Headers` for protocols with lazy parsing & detection (method `isBound()`), e.g. ethernet, TCP/IP, TLS record, HTTP, DNS, ..., in `package de.rub.nds.virtualnetworklayer.packet.header`
* A subclass of `de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler` passed to `Pcap.loop()` is being called back upon each new connection

## (SSL) Stack
`package de.rub.ssl.stack`
* TLS implementation: mostly parsing (PassiveAnalyzer doesn't use handshake states, message flows, etc.)
* TLS subprotocols (`package de.rub.ssl.stack.protocols`): handshake, alert
* handshake messages, hello extensions in `package de.rub.ssl.stack.protocols.handshake`

## PassiveAnalyzer structure
`package de.rub.nds.ssl.analyzer.vnl`

* `SslReportingConnectionHandler`
  * observes pcap (vnl binding in `PassiveSslReporter` by calling `Pcap.loop(SslReportingConnectionHandler)`)
  * constructs `Connection` instances upon received connections
  * extracts/creates fingerprint(s) (instances of `TLSFingerprint`)
  * pushes fingerprints to `FingerprintListener`
* `Connection.decodeTrace()`
  * receives all `PcapConnections` (i.e. TCP, with vnl filter for TLS header)
  * extracts & parses TLS records (`class de.rub.nds.ssl.stack.protocols.ARecordFrame` and subclasses)
  * searches for Handshake completion (one `ChangeCipherSpec` in each direction)
* `FingerprintListener`
  * stores all known fingerprints, reads them from "savefile" (writing is done by `SaveFileFingerprintReporter`)
  * classifies incoming fps as new/update/changed/artificial ("artifical" currently only used by `ResumptionFingerprintGuesser`)
  * reports fps to all registered `FingerprintReporter`s
* `interface FingerprintReporter`: react upon fingerprint reports
  * `SaveFileFingerprintReporter`
  * `ResumptionFingerprintGuesser`
  * `SslReportingConnectionHandler` has an (anonymous inner) subclass to write pcaps of reported connections, see method `writeCapture()`
  * `LoggingFingerprintReporter` writes to [log4j](https://logging.apache.org/log4j/1.2/) Logger, can be configured in file `resources/log4j.properties`
  * `FingerprintStatistics` counts reports & "diffs to previous" fingerprints, for statistical analysis
  * `package de.rub.nds.ssl.analyzer.vnl.gui` has reporters for displaying the reports & the fingerprints graphically

