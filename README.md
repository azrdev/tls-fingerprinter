Some Java network components, related to my Bachelor's Thesis.

You can build the whole thing using Maven running

    mvn install

It might require two runs due to the inter-project dependencies.

# repository structure
## [PassiveAnalyzer](PassiveAnalyzer/)
The application of my [Bachelor's Thesis "Non-certificate-based TLS Fingerprinting and MITM detection"](https://github.com/azrdev/tls-fingerprinter/releases).

See also the [README](PassiveAnalyzer/README.md), [INSTALL](PassiveAnalyzer/INSTALL.md) and [HACKING](PassiveAnalyzer/HACKING.md) files.

## [Stack](Stack/)
`package de.rub.ssl.stack`

*T.I.M.E. TLS Stack* by Christopher Meyer. See his [Ph.D. Thesis "20 years of SSL/TLS research : An analysis of the Internet’s security foundation"](http://www-brs.ub.ruhr-uni-bochum.de/netahtml/HSS/Diss/MeyerChristopher/diss.pdf).

## [VirtualNetworkLayer](VirtualNetworkLayer/)
`package de.rub.nds.virtualnetworklayer`

pcap interface, Network Stack (Link Layer, Network Layer, Transport Layer, some application protocols) by Marco Faltermeyer.
See his [Bachelor's Thesis "TCP/IP Fingerprinting in Java"](https://hds.hebis.de/ulbda/Record/HEB343817683).

## other subprojects

### [Analyzer](Analyzer/)
`package de.rub.nds.ssl.analyzer`
Application from cmeyer's Ph.D. Thesis.
#### [BleichenbacherTests](BleichenbacherTests/)
`package de.rub.nds.ssl.analyzer.attacker`
#### [BleichenbacherTimingStripped](BleichenbacherTimingStripped/)
`package de.rub.nds.ssl.analyzer.attacker`
### [ECCTests](ECCTests/)
`package de.rub.nds.ecdhattack`

drives a client-side attack against TLS_ECDH_RSA_WITH_AES_128_CBC_SHA

### [TimingSocket](TimingSocket/)
`package de.rub.nds.research.timingsocket`, 

`package de.rub.nds.ssl.stack.workflows.response.fetcher`

subclass java.net.Socket doing exact time measurement in C using JNI

### [TinyTLSServer](TinyTLSServer/)
`package de.rub.nds.tinytlssocket`

uses java.net.ssl to open a minimal TLS server

