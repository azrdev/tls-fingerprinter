# building
The TLS Fingerprinter is built using maven, as specified in the file pom.xml
To compile the project, and package as .jar(s), do:

    ```sh

    cd $PATH_TO_VIRTUALNETWORKLAYER
    mvn install   # compile, package, install .jar to local repository ~/.m2

    cd $PATH_TO_SSL_STACK
    mvn install   # compile, package, install .jar to local repository ~/.m2

    cd $PATH_TO_PASSIVEANALYZER
    mvn package   # compile, package

    ls target/*.jar
    ```

In addition to the "normal" .jar file containing all compiled classes of the project, a "standalone" version is built for the TLS fingerprinter, that includes all needed dependencies. It can be run without any further preparation, except for installation of the pcap library.

# dependencies
* `virtualnetworklayer`: artifact (.jar) hast to be in local repository to be found (see above)
* `SSL Stack`: artifact (.jar) hast to be in local repository to be found (see above)

The following should be pulled automatically by maven from the central repository at <https://search.maven.org/>
* *maven-shade-plugin*: generation of the standalone .jar
* *ANTLR4*: parsing of fingerprint savefiles
* *Maven IDEA UI Designer* plugin: generation of gui classes
* *Google Guava*
* *JUnit4*: tests
* *log4j 1.2*: logging
* *argparse4j*: command-line interface
* *JFreeChart*: Charts in gui Statistics view
* *JFreeSVG*: SVG export of charts

