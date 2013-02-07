#!/bin/bash

# Compile the TimingSocketImpl class
javac de/rub/nds/research/timingsocket/TimingSocketImpl.java

# Generate the JNI stub from the TimingsocketImpl class
javah -classpath . de.rub.nds.research.timingsocket.TimingSocketImpl

# Compile the native code and create dynamic library
gcc -fPIC -Wall -o libnativecode.dylib -shared -I/System/Library/Frameworks/JavaVM.framework/Versions/Current/Headers/ TimingSocket.c
# gcc -O2 -fPIC -Wall -o libnativecode.dylib -shared -I/usr/lib/jvm/java-6-openjdk-amd64/include TimingSocket.c
