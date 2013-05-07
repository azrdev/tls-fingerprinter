#!/bin/bash

# Windows only:
# export PATH=$PATH:/cygdrive/c/Programme/Java/jdk1.7.0_13/bin/

cd "de/rub/nds/research/timingsocket/"

javac TimingSocketImpl.java


cd -

# Generate the JNI stub from the TimingsocketImpl class
javah -classpath . de.rub.nds.research.timingsocket.TimingSocketImpl

# Compile the native code and create dynamic library
# gcc -fPIC -Wall -o libnativecode.dylib -shared -I/System/Library/Frameworks/JavaVM.framework/Versions/Current/Headers/ TimingSocket.c
# gcc -O2 -fPIC -Wall -o libnativecode.dylib -shared -I/usr/lib/jvm/java-6-openjdk-amd64/include TimingSocket.c
# gcc -fPIC -O2 -Wall -o libnativecode.dylib -shared  -I/opt/java/jdk1.7.0_17/include/linux -I/opt/java/jdk1.7.0_17/include TimingSocket.c
gcc -fPIC -O2 -Wall -o libnativecode.dylib -shared  -I/usr/lib/jvm/java-7-openjdk-amd64/include/linux -I/usr/lib/jvm/java-7-openjdk-amd64/include TimingSocket.c

# Cygwin
# gcc -O2 -fPIC -Wall -o libnativecode.dylib -static -shared -Wl,--add-stdcall-alias -I/cygdrive/c/Programme/Java/jdk1.7.0_13/include/  -I/cygdrive/c/Programme/Java/jdk1.7.0_13/include/win32/ TimingSocket.c 



