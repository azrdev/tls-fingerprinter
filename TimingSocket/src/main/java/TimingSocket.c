#include "de_rub_nds_research_timingsocket_TimingSocketImpl.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include "fau_timer.c"

#define _debug

static int sock = -1;
static int start_measurement = 0;
static unsigned long long start = 0;
static unsigned long long end = 0;
static unsigned long long ticks_measured = 0;

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1create(JNIEnv * env, jobject obj, jboolean stream)
{
#ifdef _debug
        puts("Called c_create()\n");
        fflush(stdout);
#endif
        sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	return sock;
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1connect(JNIEnv * env, jobject obj, jint sock, jstring host, jint port)
{
        // extern int errno;
        int ret = -1;
        struct hostent *server;
        struct sockaddr_in serv_addr;

        const char *c_host = (*env)->GetStringUTFChars(env, host, 0);
        server = gethostbyname(c_host);
        if (server == NULL) {
                ret = -10;
                goto err;
        }

        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
        serv_addr.sin_port = htons(port);

        ret = connect(sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr));

#ifdef _debug
        printf("Called c_connect(%d, %s (%x %x, %d), %d) --> %d\n", sock, c_host, *(server->h_addr), *((server->h_addr) + 3), server->h_length, port, ret);
        fflush(stdout);
#endif

err:
        // Cleanup garbage
        (*env)->ReleaseStringUTFChars(env, host, c_host);

        return ret;
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1setOption(JNIEnv *env, jobject obj, jint opt_name, jint opt_value)
{
#ifdef _debug
        puts("Called c_setOption()\n");
        fflush(stdout);
#endif
        int c_true = (0 == 0);
        int ret;

        struct linger so_linger;
        so_linger.l_onoff = c_true;
        so_linger.l_linger = 30;

        ret = setsockopt(sock, SOL_SOCKET, SO_LINGER, &so_linger, sizeof so_linger);

        return ret;
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1write(JNIEnv *env, jobject obj, jbyteArray ar) {
        jbyte *c_array = (*env)->GetByteArrayElements(env, ar, 0);
        jsize len = (*env)->GetArrayLength(env, ar);
        ssize_t len_sent = -1;

#ifdef _debug
        printf("Called c_write(len=%d)\n", len);
        fflush(stdout);
#endif
        len_sent = write(sock, c_array, len);
        start = get_ticks();
#ifdef _debug
        printf("finished write(), sent %d bytes\n", (int)len_sent);
        fflush(stdout);
#endif

        // Todo: whatever this last argument "0" means...
        (*env)->ReleaseByteArrayElements(env, ar, c_array, 0);

        return len_sent;
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1read(JNIEnv *env, jobject obj, jbyteArray ar) {
#ifdef _debug
        printf("Called c_read(ar)\n");
        fflush(stdout);
#endif
        jbyte *c_array = (*env)->GetByteArrayElements(env, ar, 0);

        jsize len = (*env)->GetArrayLength(env, ar);
        ssize_t len_read = -1;

        len_read = read(sock, c_array, len);
        end = get_ticks();
        printf("finished c_1read: %d\n", len);
        fflush(stdout);

        // Todo: whatever this last argument "0" means...
        (*env)->ReleaseByteArrayElements(env, ar, c_array, 0);

        return len_read;
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1close(JNIEnv *env, jobject obj)
{
#ifdef _debug
        puts("Called c_close()\n");
        fflush(stdout);
#endif
        return close(sock);
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1read_1no_1param(JNIEnv * env, jobject obj)
{
#ifdef _debug
        printf("r");
        fflush(stdout);
#endif
        jint buf;
        ssize_t len_read = -1;
        len_read = read(sock, &buf, 1);

        return buf;
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1available(JNIEnv *env, jobject obj)
{
        fd_set fdset;
        struct timeval timeout;
        int ret = -1;

        bzero(&timeout, sizeof timeout);
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        ret = select(100, &fdset, NULL, NULL, &timeout);

#ifdef _debug
        printf("called c_available --> %d\n", ret);
        fflush(stdout);
#endif

        return ret;       
}

JNIEXPORT void JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1startTimeMeasurement(JNIEnv *env, jobject obj)
{
#ifdef _debug
        puts("Called c_startTimeMeasurement()\n");
        fflush(stdout);
#endif
        ticks_measured = 0;
        start_measurement = 1;
        start = 0L;
        end = 0L;
}

JNIEXPORT jlong JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1getTiming(JNIEnv *evn, jobject obj)
{
        return ticks_measured;
}

void calc_ticks() {
        ticks_measured = end - start;
        start_measurement = 0;
        start = 0L;
        end = 0L;
}
