#include "de_rub_nds_research_timingsocket_TimingSocketImpl.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include "fau_timer.c"
#include <netinet/tcp.h>
#include <errno.h>
#include <pthread.h>


#define _debug

static char first_byte = 0x0;
static int sock = -1;
static int start_measurement = 0;
static int ready_measurement = 0;
static unsigned long long start = 0;
static unsigned long long end = 0;
static unsigned long long ticks_measured = 0;

pthread_mutex_t lock;

void calc_ticks() {
        start_measurement = 0;
        ticks_measured = end - start;
        ready_measurement = 1;

        printf("%llu;XXXXXX\n", ticks_measured);
        fflush(stdout);
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1create(JNIEnv * env, jobject obj, jboolean stream)
{
#ifdef _debug
        puts("Called c_create()\n");
        fflush(stdout);
#endif
        ready_measurement = 0;
        start_measurement = 0;
        sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

        /*
         * Disable Nagle's algorithm (RFC 896)
         */
        int flag = 1;
        int result = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
        if (result < 0) {
                printf("ERROR calling setsockopt");
                fflush(stdout);
                return -1;
        }

	if(pthread_mutex_init(&lock, NULL) != 0) {
                printf("ERROR initializing mutex!");
                fflush(stdout);
	}

	return sock;
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1connect(JNIEnv * env, jobject obj, jint sock, jstring host, jint port)
{
        extern int errno;
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
        if(ret != 0) {
                printf("Called c_connect(sock=%d, host=%s, port=%d --> %d, (%s))\n", sock, c_host, port, ret, strerror(errno));
                fflush(stdout);
        }

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

        if(opt_name == 0x0080) { // SO_LINGER
#ifdef _debug
                printf("setting SO_LINGER to l_linger=%d\n", opt_value);
                fflush(stdout);
#endif
                struct linger so_linger;
                so_linger.l_onoff = c_true;
                so_linger.l_linger = opt_value;
        
                ret = setsockopt(sock, SOL_SOCKET, SO_LINGER, &so_linger, sizeof so_linger);
        } else if(opt_name == 0x1006) {
#ifdef _debug
                printf("setting SO_RCVTIMEO to tv_sec=%d\n", opt_value);
                fflush(stdout);
#endif
                struct timeval tv;

                bzero(&tv, sizeof tv);
                tv.tv_sec = opt_value;

                ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));
        } else {
                printf("c_setOption(): Wrong optID: %x\n", opt_name);
                ret = -1;
        }

        return ret;
}


JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1read_1off(JNIEnv *env, jobject obj, jbyteArray ar, jint offset, jint length) { 

        jint len_read = -1;
	struct timeval tv;
	int i;

        jbyte *c_array = (*env)->GetByteArrayElements(env, ar, 0);

	tv.tv_sec  = 0;
	tv.tv_usec = 100000; // Timeout is 100 milliseconds
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));

#ifdef _debug
        printf("Called c_read(ar, offset=%d, length=%d)\n", offset, length);
        fflush(stdout);
#endif

        /**
         * We set a short timeout for the socket and then execute read() in a
         * loop. Because of this, we unlock the mutex periodically and give
         * the write method the opportunity to send data and perform the 
         * measurement.
         * If the timing measurement is ready, just return EOF, which finishes
         * the measurement (kinda rude, I know).
         */
	for(i = 0; i < 20 && len_read == -1 ; i++) { // Overall time out is 100 milliseconds * 50 = 5 seconds
        	pthread_mutex_lock(&lock);
#ifdef _debug
        	printf("read() locked. ");
	        fflush(stdout);
#endif

        if(ready_measurement != 0) {
                /*
                 * Timing measurement is finished. Just return EOF, because
                 * we are done.
                 */
                return -1;
        }
        
        	if(start_measurement == 2) {
			c_array[0] = first_byte;
			len_read = 0;
			if(length > 1) {
                		len_read += read(sock, c_array + offset + 1, length - 1);
			}
        	} else {
                	len_read = read(sock, c_array + offset, length);
        	}

        	pthread_mutex_unlock(&lock);
#ifdef _debug
                // printf("ERRNO %i --> (%s))\n", errno, strerror(errno));
        	printf("Now unlocked. Errno %d --> %s\n", errno, strerror(errno));
	        fflush(stdout);
#endif
	}

#ifdef _debug
        printf("finished c_read --> %d)\n", len_read);
        fflush(stdout);
#endif

        if(len_read < 0) {
                printf("ERROR len_read --> %d, (%s))\n", len_read, strerror(errno));
                fflush(stdout);
        }

        (*env)->ReleaseByteArrayElements(env, ar, c_array, 0);

	tv.tv_sec  = 10;
	tv.tv_usec = 0; // Timeout is 10 seconds
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));

        return len_read;

}


JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1write(JNIEnv *env, jobject obj, jbyteArray ar) {

        jbyte *c_array = (*env)->GetByteArrayElements(env, ar, 0);
        jsize len = (*env)->GetArrayLength(env, ar);
        ssize_t len_sent = -1;

      	pthread_mutex_lock(&lock);

#ifdef _debug
        printf("locked c_write(len=%d)\n", len);
        fflush(stdout);
#endif

	if(start_measurement == 1) {
        	len_sent = write(sock, c_array, len);
        	start = get_ticks();
		start_measurement = 2;
#ifdef _debug
	        puts("Starting measurement");
       		fflush(stdout);
#endif
		read(sock, &first_byte, 1);
        	end = get_ticks();
		calc_ticks();
	} else {
        	len_sent = write(sock, c_array, len);
	}

      	pthread_mutex_unlock(&lock);

#ifdef _debug
        printf("unlocked write(), sent %d bytes\n", (int)len_sent);
        fflush(stdout);
#endif

        // Just write the buffer and don't copy the array back to Java
        (*env)->ReleaseByteArrayElements(env, ar, c_array, JNI_ABORT);

        return len_sent;
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1read(JNIEnv *env, jobject obj, jbyteArray ar) {
#ifdef _debug
        printf("ERROR do not call\n");
        fflush(stdout);
#endif

        return -1;
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1close(JNIEnv *env, jobject obj)
{
#ifdef _debug
        puts("Called c_close()\n");
        fflush(stdout);
#endif
	pthread_mutex_destroy(&lock);

        return close(sock);
}

JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1read_1no_1param(JNIEnv * env, jobject obj)
{
#ifdef _debug
        printf("ERROR do not call this!");
        fflush(stdout);
#endif
        return NULL;
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

JNIEXPORT void JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1start_1measurement(JNIEnv *env, jobject obj)
{
#ifdef _debug
        puts("Called c_start_Measurement()\n");
        fflush(stdout);
#endif
        start_measurement = 1;
        ticks_measured = 0;
        ready_measurement = 0;
        start = 0L;
        end = 0L;
}

JNIEXPORT jlong JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1getTiming(JNIEnv *evn, jobject obj)
{
        return ticks_measured;
}


