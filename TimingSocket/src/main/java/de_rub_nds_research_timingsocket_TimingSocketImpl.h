/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class de_rub_nds_research_timingsocket_TimingSocketImpl */

#ifndef _Included_de_rub_nds_research_timingsocket_TimingSocketImpl
#define _Included_de_rub_nds_research_timingsocket_TimingSocketImpl
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_create
 * Signature: (Z)I
 */
JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1create
  (JNIEnv *, jobject, jboolean);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_connect
 * Signature: (ILjava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1connect
  (JNIEnv *, jobject, jint, jstring, jint);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_available
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1available
  (JNIEnv *, jobject);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_close
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1close
  (JNIEnv *, jobject);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_setOption
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1setOption
  (JNIEnv *, jobject, jint, jint);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_getTiming
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1getTiming
  (JNIEnv *, jobject);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_write
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1write
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_read
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1read
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_start_measurement
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1start_1measurement
  (JNIEnv *, jclass);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_read_off
 * Signature: ([BII)I
 */
JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1read_1off
  (JNIEnv *, jobject, jbyteArray, jint, jint);

/*
 * Class:     de_rub_nds_research_timingsocket_TimingSocketImpl
 * Method:    c_read_no_param
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_de_rub_nds_research_timingsocket_TimingSocketImpl_c_1read_1no_1param
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif
