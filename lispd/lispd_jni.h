/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <jni.h>

#ifndef LISPD_JNI_H_
#define LISPD_JNI_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
* Class: org_lispmob_noroot_LISPmob_JNI
* Method: startLispd
* Signature: (I)[I
*/
JNIEXPORT jint JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_startLispd
  (JNIEnv * env, jobject thisObj, jint vpn_tun_fd, jstring storage_path);

/*
* Class: org_lispmob_noroot_LISPmob_JNI
* Method: lispd_loop
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_lispd_1loop
  (JNIEnv * env, jclass cl);

/*
* Class: org_lispmob_noroot_LISPmob_JNI
* Method: lispd_exit
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_lispd_1exit
   (JNIEnv * env, jclass cl);


void jni_init(JNIEnv *env, jobject object);
void jni_uninit();
void lispd_jni_protect_socket(int socket);


#ifdef __cplusplus
}
#endif

#endif /* LISPD_JNI_H_ */
