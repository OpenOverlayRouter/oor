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

#ifndef OOR_JNI_H_
#define OOR_JNI_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
* Class: org_openoverlayrouter_noroot_OOR_JNI
* Method: oor_start
* Signature: (I)[I
*/
JNIEXPORT jint JNICALL Java_org_openoverlayrouter_noroot_OOR_1JNI_oor_1start
  (JNIEnv * env, jobject thisObj, jint vpn_tun_fd, jstring storage_path);

/*
* Class: org_openoverlayrouter_noroot_OOR_JNI
* Method: oor_loop
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_org_openoverlayrouter_noroot_OOR_1JNI_oor_1loop
  (JNIEnv * env, jclass cl);

/*
* Class: org_openoverlayrouter_noroot_OOR_JNI
* Method: oor_exit
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_org_openoverlayrouter_noroot_OOR_1JNI_oor_1exit
   (JNIEnv * env, jclass cl);


void jni_init(JNIEnv *env, jobject object);
void jni_uninit();
void oor_jni_protect_socket(int socket);


#ifdef __cplusplus
}
#endif

#endif /* OOR_JNI_H_ */
