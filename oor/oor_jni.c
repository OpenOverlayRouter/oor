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

#include <stddef.h>
#include "defs.h"
#include "oor_jni.h"
#include "lib/oor_log.h"

static JNIEnv *jni_env;
static jobject jni_object;
static jclass  class_android_jni;



void jni_init(JNIEnv *env, jobject object)
{
    jni_env = env;
    jni_object = (*jni_env)->NewGlobalRef(jni_env, object);
    class_android_jni = (*jni_env)->FindClass(jni_env,"org/openoverlayrouter/noroot/OOR_JNI");
    if (class_android_jni == NULL){
        OOR_LOG(LINF,"JNI Error: Class not found: org.openoverlayrouter.noroot.OOR_JNI");
        return;
    }
    class_android_jni = (*jni_env)->NewGlobalRef(jni_env, class_android_jni);
}

void jni_uninit()
{
    (*jni_env)->DeleteGlobalRef(jni_env, jni_object);
    (*jni_env)->DeleteGlobalRef(jni_env, class_android_jni);
    jni_object = NULL;
    class_android_jni = NULL;
}

void oor_jni_protect_socket(int socket)
{

    jmethodID  meth_protect = NULL;

    meth_protect = (*jni_env)->GetMethodID(jni_env,class_android_jni, "jni_protect_socket", "(I)V");

    if (meth_protect == NULL){
        OOR_LOG(LINF,"JNI Error: Method not found: org.openoverlayrouter.noroot.OOR_JNI:jni_protect_socket");
        return;
    }
    (*jni_env)->CallVoidMethod(jni_env,jni_object, meth_protect, socket);
}
