#include "lispd_jni.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <stdlib.h>

JNIEnv* create_vm()
{
    JavaVM *jvm;
    JNIEnv *env;
    JavaVMInitArgs vm_args;

    JavaVMOption options[1];

    options[0].optionString = "-Djava.class.path=/home/giri";

    vm_args.version = JNI_VERSION_1_6;
    vm_args.nOptions = 1;
    vm_args.options = &options;
    vm_args.ignoreUnrecognized = JNI_FALSE;

    JNI_CreateJavaVM(&jvm, (void **) &env, &vm_args);

    return env;
}

void invoke_class(JNIEnv *env)
{
    jclass helloWorldClass;
    jmethodID mainMethod;
    jobjectArray applicationArgs;
    jstring applicationArg0;

    helloWorldClass = (*env)->FindClass(env, "MainClass");
    mainMethod = (*env)->GetStaticMethodID(env, helloWorldClass, "main", "([Ljava/lang/String;)V");

    applicationArgs = (*env)->NewObjectArray(env, 1, (*env)->FindClass(env, "java/lang/String"), NULL);

    applicationArg0 = (*env)->NewStringUTF(env, "From-C-Program");

    (*env)->SetObjectArrayElement(env, applicationArgs, 0, applicationArg0);

    (*env)->CallStaticVoidMethod(env, helloWorldClass, mainMethod, applicationArgs);

}


int main()
{
    JNIEnv *env = create_vm();
    invoke_class(env);

    return 0;
}
