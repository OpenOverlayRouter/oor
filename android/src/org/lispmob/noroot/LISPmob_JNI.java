package org.lispmob.noroot;

public class LISPmob_JNI {
	
	public static native int[] startLispd(int tunFD, String storage_path);
	
	public static native void lispd_loop();
	
	public static native void lispd_exit();
	
	static {
		System.loadLibrary("lispd");
	}
}
