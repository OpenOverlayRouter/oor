ANDROID_HOME=/home/chris/source/cyanogen
. $ANDROID_HOME/build/envsetup.sh
#setpaths
OUT_ROOT=$ANDROID_HOME/$(get_build_var PRODUCT_OUT)
echo "OUT_ROOT = $OUT_ROOT"
OUT_SYMBOLS=$ANDROID_HOME/$(get_build_var TARGET_OUT_UNSTRIPPED)
echo "OUT_SYMBOLS = $OUT_SYMBOLS"
OUT_SO_SYMBOLS=$ANDROID_HOME/$(get_build_var TARGET_OUT_SHARED_LIBRARIES_UNSTRIPPED)
echo "OUT_SO_SYMBOLS = $OUT_SO_SYMBOLS"
OUT_EXE_SYMBOLS=$ANDROID_HOME/$(get_build_var TARGET_OUT_EXECUTABLES_UNSTRIPPED)
echo "OUT_EXE_SYMBOLS = $OUT_EXE_SYMBOLS"
PREBUILTS=$ANDROID_HOME/$(get_build_var ANDROID_PREBUILTS)
echo "PREBUILTS = $PREBUILTS"
LOCAL_EXE="$1"
if [ -z "$LOCAL_EXE" ] ; then
echo "usage: debug local_exe remote_exe arguments"
exit
fi
REM_EXE="$2"
if [ -z "$REM_EXE" ] ; then
echo "usage: debug local_exe remote_exe arguments"
exit
fi
ARG_LIST="$3"
if [ -z "$ARG_LIST" ] ; then
echo "usage: debug local_exe remote_exe arguments"
exit
fi
PORT=":5039"
adb forward "tcp$PORT" "tcp$PORT"
echo "PORT = $PORT, LOCAL_EXE = $LOCAL_EXE, REM_EXE = $REM_EXE, ARG_LIST = $ARG_LIST"
adb shell gdbserver $PORT $REM_EXE $ARG_LIST &
sleep 2 
echo >|"$OUT_ROOT/gdbclient.cmds" "set solib-absolute-prefix $OUT_SYMBOLS"
echo >>"$OUT_ROOT/gdbclient.cmds" "set solib-search-path $OUT_SO_SYMBOLS"
echo >>"$OUT_ROOT/gdbclient.cmds" "target remote $PORT"
echo >>"$OUT_ROOT/gdbclient.cmds" ""
GDB_DIR=$ANDROID_EABI_TOOLCHAIN 
echo "GDB_DIR = $GDB_DIR"
$GDB_DIR/arm-eabi-gdb -silent -x "$OUT_ROOT/gdbclient.cmds" "$OUT_EXE_SYMBOLS/$LOCAL_EXE"
