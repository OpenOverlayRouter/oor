package org.lispmob.noroot;

import java.io.IOException;
import java.lang.*;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

import org.apache.http.util.EncodingUtils;
import org.json.JSONObject;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;

public class IPC implements Runnable {
	
	private Context context = null;
	private Notifications notifications = null;
	private boolean isRunning	= false;
	private Thread ipc_thread;
	private DatagramChannel ipc_channel;
	private static final String ipc_addr  = "127.0.1.1";
	private static final int ipc_dst_port = 10000;
	private static final int ipc_src_port = 10001;
	
	
	private static final int IPC_LOG_MSG = 6;

	
	public IPC(Context context){
		this.context = context;
		notifications = new Notifications(this.context);
		try {
			ipc_channel = DatagramChannel.open();
			ipc_channel.socket().bind(new InetSocketAddress(ipc_addr, ipc_src_port));
			ipc_channel.connect(new InetSocketAddress(ipc_addr, ipc_dst_port));
		} catch (Exception e) {
			e.printStackTrace();
		}
		ipc_thread =  new Thread(this, "IPC");
	}
	
	public void start(){
		ipc_thread.start();
		isRunning = true;
	}
	
	public void stop(){
		ipc_thread.interrupt();
		try {
			ipc_channel.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		isRunning = false;
	}
	
	public void run()
	{
		int len = 0;
		ByteBuffer buf = ByteBuffer.allocate(9000);
		while (!ipc_thread.isInterrupted()){
			buf.clear();
			try {
				len = ipc_channel.read(buf);
				if (len == 0){
					continue;
				}
				buf.flip();
				String json_str = EncodingUtils.getString(buf.array(), "utf8");
				JSONObject jObj = new JSONObject(json_str);
				int ipc_type = jObj.getInt("type");
				System.out.println("LISPmob: Received IPC message: "+ipc_type);
				switch (ipc_type){
				case IPC_LOG_MSG:
					String log_msg = jObj.getString("log_msg");
					notifications.notify_msg(log_msg);
					break;
				default:
					System.out.println("***** Unknown IPC message: "+ipc_type);
					break;
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
	public boolean is_IPC_running(){
		return (isRunning);
	}
}