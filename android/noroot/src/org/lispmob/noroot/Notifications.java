package org.lispmob.noroot;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.media.RingtoneManager;
import android.net.Uri;

public class Notifications{
	
	private Context context;
	
	public Notifications(Context context){
		this.context = context;
	}
	
	public void notify_msg(String log_msg)
	{
		NotificationManager notificationManager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
		// Intent to be call when pushing the notification. 
		Intent startIntent = new Intent(context, LISPmob.class);
		PendingIntent contentIntent = PendingIntent.getActivity(context,0,startIntent,PendingIntent.FLAG_CANCEL_CURRENT);

		// Allways overwriting same notification.
		int notification_id = 1;
		
		Notification.Builder notify_b = new Notification.Builder(context);
		notify_b.setContentTitle("LISPmob Alert");
		notify_b.setContentText(log_msg);
		notify_b.setSmallIcon(R.drawable.lispmob_logo_small);
		notify_b.setWhen(System.currentTimeMillis());
		notify_b.setContentIntent(contentIntent);
		notify_b.setAutoCancel(true);
		Uri uri= RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
		notify_b.setSound(uri);
		
		Notification notify_msg = notify_b.getNotification();
		notificationManager.notify(notification_id,notify_msg);
	}
}
