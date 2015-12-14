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

package org.openoverlayrouter.noroot;

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
		Intent startIntent = new Intent(context, OOR.class);
		PendingIntent contentIntent = PendingIntent.getActivity(context,0,startIntent,PendingIntent.FLAG_CANCEL_CURRENT);

		// Allways overwriting same notification.
		int notification_id = 1;
		
		Notification.Builder notify_b = new Notification.Builder(context);
		notify_b.setContentTitle("OOR Alert");
		notify_b.setContentText(log_msg);
		notify_b.setSmallIcon(R.drawable.oor_logo_small);
		notify_b.setWhen(System.currentTimeMillis());
		notify_b.setContentIntent(contentIntent);
		notify_b.setAutoCancel(true);
		Uri uri= RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
		notify_b.setSound(uri);
		
		Notification notify_msg = notify_b.getNotification();
		notificationManager.notify(notification_id,notify_msg);
	}
}
