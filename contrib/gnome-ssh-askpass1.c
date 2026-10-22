/*
 * Copyright (c) 2000-2002 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This is a simple GNOME SSH passphrase grabber. To use it, set the
 * environment variable SSH_ASKPASS to point to the location of
 * gnome-ssh-askpass before calling "ssh-add < /dev/null".
 *
 * There is only two run-time options: if you set the environment variable
 * "GNOME_SSH_ASKPASS_GRAB_SERVER=true" then gnome-ssh-askpass will grab
 * the X server. If you set "GNOME_SSH_ASKPASS_GRAB_POINTER=true", then the
 * pointer will be grabbed too. These may have some benefit to security if
 * you don't trust your X server. We grab the keyboard always.
 */

/*
 * Compile with:
 *
 * cc `gnome-config --cflags gnome gnomeui` \
 *    gnome-ssh-askpass1.c -o gnome-ssh-askpass \
 *    `gnome-config --libs gnome gnomeui`
 *
 */

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <gnome.h>
#अन्तर्भाव <X11/Xlib.h>
#अन्तर्भाव <gdk/gdkx.h>

शून्य
report_failed_grab (शून्य)
{
	GtkWidget *err;

	err = gnome_सन्देशः_box_new("Could not grab keyboard or mouse.\n"
		"A malicious client may be eavesdropping on your session.",
				    GNOME_सन्देशः_BOX_ERROR, "EXIT", रिक्त);
	gtk_गवाक्षः_समुच्चयः_position(GTK_गवाक्षः(err), GTK_WIN_POS_CENTER);
	gtk_object_समुच्चयः(GTK_OBJECT(err), "type", GTK_गवाक्षः_POPUP, रिक्त);

	gnome_dialog_सततम्_and_close(GNOME_DIALOG(err));
}

पूर्णाङ्क
passphrase_dialog(वर्ण *सन्देशः_2)
{
	वर्ण *passphrase;
	वर्ण **messages;
	पूर्णाङ्क परिणाम, i, grab_server, grab_pointer;
	GtkWidget *dialog, *प्रविष्टिः, *label;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != रिक्त);
	grab_pointer = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != रिक्त);

	dialog = gnome_dialog_new("OpenSSH", GNOME_STOCK_BUTTON_OK,
	    GNOME_STOCK_BUTTON_CANCEL, रिक्त);

	messages = g_strsplit(सन्देशः_2, "\\n", 0);
	यदि (messages)
		प्रति(i = 0; messages[i]; i++) {
			label = gtk_label_new(messages[i]);
			gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),
			    label, FALSE, FALSE, 0);
		}

	प्रविष्टिः = gtk_प्रविष्टिः_new();
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox), प्रविष्टिः, FALSE,
	    FALSE, 0);
	gtk_प्रविष्टिः_समुच्चयः_visibility(GTK_प्रविष्टिः(प्रविष्टिः), FALSE);
	gtk_widget_grab_focus(प्रविष्टिः);

	/* Center window and prepare for grab */
	gtk_object_समुच्चयः(GTK_OBJECT(dialog), "type", GTK_गवाक्षः_POPUP, रिक्त);
	gnome_dialog_समुच्चयः_default(GNOME_DIALOG(dialog), 0);
	gtk_गवाक्षः_समुच्चयः_position (GTK_गवाक्षः(dialog), GTK_WIN_POS_CENTER);
	gtk_गवाक्षः_समुच्चयः_policy(GTK_गवाक्षः(dialog), FALSE, FALSE, TRUE);
	gnome_dialog_close_hides(GNOME_DIALOG(dialog), TRUE);
	gtk_container_समुच्चयः_border_विस्तारः(GTK_CONTAINER(GNOME_DIALOG(dialog)->vbox),
	    GNOME_PAD);
	gtk_widget_show_all(dialog);

	/* Grab focus */
	यदि (grab_server)
		XGrabServer(GDK_DISPLAY());
	यदि (grab_pointer && gdk_pointer_grab(dialog->गवाक्षः, TRUE, 0,
	    रिक्त, रिक्त, GDK_CURRENT_TIME))
		गच्छ nograb;
	यदि (gdk_keyboard_grab(dialog->गवाक्षः, FALSE, GDK_CURRENT_TIME))
		गच्छ nograbkb;

	/* Make <enter> close dialog */
	gnome_dialog_editable_enters(GNOME_DIALOG(dialog), GTK_EDITABLE(प्रविष्टिः));

	/* Run dialog */
	परिणाम = gnome_dialog_सततम्(GNOME_DIALOG(dialog));

	/* Ungrab */
	यदि (grab_server)
		XUngrabServer(GDK_DISPLAY());
	यदि (grab_pointer)
		gdk_pointer_ungrab(GDK_CURRENT_TIME);
	gdk_keyboard_ungrab(GDK_CURRENT_TIME);
	gdk_flush();

	/* Report passphrase if user selected OK */
	passphrase = gtk_प्रविष्टिः_get_text(GTK_प्रविष्टिः(प्रविष्टिः));
	यदि (परिणाम == 0)
		पङ्क्तिं_लिख(passphrase);
		
	/* Zero passphrase in memory */
	स्मृतिं_पूरय(passphrase, '\0', वाक्यदैर्घ्यम्(passphrase));
	gtk_प्रविष्टिः_समुच्चयः_text(GTK_प्रविष्टिः(प्रविष्टिः), passphrase);
			
	gnome_dialog_close(GNOME_DIALOG(dialog));
	प्रत्यागम (परिणाम == 0 ? 0 : -1);

	/*
	 * At least one grab failed - ungrab what we got, and report the
	 * failure to the user. Note that XGrabServer() cannot fail.
	 */
 nograbkb:
	gdk_pointer_ungrab(GDK_CURRENT_TIME);
 nograb:
	यदि (grab_server)
		XUngrabServer(GDK_DISPLAY());
	gnome_dialog_close(GNOME_DIALOG(dialog));
	
	report_failed_grab();
	प्रत्यागम (-1);
}

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	वर्ण *सन्देशः_2;
	पूर्णाङ्क परिणाम;

	gnome_init("GNOME ssh-askpass", "0.1", argc, argv);

	यदि (argc == 2)
		सन्देशः_2 = argv[1];
	अन्यथा
		सन्देशः_2 = "Enter your OpenSSH passphrase:";

	setvbuf(stdout, 0, _IONBF, 0);
	परिणाम = passphrase_dialog(सन्देशः_2);

	प्रत्यागम (परिणाम);
}
