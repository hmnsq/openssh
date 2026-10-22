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

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <gnome.h>
#అన్తర్భావ <X11/Xlib.h>
#అన్తర్భావ <gdk/gdkx.h>

శూన్య
report_failed_grab (శూన్య)
{
	GtkWidget *err;

	err = gnome_సందేశం_box_new("Could not grab keyboard or mouse.\n"
		"A malicious client may be eavesdropping on your session.",
				    GNOME_సందేశం_BOX_ERROR, "EXIT", ఖాళీ);
	gtk_కిటికీ_సమితి_position(GTK_కిటికీ(err), GTK_WIN_POS_CENTER);
	gtk_object_సమితి(GTK_OBJECT(err), "type", GTK_కిటికీ_POPUP, ఖాళీ);

	gnome_dialog_నిరంతరం_and_close(GNOME_DIALOG(err));
}

పూర్ణాంకం
passphrase_dialog(అక్షరం *సందేశం_2)
{
	అక్షరం *passphrase;
	అక్షరం **messages;
	పూర్ణాంకం ఫలితం, i, grab_server, grab_సూచిక;
	GtkWidget *dialog, *నమోదు_2, *label;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != ఖాళీ);
	grab_సూచిక = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != ఖాళీ);

	dialog = gnome_dialog_new("OpenSSH", GNOME_STOCK_BUTTON_OK,
	    GNOME_STOCK_BUTTON_CANCEL, ఖాళీ);

	messages = g_strsplit(సందేశం_2, "\\n", 0);
	ఒకవేళ (messages)
		కొరకు(i = 0; messages[i]; i++) {
			label = gtk_label_new(messages[i]);
			gtk_box_pack_ప్రారంభం(GTK_BOX(GNOME_DIALOG(dialog)->vbox),
			    label, FALSE, FALSE, 0);
		}

	నమోదు_2 = gtk_నమోదు_new();
	gtk_box_pack_ప్రారంభం(GTK_BOX(GNOME_DIALOG(dialog)->vbox), నమోదు_2, FALSE,
	    FALSE, 0);
	gtk_నమోదు_సమితి_visibility(GTK_నమోదు(నమోదు_2), FALSE);
	gtk_widget_grab_focus(నమోదు_2);

	/* Center window and prepare for grab */
	gtk_object_సమితి(GTK_OBJECT(dialog), "type", GTK_కిటికీ_POPUP, ఖాళీ);
	gnome_dialog_సమితి_default(GNOME_DIALOG(dialog), 0);
	gtk_కిటికీ_సమితి_position (GTK_కిటికీ(dialog), GTK_WIN_POS_CENTER);
	gtk_కిటికీ_సమితి_policy(GTK_కిటికీ(dialog), FALSE, FALSE, TRUE);
	gnome_dialog_close_hides(GNOME_DIALOG(dialog), TRUE);
	gtk_container_సమితి_border_వెడల్పు(GTK_CONTAINER(GNOME_DIALOG(dialog)->vbox),
	    GNOME_PAD);
	gtk_widget_show_all(dialog);

	/* Grab focus */
	ఒకవేళ (grab_server)
		XGrabServer(GDK_DISPLAY());
	ఒకవేళ (grab_సూచిక && gdk_సూచిక_grab(dialog->కిటికీ, TRUE, 0,
	    ఖాళీ, ఖాళీ, GDK_CURRENT_సమయం))
		వెళ్ళు nograb;
	ఒకవేళ (gdk_keyboard_grab(dialog->కిటికీ, FALSE, GDK_CURRENT_సమయం))
		వెళ్ళు nograbkb;

	/* Make <enter> close dialog */
	gnome_dialog_editable_enters(GNOME_DIALOG(dialog), GTK_EDITABLE(నమోదు_2));

	/* Run dialog */
	ఫలితం = gnome_dialog_నిరంతరం(GNOME_DIALOG(dialog));

	/* Ungrab */
	ఒకవేళ (grab_server)
		XUngrabServer(GDK_DISPLAY());
	ఒకవేళ (grab_సూచిక)
		gdk_సూచిక_ungrab(GDK_CURRENT_సమయం);
	gdk_keyboard_ungrab(GDK_CURRENT_సమయం);
	gdk_flush();

	/* Report passphrase if user selected OK */
	passphrase = gtk_నమోదు_get_పాఠ్యం(GTK_నమోదు(నమోదు_2));
	ఒకవేళ (ఫలితం == 0)
		puts(passphrase);
		
	/* Zero passphrase in memory */
	memset(passphrase, '\0', అక్షరశ్రేణి_పొడవు(passphrase));
	gtk_నమోదు_సమితి_పాఠ్యం(GTK_నమోదు(నమోదు_2), passphrase);
			
	gnome_dialog_close(GNOME_DIALOG(dialog));
	తిరిగి (ఫలితం == 0 ? 0 : -1);

	/*
	 * At least one grab failed - ungrab what we got, and report the
	 * failure to the user. Note that XGrabServer() cannot fail.
	 */
 nograbkb:
	gdk_సూచిక_ungrab(GDK_CURRENT_సమయం);
 nograb:
	ఒకవేళ (grab_server)
		XUngrabServer(GDK_DISPLAY());
	gnome_dialog_close(GNOME_DIALOG(dialog));
	
	report_failed_grab();
	తిరిగి (-1);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	అక్షరం *సందేశం_2;
	పూర్ణాంకం ఫలితం;

	gnome_init("GNOME ssh-askpass", "0.1", argc, argv);

	ఒకవేళ (argc == 2)
		సందేశం_2 = argv[1];
	లేకపోతే
		సందేశం_2 = "Enter your OpenSSH passphrase:";

	setvbuf(stdout, 0, _IONBF, 0);
	ఫలితం = passphrase_dialog(సందేశం_2);

	తిరిగి (ఫలితం);
}
