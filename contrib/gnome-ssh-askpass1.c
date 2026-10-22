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

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <gnome.h>
#অন্তর্ভাব <X11/Xlib.h>
#অন্তর্ভাব <gdk/gdkx.h>

শূন্য
report_failed_grab (শূন্য)
{
	GtkWidget *err;

	err = gnome_message_box_new("Could not grab keyboard or mouse.\n"
		"A malicious client may be eavesdropping on your session.",
				    GNOME_MESSAGE_BOX_ERROR, "EXIT", রিক্ত);
	gtk_window_set_position(GTK_WINDOW(err), GTK_WIN_POS_CENTER);
	gtk_object_set(GTK_OBJECT(err), "type", GTK_WINDOW_POPUP, রিক্ত);

	gnome_dialog_run_and_close(GNOME_DIALOG(err));
}

পূর্ণাঙ্ক
passphrase_dialog(বর্ণ *message)
{
	বর্ণ *passphrase;
	বর্ণ **messages;
	পূর্ণাঙ্ক result, i, grab_server, grab_pointer;
	GtkWidget *dialog, *entry, *label;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != রিক্ত);
	grab_pointer = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != রিক্ত);

	dialog = gnome_dialog_new("OpenSSH", GNOME_STOCK_BUTTON_OK,
	    GNOME_STOCK_BUTTON_CANCEL, রিক্ত);

	messages = g_strsplit(message, "\\n", 0);
	যদি (messages)
		প্রতি(i = 0; messages[i]; i++) {
			label = gtk_label_new(messages[i]);
			gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),
			    label, FALSE, FALSE, 0);
		}

	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox), entry, FALSE,
	    FALSE, 0);
	gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
	gtk_widget_grab_focus(entry);

	/* Center window and prepare for grab */
	gtk_object_set(GTK_OBJECT(dialog), "type", GTK_WINDOW_POPUP, রিক্ত);
	gnome_dialog_set_default(GNOME_DIALOG(dialog), 0);
	gtk_window_set_position (GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_policy(GTK_WINDOW(dialog), FALSE, FALSE, TRUE);
	gnome_dialog_close_hides(GNOME_DIALOG(dialog), TRUE);
	gtk_container_set_border_width(GTK_CONTAINER(GNOME_DIALOG(dialog)->vbox),
	    GNOME_PAD);
	gtk_widget_show_all(dialog);

	/* Grab focus */
	যদি (grab_server)
		XGrabServer(GDK_DISPLAY());
	যদি (grab_pointer && gdk_pointer_grab(dialog->window, TRUE, 0,
	    রিক্ত, রিক্ত, GDK_CURRENT_TIME))
		গচ্ছ nograb;
	যদি (gdk_keyboard_grab(dialog->window, FALSE, GDK_CURRENT_TIME))
		গচ্ছ nograbkb;

	/* Make <enter> close dialog */
	gnome_dialog_editable_enters(GNOME_DIALOG(dialog), GTK_EDITABLE(entry));

	/* Run dialog */
	result = gnome_dialog_run(GNOME_DIALOG(dialog));

	/* Ungrab */
	যদি (grab_server)
		XUngrabServer(GDK_DISPLAY());
	যদি (grab_pointer)
		gdk_pointer_ungrab(GDK_CURRENT_TIME);
	gdk_keyboard_ungrab(GDK_CURRENT_TIME);
	gdk_flush();

	/* Report passphrase if user selected OK */
	passphrase = gtk_entry_get_text(GTK_ENTRY(entry));
	যদি (result == 0)
		puts(passphrase);
		
	/* Zero passphrase in memory */
	memset(passphrase, '\0', strlen(passphrase));
	gtk_entry_set_text(GTK_ENTRY(entry), passphrase);
			
	gnome_dialog_close(GNOME_DIALOG(dialog));
	প্রত্যাগম (result == 0 ? 0 : -1);

	/*
	 * At least one grab failed - ungrab what we got, and report the
	 * failure to the user. Note that XGrabServer() cannot fail.
	 */
 nograbkb:
	gdk_pointer_ungrab(GDK_CURRENT_TIME);
 nograb:
	যদি (grab_server)
		XUngrabServer(GDK_DISPLAY());
	gnome_dialog_close(GNOME_DIALOG(dialog));
	
	report_failed_grab();
	প্রত্যাগম (-1);
}

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	বর্ণ *message;
	পূর্ণাঙ্ক result;

	gnome_init("GNOME ssh-askpass", "0.1", argc, argv);

	যদি (argc == 2)
		message = argv[1];
	অন্যথা
		message = "Enter your OpenSSH passphrase:";

	setvbuf(stdout, 0, _IONBF, 0);
	result = passphrase_dialog(message);

	প্রত্যাগম (result);
}
