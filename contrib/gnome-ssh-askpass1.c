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

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <gnome.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <X11/Xlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <gdk/gdkx.h>

ਖਾਲੀ
report_failed_grab (ਖਾਲੀ)
{
	GtkWidget *err;

	err = gnome_ਸੁਨੇਹਾ_box_new("Could not grab keyboard or mouse.\n"
		"A malicious client may be eavesdropping on your session.",
				    GNOME_ਸੁਨੇਹਾ_BOX_ERROR, "EXIT", ਨਿਰਾ);
	gtk_ਖਿੜਕੀ_ਸੈੱਟ_position(GTK_ਖਿੜਕੀ(err), GTK_WIN_POS_CENTER);
	gtk_object_ਸੈੱਟ(GTK_OBJECT(err), "type", GTK_ਖਿੜਕੀ_POPUP, ਨਿਰਾ);

	gnome_dialog_ਲੜੀਵਾਰ_and_close(GNOME_DIALOG(err));
}

ਪੂਰਨ
passphrase_dialog(ਅੱਖਰ *ਸੁਨੇਹਾ_2)
{
	ਅੱਖਰ *passphrase;
	ਅੱਖਰ **messages;
	ਪੂਰਨ ਨਤੀਜਾ, i, grab_server, grab_ਸੂਚਕ;
	GtkWidget *dialog, *ਇੰਦਰਾਜ, *label;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != ਨਿਰਾ);
	grab_ਸੂਚਕ = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != ਨਿਰਾ);

	dialog = gnome_dialog_new("OpenSSH", GNOME_STOCK_BUTTON_OK,
	    GNOME_STOCK_BUTTON_CANCEL, ਨਿਰਾ);

	messages = g_strsplit(ਸੁਨੇਹਾ_2, "\\n", 0);
	ਜੇ (messages)
		ਲਈ(i = 0; messages[i]; i++) {
			label = gtk_label_new(messages[i]);
			gtk_box_pack_ਸ਼ੁਰੂ(GTK_BOX(GNOME_DIALOG(dialog)->vbox),
			    label, FALSE, FALSE, 0);
		}

	ਇੰਦਰਾਜ = gtk_ਇੰਦਰਾਜ_new();
	gtk_box_pack_ਸ਼ੁਰੂ(GTK_BOX(GNOME_DIALOG(dialog)->vbox), ਇੰਦਰਾਜ, FALSE,
	    FALSE, 0);
	gtk_ਇੰਦਰਾਜ_ਸੈੱਟ_visibility(GTK_ਇੰਦਰਾਜ(ਇੰਦਰਾਜ), FALSE);
	gtk_widget_grab_focus(ਇੰਦਰਾਜ);

	/* Center window and prepare for grab */
	gtk_object_ਸੈੱਟ(GTK_OBJECT(dialog), "type", GTK_ਖਿੜਕੀ_POPUP, ਨਿਰਾ);
	gnome_dialog_ਸੈੱਟ_default(GNOME_DIALOG(dialog), 0);
	gtk_ਖਿੜਕੀ_ਸੈੱਟ_position (GTK_ਖਿੜਕੀ(dialog), GTK_WIN_POS_CENTER);
	gtk_ਖਿੜਕੀ_ਸੈੱਟ_policy(GTK_ਖਿੜਕੀ(dialog), FALSE, FALSE, TRUE);
	gnome_dialog_close_hides(GNOME_DIALOG(dialog), TRUE);
	gtk_container_ਸੈੱਟ_border_ਚੌੜਾਈ(GTK_CONTAINER(GNOME_DIALOG(dialog)->vbox),
	    GNOME_PAD);
	gtk_widget_show_all(dialog);

	/* Grab focus */
	ਜੇ (grab_server)
		XGrabServer(GDK_DISPLAY());
	ਜੇ (grab_ਸੂਚਕ && gdk_ਸੂਚਕ_grab(dialog->ਖਿੜਕੀ, TRUE, 0,
	    ਨਿਰਾ, ਨਿਰਾ, GDK_CURRENT_ਸਮਾਂ))
		ਜਾਓ nograb;
	ਜੇ (gdk_keyboard_grab(dialog->ਖਿੜਕੀ, FALSE, GDK_CURRENT_ਸਮਾਂ))
		ਜਾਓ nograbkb;

	/* Make <enter> close dialog */
	gnome_dialog_editable_enters(GNOME_DIALOG(dialog), GTK_EDITABLE(ਇੰਦਰਾਜ));

	/* Run dialog */
	ਨਤੀਜਾ = gnome_dialog_ਲੜੀਵਾਰ(GNOME_DIALOG(dialog));

	/* Ungrab */
	ਜੇ (grab_server)
		XUngrabServer(GDK_DISPLAY());
	ਜੇ (grab_ਸੂਚਕ)
		gdk_ਸੂਚਕ_ungrab(GDK_CURRENT_ਸਮਾਂ);
	gdk_keyboard_ungrab(GDK_CURRENT_ਸਮਾਂ);
	gdk_flush();

	/* Report passphrase if user selected OK */
	passphrase = gtk_ਇੰਦਰਾਜ_get_ਪਾਠ(GTK_ਇੰਦਰਾਜ(ਇੰਦਰਾਜ));
	ਜੇ (ਨਤੀਜਾ == 0)
		puts(passphrase);
		
	/* Zero passphrase in memory */
	memset(passphrase, '\0', ਲੜੀ_ਲੰਬਾਈ(passphrase));
	gtk_ਇੰਦਰਾਜ_ਸੈੱਟ_ਪਾਠ(GTK_ਇੰਦਰਾਜ(ਇੰਦਰਾਜ), passphrase);
			
	gnome_dialog_close(GNOME_DIALOG(dialog));
	ਵਾਪਸ (ਨਤੀਜਾ == 0 ? 0 : -1);

	/*
	 * At least one grab failed - ungrab what we got, and report the
	 * failure to the user. Note that XGrabServer() cannot fail.
	 */
 nograbkb:
	gdk_ਸੂਚਕ_ungrab(GDK_CURRENT_ਸਮਾਂ);
 nograb:
	ਜੇ (grab_server)
		XUngrabServer(GDK_DISPLAY());
	gnome_dialog_close(GNOME_DIALOG(dialog));
	
	report_failed_grab();
	ਵਾਪਸ (-1);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ_2;
	ਪੂਰਨ ਨਤੀਜਾ;

	gnome_init("GNOME ssh-askpass", "0.1", argc, argv);

	ਜੇ (argc == 2)
		ਸੁਨੇਹਾ_2 = argv[1];
	ਨਹੀਂਤਾਂ
		ਸੁਨੇਹਾ_2 = "Enter your OpenSSH passphrase:";

	setvbuf(stdout, 0, _IONBF, 0);
	ਨਤੀਜਾ = passphrase_dialog(ਸੁਨੇਹਾ_2);

	ਵਾਪਸ (ਨਤੀਜਾ);
}
