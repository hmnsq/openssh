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

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <gnome.h>
#ضمن <X11/Xlib.h>
#ضمن <gdk/gdkx.h>

فراغ
report_failed_grab (فراغ)
{
	GtkWidget *err;

	err = gnome_پيغام_box_new("Could not grab keyboard or mouse.\n"
		"A malicious client may be eavesdropping on your session.",
				    GNOME_پيغام_BOX_ERROR, "EXIT", عدم);
	gtk_دري_سيٽ_position(GTK_دري(err), GTK_WIN_POS_CENTER);
	gtk_object_سيٽ(GTK_OBJECT(err), "type", GTK_دري_POPUP, عدم);

	gnome_dialog_لاڳيتو_and_close(GNOME_DIALOG(err));
}

صحيح
passphrase_dialog(حرف *پيغام)
{
	حرف *passphrase;
	حرف **messages;
	صحيح نتيجو, i, grab_server, grab_اشارو;
	GtkWidget *dialog, *داخلا, *label;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != عدم);
	grab_اشارو = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != عدم);

	dialog = gnome_dialog_new("OpenSSH", GNOME_STOCK_BUTTON_OK,
	    GNOME_STOCK_BUTTON_CANCEL, عدم);

	messages = g_strsplit(پيغام, "\\n", 0);
	إذا (messages)
		لكل(i = 0; messages[i]; i++) {
			label = gtk_label_new(messages[i]);
			gtk_box_pack_شروعات(GTK_BOX(GNOME_DIALOG(dialog)->vbox),
			    label, FALSE, FALSE, 0);
		}

	داخلا = gtk_داخلا_new();
	gtk_box_pack_شروعات(GTK_BOX(GNOME_DIALOG(dialog)->vbox), داخلا, FALSE,
	    FALSE, 0);
	gtk_داخلا_سيٽ_visibility(GTK_داخلا(داخلا), FALSE);
	gtk_widget_grab_focus(داخلا);

	/* Center window and prepare for grab */
	gtk_object_سيٽ(GTK_OBJECT(dialog), "type", GTK_دري_POPUP, عدم);
	gnome_dialog_سيٽ_default(GNOME_DIALOG(dialog), 0);
	gtk_دري_سيٽ_position (GTK_دري(dialog), GTK_WIN_POS_CENTER);
	gtk_دري_سيٽ_policy(GTK_دري(dialog), FALSE, FALSE, TRUE);
	gnome_dialog_close_hides(GNOME_DIALOG(dialog), TRUE);
	gtk_container_سيٽ_border_ويڪر(GTK_CONTAINER(GNOME_DIALOG(dialog)->vbox),
	    GNOME_PAD);
	gtk_widget_show_all(dialog);

	/* Grab focus */
	إذا (grab_server)
		XGrabServer(GDK_DISPLAY());
	إذا (grab_اشارو && gdk_اشارو_grab(dialog->دري, TRUE, 0,
	    عدم, عدم, GDK_CURRENT_وقت))
		اذهب nograb;
	إذا (gdk_keyboard_grab(dialog->دري, FALSE, GDK_CURRENT_وقت))
		اذهب nograbkb;

	/* Make <enter> close dialog */
	gnome_dialog_editable_enters(GNOME_DIALOG(dialog), GTK_EDITABLE(داخلا));

	/* Run dialog */
	نتيجو = gnome_dialog_لاڳيتو(GNOME_DIALOG(dialog));

	/* Ungrab */
	إذا (grab_server)
		XUngrabServer(GDK_DISPLAY());
	إذا (grab_اشارو)
		gdk_اشارو_ungrab(GDK_CURRENT_وقت);
	gdk_keyboard_ungrab(GDK_CURRENT_وقت);
	gdk_flush();

	/* Report passphrase if user selected OK */
	passphrase = gtk_داخلا_get_متن(GTK_داخلا(داخلا));
	إذا (نتيجو == 0)
		puts(passphrase);
		
	/* Zero passphrase in memory */
	memset(passphrase, '\0', لڙي_ڊيگهه(passphrase));
	gtk_داخلا_سيٽ_متن(GTK_داخلا(داخلا), passphrase);
			
	gnome_dialog_close(GNOME_DIALOG(dialog));
	أرجع (نتيجو == 0 ? 0 : -1);

	/*
	 * At least one grab failed - ungrab what we got, and report the
	 * failure to the user. Note that XGrabServer() cannot fail.
	 */
 nograbkb:
	gdk_اشارو_ungrab(GDK_CURRENT_وقت);
 nograb:
	إذا (grab_server)
		XUngrabServer(GDK_DISPLAY());
	gnome_dialog_close(GNOME_DIALOG(dialog));
	
	report_failed_grab();
	أرجع (-1);
}

صحيح
مکيه(صحيح argc, حرف **argv)
{
	حرف *پيغام;
	صحيح نتيجو;

	gnome_init("GNOME ssh-askpass", "0.1", argc, argv);

	إذا (argc == 2)
		پيغام = argv[1];
	وإلا
		پيغام = "Enter your OpenSSH passphrase:";

	setvbuf(stdout, 0, _IONBF, 0);
	نتيجو = passphrase_dialog(پيغام);

	أرجع (نتيجو);
}
