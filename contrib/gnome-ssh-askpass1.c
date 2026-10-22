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

	err = gnome_سنیہا_box_new("Could not grab keyboard or mouse.\n"
		"A malicious client may be eavesdropping on your session.",
				    GNOME_سنیہا_BOX_ERROR, "EXIT", عدم);
	gtk_کھڑکی_سیٹ_position(GTK_کھڑکی(err), GTK_WIN_POS_CENTER);
	gtk_object_سیٹ(GTK_OBJECT(err), "type", GTK_کھڑکی_POPUP, عدم);

	gnome_dialog_لگاتار_and_close(GNOME_DIALOG(err));
}

صحيح
passphrase_dialog(حرف *سنیہا)
{
	حرف *passphrase;
	حرف **messages;
	صحيح نتیجہ, i, grab_server, grab_اشارہ_گر;
	GtkWidget *dialog, *اندراج, *label;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != عدم);
	grab_اشارہ_گر = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != عدم);

	dialog = gnome_dialog_new("OpenSSH", GNOME_STOCK_BUTTON_OK,
	    GNOME_STOCK_BUTTON_CANCEL, عدم);

	messages = g_strsplit(سنیہا, "\\n", 0);
	إذا (messages)
		لكل(i = 0; messages[i]; i++) {
			label = gtk_label_new(messages[i]);
			gtk_box_pack_شروع(GTK_BOX(GNOME_DIALOG(dialog)->vbox),
			    label, FALSE, FALSE, 0);
		}

	اندراج = gtk_اندراج_new();
	gtk_box_pack_شروع(GTK_BOX(GNOME_DIALOG(dialog)->vbox), اندراج, FALSE,
	    FALSE, 0);
	gtk_اندراج_سیٹ_visibility(GTK_اندراج(اندراج), FALSE);
	gtk_widget_grab_focus(اندراج);

	/* Center window and prepare for grab */
	gtk_object_سیٹ(GTK_OBJECT(dialog), "type", GTK_کھڑکی_POPUP, عدم);
	gnome_dialog_سیٹ_default(GNOME_DIALOG(dialog), 0);
	gtk_کھڑکی_سیٹ_position (GTK_کھڑکی(dialog), GTK_WIN_POS_CENTER);
	gtk_کھڑکی_سیٹ_policy(GTK_کھڑکی(dialog), FALSE, FALSE, TRUE);
	gnome_dialog_close_hides(GNOME_DIALOG(dialog), TRUE);
	gtk_container_سیٹ_border_چوڑائی(GTK_CONTAINER(GNOME_DIALOG(dialog)->vbox),
	    GNOME_PAD);
	gtk_widget_show_all(dialog);

	/* Grab focus */
	إذا (grab_server)
		XGrabServer(GDK_DISPLAY());
	إذا (grab_اشارہ_گر && gdk_اشارہ_گر_grab(dialog->کھڑکی, TRUE, 0,
	    عدم, عدم, GDK_CURRENT_ویلا))
		اذهب nograb;
	إذا (gdk_keyboard_grab(dialog->کھڑکی, FALSE, GDK_CURRENT_ویلا))
		اذهب nograbkb;

	/* Make <enter> close dialog */
	gnome_dialog_editable_enters(GNOME_DIALOG(dialog), GTK_EDITABLE(اندراج));

	/* Run dialog */
	نتیجہ = gnome_dialog_لگاتار(GNOME_DIALOG(dialog));

	/* Ungrab */
	إذا (grab_server)
		XUngrabServer(GDK_DISPLAY());
	إذا (grab_اشارہ_گر)
		gdk_اشارہ_گر_ungrab(GDK_CURRENT_ویلا);
	gdk_keyboard_ungrab(GDK_CURRENT_ویلا);
	gdk_flush();

	/* Report passphrase if user selected OK */
	passphrase = gtk_اندراج_get_متن(GTK_اندراج(اندراج));
	إذا (نتیجہ == 0)
		puts(passphrase);
		
	/* Zero passphrase in memory */
	memset(passphrase, '\0', لڑی_لمبائی(passphrase));
	gtk_اندراج_سیٹ_متن(GTK_اندراج(اندراج), passphrase);
			
	gnome_dialog_close(GNOME_DIALOG(dialog));
	أرجع (نتیجہ == 0 ? 0 : -1);

	/*
	 * At least one grab failed - ungrab what we got, and report the
	 * failure to the user. Note that XGrabServer() cannot fail.
	 */
 nograbkb:
	gdk_اشارہ_گر_ungrab(GDK_CURRENT_ویلا);
 nograb:
	إذا (grab_server)
		XUngrabServer(GDK_DISPLAY());
	gnome_dialog_close(GNOME_DIALOG(dialog));
	
	report_failed_grab();
	أرجع (-1);
}

صحيح
مکھ(صحيح argc, حرف **argv)
{
	حرف *سنیہا;
	صحيح نتیجہ;

	gnome_init("GNOME ssh-askpass", "0.1", argc, argv);

	إذا (argc == 2)
		سنیہا = argv[1];
	وإلا
		سنیہا = "Enter your OpenSSH passphrase:";

	setvbuf(stdout, 0, _IONBF, 0);
	نتیجہ = passphrase_dialog(سنیہا);

	أرجع (نتیجہ);
}
