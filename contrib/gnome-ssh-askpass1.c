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

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <gnome.h>
#ಅನ್ತರ್ಭಾವ <X11/Xlib.h>
#ಅನ್ತರ್ಭಾವ <gdk/gdkx.h>

ಶೂನ್ಯ
report_failed_grab (ಶೂನ್ಯ)
{
	GtkWidget *err;

	err = gnome_ಸಂದೇಶ_box_new("Could not grab keyboard or mouse.\n"
		"A malicious client may be eavesdropping on your session.",
				    GNOME_ಸಂದೇಶ_BOX_ERROR, "EXIT", ಖಾಲಿ);
	gtk_ಕಿಟಕಿ_ಗಣ_position(GTK_ಕಿಟಕಿ(err), GTK_WIN_POS_CENTER);
	gtk_object_ಗಣ(GTK_OBJECT(err), "type", GTK_ಕಿಟಕಿ_POPUP, ಖಾಲಿ);

	gnome_dialog_ಸತತ_and_close(GNOME_DIALOG(err));
}

ಪೂರ್ಣಾಂಕ
passphrase_dialog(ಅಕ್ಷರ *ಸಂದೇಶ_2)
{
	ಅಕ್ಷರ *passphrase;
	ಅಕ್ಷರ **messages;
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ, i, grab_server, grab_ಸೂಚಕ;
	GtkWidget *dialog, *ನಮೂದು, *label;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != ಖಾಲಿ);
	grab_ಸೂಚಕ = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != ಖಾಲಿ);

	dialog = gnome_dialog_new("OpenSSH", GNOME_STOCK_BUTTON_OK,
	    GNOME_STOCK_BUTTON_CANCEL, ಖಾಲಿ);

	messages = g_strsplit(ಸಂದೇಶ_2, "\\n", 0);
	ಆದರೆ (messages)
		ಗಾಗಿ(i = 0; messages[i]; i++) {
			label = gtk_label_new(messages[i]);
			gtk_box_pack_ಆರಂಭ(GTK_BOX(GNOME_DIALOG(dialog)->vbox),
			    label, FALSE, FALSE, 0);
		}

	ನಮೂದು = gtk_ನಮೂದು_new();
	gtk_box_pack_ಆರಂಭ(GTK_BOX(GNOME_DIALOG(dialog)->vbox), ನಮೂದು, FALSE,
	    FALSE, 0);
	gtk_ನಮೂದು_ಗಣ_visibility(GTK_ನಮೂದು(ನಮೂದು), FALSE);
	gtk_widget_grab_focus(ನಮೂದು);

	/* Center window and prepare for grab */
	gtk_object_ಗಣ(GTK_OBJECT(dialog), "type", GTK_ಕಿಟಕಿ_POPUP, ಖಾಲಿ);
	gnome_dialog_ಗಣ_default(GNOME_DIALOG(dialog), 0);
	gtk_ಕಿಟಕಿ_ಗಣ_position (GTK_ಕಿಟಕಿ(dialog), GTK_WIN_POS_CENTER);
	gtk_ಕಿಟಕಿ_ಗಣ_policy(GTK_ಕಿಟಕಿ(dialog), FALSE, FALSE, TRUE);
	gnome_dialog_close_hides(GNOME_DIALOG(dialog), TRUE);
	gtk_container_ಗಣ_border_ಅಗಲ(GTK_CONTAINER(GNOME_DIALOG(dialog)->vbox),
	    GNOME_PAD);
	gtk_widget_show_all(dialog);

	/* Grab focus */
	ಆದರೆ (grab_server)
		XGrabServer(GDK_DISPLAY());
	ಆದರೆ (grab_ಸೂಚಕ && gdk_ಸೂಚಕ_grab(dialog->ಕಿಟಕಿ, TRUE, 0,
	    ಖಾಲಿ, ಖಾಲಿ, GDK_CURRENT_ಸಮಯ))
		ಹೋಗು nograb;
	ಆದರೆ (gdk_keyboard_grab(dialog->ಕಿಟಕಿ, FALSE, GDK_CURRENT_ಸಮಯ))
		ಹೋಗು nograbkb;

	/* Make <enter> close dialog */
	gnome_dialog_editable_enters(GNOME_DIALOG(dialog), GTK_EDITABLE(ನಮೂದು));

	/* Run dialog */
	ಫಲಿತಾಂಶ = gnome_dialog_ಸತತ(GNOME_DIALOG(dialog));

	/* Ungrab */
	ಆದರೆ (grab_server)
		XUngrabServer(GDK_DISPLAY());
	ಆದರೆ (grab_ಸೂಚಕ)
		gdk_ಸೂಚಕ_ungrab(GDK_CURRENT_ಸಮಯ);
	gdk_keyboard_ungrab(GDK_CURRENT_ಸಮಯ);
	gdk_flush();

	/* Report passphrase if user selected OK */
	passphrase = gtk_ನಮೂದು_get_ಪಠ್ಯ(GTK_ನಮೂದು(ನಮೂದು));
	ಆದರೆ (ಫಲಿತಾಂಶ == 0)
		puts(passphrase);
		
	/* Zero passphrase in memory */
	memset(passphrase, '\0', ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
	gtk_ನಮೂದು_ಗಣ_ಪಠ್ಯ(GTK_ನಮೂದು(ನಮೂದು), passphrase);
			
	gnome_dialog_close(GNOME_DIALOG(dialog));
	ಹಿಂತಿರುಗಿ (ಫಲಿತಾಂಶ == 0 ? 0 : -1);

	/*
	 * At least one grab failed - ungrab what we got, and report the
	 * failure to the user. Note that XGrabServer() cannot fail.
	 */
 nograbkb:
	gdk_ಸೂಚಕ_ungrab(GDK_CURRENT_ಸಮಯ);
 nograb:
	ಆದರೆ (grab_server)
		XUngrabServer(GDK_DISPLAY());
	gnome_dialog_close(GNOME_DIALOG(dialog));
	
	report_failed_grab();
	ಹಿಂತಿರುಗಿ (-1);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಅಕ್ಷರ *ಸಂದೇಶ_2;
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ;

	gnome_init("GNOME ssh-askpass", "0.1", argc, argv);

	ಆದರೆ (argc == 2)
		ಸಂದೇಶ_2 = argv[1];
	ಇಲ್ಲದಿದ್ದರೆ
		ಸಂದೇಶ_2 = "Enter your OpenSSH passphrase:";

	setvbuf(stdout, 0, _IONBF, 0);
	ಫಲಿತಾಂಶ = passphrase_dialog(ಸಂದೇಶ_2);

	ಹಿಂತಿರುಗಿ (ಫಲಿತಾಂಶ);
}
