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

/* GTK2 support by Nalin Dahyabhai <nalin@redhat.com> */

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

#ವ್ಯಾಖ್ಯಾನಿಸು GRAB_TRIES	16
#ವ್ಯಾಖ್ಯಾನಿಸು GRAB_WAIT	250 /* milliseconds */

#ವ್ಯಾಖ್ಯಾನಿಸು PROMPT_ನಮೂದು	0
#ವ್ಯಾಖ್ಯಾನಿಸು PROMPT_CONFIRM	1
#ವ್ಯಾಖ್ಯಾನಿಸು PROMPT_NONE	2

/*
 * Compile with:
 *
 * cc -Wall `pkg-config --cflags gtk+-2.0` \
 *    gnome-ssh-askpass2.c -o gnome-ssh-askpass \
 *    `pkg-config --libs gtk+-2.0`
 *
 */

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ <X11/Xlib.h>
#ಅನ್ತರ್ಭಾವ <gtk/gtk.h>
#ಅನ್ತರ್ಭಾವ <gdk/gdkx.h>
#ಅನ್ತರ್ಭಾವ <gdk/gdkkeysyms.h>

ಸ್ಥಿರ ಶೂನ್ಯ
ok_dialog(GtkWidget *ನಮೂದು, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

ಸ್ಥಿರ gboolean
check_none(GtkWidget *widget, Gdk_Event_ಕೀಲಿ *event, gpointer dialog)
{
	ಆಯ್ಕೆ (event->keyval) {
	ಸ್ಥಿತಿ GDK_ಕೀಲಿ_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		ಹಿಂತಿರುಗಿ TRUE;
	ಸ್ಥಿತಿ GDK_ಕೀಲಿ_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		ಹಿಂತಿರುಗಿ TRUE;
	ಪೂರ್ವನಿಯೋಜಿತ:
		/* eat all other key events */
		ಹಿಂತಿರುಗಿ TRUE;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_env_hex_color(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *env, GdkColor *c)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul;
	ಅಕ್ಷರ *ep;
	ಗಾತ್ರ_t n;

	ಆದರೆ ((s = getenv(env)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	memset(c, 0, ಗಾತ್ರ(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	ಆದರೆ (*s == '#')
		s++;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(s, "0x", 2) == 0)
		s += 2;
	n = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s);
	ಆದರೆ (n != 3 && n != 6)
		ಹೋಗು bad;
	ul = strtoul(s, &ep, 16);
	ಆದರೆ (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		ಹಿಂತಿರುಗಿ 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	ಆದರೆ (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
passphrase_dialog(ಅಕ್ಷರ *ಸಂದೇಶ_2, ಪೂರ್ಣಾಂಕ prompt_type)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *failed;
	ಅಕ್ಷರ *passphrase, *local;
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ, grab_tries, grab_server, grab_ಸೂಚಕ;
	ಪೂರ್ಣಾಂಕ buttons, default_response;
	GtkWidget *ಪೋಷಕ_ಕಿಟಕಿ, *dialog, *ನಮೂದು, *err;
	Gdk_Grab_ಸ್ಥಿತಿ ಸ್ಥಿತಿ_2;
	GdkColor fg, bg;
	GdkSeat *seat;
	GdkDisplay *display;
	GdkSeatCapabilities caps;
	ಪೂರ್ಣಾಂಕ fg_ಗಣ = 0, bg_ಗಣ = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != ಖಾಲಿ);
	grab_ಸೂಚಕ = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != ಖಾಲಿ);
	grab_tries = 0;

	fg_ಗಣ = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_ಗಣ = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	ಪೋಷಕ_ಕಿಟಕಿ = gtk_ಕಿಟಕಿ_new(GTK_ಕಿಟಕಿ_TOPLEVEL);

	ಆಯ್ಕೆ (prompt_type) {
	ಸ್ಥಿತಿ PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		ನಿಲ್ಲಿಸು;
	}

	dialog = gtk_ಸಂದೇಶ_dialog_new(GTK_ಕಿಟಕಿ(ಪೋಷಕ_ಕಿಟಕಿ), 0,
	    GTK_ಸಂದೇಶ_QUESTION, buttons, "%s", ಸಂದೇಶ_2);

	gtk_ಕಿಟಕಿ_ಗಣ_title(GTK_ಕಿಟಕಿ(dialog), "OpenSSH");
	gtk_ಕಿಟಕಿ_ಗಣ_position (GTK_ಕಿಟಕಿ(dialog), GTK_WIN_POS_CENTER);
	gtk_ಕಿಟಕಿ_ಗಣ_keep_above(GTK_ಕಿಟಕಿ(dialog), TRUE);
	gtk_dialog_ಗಣ_default_response(GTK_DIALOG(dialog), default_response);
	gtk_ಕಿಟಕಿ_ಗಣ_keep_above(GTK_ಕಿಟಕಿ(dialog), TRUE);

	ಆದರೆ (fg_ಗಣ)
		gtk_widget_modify_fg(dialog, GTK_STATE_ಸಾಮಾನ್ಯ, &fg);
	ಆದರೆ (bg_ಗಣ)
		gtk_widget_modify_bg(dialog, GTK_STATE_ಸಾಮಾನ್ಯ, &bg);

	ಆದರೆ (prompt_type == PROMPT_ನಮೂದು || prompt_type == PROMPT_NONE) {
		ನಮೂದು = gtk_ನಮೂದು_new();
		ಆದರೆ (fg_ಗಣ)
			gtk_widget_modify_fg(ನಮೂದು, GTK_STATE_ಸಾಮಾನ್ಯ, &fg);
		ಆದರೆ (bg_ಗಣ)
			gtk_widget_modify_bg(ನಮೂದು, GTK_STATE_ಸಾಮಾನ್ಯ, &bg);
		gtk_box_pack_ಆರಂಭ(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    ನಮೂದು, FALSE, FALSE, 0);
		gtk_ನಮೂದು_ಗಣ_visibility(GTK_ನಮೂದು(ನಮೂದು), FALSE);
		gtk_widget_grab_focus(ನಮೂದು);
		ಆದರೆ (prompt_type == PROMPT_ನಮೂದು) {
			gtk_widget_show(ನಮೂದು);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(ನಮೂದು), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} ಇಲ್ಲದಿದ್ದರೆ {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(ನಮೂದು);
			g_signal_connect(G_OBJECT(ನಮೂದು), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}
	/* Grab focus */
	gtk_widget_show_now(dialog);
	display = gtk_widget_get_display(GTK_WIDGET(dialog));
	seat = gdk_display_get_default_seat(display);
	caps = GDK_SEAT_CAPABILITY_KEYBOARD;
	ಆದರೆ (grab_ಸೂಚಕ)
		caps |= GDK_SEAT_CAPABILITY_ALL_POINTING;
	ಆದರೆ (grab_server)
		caps = GDK_SEAT_CAPABILITY_ALL;
	ಗಾಗಿ (;;) {
		ಸ್ಥಿತಿ_2 = gdk_seat_grab(seat, gtk_widget_get_ಕಿಟಕಿ(dialog),
		    caps, TRUE, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ);
		ಆದರೆ (ಸ್ಥಿತಿ_2 == GDK_GRAB_SUCCESS)
			ನಿಲ್ಲಿಸು;
		usleep(GRAB_WAIT * 1000);
		ಆದರೆ (++grab_tries > GRAB_TRIES)
			ಹೋಗು nograb;
	}

	ಫಲಿತಾಂಶ = gtk_dialog_ಸತತ(GTK_DIALOG(dialog));

	/* Ungrab */
	gdk_seat_ungrab(seat);
	gdk_display_flush(display);

	/* Report passphrase if user selected OK */
	ಆದರೆ (prompt_type == PROMPT_ನಮೂದು) {
		passphrase = g_strdup(gtk_ನಮೂದು_get_ಪಠ್ಯ(GTK_ನಮೂದು(ನಮೂದು)));
		ಆದರೆ (ಫಲಿತಾಂಶ == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase), ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ);
			ಆದರೆ (local != ಖಾಲಿ) {
				puts(local);
				memset(local, '\0', ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(local));
				g_free(local);
			} ಇಲ್ಲದಿದ್ದರೆ {
				puts(passphrase);
			}
		}
		/* Zero passphrase in memory */
		memset(passphrase, '\b', ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
		gtk_ನಮೂದು_ಗಣ_ಪಠ್ಯ(GTK_ನಮೂದು(ನಮೂದು), passphrase);
		memset(passphrase, '\0', ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	ಆದರೆ (ಫಲಿತಾಂಶ != GTK_RESPONSE_OK && ಫಲಿತಾಂಶ != GTK_RESPONSE_YES)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ 0;

 nograb:
	gtk_widget_destroy(dialog);
	err = gtk_ಸಂದೇಶ_dialog_new(GTK_ಕಿಟಕಿ(ಪೋಷಕ_ಕಿಟಕಿ), 0,
	    GTK_ಸಂದೇಶ_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab input. A malicious client may be eavesdropping "
	    "on your session.");
	gtk_ಕಿಟಕಿ_ಗಣ_position(GTK_ಕಿಟಕಿ(err), GTK_WIN_POS_CENTER);
	gtk_dialog_ಸತತ(GTK_DIALOG(err));
	gtk_widget_destroy(err);
	ಹಿಂತಿರುಗಿ -1;
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಅಕ್ಷರ *ಸಂದೇಶ_2, *prompt_ಬಹುಲಕ;
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ, prompt_type = PROMPT_ನಮೂದು;

	gtk_init(&argc, &argv);

	ಆದರೆ (argc > 1) {
		ಸಂದೇಶ_2 = g_strjoinv(" ", argv + 1);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಸಂದೇಶ_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	ಆದರೆ ((prompt_ಬಹುಲಕ = getenv("SSH_ASKPASS_PROMPT")) != ಖಾಲಿ) {
		ಆದರೆ (strcasecmp(prompt_ಬಹುಲಕ, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(prompt_ಬಹುಲಕ, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	ಫಲಿತಾಂಶ = passphrase_dialog(ಸಂದೇಶ_2, prompt_type);
	g_free(ಸಂದೇಶ_2);

	ಹಿಂತಿರುಗಿ (ಫಲಿತಾಂಶ);
}
