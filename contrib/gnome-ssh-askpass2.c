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

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ GRAB_TRIES	16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ GRAB_WAIT	250 /* milliseconds */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PROMPT_ਇੰਦਰਾਜ	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PROMPT_CONFIRM	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PROMPT_NONE	2

/*
 * Compile with:
 *
 * cc -Wall `pkg-config --cflags gtk+-2.0` \
 *    gnome-ssh-askpass2.c -o gnome-ssh-askpass \
 *    `pkg-config --libs gtk+-2.0`
 *
 */

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <X11/Xlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <gtk/gtk.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <gdk/gdkx.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <gdk/gdkkeysyms.h>

ਸਥਿਰ ਖਾਲੀ
report_failed_grab (GtkWidget *ਮਾਪਾ_ਖਿੜਕੀ, ਅਚਲ ਅੱਖਰ *what)
{
	GtkWidget *err;

	err = gtk_ਸੁਨੇਹਾ_dialog_new(GTK_ਖਿੜਕੀ(ਮਾਪਾ_ਖਿੜਕੀ), 0,
	    GTK_ਸੁਨੇਹਾ_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab %s. A malicious client may be eavesdropping "
	    "on your session.", what);
	gtk_ਖਿੜਕੀ_ਸੈੱਟ_position(GTK_ਖਿੜਕੀ(err), GTK_WIN_POS_CENTER);

	gtk_dialog_ਲੜੀਵਾਰ(GTK_DIALOG(err));

	gtk_widget_destroy(err);
}

ਸਥਿਰ ਖਾਲੀ
ok_dialog(GtkWidget *ਇੰਦਰਾਜ, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

ਸਥਿਰ gboolean
check_none(GtkWidget *widget, Gdk_Event_ਕੁੰਜੀ *event, gpointer dialog)
{
	ਚੋਣ (event->keyval) {
	ਹਾਲਤ GDK_ਕੁੰਜੀ_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		ਵਾਪਸ TRUE;
	ਹਾਲਤ GDK_ਕੁੰਜੀ_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		ਵਾਪਸ TRUE;
	ਮੂਲ:
		/* eat all other key events */
		ਵਾਪਸ TRUE;
	}
}

ਸਥਿਰ ਪੂਰਨ
parse_env_hex_color(ਅਚਲ ਅੱਖਰ *env, GdkColor *c)
{
	ਅਚਲ ਅੱਖਰ *s;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul;
	ਅੱਖਰ *ep;
	ਮਾਪ_t n;

	ਜੇ ((s = getenv(env)) == ਨਿਰਾ)
		ਵਾਪਸ 0;

	memset(c, 0, ਆਕਾਰ(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	ਜੇ (*s == '#')
		s++;
	ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(s, "0x", 2) == 0)
		s += 2;
	n = ਲੜੀ_ਲੰਬਾਈ(s);
	ਜੇ (n != 3 && n != 6)
		ਜਾਓ bad;
	ul = strtoul(s, &ep, 16);
	ਜੇ (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		ਵਾਪਸ 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	ਜੇ (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} ਨਹੀਂਤਾਂ {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
passphrase_dialog(ਅੱਖਰ *ਸੁਨੇਹਾ_2, ਪੂਰਨ prompt_type)
{
	ਅਚਲ ਅੱਖਰ *failed;
	ਅੱਖਰ *passphrase, *local;
	ਪੂਰਨ ਨਤੀਜਾ, grab_tries, grab_server, grab_ਸੂਚਕ;
	ਪੂਰਨ buttons, default_response;
	GtkWidget *ਮਾਪਾ_ਖਿੜਕੀ, *dialog, *ਇੰਦਰਾਜ;
	Gdk_Grab_ਸਥਿਤੀ ਸਥਿਤੀ;
	GdkColor fg, bg;
	ਪੂਰਨ fg_ਸੈੱਟ = 0, bg_ਸੈੱਟ = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != ਨਿਰਾ);
	grab_ਸੂਚਕ = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != ਨਿਰਾ);
	grab_tries = 0;

	fg_ਸੈੱਟ = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_ਸੈੱਟ = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	ਮਾਪਾ_ਖਿੜਕੀ = gtk_ਖਿੜਕੀ_new(GTK_ਖਿੜਕੀ_TOPLEVEL);

	ਚੋਣ (prompt_type) {
	ਹਾਲਤ PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		ਰੋਕੋ;
	ਹਾਲਤ PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		ਰੋਕੋ;
	ਮੂਲ:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		ਰੋਕੋ;
	}

	dialog = gtk_ਸੁਨੇਹਾ_dialog_new(GTK_ਖਿੜਕੀ(ਮਾਪਾ_ਖਿੜਕੀ), 0,
	    GTK_ਸੁਨੇਹਾ_QUESTION, buttons, "%s", ਸੁਨੇਹਾ_2);

	gtk_ਖਿੜਕੀ_ਸੈੱਟ_title(GTK_ਖਿੜਕੀ(dialog), "OpenSSH");
	gtk_ਖਿੜਕੀ_ਸੈੱਟ_position (GTK_ਖਿੜਕੀ(dialog), GTK_WIN_POS_CENTER);
	gtk_ਖਿੜਕੀ_ਸੈੱਟ_keep_above(GTK_ਖਿੜਕੀ(dialog), TRUE);
	gtk_dialog_ਸੈੱਟ_default_response(GTK_DIALOG(dialog), default_response);
	gtk_ਖਿੜਕੀ_ਸੈੱਟ_keep_above(GTK_ਖਿੜਕੀ(dialog), TRUE);

	ਜੇ (fg_ਸੈੱਟ)
		gtk_widget_modify_fg(dialog, GTK_STATE_ਸਾਧਾਰਨ, &fg);
	ਜੇ (bg_ਸੈੱਟ)
		gtk_widget_modify_bg(dialog, GTK_STATE_ਸਾਧਾਰਨ, &bg);

	ਜੇ (prompt_type == PROMPT_ਇੰਦਰਾਜ || prompt_type == PROMPT_NONE) {
		ਇੰਦਰਾਜ = gtk_ਇੰਦਰਾਜ_new();
		ਜੇ (fg_ਸੈੱਟ)
			gtk_widget_modify_fg(ਇੰਦਰਾਜ, GTK_STATE_ਸਾਧਾਰਨ, &fg);
		ਜੇ (bg_ਸੈੱਟ)
			gtk_widget_modify_bg(ਇੰਦਰਾਜ, GTK_STATE_ਸਾਧਾਰਨ, &bg);
		gtk_box_pack_ਸ਼ੁਰੂ(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    ਇੰਦਰਾਜ, FALSE, FALSE, 0);
		gtk_ਇੰਦਰਾਜ_ਸੈੱਟ_visibility(GTK_ਇੰਦਰਾਜ(ਇੰਦਰਾਜ), FALSE);
		gtk_widget_grab_focus(ਇੰਦਰਾਜ);
		ਜੇ (prompt_type == PROMPT_ਇੰਦਰਾਜ) {
			gtk_widget_show(ਇੰਦਰਾਜ);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(ਇੰਦਰਾਜ), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} ਨਹੀਂਤਾਂ {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(ਇੰਦਰਾਜ);
			g_signal_connect(G_OBJECT(ਇੰਦਰਾਜ), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}

	/* Grab focus */
	gtk_widget_show_now(dialog);
	ਜੇ (grab_ਸੂਚਕ) {
		ਲਈ(;;) {
			ਸਥਿਤੀ = gdk_ਸੂਚਕ_grab(
			    (gtk_widget_get_ਖਿੜਕੀ(GTK_WIDGET(dialog))), TRUE,
			    0, ਨਿਰਾ, ਨਿਰਾ, GDK_CURRENT_ਸਮਾਂ);
			ਜੇ (ਸਥਿਤੀ == GDK_GRAB_SUCCESS)
				ਰੋਕੋ;
			usleep(GRAB_WAIT * 1000);
			ਜੇ (++grab_tries > GRAB_TRIES) {
				failed = "mouse";
				ਜਾਓ nograb;
			}
		}
	}
	ਲਈ(;;) {
		ਸਥਿਤੀ = gdk_keyboard_grab(
		    gtk_widget_get_ਖਿੜਕੀ(GTK_WIDGET(dialog)), FALSE,
		    GDK_CURRENT_ਸਮਾਂ);
		ਜੇ (ਸਥਿਤੀ == GDK_GRAB_SUCCESS)
			ਰੋਕੋ;
		usleep(GRAB_WAIT * 1000);
		ਜੇ (++grab_tries > GRAB_TRIES) {
			failed = "keyboard";
			ਜਾਓ nograbkb;
		}
	}
	ਜੇ (grab_server) {
		gdk_x11_grab_server();
	}

	ਨਤੀਜਾ = gtk_dialog_ਲੜੀਵਾਰ(GTK_DIALOG(dialog));

	/* Ungrab */
	ਜੇ (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	ਜੇ (grab_ਸੂਚਕ)
		gdk_ਸੂਚਕ_ungrab(GDK_CURRENT_ਸਮਾਂ);
	gdk_keyboard_ungrab(GDK_CURRENT_ਸਮਾਂ);
	gdk_flush();

	/* Report passphrase if user selected OK */
	ਜੇ (prompt_type == PROMPT_ਇੰਦਰਾਜ) {
		passphrase = g_strdup(gtk_ਇੰਦਰਾਜ_get_ਪਾਠ(GTK_ਇੰਦਰਾਜ(ਇੰਦਰਾਜ)));
		ਜੇ (ਨਤੀਜਾ == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    ਲੜੀ_ਲੰਬਾਈ(passphrase), ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ);
			ਜੇ (local != ਨਿਰਾ) {
				puts(local);
				memset(local, '\0', ਲੜੀ_ਲੰਬਾਈ(local));
				g_free(local);
			} ਨਹੀਂਤਾਂ {
				puts(passphrase);
			}
		}
		/* Zero passphrase in memory */
		memset(passphrase, '\b', ਲੜੀ_ਲੰਬਾਈ(passphrase));
		gtk_ਇੰਦਰਾਜ_ਸੈੱਟ_ਪਾਠ(GTK_ਇੰਦਰਾਜ(ਇੰਦਰਾਜ), passphrase);
		memset(passphrase, '\0', ਲੜੀ_ਲੰਬਾਈ(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	ਜੇ (ਨਤੀਜਾ != GTK_RESPONSE_OK && ਨਤੀਜਾ != GTK_RESPONSE_YES)
		ਵਾਪਸ -1;
	ਵਾਪਸ 0;

 nograbkb:
	/*
	 * At least one grab failed - ungrab what we got, and report
	 * the failure to the user.  Note that XGrabServer() cannot
	 * fail.
	 */
	gdk_ਸੂਚਕ_ungrab(GDK_CURRENT_ਸਮਾਂ);
 nograb:
	ਜੇ (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	gtk_widget_destroy(dialog);
	
	report_failed_grab(ਮਾਪਾ_ਖਿੜਕੀ, failed);

	ਵਾਪਸ (-1);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ_2, *prompt_ਬਹੁਲਕ;
	ਪੂਰਨ ਨਤੀਜਾ, prompt_type = PROMPT_ਇੰਦਰਾਜ;

	gtk_init(&argc, &argv);

	ਜੇ (argc > 1) {
		ਸੁਨੇਹਾ_2 = g_strjoinv(" ", argv + 1);
	} ਨਹੀਂਤਾਂ {
		ਸੁਨੇਹਾ_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	ਜੇ ((prompt_ਬਹੁਲਕ = getenv("SSH_ASKPASS_PROMPT")) != ਨਿਰਾ) {
		ਜੇ (strcasecmp(prompt_ਬਹੁਲਕ, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(prompt_ਬਹੁਲਕ, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	ਨਤੀਜਾ = passphrase_dialog(ਸੁਨੇਹਾ_2, prompt_type);
	g_free(ਸੁਨੇਹਾ_2);

	ਵਾਪਸ (ਨਤੀਜਾ);
}
