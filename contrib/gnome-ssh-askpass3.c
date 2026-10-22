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

#وصف_ڪريو GRAB_TRIES	16
#وصف_ڪريو GRAB_WAIT	250 /* milliseconds */

#وصف_ڪريو PROMPT_داخلا	0
#وصف_ڪريو PROMPT_CONFIRM	1
#وصف_ڪريو PROMPT_NONE	2

/*
 * Compile with:
 *
 * cc -Wall `pkg-config --cflags gtk+-2.0` \
 *    gnome-ssh-askpass2.c -o gnome-ssh-askpass \
 *    `pkg-config --libs gtk+-2.0`
 *
 */

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن <X11/Xlib.h>
#ضمن <gtk/gtk.h>
#ضمن <gdk/gdkx.h>
#ضمن <gdk/gdkkeysyms.h>

ساكن فراغ
ok_dialog(GtkWidget *داخلا, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

ساكن gboolean
check_none(GtkWidget *widget, Gdk_Event_ڪنجي *event, gpointer dialog)
{
	بدل (event->keyval) {
	حالة GDK_ڪنجي_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		أرجع TRUE;
	حالة GDK_ڪنجي_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		أرجع TRUE;
	افتراضي:
		/* eat all other key events */
		أرجع TRUE;
	}
}

ساكن صحيح
parse_env_hex_color(ثابت حرف *env, GdkColor *c)
{
	ثابت حرف *s;
	بنانشان ڊگهو ul;
	حرف *ep;
	سائيز_t n;

	إذا ((s = getenv(env)) == عدم)
		أرجع 0;

	memset(c, 0, حجم(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	إذا (*s == '#')
		s++;
	وإلا إذا (لڙي_ڀيٽ(s, "0x", 2) == 0)
		s += 2;
	n = لڙي_ڊيگهه(s);
	إذا (n != 3 && n != 6)
		اذهب bad;
	ul = strtoul(s, &ep, 16);
	إذا (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		أرجع 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	إذا (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} وإلا {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	أرجع 1;
}

ساكن صحيح
passphrase_dialog(حرف *پيغام, صحيح prompt_type)
{
	ثابت حرف *failed;
	حرف *passphrase, *local;
	صحيح نتيجو, grab_tries, grab_server, grab_اشارو;
	صحيح buttons, default_response;
	GtkWidget *والد_دري, *dialog, *داخلا, *err;
	Gdk_Grab_حالت حالت;
	GdkColor fg, bg;
	GdkSeat *seat;
	GdkDisplay *display;
	GdkSeatCapabilities caps;
	صحيح fg_سيٽ = 0, bg_سيٽ = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != عدم);
	grab_اشارو = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != عدم);
	grab_tries = 0;

	fg_سيٽ = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_سيٽ = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	والد_دري = gtk_دري_new(GTK_دري_TOPLEVEL);

	بدل (prompt_type) {
	حالة PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		اكسر;
	حالة PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		اكسر;
	افتراضي:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		اكسر;
	}

	dialog = gtk_پيغام_dialog_new(GTK_دري(والد_دري), 0,
	    GTK_پيغام_QUESTION, buttons, "%s", پيغام);

	gtk_دري_سيٽ_title(GTK_دري(dialog), "OpenSSH");
	gtk_دري_سيٽ_position (GTK_دري(dialog), GTK_WIN_POS_CENTER);
	gtk_دري_سيٽ_keep_above(GTK_دري(dialog), TRUE);
	gtk_dialog_سيٽ_default_response(GTK_DIALOG(dialog), default_response);
	gtk_دري_سيٽ_keep_above(GTK_دري(dialog), TRUE);

	إذا (fg_سيٽ)
		gtk_widget_modify_fg(dialog, GTK_STATE_عام, &fg);
	إذا (bg_سيٽ)
		gtk_widget_modify_bg(dialog, GTK_STATE_عام, &bg);

	إذا (prompt_type == PROMPT_داخلا || prompt_type == PROMPT_NONE) {
		داخلا = gtk_داخلا_new();
		إذا (fg_سيٽ)
			gtk_widget_modify_fg(داخلا, GTK_STATE_عام, &fg);
		إذا (bg_سيٽ)
			gtk_widget_modify_bg(داخلا, GTK_STATE_عام, &bg);
		gtk_box_pack_شروعات(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    داخلا, FALSE, FALSE, 0);
		gtk_داخلا_سيٽ_visibility(GTK_داخلا(داخلا), FALSE);
		gtk_widget_grab_focus(داخلا);
		إذا (prompt_type == PROMPT_داخلا) {
			gtk_widget_show(داخلا);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(داخلا), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} وإلا {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(داخلا);
			g_signal_connect(G_OBJECT(داخلا), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}
	/* Grab focus */
	gtk_widget_show_now(dialog);
	display = gtk_widget_get_display(GTK_WIDGET(dialog));
	seat = gdk_display_get_default_seat(display);
	caps = GDK_SEAT_CAPABILITY_KEYBOARD;
	إذا (grab_اشارو)
		caps |= GDK_SEAT_CAPABILITY_ALL_POINTING;
	إذا (grab_server)
		caps = GDK_SEAT_CAPABILITY_ALL;
	لكل (;;) {
		حالت = gdk_seat_grab(seat, gtk_widget_get_دري(dialog),
		    caps, TRUE, عدم, عدم, عدم, عدم);
		إذا (حالت == GDK_GRAB_SUCCESS)
			اكسر;
		usleep(GRAB_WAIT * 1000);
		إذا (++grab_tries > GRAB_TRIES)
			اذهب nograb;
	}

	نتيجو = gtk_dialog_لاڳيتو(GTK_DIALOG(dialog));

	/* Ungrab */
	gdk_seat_ungrab(seat);
	gdk_display_flush(display);

	/* Report passphrase if user selected OK */
	إذا (prompt_type == PROMPT_داخلا) {
		passphrase = g_strdup(gtk_داخلا_get_متن(GTK_داخلا(داخلا)));
		إذا (نتيجو == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    لڙي_ڊيگهه(passphrase), عدم, عدم, عدم);
			إذا (local != عدم) {
				puts(local);
				memset(local, '\0', لڙي_ڊيگهه(local));
				g_free(local);
			} وإلا {
				puts(passphrase);
			}
		}
		/* Zero passphrase in memory */
		memset(passphrase, '\b', لڙي_ڊيگهه(passphrase));
		gtk_داخلا_سيٽ_متن(GTK_داخلا(داخلا), passphrase);
		memset(passphrase, '\0', لڙي_ڊيگهه(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	إذا (نتيجو != GTK_RESPONSE_OK && نتيجو != GTK_RESPONSE_YES)
		أرجع -1;
	أرجع 0;

 nograb:
	gtk_widget_destroy(dialog);
	err = gtk_پيغام_dialog_new(GTK_دري(والد_دري), 0,
	    GTK_پيغام_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab input. A malicious client may be eavesdropping "
	    "on your session.");
	gtk_دري_سيٽ_position(GTK_دري(err), GTK_WIN_POS_CENTER);
	gtk_dialog_لاڳيتو(GTK_DIALOG(err));
	gtk_widget_destroy(err);
	أرجع -1;
}

صحيح
مکيه(صحيح argc, حرف **argv)
{
	حرف *پيغام, *prompt_گهڻائي;
	صحيح نتيجو, prompt_type = PROMPT_داخلا;

	gtk_init(&argc, &argv);

	إذا (argc > 1) {
		پيغام = g_strjoinv(" ", argv + 1);
	} وإلا {
		پيغام = g_strdup("Enter your OpenSSH passphrase:");
	}

	إذا ((prompt_گهڻائي = getenv("SSH_ASKPASS_PROMPT")) != عدم) {
		إذا (strcasecmp(prompt_گهڻائي, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		وإلا إذا (strcasecmp(prompt_گهڻائي, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	نتيجو = passphrase_dialog(پيغام, prompt_type);
	g_free(پيغام);

	أرجع (نتيجو);
}
