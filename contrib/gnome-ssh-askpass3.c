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

#تعریف_کرو GRAB_TRIES	16
#تعریف_کرو GRAB_WAIT	250 /* milliseconds */

#تعریف_کرو PROMPT_اندراج	0
#تعریف_کرو PROMPT_CONFIRM	1
#تعریف_کرو PROMPT_NONE	2

/*
 * Compile with:
 *
 * cc -Wall `pkg-config --cflags gtk+-2.0` \
 *    gnome-ssh-askpass2.c -o gnome-ssh-askpass \
 *    `pkg-config --libs gtk+-2.0`
 *
 */

#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل <X11/Xlib.h>
#شامل <gtk/gtk.h>
#شامل <gdk/gdkx.h>
#شامل <gdk/gdkkeysyms.h>

ساکن خالی
ok_dialog(GtkWidget *اندراج_2, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

ساکن gboolean
check_none(GtkWidget *widget, Gdk_Event_کلید *event, gpointer dialog)
{
	انتخاب (event->keyval) {
	حالت GDK_کلید_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		واپس TRUE;
	حالت GDK_کلید_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		واپس TRUE;
	طےشدہ:
		/* eat all other key events */
		واپس TRUE;
	}
}

ساکن صحیح
parse_env_hex_color(ثابت حرف *env, GdkColor *c)
{
	ثابت حرف *s;
	غیرعلامتی طویل ul;
	حرف *ep;
	سائز_t n;

	اگر ((s = getenv(env)) == تہی)
		واپس 0;

	memset(c, 0, حجم(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	اگر (*s == '#')
		s++;
	ورنہ اگر (لڑی_موازنہ(s, "0x", 2) == 0)
		s += 2;
	n = لڑی_لمبائی(s);
	اگر (n != 3 && n != 6)
		جاؤ bad;
	ul = strtoul(s, &ep, 16);
	اگر (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		واپس 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	اگر (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} ورنہ {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	واپس 1;
}

ساکن صحیح
passphrase_dialog(حرف *پیغام_2, صحیح prompt_type)
{
	ثابت حرف *failed;
	حرف *passphrase, *local;
	صحیح نتیجہ, grab_tries, grab_server, grab_اشارہ_گر;
	صحیح buttons, default_response;
	GtkWidget *والد_کھڑکی, *dialog, *اندراج_2, *err;
	Gdk_Grab_حالت حالت_2;
	GdkColor fg, bg;
	GdkSeat *seat;
	GdkDisplay *display;
	GdkSeatCapabilities caps;
	صحیح fg_سیٹ = 0, bg_سیٹ = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != تہی);
	grab_اشارہ_گر = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != تہی);
	grab_tries = 0;

	fg_سیٹ = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_سیٹ = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	والد_کھڑکی = gtk_کھڑکی_new(GTK_کھڑکی_TOPLEVEL);

	انتخاب (prompt_type) {
	حالت PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		توڑو;
	حالت PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		توڑو;
	طےشدہ:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		توڑو;
	}

	dialog = gtk_پیغام_dialog_new(GTK_کھڑکی(والد_کھڑکی), 0,
	    GTK_پیغام_QUESTION, buttons, "%s", پیغام_2);

	gtk_کھڑکی_سیٹ_title(GTK_کھڑکی(dialog), "OpenSSH");
	gtk_کھڑکی_سیٹ_position (GTK_کھڑکی(dialog), GTK_WIN_POS_CENTER);
	gtk_کھڑکی_سیٹ_keep_above(GTK_کھڑکی(dialog), TRUE);
	gtk_dialog_سیٹ_default_response(GTK_DIALOG(dialog), default_response);
	gtk_کھڑکی_سیٹ_keep_above(GTK_کھڑکی(dialog), TRUE);

	اگر (fg_سیٹ)
		gtk_widget_modify_fg(dialog, GTK_STATE_معمول, &fg);
	اگر (bg_سیٹ)
		gtk_widget_modify_bg(dialog, GTK_STATE_معمول, &bg);

	اگر (prompt_type == PROMPT_اندراج || prompt_type == PROMPT_NONE) {
		اندراج_2 = gtk_اندراج_new();
		اگر (fg_سیٹ)
			gtk_widget_modify_fg(اندراج_2, GTK_STATE_معمول, &fg);
		اگر (bg_سیٹ)
			gtk_widget_modify_bg(اندراج_2, GTK_STATE_معمول, &bg);
		gtk_box_pack_آغاز(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    اندراج_2, FALSE, FALSE, 0);
		gtk_اندراج_سیٹ_visibility(GTK_اندراج(اندراج_2), FALSE);
		gtk_widget_grab_focus(اندراج_2);
		اگر (prompt_type == PROMPT_اندراج) {
			gtk_widget_show(اندراج_2);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(اندراج_2), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} ورنہ {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(اندراج_2);
			g_signal_connect(G_OBJECT(اندراج_2), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}
	/* Grab focus */
	gtk_widget_show_now(dialog);
	display = gtk_widget_get_display(GTK_WIDGET(dialog));
	seat = gdk_display_get_default_seat(display);
	caps = GDK_SEAT_CAPABILITY_KEYBOARD;
	اگر (grab_اشارہ_گر)
		caps |= GDK_SEAT_CAPABILITY_ALL_POINTING;
	اگر (grab_server)
		caps = GDK_SEAT_CAPABILITY_ALL;
	برائے (;;) {
		حالت_2 = gdk_seat_grab(seat, gtk_widget_get_کھڑکی(dialog),
		    caps, TRUE, تہی, تہی, تہی, تہی);
		اگر (حالت_2 == GDK_GRAB_SUCCESS)
			توڑو;
		usleep(GRAB_WAIT * 1000);
		اگر (++grab_tries > GRAB_TRIES)
			جاؤ nograb;
	}

	نتیجہ = gtk_dialog_تسلسل(GTK_DIALOG(dialog));

	/* Ungrab */
	gdk_seat_ungrab(seat);
	gdk_display_flush(display);

	/* Report passphrase if user selected OK */
	اگر (prompt_type == PROMPT_اندراج) {
		passphrase = g_strdup(gtk_اندراج_get_متن(GTK_اندراج(اندراج_2)));
		اگر (نتیجہ == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    لڑی_لمبائی(passphrase), تہی, تہی, تہی);
			اگر (local != تہی) {
				puts(local);
				memset(local, '\0', لڑی_لمبائی(local));
				g_free(local);
			} ورنہ {
				puts(passphrase);
			}
		}
		/* Zero passphrase in memory */
		memset(passphrase, '\b', لڑی_لمبائی(passphrase));
		gtk_اندراج_سیٹ_متن(GTK_اندراج(اندراج_2), passphrase);
		memset(passphrase, '\0', لڑی_لمبائی(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	اگر (نتیجہ != GTK_RESPONSE_OK && نتیجہ != GTK_RESPONSE_YES)
		واپس -1;
	واپس 0;

 nograb:
	gtk_widget_destroy(dialog);
	err = gtk_پیغام_dialog_new(GTK_کھڑکی(والد_کھڑکی), 0,
	    GTK_پیغام_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab input. A malicious client may be eavesdropping "
	    "on your session.");
	gtk_کھڑکی_سیٹ_position(GTK_کھڑکی(err), GTK_WIN_POS_CENTER);
	gtk_dialog_تسلسل(GTK_DIALOG(err));
	gtk_widget_destroy(err);
	واپس -1;
}

صحیح
مین(صحیح argc, حرف **argv)
{
	حرف *پیغام_2, *prompt_منوال;
	صحیح نتیجہ, prompt_type = PROMPT_اندراج;

	gtk_init(&argc, &argv);

	اگر (argc > 1) {
		پیغام_2 = g_strjoinv(" ", argv + 1);
	} ورنہ {
		پیغام_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	اگر ((prompt_منوال = getenv("SSH_ASKPASS_PROMPT")) != تہی) {
		اگر (strcasecmp(prompt_منوال, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		ورنہ اگر (strcasecmp(prompt_منوال, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	نتیجہ = passphrase_dialog(پیغام_2, prompt_type);
	g_free(پیغام_2);

	واپس (نتیجہ);
}
