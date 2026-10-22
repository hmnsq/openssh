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

#تعریف_کن GRAB_TRIES	16
#تعریف_کن GRAB_WAIT	250 /* milliseconds */

#تعریف_کن PROMPT_مدخل	0
#تعریف_کن PROMPT_CONFIRM	1
#تعریف_کن PROMPT_NONE	2

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
ok_dialog(GtkWidget *مدخل, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

ساكن gboolean
check_none(GtkWidget *widget, Gdk_Event_کلید *event, gpointer dialog)
{
	بدل (event->keyval) {
	حالة GDK_کلید_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		أرجع TRUE;
	حالة GDK_کلید_Tab:
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
	بیعلامت دراز ul;
	حرف *ep;
	اندازه_t n;

	إذا ((s = getenv(env)) == عدم)
		أرجع 0;

	memset(c, 0, حجم(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	إذا (*s == '#')
		s++;
	وإلا إذا (مقایسه_رشته(s, "0x", 2) == 0)
		s += 2;
	n = طول_رشته(s);
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
passphrase_dialog(حرف *پیام_2, صحيح prompt_type)
{
	ثابت حرف *failed;
	حرف *passphrase, *local;
	صحيح نتیجه, grab_tries, grab_server, grab_اشاره_گر;
	صحيح buttons, default_response;
	GtkWidget *والد_پنجره, *dialog, *مدخل, *err;
	Gdk_Grab_وضعیت وضعیت;
	GdkColor fg, bg;
	GdkSeat *seat;
	GdkDisplay *display;
	GdkSeatCapabilities caps;
	صحيح fg_مجموعه = 0, bg_مجموعه = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != عدم);
	grab_اشاره_گر = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != عدم);
	grab_tries = 0;

	fg_مجموعه = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_مجموعه = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	والد_پنجره = gtk_پنجره_new(GTK_پنجره_TOPLEVEL);

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

	dialog = gtk_پیام_dialog_new(GTK_پنجره(والد_پنجره), 0,
	    GTK_پیام_QUESTION, buttons, "%s", پیام_2);

	gtk_پنجره_مجموعه_title(GTK_پنجره(dialog), "OpenSSH");
	gtk_پنجره_مجموعه_position (GTK_پنجره(dialog), GTK_WIN_POS_CENTER);
	gtk_پنجره_مجموعه_keep_above(GTK_پنجره(dialog), TRUE);
	gtk_dialog_مجموعه_default_response(GTK_DIALOG(dialog), default_response);
	gtk_پنجره_مجموعه_keep_above(GTK_پنجره(dialog), TRUE);

	إذا (fg_مجموعه)
		gtk_widget_modify_fg(dialog, GTK_STATE_نرمال, &fg);
	إذا (bg_مجموعه)
		gtk_widget_modify_bg(dialog, GTK_STATE_نرمال, &bg);

	إذا (prompt_type == PROMPT_مدخل || prompt_type == PROMPT_NONE) {
		مدخل = gtk_مدخل_new();
		إذا (fg_مجموعه)
			gtk_widget_modify_fg(مدخل, GTK_STATE_نرمال, &fg);
		إذا (bg_مجموعه)
			gtk_widget_modify_bg(مدخل, GTK_STATE_نرمال, &bg);
		gtk_box_pack_شروع(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    مدخل, FALSE, FALSE, 0);
		gtk_مدخل_مجموعه_visibility(GTK_مدخل(مدخل), FALSE);
		gtk_widget_grab_focus(مدخل);
		إذا (prompt_type == PROMPT_مدخل) {
			gtk_widget_show(مدخل);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(مدخل), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} وإلا {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(مدخل);
			g_signal_connect(G_OBJECT(مدخل), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}
	/* Grab focus */
	gtk_widget_show_now(dialog);
	display = gtk_widget_get_display(GTK_WIDGET(dialog));
	seat = gdk_display_get_default_seat(display);
	caps = GDK_SEAT_CAPABILITY_KEYBOARD;
	إذا (grab_اشاره_گر)
		caps |= GDK_SEAT_CAPABILITY_ALL_POINTING;
	إذا (grab_server)
		caps = GDK_SEAT_CAPABILITY_ALL;
	لكل (;;) {
		وضعیت = gdk_seat_grab(seat, gtk_widget_get_پنجره(dialog),
		    caps, TRUE, عدم, عدم, عدم, عدم);
		إذا (وضعیت == GDK_GRAB_SUCCESS)
			اكسر;
		usleep(GRAB_WAIT * 1000);
		إذا (++grab_tries > GRAB_TRIES)
			اذهب nograb;
	}

	نتیجه = gtk_dialog_پیاپی(GTK_DIALOG(dialog));

	/* Ungrab */
	gdk_seat_ungrab(seat);
	gdk_display_flush(display);

	/* Report passphrase if user selected OK */
	إذا (prompt_type == PROMPT_مدخل) {
		passphrase = g_strdup(gtk_مدخل_get_متن(GTK_مدخل(مدخل)));
		إذا (نتیجه == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    طول_رشته(passphrase), عدم, عدم, عدم);
			إذا (local != عدم) {
				puts(local);
				memset(local, '\0', طول_رشته(local));
				g_free(local);
			} وإلا {
				puts(passphrase);
			}
		}
		/* Zero passphrase in memory */
		memset(passphrase, '\b', طول_رشته(passphrase));
		gtk_مدخل_مجموعه_متن(GTK_مدخل(مدخل), passphrase);
		memset(passphrase, '\0', طول_رشته(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	إذا (نتیجه != GTK_RESPONSE_OK && نتیجه != GTK_RESPONSE_YES)
		أرجع -1;
	أرجع 0;

 nograb:
	gtk_widget_destroy(dialog);
	err = gtk_پیام_dialog_new(GTK_پنجره(والد_پنجره), 0,
	    GTK_پیام_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab input. A malicious client may be eavesdropping "
	    "on your session.");
	gtk_پنجره_مجموعه_position(GTK_پنجره(err), GTK_WIN_POS_CENTER);
	gtk_dialog_پیاپی(GTK_DIALOG(err));
	gtk_widget_destroy(err);
	أرجع -1;
}

صحيح
اصلی(صحيح argc, حرف **argv)
{
	حرف *پیام_2, *prompt_نما;
	صحيح نتیجه, prompt_type = PROMPT_مدخل;

	gtk_init(&argc, &argv);

	إذا (argc > 1) {
		پیام_2 = g_strjoinv(" ", argv + 1);
	} وإلا {
		پیام_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	إذا ((prompt_نما = getenv("SSH_ASKPASS_PROMPT")) != عدم) {
		إذا (strcasecmp(prompt_نما, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		وإلا إذا (strcasecmp(prompt_نما, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	نتیجه = passphrase_dialog(پیام_2, prompt_type);
	g_free(پیام_2);

	أرجع (نتیجه);
}
