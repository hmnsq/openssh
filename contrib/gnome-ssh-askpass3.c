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

#define GRAB_TRIES	16
#define GRAB_WAIT	250 /* milliseconds */

#define PROMPT_ENTRY	0
#define PROMPT_CONFIRM	1
#define PROMPT_NONE	2

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
ok_dialog(GtkWidget *entry, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

ساكن gboolean
check_none(GtkWidget *widget, GdkEventKey *event, gpointer dialog)
{
	بدل (event->keyval) {
	حالة GDK_KEY_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		החזר TRUE;
	حالة GDK_KEY_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		החזר TRUE;
	افتراضي:
		/* eat all other key events */
		החזר TRUE;
	}
}

ساكن صحيح
parse_env_hex_color(ثابت حرف *env, GdkColor *c)
{
	ثابت حرف *s;
	unsigned long ul;
	حرف *ep;
	size_t n;

	אם ((s = getenv(env)) == عدم)
		החזר 0;

	memset(c, 0, حجم(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	אם (*s == '#')
		s++;
	אחרת אם (strncmp(s, "0x", 2) == 0)
		s += 2;
	n = strlen(s);
	אם (n != 3 && n != 6)
		اذهب bad;
	ul = strtoul(s, &ep, 16);
	אם (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		החזר 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	אם (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} אחרת {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	החזר 1;
}

ساكن صحيح
passphrase_dialog(حرف *message, صحيح prompt_type)
{
	ثابت حرف *failed;
	حرف *passphrase, *local;
	صحيح result, grab_tries, grab_server, grab_pointer;
	صحيح buttons, default_response;
	GtkWidget *parent_window, *dialog, *entry, *err;
	GdkGrabStatus status;
	GdkColor fg, bg;
	GdkSeat *seat;
	GdkDisplay *display;
	GdkSeatCapabilities caps;
	صحيح fg_set = 0, bg_set = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != عدم);
	grab_pointer = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != عدم);
	grab_tries = 0;

	fg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	parent_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

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

	dialog = gtk_message_dialog_new(GTK_WINDOW(parent_window), 0,
	    GTK_MESSAGE_QUESTION, buttons, "%s", message);

	gtk_window_set_title(GTK_WINDOW(dialog), "OpenSSH");
	gtk_window_set_position (GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), default_response);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);

	אם (fg_set)
		gtk_widget_modify_fg(dialog, GTK_STATE_NORMAL, &fg);
	אם (bg_set)
		gtk_widget_modify_bg(dialog, GTK_STATE_NORMAL, &bg);

	אם (prompt_type == PROMPT_ENTRY || prompt_type == PROMPT_NONE) {
		entry = gtk_entry_new();
		אם (fg_set)
			gtk_widget_modify_fg(entry, GTK_STATE_NORMAL, &fg);
		אם (bg_set)
			gtk_widget_modify_bg(entry, GTK_STATE_NORMAL, &bg);
		gtk_box_pack_start(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    entry, FALSE, FALSE, 0);
		gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
		gtk_widget_grab_focus(entry);
		אם (prompt_type == PROMPT_ENTRY) {
			gtk_widget_show(entry);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(entry), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} אחרת {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(entry);
			g_signal_connect(G_OBJECT(entry), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}
	/* Grab focus */
	gtk_widget_show_now(dialog);
	display = gtk_widget_get_display(GTK_WIDGET(dialog));
	seat = gdk_display_get_default_seat(display);
	caps = GDK_SEAT_CAPABILITY_KEYBOARD;
	אם (grab_pointer)
		caps |= GDK_SEAT_CAPABILITY_ALL_POINTING;
	אם (grab_server)
		caps = GDK_SEAT_CAPABILITY_ALL;
	עבור (;;) {
		status = gdk_seat_grab(seat, gtk_widget_get_window(dialog),
		    caps, TRUE, عدم, عدم, عدم, عدم);
		אם (status == GDK_GRAB_SUCCESS)
			اكسر;
		usleep(GRAB_WAIT * 1000);
		אם (++grab_tries > GRAB_TRIES)
			اذهب nograb;
	}

	result = gtk_dialog_run(GTK_DIALOG(dialog));

	/* Ungrab */
	gdk_seat_ungrab(seat);
	gdk_display_flush(display);

	/* Report passphrase if user selected OK */
	אם (prompt_type == PROMPT_ENTRY) {
		passphrase = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
		אם (result == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    strlen(passphrase), عدم, عدم, عدم);
			אם (local != عدم) {
				puts(local);
				memset(local, '\0', strlen(local));
				g_free(local);
			} אחרת {
				puts(passphrase);
			}
		}
		/* Zero passphrase in memory */
		memset(passphrase, '\b', strlen(passphrase));
		gtk_entry_set_text(GTK_ENTRY(entry), passphrase);
		memset(passphrase, '\0', strlen(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	אם (result != GTK_RESPONSE_OK && result != GTK_RESPONSE_YES)
		החזר -1;
	החזר 0;

 nograb:
	gtk_widget_destroy(dialog);
	err = gtk_message_dialog_new(GTK_WINDOW(parent_window), 0,
	    GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab input. A malicious client may be eavesdropping "
	    "on your session.");
	gtk_window_set_position(GTK_WINDOW(err), GTK_WIN_POS_CENTER);
	gtk_dialog_run(GTK_DIALOG(err));
	gtk_widget_destroy(err);
	החזר -1;
}

صحيح
main(صحيح argc, حرف **argv)
{
	حرف *message, *prompt_mode;
	صحيح result, prompt_type = PROMPT_ENTRY;

	gtk_init(&argc, &argv);

	אם (argc > 1) {
		message = g_strjoinv(" ", argv + 1);
	} אחרת {
		message = g_strdup("Enter your OpenSSH passphrase:");
	}

	אם ((prompt_mode = getenv("SSH_ASKPASS_PROMPT")) != عدم) {
		אם (strcasecmp(prompt_mode, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		אחרת אם (strcasecmp(prompt_mode, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	result = passphrase_dialog(message, prompt_type);
	g_free(message);

	החזר (result);
}
