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

#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل <X11/Xlib.h>
#شامل <gtk/gtk.h>
#شامل <gdk/gdkx.h>
#شامل <gdk/gdkkeysyms.h>

ایستا تهی
ok_dialog(GtkWidget *entry, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

ایستا gboolean
check_none(GtkWidget *widget, Gdk_Event_کلید *event, gpointer dialog)
{
	انتخاب (event->keyval) {
	حالت GDK_کلید_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		بازگشت TRUE;
	حالت GDK_کلید_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		بازگشت TRUE;
	پیشفرض:
		/* eat all other key events */
		بازگشت TRUE;
	}
}

ایستا صحیح
parse_env_hex_color(ثابت نویسه *env, GdkColor *c)
{
	ثابت نویسه *s;
	unsigned long ul;
	نویسه *ep;
	size_t n;

	اگر ((s = getenv(env)) == پوچ)
		بازگشت 0;

	memset(c, 0, اندازه(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	اگر (*s == '#')
		s++;
	وگرنه اگر (strncmp(s, "0x", 2) == 0)
		s += 2;
	n = strlen(s);
	اگر (n != 3 && n != 6)
		برو bad;
	ul = strtoul(s, &ep, 16);
	اگر (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		بازگشت 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	اگر (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} وگرنه {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	بازگشت 1;
}

ایستا صحیح
passphrase_dialog(نویسه *message, صحیح prompt_type)
{
	ثابت نویسه *failed;
	نویسه *passphrase, *local;
	صحیح result, grab_tries, grab_server, grab_pointer;
	صحیح buttons, default_response;
	GtkWidget *parent_window, *dialog, *entry, *err;
	GdkGrabStatus status;
	GdkColor fg, bg;
	GdkSeat *seat;
	GdkDisplay *display;
	GdkSeatCapabilities caps;
	صحیح fg_set = 0, bg_set = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != پوچ);
	grab_pointer = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != پوچ);
	grab_tries = 0;

	fg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	parent_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

	انتخاب (prompt_type) {
	حالت PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		بشکن;
	حالت PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		بشکن;
	پیشفرض:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		بشکن;
	}

	dialog = gtk_message_dialog_new(GTK_WINDOW(parent_window), 0,
	    GTK_MESSAGE_QUESTION, buttons, "%s", message);

	gtk_window_set_title(GTK_WINDOW(dialog), "OpenSSH");
	gtk_window_set_position (GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), default_response);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);

	اگر (fg_set)
		gtk_widget_modify_fg(dialog, GTK_STATE_NORMAL, &fg);
	اگر (bg_set)
		gtk_widget_modify_bg(dialog, GTK_STATE_NORMAL, &bg);

	اگر (prompt_type == PROMPT_ENTRY || prompt_type == PROMPT_NONE) {
		entry = gtk_entry_new();
		اگر (fg_set)
			gtk_widget_modify_fg(entry, GTK_STATE_NORMAL, &fg);
		اگر (bg_set)
			gtk_widget_modify_bg(entry, GTK_STATE_NORMAL, &bg);
		gtk_box_pack_start(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    entry, FALSE, FALSE, 0);
		gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
		gtk_widget_grab_focus(entry);
		اگر (prompt_type == PROMPT_ENTRY) {
			gtk_widget_show(entry);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(entry), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} وگرنه {
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
	اگر (grab_pointer)
		caps |= GDK_SEAT_CAPABILITY_ALL_POINTING;
	اگر (grab_server)
		caps = GDK_SEAT_CAPABILITY_ALL;
	برای (;;) {
		status = gdk_seat_grab(seat, gtk_widget_get_window(dialog),
		    caps, TRUE, پوچ, پوچ, پوچ, پوچ);
		اگر (status == GDK_GRAB_SUCCESS)
			بشکن;
		usleep(GRAB_WAIT * 1000);
		اگر (++grab_tries > GRAB_TRIES)
			برو nograb;
	}

	result = gtk_dialog_run(GTK_DIALOG(dialog));

	/* Ungrab */
	gdk_seat_ungrab(seat);
	gdk_display_flush(display);

	/* Report passphrase if user selected OK */
	اگر (prompt_type == PROMPT_ENTRY) {
		passphrase = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
		اگر (result == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    strlen(passphrase), پوچ, پوچ, پوچ);
			اگر (local != پوچ) {
				puts(local);
				memset(local, '\0', strlen(local));
				g_free(local);
			} وگرنه {
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
	اگر (result != GTK_RESPONSE_OK && result != GTK_RESPONSE_YES)
		بازگشت -1;
	بازگشت 0;

 nograb:
	gtk_widget_destroy(dialog);
	err = gtk_message_dialog_new(GTK_WINDOW(parent_window), 0,
	    GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab input. A malicious client may be eavesdropping "
	    "on your session.");
	gtk_window_set_position(GTK_WINDOW(err), GTK_WIN_POS_CENTER);
	gtk_dialog_run(GTK_DIALOG(err));
	gtk_widget_destroy(err);
	بازگشت -1;
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	نویسه *message, *prompt_mode;
	صحیح result, prompt_type = PROMPT_ENTRY;

	gtk_init(&argc, &argv);

	اگر (argc > 1) {
		message = g_strjoinv(" ", argv + 1);
	} وگرنه {
		message = g_strdup("Enter your OpenSSH passphrase:");
	}

	اگر ((prompt_mode = getenv("SSH_ASKPASS_PROMPT")) != پوچ) {
		اگر (strcasecmp(prompt_mode, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		وگرنه اگر (strcasecmp(prompt_mode, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	result = passphrase_dialog(message, prompt_type);
	g_free(message);

	بازگشت (result);
}
