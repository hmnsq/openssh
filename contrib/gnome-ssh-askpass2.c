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

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ <X11/Xlib.h>
#அந்தர்பாவ <gtk/gtk.h>
#அந்தர்பாவ <gdk/gdkx.h>
#அந்தர்பாவ <gdk/gdkkeysyms.h>

நிலையான வெறுமை
report_failed_grab (GtkWidget *parent_window, மாறிலி எழுத்து *what)
{
	GtkWidget *err;

	err = gtk_message_dialog_new(GTK_WINDOW(parent_window), 0,
	    GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab %s. A malicious client may be eavesdropping "
	    "on your session.", what);
	gtk_window_set_position(GTK_WINDOW(err), GTK_WIN_POS_CENTER);

	gtk_dialog_run(GTK_DIALOG(err));

	gtk_widget_destroy(err);
}

நிலையான வெறுமை
ok_dialog(GtkWidget *entry, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

நிலையான gboolean
check_none(GtkWidget *widget, Gdk_Event_சாவி *event, gpointer dialog)
{
	தேர்வு (event->keyval) {
	நிலை GDK_சாவி_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		திரும்பு TRUE;
	நிலை GDK_சாவி_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		திரும்பு TRUE;
	இயல்பு:
		/* eat all other key events */
		திரும்பு TRUE;
	}
}

நிலையான முழு
parse_env_hex_color(மாறிலி எழுத்து *env, GdkColor *c)
{
	மாறிலி எழுத்து *s;
	unsigned long ul;
	எழுத்து *ep;
	size_t n;

	எனில் ((s = getenv(env)) == வெற்று)
		திரும்பு 0;

	memset(c, 0, அளவு(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	எனில் (*s == '#')
		s++;
	இல்லையெனில் எனில் (strncmp(s, "0x", 2) == 0)
		s += 2;
	n = strlen(s);
	எனில் (n != 3 && n != 6)
		செல் bad;
	ul = strtoul(s, &ep, 16);
	எனில் (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		திரும்பு 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	எனில் (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} இல்லையெனில் {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	திரும்பு 1;
}

நிலையான முழு
passphrase_dialog(எழுத்து *message, முழு prompt_type)
{
	மாறிலி எழுத்து *failed;
	எழுத்து *passphrase, *local;
	முழு result, grab_tries, grab_server, grab_pointer;
	முழு buttons, default_response;
	GtkWidget *parent_window, *dialog, *entry;
	GdkGrabStatus status;
	GdkColor fg, bg;
	முழு fg_set = 0, bg_set = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != வெற்று);
	grab_pointer = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != வெற்று);
	grab_tries = 0;

	fg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	parent_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

	தேர்வு (prompt_type) {
	நிலை PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		நிறுத்து;
	நிலை PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		நிறுத்து;
	இயல்பு:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		நிறுத்து;
	}

	dialog = gtk_message_dialog_new(GTK_WINDOW(parent_window), 0,
	    GTK_MESSAGE_QUESTION, buttons, "%s", message);

	gtk_window_set_title(GTK_WINDOW(dialog), "OpenSSH");
	gtk_window_set_position (GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), default_response);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);

	எனில் (fg_set)
		gtk_widget_modify_fg(dialog, GTK_STATE_NORMAL, &fg);
	எனில் (bg_set)
		gtk_widget_modify_bg(dialog, GTK_STATE_NORMAL, &bg);

	எனில் (prompt_type == PROMPT_ENTRY || prompt_type == PROMPT_NONE) {
		entry = gtk_entry_new();
		எனில் (fg_set)
			gtk_widget_modify_fg(entry, GTK_STATE_NORMAL, &fg);
		எனில் (bg_set)
			gtk_widget_modify_bg(entry, GTK_STATE_NORMAL, &bg);
		gtk_box_pack_start(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    entry, FALSE, FALSE, 0);
		gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
		gtk_widget_grab_focus(entry);
		எனில் (prompt_type == PROMPT_ENTRY) {
			gtk_widget_show(entry);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(entry), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} இல்லையெனில் {
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
	எனில் (grab_pointer) {
		க்கு(;;) {
			status = gdk_pointer_grab(
			    (gtk_widget_get_window(GTK_WIDGET(dialog))), TRUE,
			    0, வெற்று, வெற்று, GDK_CURRENT_TIME);
			எனில் (status == GDK_GRAB_SUCCESS)
				நிறுத்து;
			usleep(GRAB_WAIT * 1000);
			எனில் (++grab_tries > GRAB_TRIES) {
				failed = "mouse";
				செல் nograb;
			}
		}
	}
	க்கு(;;) {
		status = gdk_keyboard_grab(
		    gtk_widget_get_window(GTK_WIDGET(dialog)), FALSE,
		    GDK_CURRENT_TIME);
		எனில் (status == GDK_GRAB_SUCCESS)
			நிறுத்து;
		usleep(GRAB_WAIT * 1000);
		எனில் (++grab_tries > GRAB_TRIES) {
			failed = "keyboard";
			செல் nograbkb;
		}
	}
	எனில் (grab_server) {
		gdk_x11_grab_server();
	}

	result = gtk_dialog_run(GTK_DIALOG(dialog));

	/* Ungrab */
	எனில் (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	எனில் (grab_pointer)
		gdk_pointer_ungrab(GDK_CURRENT_TIME);
	gdk_keyboard_ungrab(GDK_CURRENT_TIME);
	gdk_flush();

	/* Report passphrase if user selected OK */
	எனில் (prompt_type == PROMPT_ENTRY) {
		passphrase = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
		எனில் (result == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    strlen(passphrase), வெற்று, வெற்று, வெற்று);
			எனில் (local != வெற்று) {
				puts(local);
				memset(local, '\0', strlen(local));
				g_free(local);
			} இல்லையெனில் {
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
	எனில் (result != GTK_RESPONSE_OK && result != GTK_RESPONSE_YES)
		திரும்பு -1;
	திரும்பு 0;

 nograbkb:
	/*
	 * At least one grab failed - ungrab what we got, and report
	 * the failure to the user.  Note that XGrabServer() cannot
	 * fail.
	 */
	gdk_pointer_ungrab(GDK_CURRENT_TIME);
 nograb:
	எனில் (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	gtk_widget_destroy(dialog);
	
	report_failed_grab(parent_window, failed);

	திரும்பு (-1);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	எழுத்து *message, *prompt_mode;
	முழு result, prompt_type = PROMPT_ENTRY;

	gtk_init(&argc, &argv);

	எனில் (argc > 1) {
		message = g_strjoinv(" ", argv + 1);
	} இல்லையெனில் {
		message = g_strdup("Enter your OpenSSH passphrase:");
	}

	எனில் ((prompt_mode = getenv("SSH_ASKPASS_PROMPT")) != வெற்று) {
		எனில் (strcasecmp(prompt_mode, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		இல்லையெனில் எனில் (strcasecmp(prompt_mode, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	result = passphrase_dialog(message, prompt_type);
	g_free(message);

	திரும்பு (result);
}
