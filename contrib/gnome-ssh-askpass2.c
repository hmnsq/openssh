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

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ <X11/Xlib.h>
#അന്തര്ഭാവ <gtk/gtk.h>
#അന്തര്ഭാവ <gdk/gdkx.h>
#അന്തര്ഭാവ <gdk/gdkkeysyms.h>

സ്ഥിതം ശൂന്യം
report_failed_grab (GtkWidget *parent_window, സ്ഥിരം അക്ഷരം *what)
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

സ്ഥിതം ശൂന്യം
ok_dialog(GtkWidget *entry, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

സ്ഥിതം gboolean
check_none(GtkWidget *widget, Gdk_Event_താക്കോൽ *event, gpointer dialog)
{
	തിരഞ്ഞെടുപ്പ് (event->keyval) {
	അവസ്ഥ GDK_താക്കോൽ_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		തിരികെ TRUE;
	അവസ്ഥ GDK_താക്കോൽ_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		തിരികെ TRUE;
	സ്ഥിരസ്ഥിതി:
		/* eat all other key events */
		തിരികെ TRUE;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_env_hex_color(സ്ഥിരം അക്ഷരം *env, GdkColor *c)
{
	സ്ഥിരം അക്ഷരം *s;
	unsigned long ul;
	അക്ഷരം *ep;
	size_t n;

	എങ്കിൽ ((s = getenv(env)) == ശൂന്യ)
		തിരികെ 0;

	memset(c, 0, വലുപ്പം(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	എങ്കിൽ (*s == '#')
		s++;
	അല്ലെങ്കിൽ എങ്കിൽ (strncmp(s, "0x", 2) == 0)
		s += 2;
	n = strlen(s);
	എങ്കിൽ (n != 3 && n != 6)
		പോകുക bad;
	ul = strtoul(s, &ep, 16);
	എങ്കിൽ (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		തിരികെ 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	എങ്കിൽ (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} അല്ലെങ്കിൽ {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
passphrase_dialog(അക്ഷരം *message, പൂർണ്ണസംഖ്യ prompt_type)
{
	സ്ഥിരം അക്ഷരം *failed;
	അക്ഷരം *passphrase, *local;
	പൂർണ്ണസംഖ്യ result, grab_tries, grab_server, grab_pointer;
	പൂർണ്ണസംഖ്യ buttons, default_response;
	GtkWidget *parent_window, *dialog, *entry;
	GdkGrabStatus status;
	GdkColor fg, bg;
	പൂർണ്ണസംഖ്യ fg_set = 0, bg_set = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != ശൂന്യ);
	grab_pointer = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != ശൂന്യ);
	grab_tries = 0;

	fg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	parent_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

	തിരഞ്ഞെടുപ്പ് (prompt_type) {
	അവസ്ഥ PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		നിർത്തുക;
	അവസ്ഥ PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		നിർത്തുക;
	}

	dialog = gtk_message_dialog_new(GTK_WINDOW(parent_window), 0,
	    GTK_MESSAGE_QUESTION, buttons, "%s", message);

	gtk_window_set_title(GTK_WINDOW(dialog), "OpenSSH");
	gtk_window_set_position (GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), default_response);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);

	എങ്കിൽ (fg_set)
		gtk_widget_modify_fg(dialog, GTK_STATE_NORMAL, &fg);
	എങ്കിൽ (bg_set)
		gtk_widget_modify_bg(dialog, GTK_STATE_NORMAL, &bg);

	എങ്കിൽ (prompt_type == PROMPT_ENTRY || prompt_type == PROMPT_NONE) {
		entry = gtk_entry_new();
		എങ്കിൽ (fg_set)
			gtk_widget_modify_fg(entry, GTK_STATE_NORMAL, &fg);
		എങ്കിൽ (bg_set)
			gtk_widget_modify_bg(entry, GTK_STATE_NORMAL, &bg);
		gtk_box_pack_start(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    entry, FALSE, FALSE, 0);
		gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
		gtk_widget_grab_focus(entry);
		എങ്കിൽ (prompt_type == PROMPT_ENTRY) {
			gtk_widget_show(entry);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(entry), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} അല്ലെങ്കിൽ {
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
	എങ്കിൽ (grab_pointer) {
		വേണ്ടി(;;) {
			status = gdk_pointer_grab(
			    (gtk_widget_get_window(GTK_WIDGET(dialog))), TRUE,
			    0, ശൂന്യ, ശൂന്യ, GDK_CURRENT_TIME);
			എങ്കിൽ (status == GDK_GRAB_SUCCESS)
				നിർത്തുക;
			usleep(GRAB_WAIT * 1000);
			എങ്കിൽ (++grab_tries > GRAB_TRIES) {
				failed = "mouse";
				പോകുക nograb;
			}
		}
	}
	വേണ്ടി(;;) {
		status = gdk_keyboard_grab(
		    gtk_widget_get_window(GTK_WIDGET(dialog)), FALSE,
		    GDK_CURRENT_TIME);
		എങ്കിൽ (status == GDK_GRAB_SUCCESS)
			നിർത്തുക;
		usleep(GRAB_WAIT * 1000);
		എങ്കിൽ (++grab_tries > GRAB_TRIES) {
			failed = "keyboard";
			പോകുക nograbkb;
		}
	}
	എങ്കിൽ (grab_server) {
		gdk_x11_grab_server();
	}

	result = gtk_dialog_run(GTK_DIALOG(dialog));

	/* Ungrab */
	എങ്കിൽ (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	എങ്കിൽ (grab_pointer)
		gdk_pointer_ungrab(GDK_CURRENT_TIME);
	gdk_keyboard_ungrab(GDK_CURRENT_TIME);
	gdk_flush();

	/* Report passphrase if user selected OK */
	എങ്കിൽ (prompt_type == PROMPT_ENTRY) {
		passphrase = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
		എങ്കിൽ (result == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    strlen(passphrase), ശൂന്യ, ശൂന്യ, ശൂന്യ);
			എങ്കിൽ (local != ശൂന്യ) {
				puts(local);
				memset(local, '\0', strlen(local));
				g_free(local);
			} അല്ലെങ്കിൽ {
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
	എങ്കിൽ (result != GTK_RESPONSE_OK && result != GTK_RESPONSE_YES)
		തിരികെ -1;
	തിരികെ 0;

 nograbkb:
	/*
	 * At least one grab failed - ungrab what we got, and report
	 * the failure to the user.  Note that XGrabServer() cannot
	 * fail.
	 */
	gdk_pointer_ungrab(GDK_CURRENT_TIME);
 nograb:
	എങ്കിൽ (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	gtk_widget_destroy(dialog);
	
	report_failed_grab(parent_window, failed);

	തിരികെ (-1);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	അക്ഷരം *message, *prompt_mode;
	പൂർണ്ണസംഖ്യ result, prompt_type = PROMPT_ENTRY;

	gtk_init(&argc, &argv);

	എങ്കിൽ (argc > 1) {
		message = g_strjoinv(" ", argv + 1);
	} അല്ലെങ്കിൽ {
		message = g_strdup("Enter your OpenSSH passphrase:");
	}

	എങ്കിൽ ((prompt_mode = getenv("SSH_ASKPASS_PROMPT")) != ശൂന്യ) {
		എങ്കിൽ (strcasecmp(prompt_mode, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(prompt_mode, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	result = passphrase_dialog(message, prompt_type);
	g_free(message);

	തിരികെ (result);
}
