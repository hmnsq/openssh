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

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव <X11/Xlib.h>
#अन्तर्भाव <gtk/gtk.h>
#अन्तर्भाव <gdk/gdkx.h>
#अन्तर्भाव <gdk/gdkkeysyms.h>

स्थिर शून्य
report_failed_grab (GtkWidget *parent_window, ध्रुव वर्ण *what)
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

स्थिर शून्य
ok_dialog(GtkWidget *entry, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

स्थिर gboolean
check_none(GtkWidget *widget, Gdk_Event_किल्ली *event, gpointer dialog)
{
	विकल्प (event->keyval) {
	पक्ष GDK_किल्ली_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		प्रत्यागम TRUE;
	पक्ष GDK_किल्ली_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		प्रत्यागम TRUE;
	स्वभाव:
		/* eat all other key events */
		प्रत्यागम TRUE;
	}
}

स्थिर पूर्णाङ्क
parse_env_hex_color(ध्रुव वर्ण *env, GdkColor *c)
{
	ध्रुव वर्ण *s;
	unsigned long ul;
	वर्ण *ep;
	size_t n;

	यदि ((s = getenv(env)) == रिक्त)
		प्रत्यागम 0;

	memset(c, 0, परिमाण(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	यदि (*s == '#')
		s++;
	अन्यथा यदि (strncmp(s, "0x", 2) == 0)
		s += 2;
	n = strlen(s);
	यदि (n != 3 && n != 6)
		गच्छ bad;
	ul = strtoul(s, &ep, 16);
	यदि (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		प्रत्यागम 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	यदि (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} अन्यथा {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	प्रत्यागम 1;
}

स्थिर पूर्णाङ्क
passphrase_dialog(वर्ण *message, पूर्णाङ्क prompt_type)
{
	ध्रुव वर्ण *failed;
	वर्ण *passphrase, *local;
	पूर्णाङ्क result, grab_tries, grab_server, grab_pointer;
	पूर्णाङ्क buttons, default_response;
	GtkWidget *parent_window, *dialog, *entry;
	GdkGrabStatus status;
	GdkColor fg, bg;
	पूर्णाङ्क fg_set = 0, bg_set = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != रिक्त);
	grab_pointer = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != रिक्त);
	grab_tries = 0;

	fg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	parent_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

	विकल्प (prompt_type) {
	पक्ष PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		भङ्ग;
	पक्ष PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		भङ्ग;
	स्वभाव:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		भङ्ग;
	}

	dialog = gtk_message_dialog_new(GTK_WINDOW(parent_window), 0,
	    GTK_MESSAGE_QUESTION, buttons, "%s", message);

	gtk_window_set_title(GTK_WINDOW(dialog), "OpenSSH");
	gtk_window_set_position (GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), default_response);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);

	यदि (fg_set)
		gtk_widget_modify_fg(dialog, GTK_STATE_NORMAL, &fg);
	यदि (bg_set)
		gtk_widget_modify_bg(dialog, GTK_STATE_NORMAL, &bg);

	यदि (prompt_type == PROMPT_ENTRY || prompt_type == PROMPT_NONE) {
		entry = gtk_entry_new();
		यदि (fg_set)
			gtk_widget_modify_fg(entry, GTK_STATE_NORMAL, &fg);
		यदि (bg_set)
			gtk_widget_modify_bg(entry, GTK_STATE_NORMAL, &bg);
		gtk_box_pack_start(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    entry, FALSE, FALSE, 0);
		gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
		gtk_widget_grab_focus(entry);
		यदि (prompt_type == PROMPT_ENTRY) {
			gtk_widget_show(entry);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(entry), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} अन्यथा {
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
	यदि (grab_pointer) {
		प्रति(;;) {
			status = gdk_pointer_grab(
			    (gtk_widget_get_window(GTK_WIDGET(dialog))), TRUE,
			    0, रिक्त, रिक्त, GDK_CURRENT_TIME);
			यदि (status == GDK_GRAB_SUCCESS)
				भङ्ग;
			usleep(GRAB_WAIT * 1000);
			यदि (++grab_tries > GRAB_TRIES) {
				failed = "mouse";
				गच्छ nograb;
			}
		}
	}
	प्रति(;;) {
		status = gdk_keyboard_grab(
		    gtk_widget_get_window(GTK_WIDGET(dialog)), FALSE,
		    GDK_CURRENT_TIME);
		यदि (status == GDK_GRAB_SUCCESS)
			भङ्ग;
		usleep(GRAB_WAIT * 1000);
		यदि (++grab_tries > GRAB_TRIES) {
			failed = "keyboard";
			गच्छ nograbkb;
		}
	}
	यदि (grab_server) {
		gdk_x11_grab_server();
	}

	result = gtk_dialog_run(GTK_DIALOG(dialog));

	/* Ungrab */
	यदि (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	यदि (grab_pointer)
		gdk_pointer_ungrab(GDK_CURRENT_TIME);
	gdk_keyboard_ungrab(GDK_CURRENT_TIME);
	gdk_flush();

	/* Report passphrase if user selected OK */
	यदि (prompt_type == PROMPT_ENTRY) {
		passphrase = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
		यदि (result == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    strlen(passphrase), रिक्त, रिक्त, रिक्त);
			यदि (local != रिक्त) {
				puts(local);
				memset(local, '\0', strlen(local));
				g_free(local);
			} अन्यथा {
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
	यदि (result != GTK_RESPONSE_OK && result != GTK_RESPONSE_YES)
		प्रत्यागम -1;
	प्रत्यागम 0;

 nograbkb:
	/*
	 * At least one grab failed - ungrab what we got, and report
	 * the failure to the user.  Note that XGrabServer() cannot
	 * fail.
	 */
	gdk_pointer_ungrab(GDK_CURRENT_TIME);
 nograb:
	यदि (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	gtk_widget_destroy(dialog);
	
	report_failed_grab(parent_window, failed);

	प्रत्यागम (-1);
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	वर्ण *message, *prompt_mode;
	पूर्णाङ्क result, prompt_type = PROMPT_ENTRY;

	gtk_init(&argc, &argv);

	यदि (argc > 1) {
		message = g_strjoinv(" ", argv + 1);
	} अन्यथा {
		message = g_strdup("Enter your OpenSSH passphrase:");
	}

	यदि ((prompt_mode = getenv("SSH_ASKPASS_PROMPT")) != रिक्त) {
		यदि (strcasecmp(prompt_mode, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		अन्यथा यदि (strcasecmp(prompt_mode, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	result = passphrase_dialog(message, prompt_type);
	g_free(message);

	प्रत्यागम (result);
}
