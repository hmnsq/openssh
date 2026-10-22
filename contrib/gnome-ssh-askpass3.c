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

#परिभाषय GRAB_TRIES	16
#परिभाषय GRAB_WAIT	250 /* milliseconds */

#परिभाषय PROMPT_प्रविष्टिः	0
#परिभाषय PROMPT_CONFIRM	1
#परिभाषय PROMPT_NONE	2

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
ok_dialog(GtkWidget *प्रविष्टिः, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

स्थिर gboolean
check_none(GtkWidget *widget, Gdk_Event_कुञ्चिका *event, gpointer dialog)
{
	विकल्प (event->keyval) {
	पक्ष GDK_कुञ्चिका_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		प्रत्यागम TRUE;
	पक्ष GDK_कुञ्चिका_Tab:
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
	अचिह्नित दीर्घ ul;
	वर्ण *ep;
	आकार_t n;

	यदि ((s = getenv(env)) == रिक्त)
		प्रत्यागम 0;

	स्मृतिं_पूरय(c, 0, परिमाण(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	यदि (*s == '#')
		s++;
	अन्यथा यदि (वाक्ये_तुलय(s, "0x", 2) == 0)
		s += 2;
	n = वाक्यदैर्घ्यम्(s);
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
passphrase_dialog(वर्ण *सन्देशः_2, पूर्णाङ्क prompt_type)
{
	ध्रुव वर्ण *failed;
	वर्ण *passphrase, *local;
	पूर्णाङ्क परिणाम, grab_tries, grab_server, grab_pointer;
	पूर्णाङ्क buttons, default_response;
	GtkWidget *parent_गवाक्षः, *dialog, *प्रविष्टिः, *err;
	Gdk_Grab_स्थितिः स्थितिः;
	GdkColor fg, bg;
	GdkSeat *seat;
	GdkDisplay *display;
	GdkSeatCapabilities caps;
	पूर्णाङ्क fg_समुच्चयः = 0, bg_समुच्चयः = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != रिक्त);
	grab_pointer = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != रिक्त);
	grab_tries = 0;

	fg_समुच्चयः = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_समुच्चयः = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	parent_गवाक्षः = gtk_गवाक्षः_new(GTK_गवाक्षः_TOPLEVEL);

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

	dialog = gtk_सन्देशः_dialog_new(GTK_गवाक्षः(parent_गवाक्षः), 0,
	    GTK_सन्देशः_QUESTION, buttons, "%s", सन्देशः_2);

	gtk_गवाक्षः_समुच्चयः_title(GTK_गवाक्षः(dialog), "OpenSSH");
	gtk_गवाक्षः_समुच्चयः_position (GTK_गवाक्षः(dialog), GTK_WIN_POS_CENTER);
	gtk_गवाक्षः_समुच्चयः_keep_above(GTK_गवाक्षः(dialog), TRUE);
	gtk_dialog_समुच्चयः_default_response(GTK_DIALOG(dialog), default_response);
	gtk_गवाक्षः_समुच्चयः_keep_above(GTK_गवाक्षः(dialog), TRUE);

	यदि (fg_समुच्चयः)
		gtk_widget_modify_fg(dialog, GTK_STATE_प्रसामान्यम्, &fg);
	यदि (bg_समुच्चयः)
		gtk_widget_modify_bg(dialog, GTK_STATE_प्रसामान्यम्, &bg);

	यदि (prompt_type == PROMPT_प्रविष्टिः || prompt_type == PROMPT_NONE) {
		प्रविष्टिः = gtk_प्रविष्टिः_new();
		यदि (fg_समुच्चयः)
			gtk_widget_modify_fg(प्रविष्टिः, GTK_STATE_प्रसामान्यम्, &fg);
		यदि (bg_समुच्चयः)
			gtk_widget_modify_bg(प्रविष्टिः, GTK_STATE_प्रसामान्यम्, &bg);
		gtk_box_pack_start(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    प्रविष्टिः, FALSE, FALSE, 0);
		gtk_प्रविष्टिः_समुच्चयः_visibility(GTK_प्रविष्टिः(प्रविष्टिः), FALSE);
		gtk_widget_grab_focus(प्रविष्टिः);
		यदि (prompt_type == PROMPT_प्रविष्टिः) {
			gtk_widget_show(प्रविष्टिः);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(प्रविष्टिः), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} अन्यथा {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(प्रविष्टिः);
			g_signal_connect(G_OBJECT(प्रविष्टिः), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}
	/* Grab focus */
	gtk_widget_show_now(dialog);
	display = gtk_widget_get_display(GTK_WIDGET(dialog));
	seat = gdk_display_get_default_seat(display);
	caps = GDK_SEAT_CAPABILITY_KEYBOARD;
	यदि (grab_pointer)
		caps |= GDK_SEAT_CAPABILITY_ALL_POINTING;
	यदि (grab_server)
		caps = GDK_SEAT_CAPABILITY_ALL;
	प्रति (;;) {
		स्थितिः = gdk_seat_grab(seat, gtk_widget_get_गवाक्षः(dialog),
		    caps, TRUE, रिक्त, रिक्त, रिक्त, रिक्त);
		यदि (स्थितिः == GDK_GRAB_SUCCESS)
			भङ्ग;
		usleep(GRAB_WAIT * 1000);
		यदि (++grab_tries > GRAB_TRIES)
			गच्छ nograb;
	}

	परिणाम = gtk_dialog_सततम्(GTK_DIALOG(dialog));

	/* Ungrab */
	gdk_seat_ungrab(seat);
	gdk_display_flush(display);

	/* Report passphrase if user selected OK */
	यदि (prompt_type == PROMPT_प्रविष्टिः) {
		passphrase = g_strdup(gtk_प्रविष्टिः_get_text(GTK_प्रविष्टिः(प्रविष्टिः)));
		यदि (परिणाम == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    वाक्यदैर्घ्यम्(passphrase), रिक्त, रिक्त, रिक्त);
			यदि (local != रिक्त) {
				पङ्क्तिं_लिख(local);
				स्मृतिं_पूरय(local, '\0', वाक्यदैर्घ्यम्(local));
				g_free(local);
			} अन्यथा {
				पङ्क्तिं_लिख(passphrase);
			}
		}
		/* Zero passphrase in memory */
		स्मृतिं_पूरय(passphrase, '\b', वाक्यदैर्घ्यम्(passphrase));
		gtk_प्रविष्टिः_समुच्चयः_text(GTK_प्रविष्टिः(प्रविष्टिः), passphrase);
		स्मृतिं_पूरय(passphrase, '\0', वाक्यदैर्घ्यम्(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	यदि (परिणाम != GTK_RESPONSE_OK && परिणाम != GTK_RESPONSE_YES)
		प्रत्यागम -1;
	प्रत्यागम 0;

 nograb:
	gtk_widget_destroy(dialog);
	err = gtk_सन्देशः_dialog_new(GTK_गवाक्षः(parent_गवाक्षः), 0,
	    GTK_सन्देशः_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab input. A malicious client may be eavesdropping "
	    "on your session.");
	gtk_गवाक्षः_समुच्चयः_position(GTK_गवाक्षः(err), GTK_WIN_POS_CENTER);
	gtk_dialog_सततम्(GTK_DIALOG(err));
	gtk_widget_destroy(err);
	प्रत्यागम -1;
}

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	वर्ण *सन्देशः_2, *prompt_बहुलकम्;
	पूर्णाङ्क परिणाम, prompt_type = PROMPT_प्रविष्टिः;

	gtk_init(&argc, &argv);

	यदि (argc > 1) {
		सन्देशः_2 = g_strjoinv(" ", argv + 1);
	} अन्यथा {
		सन्देशः_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	यदि ((prompt_बहुलकम् = getenv("SSH_ASKPASS_PROMPT")) != रिक्त) {
		यदि (strcasecmp(prompt_बहुलकम्, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		अन्यथा यदि (strcasecmp(prompt_बहुलकम्, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	परिणाम = passphrase_dialog(सन्देशः_2, prompt_type);
	g_free(सन्देशः_2);

	प्रत्यागम (परिणाम);
}
