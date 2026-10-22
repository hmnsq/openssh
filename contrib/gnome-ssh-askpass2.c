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

#నిర్వచించు GRAB_TRIES	16
#నిర్వచించు GRAB_WAIT	250 /* milliseconds */

#నిర్వచించు PROMPT_నమోదు	0
#నిర్వచించు PROMPT_CONFIRM	1
#నిర్వచించు PROMPT_NONE	2

/*
 * Compile with:
 *
 * cc -Wall `pkg-config --cflags gtk+-2.0` \
 *    gnome-ssh-askpass2.c -o gnome-ssh-askpass \
 *    `pkg-config --libs gtk+-2.0`
 *
 */

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ <X11/Xlib.h>
#అన్తర్భావ <gtk/gtk.h>
#అన్తర్భావ <gdk/gdkx.h>
#అన్తర్భావ <gdk/gdkkeysyms.h>

స్థిర శూన్య
report_failed_grab (GtkWidget *మాతృ_కిటికీ, స్థిరరాశి అక్షరం *what)
{
	GtkWidget *err;

	err = gtk_సందేశం_dialog_new(GTK_కిటికీ(మాతృ_కిటికీ), 0,
	    GTK_సందేశం_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab %s. A malicious client may be eavesdropping "
	    "on your session.", what);
	gtk_కిటికీ_సమితి_position(GTK_కిటికీ(err), GTK_WIN_POS_CENTER);

	gtk_dialog_నిరంతరం(GTK_DIALOG(err));

	gtk_widget_destroy(err);
}

స్థిర శూన్య
ok_dialog(GtkWidget *నమోదు_2, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

స్థిర gboolean
check_none(GtkWidget *widget, Gdk_Event_కీలకం *event, gpointer dialog)
{
	ఎంపిక (event->keyval) {
	స్థితి GDK_కీలకం_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		తిరిగి TRUE;
	స్థితి GDK_కీలకం_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		తిరిగి TRUE;
	అప్రమేయ:
		/* eat all other key events */
		తిరిగి TRUE;
	}
}

స్థిర పూర్ణాంకం
parse_env_hex_color(స్థిరరాశి అక్షరం *env, GdkColor *c)
{
	స్థిరరాశి అక్షరం *s;
	గుర్తులేని దీర్ఘ ul;
	అక్షరం *ep;
	కొలత_t n;

	ఒకవేళ ((s = getenv(env)) == ఖాళీ)
		తిరిగి 0;

	memset(c, 0, పరిమాణం(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	ఒకవేళ (*s == '#')
		s++;
	లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(s, "0x", 2) == 0)
		s += 2;
	n = అక్షరశ్రేణి_పొడవు(s);
	ఒకవేళ (n != 3 && n != 6)
		వెళ్ళు bad;
	ul = strtoul(s, &ep, 16);
	ఒకవేళ (*ep != '\0' || ul > 0xffffff) {
 bad:
		fprintf(stderr, "Invalid $%s - invalid hex color code\n", env);
		తిరిగి 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	ఒకవేళ (n == 3) {
		/* 4-bit RGB */
		c->red = ((ul >> 8) & 0xf) << 12;
		c->green = ((ul >> 4) & 0xf) << 12;
		c->blue = (ul & 0xf) << 12;
	} లేకపోతే {
		/* 8-bit RGB */
		c->red = ((ul >> 16) & 0xff) << 8;
		c->green = ((ul >> 8) & 0xff) << 8;
		c->blue = (ul & 0xff) << 8;
	}
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
passphrase_dialog(అక్షరం *సందేశం_2, పూర్ణాంకం prompt_type)
{
	స్థిరరాశి అక్షరం *failed;
	అక్షరం *passphrase, *local;
	పూర్ణాంకం ఫలితం, grab_tries, grab_server, grab_సూచిక;
	పూర్ణాంకం buttons, default_response;
	GtkWidget *మాతృ_కిటికీ, *dialog, *నమోదు_2;
	Gdk_Grab_స్థితి స్థితి_2;
	GdkColor fg, bg;
	పూర్ణాంకం fg_సమితి = 0, bg_సమితి = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != ఖాళీ);
	grab_సూచిక = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != ఖాళీ);
	grab_tries = 0;

	fg_సమితి = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_సమితి = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	మాతృ_కిటికీ = gtk_కిటికీ_new(GTK_కిటికీ_TOPLEVEL);

	ఎంపిక (prompt_type) {
	స్థితి PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		ఆపు;
	స్థితి PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		ఆపు;
	అప్రమేయ:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		ఆపు;
	}

	dialog = gtk_సందేశం_dialog_new(GTK_కిటికీ(మాతృ_కిటికీ), 0,
	    GTK_సందేశం_QUESTION, buttons, "%s", సందేశం_2);

	gtk_కిటికీ_సమితి_title(GTK_కిటికీ(dialog), "OpenSSH");
	gtk_కిటికీ_సమితి_position (GTK_కిటికీ(dialog), GTK_WIN_POS_CENTER);
	gtk_కిటికీ_సమితి_keep_above(GTK_కిటికీ(dialog), TRUE);
	gtk_dialog_సమితి_default_response(GTK_DIALOG(dialog), default_response);
	gtk_కిటికీ_సమితి_keep_above(GTK_కిటికీ(dialog), TRUE);

	ఒకవేళ (fg_సమితి)
		gtk_widget_modify_fg(dialog, GTK_STATE_సాధారణ, &fg);
	ఒకవేళ (bg_సమితి)
		gtk_widget_modify_bg(dialog, GTK_STATE_సాధారణ, &bg);

	ఒకవేళ (prompt_type == PROMPT_నమోదు || prompt_type == PROMPT_NONE) {
		నమోదు_2 = gtk_నమోదు_new();
		ఒకవేళ (fg_సమితి)
			gtk_widget_modify_fg(నమోదు_2, GTK_STATE_సాధారణ, &fg);
		ఒకవేళ (bg_సమితి)
			gtk_widget_modify_bg(నమోదు_2, GTK_STATE_సాధారణ, &bg);
		gtk_box_pack_ప్రారంభం(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    నమోదు_2, FALSE, FALSE, 0);
		gtk_నమోదు_సమితి_visibility(GTK_నమోదు(నమోదు_2), FALSE);
		gtk_widget_grab_focus(నమోదు_2);
		ఒకవేళ (prompt_type == PROMPT_నమోదు) {
			gtk_widget_show(నమోదు_2);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(నమోదు_2), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} లేకపోతే {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(నమోదు_2);
			g_signal_connect(G_OBJECT(నమోదు_2), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}

	/* Grab focus */
	gtk_widget_show_now(dialog);
	ఒకవేళ (grab_సూచిక) {
		కొరకు(;;) {
			స్థితి_2 = gdk_సూచిక_grab(
			    (gtk_widget_get_కిటికీ(GTK_WIDGET(dialog))), TRUE,
			    0, ఖాళీ, ఖాళీ, GDK_CURRENT_సమయం);
			ఒకవేళ (స్థితి_2 == GDK_GRAB_SUCCESS)
				ఆపు;
			usleep(GRAB_WAIT * 1000);
			ఒకవేళ (++grab_tries > GRAB_TRIES) {
				failed = "mouse";
				వెళ్ళు nograb;
			}
		}
	}
	కొరకు(;;) {
		స్థితి_2 = gdk_keyboard_grab(
		    gtk_widget_get_కిటికీ(GTK_WIDGET(dialog)), FALSE,
		    GDK_CURRENT_సమయం);
		ఒకవేళ (స్థితి_2 == GDK_GRAB_SUCCESS)
			ఆపు;
		usleep(GRAB_WAIT * 1000);
		ఒకవేళ (++grab_tries > GRAB_TRIES) {
			failed = "keyboard";
			వెళ్ళు nograbkb;
		}
	}
	ఒకవేళ (grab_server) {
		gdk_x11_grab_server();
	}

	ఫలితం = gtk_dialog_నిరంతరం(GTK_DIALOG(dialog));

	/* Ungrab */
	ఒకవేళ (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	ఒకవేళ (grab_సూచిక)
		gdk_సూచిక_ungrab(GDK_CURRENT_సమయం);
	gdk_keyboard_ungrab(GDK_CURRENT_సమయం);
	gdk_flush();

	/* Report passphrase if user selected OK */
	ఒకవేళ (prompt_type == PROMPT_నమోదు) {
		passphrase = g_strdup(gtk_నమోదు_get_పాఠ్యం(GTK_నమోదు(నమోదు_2)));
		ఒకవేళ (ఫలితం == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    అక్షరశ్రేణి_పొడవు(passphrase), ఖాళీ, ఖాళీ, ఖాళీ);
			ఒకవేళ (local != ఖాళీ) {
				puts(local);
				memset(local, '\0', అక్షరశ్రేణి_పొడవు(local));
				g_free(local);
			} లేకపోతే {
				puts(passphrase);
			}
		}
		/* Zero passphrase in memory */
		memset(passphrase, '\b', అక్షరశ్రేణి_పొడవు(passphrase));
		gtk_నమోదు_సమితి_పాఠ్యం(GTK_నమోదు(నమోదు_2), passphrase);
		memset(passphrase, '\0', అక్షరశ్రేణి_పొడవు(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	ఒకవేళ (ఫలితం != GTK_RESPONSE_OK && ఫలితం != GTK_RESPONSE_YES)
		తిరిగి -1;
	తిరిగి 0;

 nograbkb:
	/*
	 * At least one grab failed - ungrab what we got, and report
	 * the failure to the user.  Note that XGrabServer() cannot
	 * fail.
	 */
	gdk_సూచిక_ungrab(GDK_CURRENT_సమయం);
 nograb:
	ఒకవేళ (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	gtk_widget_destroy(dialog);
	
	report_failed_grab(మాతృ_కిటికీ, failed);

	తిరిగి (-1);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	అక్షరం *సందేశం_2, *prompt_బహుళకం;
	పూర్ణాంకం ఫలితం, prompt_type = PROMPT_నమోదు;

	gtk_init(&argc, &argv);

	ఒకవేళ (argc > 1) {
		సందేశం_2 = g_strjoinv(" ", argv + 1);
	} లేకపోతే {
		సందేశం_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	ఒకవేళ ((prompt_బహుళకం = getenv("SSH_ASKPASS_PROMPT")) != ఖాళీ) {
		ఒకవేళ (strcasecmp(prompt_బహుళకం, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		లేకపోతే ఒకవేళ (strcasecmp(prompt_బహుళకం, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	ఫలితం = passphrase_dialog(సందేశం_2, prompt_type);
	g_free(సందేశం_2);

	తిరిగి (ఫలితం);
}
