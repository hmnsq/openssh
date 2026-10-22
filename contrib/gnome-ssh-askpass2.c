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

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن <X11/Xlib.h>
#ضمن <gtk/gtk.h>
#ضمن <gdk/gdkx.h>
#ضمن <gdk/gdkkeysyms.h>

ساكن فراغ
report_failed_grab (GtkWidget *ماپا_کھڑکی, ثابت حرف *what)
{
	GtkWidget *err;

	err = gtk_سنیہا_dialog_new(GTK_کھڑکی(ماپا_کھڑکی), 0,
	    GTK_سنیہا_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab %s. A malicious client may be eavesdropping "
	    "on your session.", what);
	gtk_کھڑکی_سیٹ_position(GTK_کھڑکی(err), GTK_WIN_POS_CENTER);

	gtk_dialog_لگاتار(GTK_DIALOG(err));

	gtk_widget_destroy(err);
}

ساكن فراغ
ok_dialog(GtkWidget *اندراج, gpointer dialog)
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
	بنانشانی لما ul;
	حرف *ep;
	ناپ_t n;

	إذا ((s = getenv(env)) == عدم)
		أرجع 0;

	memset(c, 0, حجم(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	إذا (*s == '#')
		s++;
	وإلا إذا (لڑی_مقابلہ(s, "0x", 2) == 0)
		s += 2;
	n = لڑی_لمبائی(s);
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
passphrase_dialog(حرف *سنیہا, صحيح prompt_type)
{
	ثابت حرف *failed;
	حرف *passphrase, *local;
	صحيح نتیجہ, grab_tries, grab_server, grab_اشارہ_گر;
	صحيح buttons, default_response;
	GtkWidget *ماپا_کھڑکی, *dialog, *اندراج;
	Gdk_Grab_حالت حالت;
	GdkColor fg, bg;
	صحيح fg_سیٹ = 0, bg_سیٹ = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != عدم);
	grab_اشارہ_گر = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != عدم);
	grab_tries = 0;

	fg_سیٹ = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_سیٹ = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	ماپا_کھڑکی = gtk_کھڑکی_new(GTK_کھڑکی_TOPLEVEL);

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

	dialog = gtk_سنیہا_dialog_new(GTK_کھڑکی(ماپا_کھڑکی), 0,
	    GTK_سنیہا_QUESTION, buttons, "%s", سنیہا);

	gtk_کھڑکی_سیٹ_title(GTK_کھڑکی(dialog), "OpenSSH");
	gtk_کھڑکی_سیٹ_position (GTK_کھڑکی(dialog), GTK_WIN_POS_CENTER);
	gtk_کھڑکی_سیٹ_keep_above(GTK_کھڑکی(dialog), TRUE);
	gtk_dialog_سیٹ_default_response(GTK_DIALOG(dialog), default_response);
	gtk_کھڑکی_سیٹ_keep_above(GTK_کھڑکی(dialog), TRUE);

	إذا (fg_سیٹ)
		gtk_widget_modify_fg(dialog, GTK_STATE_عام, &fg);
	إذا (bg_سیٹ)
		gtk_widget_modify_bg(dialog, GTK_STATE_عام, &bg);

	إذا (prompt_type == PROMPT_اندراج || prompt_type == PROMPT_NONE) {
		اندراج = gtk_اندراج_new();
		إذا (fg_سیٹ)
			gtk_widget_modify_fg(اندراج, GTK_STATE_عام, &fg);
		إذا (bg_سیٹ)
			gtk_widget_modify_bg(اندراج, GTK_STATE_عام, &bg);
		gtk_box_pack_شروع(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    اندراج, FALSE, FALSE, 0);
		gtk_اندراج_سیٹ_visibility(GTK_اندراج(اندراج), FALSE);
		gtk_widget_grab_focus(اندراج);
		إذا (prompt_type == PROMPT_اندراج) {
			gtk_widget_show(اندراج);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(اندراج), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} وإلا {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(اندراج);
			g_signal_connect(G_OBJECT(اندراج), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}

	/* Grab focus */
	gtk_widget_show_now(dialog);
	إذا (grab_اشارہ_گر) {
		لكل(;;) {
			حالت = gdk_اشارہ_گر_grab(
			    (gtk_widget_get_کھڑکی(GTK_WIDGET(dialog))), TRUE,
			    0, عدم, عدم, GDK_CURRENT_ویلا);
			إذا (حالت == GDK_GRAB_SUCCESS)
				اكسر;
			usleep(GRAB_WAIT * 1000);
			إذا (++grab_tries > GRAB_TRIES) {
				failed = "mouse";
				اذهب nograb;
			}
		}
	}
	لكل(;;) {
		حالت = gdk_keyboard_grab(
		    gtk_widget_get_کھڑکی(GTK_WIDGET(dialog)), FALSE,
		    GDK_CURRENT_ویلا);
		إذا (حالت == GDK_GRAB_SUCCESS)
			اكسر;
		usleep(GRAB_WAIT * 1000);
		إذا (++grab_tries > GRAB_TRIES) {
			failed = "keyboard";
			اذهب nograbkb;
		}
	}
	إذا (grab_server) {
		gdk_x11_grab_server();
	}

	نتیجہ = gtk_dialog_لگاتار(GTK_DIALOG(dialog));

	/* Ungrab */
	إذا (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	إذا (grab_اشارہ_گر)
		gdk_اشارہ_گر_ungrab(GDK_CURRENT_ویلا);
	gdk_keyboard_ungrab(GDK_CURRENT_ویلا);
	gdk_flush();

	/* Report passphrase if user selected OK */
	إذا (prompt_type == PROMPT_اندراج) {
		passphrase = g_strdup(gtk_اندراج_get_متن(GTK_اندراج(اندراج)));
		إذا (نتیجہ == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    لڑی_لمبائی(passphrase), عدم, عدم, عدم);
			إذا (local != عدم) {
				puts(local);
				memset(local, '\0', لڑی_لمبائی(local));
				g_free(local);
			} وإلا {
				puts(passphrase);
			}
		}
		/* Zero passphrase in memory */
		memset(passphrase, '\b', لڑی_لمبائی(passphrase));
		gtk_اندراج_سیٹ_متن(GTK_اندراج(اندراج), passphrase);
		memset(passphrase, '\0', لڑی_لمبائی(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	إذا (نتیجہ != GTK_RESPONSE_OK && نتیجہ != GTK_RESPONSE_YES)
		أرجع -1;
	أرجع 0;

 nograbkb:
	/*
	 * At least one grab failed - ungrab what we got, and report
	 * the failure to the user.  Note that XGrabServer() cannot
	 * fail.
	 */
	gdk_اشارہ_گر_ungrab(GDK_CURRENT_ویلا);
 nograb:
	إذا (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	gtk_widget_destroy(dialog);
	
	report_failed_grab(ماپا_کھڑکی, failed);

	أرجع (-1);
}

صحيح
مکھ(صحيح argc, حرف **argv)
{
	حرف *سنیہا, *prompt_منوال;
	صحيح نتیجہ, prompt_type = PROMPT_اندراج;

	gtk_init(&argc, &argv);

	إذا (argc > 1) {
		سنیہا = g_strjoinv(" ", argv + 1);
	} وإلا {
		سنیہا = g_strdup("Enter your OpenSSH passphrase:");
	}

	إذا ((prompt_منوال = getenv("SSH_ASKPASS_PROMPT")) != عدم) {
		إذا (strcasecmp(prompt_منوال, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		وإلا إذا (strcasecmp(prompt_منوال, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	نتیجہ = passphrase_dialog(سنیہا, prompt_type);
	g_free(سنیہا);

	أرجع (نتیجہ);
}
