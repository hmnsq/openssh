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

#تعریف_کړه GRAB_TRIES	16
#تعریف_کړه GRAB_WAIT	250 /* milliseconds */

#تعریف_کړه PROMPT_ثبت	0
#تعریف_کړه PROMPT_CONFIRM	1
#تعریف_کړه PROMPT_NONE	2

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
report_failed_grab (GtkWidget *پلار_کړکۍ, ثابت حرف *what)
{
	GtkWidget *err;

	err = gtk_پیغام_dialog_new(GTK_کړکۍ(پلار_کړکۍ), 0,
	    GTK_پیغام_ERROR, GTK_BUTTONS_CLOSE,
	    "Could not grab %s. A malicious client may be eavesdropping "
	    "on your session.", what);
	gtk_کړکۍ_سېټ_position(GTK_کړکۍ(err), GTK_WIN_POS_CENTER);

	gtk_dialog_پرلپسې(GTK_DIALOG(err));

	gtk_widget_destroy(err);
}

ساكن فراغ
ok_dialog(GtkWidget *ثبت, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

ساكن gboolean
check_none(GtkWidget *widget, Gdk_Event_کلی *event, gpointer dialog)
{
	بدل (event->keyval) {
	حالة GDK_کلی_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		أرجع TRUE;
	حالة GDK_کلی_Tab:
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
	بینښه اوږد ul;
	حرف *ep;
	اندازه_t n;

	إذا ((s = getenv(env)) == عدم)
		أرجع 0;

	memset(c, 0, حجم(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	إذا (*s == '#')
		s++;
	وإلا إذا (مزي_پرتله(s, "0x", 2) == 0)
		s += 2;
	n = مزي_اوږدوالی(s);
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
passphrase_dialog(حرف *پیغام_2, صحيح prompt_type)
{
	ثابت حرف *failed;
	حرف *passphrase, *local;
	صحيح پایله, grab_tries, grab_server, grab_اشاره_ګر;
	صحيح buttons, default_response;
	GtkWidget *پلار_کړکۍ, *dialog, *ثبت;
	Gdk_Grab_حالت حالت;
	GdkColor fg, bg;
	صحيح fg_سېټ = 0, bg_سېټ = 0;

	grab_server = (getenv("GNOME_SSH_ASKPASS_GRAB_SERVER") != عدم);
	grab_اشاره_ګر = (getenv("GNOME_SSH_ASKPASS_GRAB_POINTER") != عدم);
	grab_tries = 0;

	fg_سېټ = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_سېټ = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	پلار_کړکۍ = gtk_کړکۍ_new(GTK_کړکۍ_TOPLEVEL);

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

	dialog = gtk_پیغام_dialog_new(GTK_کړکۍ(پلار_کړکۍ), 0,
	    GTK_پیغام_QUESTION, buttons, "%s", پیغام_2);

	gtk_کړکۍ_سېټ_title(GTK_کړکۍ(dialog), "OpenSSH");
	gtk_کړکۍ_سېټ_position (GTK_کړکۍ(dialog), GTK_WIN_POS_CENTER);
	gtk_کړکۍ_سېټ_keep_above(GTK_کړکۍ(dialog), TRUE);
	gtk_dialog_سېټ_default_response(GTK_DIALOG(dialog), default_response);
	gtk_کړکۍ_سېټ_keep_above(GTK_کړکۍ(dialog), TRUE);

	إذا (fg_سېټ)
		gtk_widget_modify_fg(dialog, GTK_STATE_نورمال, &fg);
	إذا (bg_سېټ)
		gtk_widget_modify_bg(dialog, GTK_STATE_نورمال, &bg);

	إذا (prompt_type == PROMPT_ثبت || prompt_type == PROMPT_NONE) {
		ثبت = gtk_ثبت_new();
		إذا (fg_سېټ)
			gtk_widget_modify_fg(ثبت, GTK_STATE_نورمال, &fg);
		إذا (bg_سېټ)
			gtk_widget_modify_bg(ثبت, GTK_STATE_نورمال, &bg);
		gtk_box_pack_پیل(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    ثبت, FALSE, FALSE, 0);
		gtk_ثبت_سېټ_visibility(GTK_ثبت(ثبت), FALSE);
		gtk_widget_grab_focus(ثبت);
		إذا (prompt_type == PROMPT_ثبت) {
			gtk_widget_show(ثبت);
			/* Make <enter> close dialog */
			g_signal_connect(G_OBJECT(ثبت), "activate",
					 G_CALLBACK(ok_dialog), dialog);
		} وإلا {
			/*
			 * Ensure the 'close' button is not focused by default
			 * but is still reachable via tab. This is a bit of a
			 * hack - it uses a hidden entry that responds to a
			 * couple of keypress events (escape and tab only).
			 */
			gtk_widget_realize(ثبت);
			g_signal_connect(G_OBJECT(ثبت), "key_press_event",
			    G_CALLBACK(check_none), dialog);
		}
	}

	/* Grab focus */
	gtk_widget_show_now(dialog);
	إذا (grab_اشاره_ګر) {
		لكل(;;) {
			حالت = gdk_اشاره_ګر_grab(
			    (gtk_widget_get_کړکۍ(GTK_WIDGET(dialog))), TRUE,
			    0, عدم, عدم, GDK_CURRENT_وخت);
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
		    gtk_widget_get_کړکۍ(GTK_WIDGET(dialog)), FALSE,
		    GDK_CURRENT_وخت);
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

	پایله = gtk_dialog_پرلپسې(GTK_DIALOG(dialog));

	/* Ungrab */
	إذا (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	إذا (grab_اشاره_ګر)
		gdk_اشاره_ګر_ungrab(GDK_CURRENT_وخت);
	gdk_keyboard_ungrab(GDK_CURRENT_وخت);
	gdk_flush();

	/* Report passphrase if user selected OK */
	إذا (prompt_type == PROMPT_ثبت) {
		passphrase = g_strdup(gtk_ثبت_get_متن(GTK_ثبت(ثبت)));
		إذا (پایله == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    مزي_اوږدوالی(passphrase), عدم, عدم, عدم);
			إذا (local != عدم) {
				puts(local);
				memset(local, '\0', مزي_اوږدوالی(local));
				g_free(local);
			} وإلا {
				puts(passphrase);
			}
		}
		/* Zero passphrase in memory */
		memset(passphrase, '\b', مزي_اوږدوالی(passphrase));
		gtk_ثبت_سېټ_متن(GTK_ثبت(ثبت), passphrase);
		memset(passphrase, '\0', مزي_اوږدوالی(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	إذا (پایله != GTK_RESPONSE_OK && پایله != GTK_RESPONSE_YES)
		أرجع -1;
	أرجع 0;

 nograbkb:
	/*
	 * At least one grab failed - ungrab what we got, and report
	 * the failure to the user.  Note that XGrabServer() cannot
	 * fail.
	 */
	gdk_اشاره_ګر_ungrab(GDK_CURRENT_وخت);
 nograb:
	إذا (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	gtk_widget_destroy(dialog);
	
	report_failed_grab(پلار_کړکۍ, failed);

	أرجع (-1);
}

صحيح
اصلي(صحيح argc, حرف **argv)
{
	حرف *پیغام_2, *prompt_ډېرپېښ;
	صحيح پایله, prompt_type = PROMPT_ثبت;

	gtk_init(&argc, &argv);

	إذا (argc > 1) {
		پیغام_2 = g_strjoinv(" ", argv + 1);
	} وإلا {
		پیغام_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	إذا ((prompt_ډېرپېښ = getenv("SSH_ASKPASS_PROMPT")) != عدم) {
		إذا (strcasecmp(prompt_ډېرپېښ, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		وإلا إذا (strcasecmp(prompt_ډېرپېښ, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	پایله = passphrase_dialog(پیغام_2, prompt_type);
	g_free(پیغام_2);

	أرجع (پایله);
}
