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

#घोषणा GRAB_TRIES	16
#घोषणा GRAB_WAIT	250 /* milliseconds */

#घोषणा PROMPT_ENTRY	0
#घोषणा PROMPT_CONFIRM	1
#घोषणा PROMPT_NONE	2

/*
 * Compile with:
 *
 * cc -Wall `pkg-config --cflags gtk+-2.0` \
 *    gnome-ssh-askpass2.c -o gnome-ssh-askpass \
 *    `pkg-config --libs gtk+-2.0`
 *
 */

#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश <X11/Xlib.h>
#समावेश <gtk/gtk.h>
#समावेश <gdk/gdkx.h>
#समावेश <gdk/gdkkeysyms.h>

अटल व्योम
report_failed_grab (GtkWidget *parent_window, स्थिर अक्षर *what)
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

अटल व्योम
ok_dialog(GtkWidget *entry, gpointer dialog)
{
	g_return_if_fail(GTK_IS_DIALOG(dialog));
	gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
}

अटल gboolean
check_none(GtkWidget *widget, Gdk_Event_कुंजी *event, gpointer dialog)
{
	चयन (event->keyval) {
	हाल GDK_कुंजी_Escape:
		/* esc -> close dialog */
		gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
		वापस TRUE;
	हाल GDK_कुंजी_Tab:
		/* tab -> focus close button */
		gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(
		    dialog, GTK_RESPONSE_CLOSE));
		वापस TRUE;
	शेष:
		/* eat all other key events */
		वापस TRUE;
	}
}

अटल पूर्णांक
parse_env_hex_color(स्थिर अक्षर *env, GdkColor *c)
{
	स्थिर अक्षर *s;
	अचिन्हित दीर्घ ul;
	अक्षर *ep;
	माप_प्रकार n;

	अगर ((s = दो_पर्या(env)) == शून्य)
		वापस 0;

	स_रखो(c, 0, माप(*c));

	/* Permit hex rgb or rrggbb optionally prefixed by '#' or '0x' */
	अगर (*s == '#')
		s++;
	अन्यथा अगर (म_भेदन(s, "0x", 2) == 0)
		s += 2;
	n = म_माप(s);
	अगर (n != 3 && n != 6)
		जाओ bad;
	ul = म_से_अदीर्घ(s, &ep, 16);
	अगर (*ep != '\0' || ul > 0xffffff) {
 bad:
		ख_लिखो(मानक_त्रुटि, "Invalid $%s - invalid hex color code\n", env);
		वापस 0;
	}
	/* Valid hex sequence; expand into a GdkColor */
	अगर (n == 3) {
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
	वापस 1;
}

अटल पूर्णांक
passphrase_dialog(अक्षर *message, पूर्णांक prompt_type)
{
	स्थिर अक्षर *failed;
	अक्षर *passphrase, *local;
	पूर्णांक परिणाम, grab_tries, grab_server, grab_pointer;
	पूर्णांक buttons, default_response;
	GtkWidget *parent_window, *dialog, *entry;
	GdkGrabStatus status;
	GdkColor fg, bg;
	पूर्णांक fg_set = 0, bg_set = 0;

	grab_server = (दो_पर्या("GNOME_SSH_ASKPASS_GRAB_SERVER") != शून्य);
	grab_pointer = (दो_पर्या("GNOME_SSH_ASKPASS_GRAB_POINTER") != शून्य);
	grab_tries = 0;

	fg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_FG_COLOR", &fg);
	bg_set = parse_env_hex_color("GNOME_SSH_ASKPASS_BG_COLOR", &bg);

	/* Create an invisible parent window so that GtkDialog doesn't
	 * complain.  */
	parent_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

	चयन (prompt_type) {
	हाल PROMPT_CONFIRM:
		buttons = GTK_BUTTONS_YES_NO;
		default_response = GTK_RESPONSE_YES;
		अवरोध;
	हाल PROMPT_NONE:
		buttons = GTK_BUTTONS_CLOSE;
		default_response = GTK_RESPONSE_CLOSE;
		अवरोध;
	शेष:
		buttons = GTK_BUTTONS_OK_CANCEL;
		default_response = GTK_RESPONSE_OK;
		अवरोध;
	}

	dialog = gtk_message_dialog_new(GTK_WINDOW(parent_window), 0,
	    GTK_MESSAGE_QUESTION, buttons, "%s", message);

	gtk_window_set_title(GTK_WINDOW(dialog), "OpenSSH");
	gtk_window_set_position (GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), default_response);
	gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);

	अगर (fg_set)
		gtk_widget_modify_fg(dialog, GTK_STATE_NORMAL, &fg);
	अगर (bg_set)
		gtk_widget_modify_bg(dialog, GTK_STATE_NORMAL, &bg);

	अगर (prompt_type == PROMPT_ENTRY || prompt_type == PROMPT_NONE) {
		entry = gtk_entry_new();
		अगर (fg_set)
			gtk_widget_modify_fg(entry, GTK_STATE_NORMAL, &fg);
		अगर (bg_set)
			gtk_widget_modify_bg(entry, GTK_STATE_NORMAL, &bg);
		gtk_box_pack_start(
		    GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		    entry, FALSE, FALSE, 0);
		gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
		gtk_widget_grab_focus(entry);
		अगर (prompt_type == PROMPT_ENTRY) {
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
	अगर (grab_pointer) {
		क्रम(;;) {
			status = gdk_pointer_grab(
			    (gtk_widget_get_window(GTK_WIDGET(dialog))), TRUE,
			    0, शून्य, शून्य, GDK_CURRENT_TIME);
			अगर (status == GDK_GRAB_SUCCESS)
				अवरोध;
			usleep(GRAB_WAIT * 1000);
			अगर (++grab_tries > GRAB_TRIES) {
				failed = "mouse";
				जाओ nograb;
			}
		}
	}
	क्रम(;;) {
		status = gdk_keyboard_grab(
		    gtk_widget_get_window(GTK_WIDGET(dialog)), FALSE,
		    GDK_CURRENT_TIME);
		अगर (status == GDK_GRAB_SUCCESS)
			अवरोध;
		usleep(GRAB_WAIT * 1000);
		अगर (++grab_tries > GRAB_TRIES) {
			failed = "keyboard";
			जाओ nograbkb;
		}
	}
	अगर (grab_server) {
		gdk_x11_grab_server();
	}

	परिणाम = gtk_dialog_run(GTK_DIALOG(dialog));

	/* Ungrab */
	अगर (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	अगर (grab_pointer)
		gdk_pointer_ungrab(GDK_CURRENT_TIME);
	gdk_keyboard_ungrab(GDK_CURRENT_TIME);
	gdk_flush();

	/* Report passphrase if user selected OK */
	अगर (prompt_type == PROMPT_ENTRY) {
		passphrase = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
		अगर (परिणाम == GTK_RESPONSE_OK) {
			local = g_locale_from_utf8(passphrase,
			    म_माप(passphrase), शून्य, शून्य, शून्य);
			अगर (local != शून्य) {
				माला_दो(local);
				स_रखो(local, '\0', म_माप(local));
				g_free(local);
			} अन्यथा {
				माला_दो(passphrase);
			}
		}
		/* Zero passphrase in memory */
		स_रखो(passphrase, '\b', म_माप(passphrase));
		gtk_entry_set_text(GTK_ENTRY(entry), passphrase);
		स_रखो(passphrase, '\0', म_माप(passphrase));
		g_free(passphrase);
	}

	gtk_widget_destroy(dialog);
	अगर (परिणाम != GTK_RESPONSE_OK && परिणाम != GTK_RESPONSE_YES)
		वापस -1;
	वापस 0;

 nograbkb:
	/*
	 * At least one grab failed - ungrab what we got, and report
	 * the failure to the user.  Note that XGrabServer() cannot
	 * fail.
	 */
	gdk_pointer_ungrab(GDK_CURRENT_TIME);
 nograb:
	अगर (grab_server)
		XUngrabServer(gdk_x11_get_default_xdisplay());
	gtk_widget_destroy(dialog);
	
	report_failed_grab(parent_window, failed);

	वापस (-1);
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	अक्षर *message, *prompt_mode;
	पूर्णांक परिणाम, prompt_type = PROMPT_ENTRY;

	gtk_init(&argc, &argv);

	अगर (argc > 1) {
		message = g_strjoinv(" ", argv + 1);
	} अन्यथा {
		message = g_strdup("Enter your OpenSSH passphrase:");
	}

	अगर ((prompt_mode = दो_पर्या("SSH_ASKPASS_PROMPT")) != शून्य) {
		अगर (strcasecmp(prompt_mode, "confirm") == 0)
			prompt_type = PROMPT_CONFIRM;
		अन्यथा अगर (strcasecmp(prompt_mode, "none") == 0)
			prompt_type = PROMPT_NONE;
	}

	रखो_भबफ(मानक_निकास, 0, _IONBF, 0);
	परिणाम = passphrase_dialog(message, prompt_type);
	g_free(message);

	वापस (परिणाम);
}
