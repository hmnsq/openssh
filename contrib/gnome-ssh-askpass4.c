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

/* GCR support by Jan Tojnar <jtojnar@gmail.com> */

/*
 * This is a simple SSH passphrase grabber for GNOME. To use it, set the
 * environment variable SSH_ASKPASS to point to the location of
 * gnome-ssh-askpass before calling "ssh-add < /dev/null".
 */

/*
 * Known problems:
 *   - This depends on unstable libgcr features
 *   - long key fingerprints may be truncted:
 *     https://gitlab.gnome.org/GNOME/gnome-shell/-/issues/6781
 */

/*
 * Compile with:
 *
 * cc -Wall `pkg-config --cflags gcr-4 gio-2.0` \
 *    gnome-ssh-askpass4.c -o gnome-ssh-askpass \
 *    `pkg-config --libs gcr-4 gio-2.0`
 *
 */

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <err.h>

#अन्तर्भाव <gio/gio.h>

#परिभाषय GCR_API_SUBJECT_गन्तव्यम्_CHANGE 1
#अन्तर्भाव <gcr/gcr.h>

प्रकारनिर्देश गणना _PromptType {
	PROMPT_प्रविष्टिः,
	PROMPT_CONFIRM,
	PROMPT_NONE,
} PromptType;

प्रकारनिर्देश संरचना _PromptState {
	GApplication *app;
	वर्ण* सन्देशः_2;
	PromptType type;
	पूर्णाङ्क exit_स्थितिः;
} PromptState;

स्थिर PromptState *
prompt_state_new(GApplication *app, वर्ण* सन्देशः_2, PromptType type)
{
	PromptState *state = g_malloc(परिमाण(PromptState));
	state->app = g_object_ref(app);
	state->सन्देशः_2 = g_strdup(सन्देशः_2);
	state->type = type;
	state->exit_स्थितिः = -1;
	प्रत्यागम state;
}

स्थिर शून्य
prompt_state_free(PromptState *state)
{
	g_clear_object(&state->app);
	g_free(state->सन्देशः_2);
	g_free(state);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PromptState, prompt_state_free)

स्थिर शून्य
prompt_password_समाप्तम्(GObject *source_object, GAsync_परिणाम *res,
    gpointer user_दत्त)
{
	GcrPrompt *prompt = GCR_PROMPT(source_object);
	PromptState *state = user_दत्त;
	g_autoptr(GError) error = रिक्त;

	/*
	 * “The returned password is valid until the next time a method
	 * is called to display another prompt.”
	 */
	ध्रुव वर्ण *pw = gcr_prompt_password_finish(prompt, res, &error);

	यदि ((!pw && !error) || (error && error->संहिता == G_IO_ERROR_CANCELLED)) {
		/* Operation was cancelled or timed out. */
		state->exit_स्थितिः = -1;
	} अन्यथा यदि (error) {
		warnx("Failed to prompt for ssh-askpass: %s", error->सन्देशः_2);
		state->exit_स्थितिः = 1;
	} अन्यथा {
		/* Report passphrase if user selected Continue. */
		g_autofree वर्ण *local = g_locale_from_utf8(pw, वाक्यदैर्घ्यम्(pw),
		    रिक्त, रिक्त, रिक्त);

		यदि (local != रिक्त) {
			पङ्क्तिं_लिख(local);
			स्मृतिं_पूरय(local, '\0', वाक्यदैर्घ्यम्(local));
		} अन्यथा {
			पङ्क्तिं_लिख(pw);
		}
		state->exit_स्थितिः = 0;
	}

	g_application_release(state->app);
}

स्थिर शून्य
prompt_confirm_समाप्तम्(GObject *source_object, GAsync_परिणाम *res,
    gpointer user_दत्त)
{
	GcrPrompt *prompt = GCR_PROMPT(source_object);
	PromptState *state = user_दत्त;
	g_autoptr(GError) error = रिक्त;

	Gcr_Prompt_प्रत्युत्तरम् प्रत्युत्तरम् = gcr_prompt_confirm_finish(prompt, res, &error);
	यदि (error) {
		यदि (error->संहिता == G_IO_ERROR_CANCELLED) {
			/* Operation was cancelled or timed out. */
			state->exit_स्थितिः = -1;
		} अन्यथा {
			state->exit_स्थितिः = 1;
			warnx("Failed to prompt for ssh-askpass: %s",
			    error->सन्देशः_2);
		}
	} अन्यथा यदि (प्रत्युत्तरम् == GCR_PROMPT_प्रत्युत्तरम्_CONTINUE ||
	    state->type == PROMPT_NONE) {
		/*
		 * Since Gcr doesn’t yet support one button message
		 * boxes treat Cancel the same as Continue.
		 */
		state->exit_स्थितिः = 0;
	} अन्यथा {
		/* GCR_PROMPT_REPLY_CANCEL */
		state->exit_स्थितिः = -1;
	}

	g_application_release(state->app);
}

स्थिर पूर्णाङ्क
command_पङ्क्तिः(GApplication* app, G_GNUC_अप्रयुक्तम् GApplication_Command_पङ्क्तिः *cmdline,
    gpointer user_दत्त)
{
	PromptState *state = user_दत्त;

	/* Prevent app from exiting while waiting for the async callback. */
	g_application_hold(app);

	/* Wait indefinitely. */
	पूर्णाङ्क timeout_seconds = -1;
	g_autoptr(GError) error = रिक्त;
	GcrPrompt* prompt = gcr_system_prompt_open(timeout_seconds, रिक्त, &error);

	यदि (!prompt) {
		यदि (error->संहिता == GCR_SYSTEM_PROMPT_अन्तर्_प्रगतिः) {
			/*
			 * This means the timeout elapsed, but no prompt
			 * was ever shown.
			 */
			warnx("Timeout: the Gcr system prompter was "
			    "already in use.");
		} अन्यथा {
			warnx("Couldn’t create prompt for ssh-askpass: %s",
			    error->सन्देशः_2);
		}

		प्रत्यागम 1;
	}

	gcr_prompt_समुच्चयः_सन्देशः(prompt, "OpenSSH");
	gcr_prompt_समुच्चयः_description(prompt, state->सन्देशः_2);

	/*
	 * XXX: Remove the Cancel button for PROMPT_NONE when GCR
	 * supports that.
	 */
	यदि (state->type == PROMPT_प्रविष्टिः) {
		gcr_prompt_password_async(prompt, रिक्त, prompt_password_समाप्तम्, state);
	} अन्यथा {
		gcr_prompt_confirm_async(prompt, रिक्त, prompt_confirm_समाप्तम्, state);
	}

	/* The exit status will be changed in the async callbacks. */
	प्रत्यागम 1;
}

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	g_autoptr(GApplication) app = g_application_new(
	    "com.openssh.gnome-ssh-askpass4",
	    G_APPLICATION_HANDLES_COMMAND_पङ्क्तिः);
	g_autofree वर्ण *सन्देशः_2 = रिक्त;

	यदि (argc > 1) {
		सन्देशः_2 = g_strjoinv(" ", argv + 1);
	} अन्यथा {
		सन्देशः_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	ध्रुव वर्ण *prompt_बहुलकम् = getenv("SSH_ASKPASS_PROMPT");
	PromptType type = PROMPT_प्रविष्टिः;
	यदि (prompt_बहुलकम् != रिक्त) {
		यदि (strcasecmp(prompt_बहुलकम्, "confirm") == 0) {
			type = PROMPT_CONFIRM;
		} अन्यथा यदि (strcasecmp(prompt_बहुलकम्, "none") == 0) {
			type = PROMPT_NONE;
		}
	}

	g_autoptr(PromptState) state = prompt_state_new(app, सन्देशः_2, type);

	g_signal_connect(app, "command-line", G_CALLBACK(command_पङ्क्तिः), state);

	/*
	 * Since we are calling g_application_hold, we cannot use
	 * g_application_command_line_set_exit_status.
	 * To change the exit status returned by g_application_run:
	 *   “If the commandline invocation results in the mainloop running
	 *   (ie: because the use-count of the application increased to a
	 *   non-zero value) then the application is considered to have been
	 *   ‘successful’ in a certain sense, and the exit status is always
	 *   zero.”
	 */
	(शून्य)(g_application_सततम्(app, argc, argv));

	प्रत्यागम state->exit_स्थितिः;
}
