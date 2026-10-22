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

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <err.h>

#അന്തര്ഭാവ <gio/gio.h>

#define GCR_API_SUBJECT_TO_CHANGE 1
#അന്തര്ഭാവ <gcr/gcr.h>

തരനിർവചനം എണ്ണൽ _PromptType {
	PROMPT_ENTRY,
	PROMPT_CONFIRM,
	PROMPT_NONE,
} PromptType;

തരനിർവചനം ഘടന _PromptState {
	GApplication *app;
	അക്ഷരം* message;
	PromptType type;
	പൂർണ്ണസംഖ്യ exit_status;
} PromptState;

സ്ഥിതം PromptState *
prompt_state_new(GApplication *app, അക്ഷരം* message, PromptType type)
{
	PromptState *state = g_malloc(വലുപ്പം(PromptState));
	state->app = g_object_ref(app);
	state->message = g_strdup(message);
	state->type = type;
	state->exit_status = -1;
	തിരികെ state;
}

സ്ഥിതം ശൂന്യം
prompt_state_free(PromptState *state)
{
	g_clear_object(&state->app);
	g_free(state->message);
	g_free(state);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PromptState, prompt_state_free)

സ്ഥിതം ശൂന്യം
prompt_password_done(GObject *source_object, GAsyncResult *res,
    gpointer user_data)
{
	GcrPrompt *prompt = GCR_PROMPT(source_object);
	PromptState *state = user_data;
	g_autoptr(GError) error = ശൂന്യ;

	/*
	 * “The returned password is valid until the next time a method
	 * is called to display another prompt.”
	 */
	സ്ഥിരം അക്ഷരം *pw = gcr_prompt_password_finish(prompt, res, &error);

	എങ്കിൽ ((!pw && !error) || (error && error->code == G_IO_ERROR_CANCELLED)) {
		/* Operation was cancelled or timed out. */
		state->exit_status = -1;
	} അല്ലെങ്കിൽ എങ്കിൽ (error) {
		warnx("Failed to prompt for ssh-askpass: %s", error->message);
		state->exit_status = 1;
	} അല്ലെങ്കിൽ {
		/* Report passphrase if user selected Continue. */
		g_autofree അക്ഷരം *local = g_locale_from_utf8(pw, strlen(pw),
		    ശൂന്യ, ശൂന്യ, ശൂന്യ);

		എങ്കിൽ (local != ശൂന്യ) {
			puts(local);
			memset(local, '\0', strlen(local));
		} അല്ലെങ്കിൽ {
			puts(pw);
		}
		state->exit_status = 0;
	}

	g_application_release(state->app);
}

സ്ഥിതം ശൂന്യം
prompt_confirm_done(GObject *source_object, GAsyncResult *res,
    gpointer user_data)
{
	GcrPrompt *prompt = GCR_PROMPT(source_object);
	PromptState *state = user_data;
	g_autoptr(GError) error = ശൂന്യ;

	GcrPromptReply reply = gcr_prompt_confirm_finish(prompt, res, &error);
	എങ്കിൽ (error) {
		എങ്കിൽ (error->code == G_IO_ERROR_CANCELLED) {
			/* Operation was cancelled or timed out. */
			state->exit_status = -1;
		} അല്ലെങ്കിൽ {
			state->exit_status = 1;
			warnx("Failed to prompt for ssh-askpass: %s",
			    error->message);
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (reply == GCR_PROMPT_REPLY_CONTINUE ||
	    state->type == PROMPT_NONE) {
		/*
		 * Since Gcr doesn’t yet support one button message
		 * boxes treat Cancel the same as Continue.
		 */
		state->exit_status = 0;
	} അല്ലെങ്കിൽ {
		/* GCR_PROMPT_REPLY_CANCEL */
		state->exit_status = -1;
	}

	g_application_release(state->app);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
command_വരി(GApplication* app, G_GNUC_UNUSED GApplication_Command_വരി *cmdline,
    gpointer user_data)
{
	PromptState *state = user_data;

	/* Prevent app from exiting while waiting for the async callback. */
	g_application_hold(app);

	/* Wait indefinitely. */
	പൂർണ്ണസംഖ്യ timeout_seconds = -1;
	g_autoptr(GError) error = ശൂന്യ;
	GcrPrompt* prompt = gcr_system_prompt_open(timeout_seconds, ശൂന്യ, &error);

	എങ്കിൽ (!prompt) {
		എങ്കിൽ (error->code == GCR_SYSTEM_PROMPT_IN_PROGRESS) {
			/*
			 * This means the timeout elapsed, but no prompt
			 * was ever shown.
			 */
			warnx("Timeout: the Gcr system prompter was "
			    "already in use.");
		} അല്ലെങ്കിൽ {
			warnx("Couldn’t create prompt for ssh-askpass: %s",
			    error->message);
		}

		തിരികെ 1;
	}

	gcr_prompt_set_message(prompt, "OpenSSH");
	gcr_prompt_set_description(prompt, state->message);

	/*
	 * XXX: Remove the Cancel button for PROMPT_NONE when GCR
	 * supports that.
	 */
	എങ്കിൽ (state->type == PROMPT_ENTRY) {
		gcr_prompt_password_async(prompt, ശൂന്യ, prompt_password_done, state);
	} അല്ലെങ്കിൽ {
		gcr_prompt_confirm_async(prompt, ശൂന്യ, prompt_confirm_done, state);
	}

	/* The exit status will be changed in the async callbacks. */
	തിരികെ 1;
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	g_autoptr(GApplication) app = g_application_new(
	    "com.openssh.gnome-ssh-askpass4",
	    G_APPLICATION_HANDLES_COMMAND_വരി);
	g_autofree അക്ഷരം *message = ശൂന്യ;

	എങ്കിൽ (argc > 1) {
		message = g_strjoinv(" ", argv + 1);
	} അല്ലെങ്കിൽ {
		message = g_strdup("Enter your OpenSSH passphrase:");
	}

	സ്ഥിരം അക്ഷരം *prompt_mode = getenv("SSH_ASKPASS_PROMPT");
	PromptType type = PROMPT_ENTRY;
	എങ്കിൽ (prompt_mode != ശൂന്യ) {
		എങ്കിൽ (strcasecmp(prompt_mode, "confirm") == 0) {
			type = PROMPT_CONFIRM;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(prompt_mode, "none") == 0) {
			type = PROMPT_NONE;
		}
	}

	g_autoptr(PromptState) state = prompt_state_new(app, message, type);

	g_signal_connect(app, "command-line", G_CALLBACK(command_വരി), state);

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
	(ശൂന്യം)(g_application_run(app, argc, argv));

	തിരികെ state->exit_status;
}
