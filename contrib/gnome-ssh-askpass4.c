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

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <err.h>

#ಅನ್ತರ್ಭಾವ <gio/gio.h>

#define GCR_API_SUBJECT_TO_CHANGE 1
#ಅನ್ತರ್ಭಾವ <gcr/gcr.h>

ಪ್ರಕಾರನಿರ್ದೇಶ ಗಣನಾ _PromptType {
	PROMPT_ENTRY,
	PROMPT_CONFIRM,
	PROMPT_NONE,
} PromptType;

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ _PromptState {
	GApplication *app;
	ವರ್ಣ* message;
	PromptType type;
	ಪೂರ್ಣಾಙ್ಕ exit_status;
} PromptState;

ಸ್ಥಿರ PromptState *
prompt_state_new(GApplication *app, ವರ್ಣ* message, PromptType type)
{
	PromptState *state = g_malloc(ಪರಿಮಾಣ(PromptState));
	state->app = g_object_ref(app);
	state->message = g_strdup(message);
	state->type = type;
	state->exit_status = -1;
	ಪ್ರತ್ಯಾಗಮ state;
}

ಸ್ಥಿರ ಶೂನ್ಯ
prompt_state_free(PromptState *state)
{
	g_clear_object(&state->app);
	g_free(state->message);
	g_free(state);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PromptState, prompt_state_free)

ಸ್ಥಿರ ಶೂನ್ಯ
prompt_password_done(GObject *source_object, GAsyncResult *res,
    gpointer user_data)
{
	GcrPrompt *prompt = GCR_PROMPT(source_object);
	PromptState *state = user_data;
	g_autoptr(GError) error = ರಿಕ್ತ;

	/*
	 * “The returned password is valid until the next time a method
	 * is called to display another prompt.”
	 */
	ಧ್ರುವ ವರ್ಣ *pw = gcr_prompt_password_finish(prompt, res, &error);

	ಯದಿ ((!pw && !error) || (error && error->code == G_IO_ERROR_CANCELLED)) {
		/* Operation was cancelled or timed out. */
		state->exit_status = -1;
	} ಅನ್ಯಥಾ ಯದಿ (error) {
		warnx("Failed to prompt for ssh-askpass: %s", error->message);
		state->exit_status = 1;
	} ಅನ್ಯಥಾ {
		/* Report passphrase if user selected Continue. */
		g_autofree ವರ್ಣ *local = g_locale_from_utf8(pw, strlen(pw),
		    ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ);

		ಯದಿ (local != ರಿಕ್ತ) {
			puts(local);
			memset(local, '\0', strlen(local));
		} ಅನ್ಯಥಾ {
			puts(pw);
		}
		state->exit_status = 0;
	}

	g_application_release(state->app);
}

ಸ್ಥಿರ ಶೂನ್ಯ
prompt_confirm_done(GObject *source_object, GAsyncResult *res,
    gpointer user_data)
{
	GcrPrompt *prompt = GCR_PROMPT(source_object);
	PromptState *state = user_data;
	g_autoptr(GError) error = ರಿಕ್ತ;

	GcrPromptReply reply = gcr_prompt_confirm_finish(prompt, res, &error);
	ಯದಿ (error) {
		ಯದಿ (error->code == G_IO_ERROR_CANCELLED) {
			/* Operation was cancelled or timed out. */
			state->exit_status = -1;
		} ಅನ್ಯಥಾ {
			state->exit_status = 1;
			warnx("Failed to prompt for ssh-askpass: %s",
			    error->message);
		}
	} ಅನ್ಯಥಾ ಯದಿ (reply == GCR_PROMPT_REPLY_CONTINUE ||
	    state->type == PROMPT_NONE) {
		/*
		 * Since Gcr doesn’t yet support one button message
		 * boxes treat Cancel the same as Continue.
		 */
		state->exit_status = 0;
	} ಅನ್ಯಥಾ {
		/* GCR_PROMPT_REPLY_CANCEL */
		state->exit_status = -1;
	}

	g_application_release(state->app);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
command_ಸಾಲು(GApplication* app, G_GNUC_UNUSED GApplication_Command_ಸಾಲು *cmdline,
    gpointer user_data)
{
	PromptState *state = user_data;

	/* Prevent app from exiting while waiting for the async callback. */
	g_application_hold(app);

	/* Wait indefinitely. */
	ಪೂರ್ಣಾಙ್ಕ timeout_seconds = -1;
	g_autoptr(GError) error = ರಿಕ್ತ;
	GcrPrompt* prompt = gcr_system_prompt_open(timeout_seconds, ರಿಕ್ತ, &error);

	ಯದಿ (!prompt) {
		ಯದಿ (error->code == GCR_SYSTEM_PROMPT_IN_PROGRESS) {
			/*
			 * This means the timeout elapsed, but no prompt
			 * was ever shown.
			 */
			warnx("Timeout: the Gcr system prompter was "
			    "already in use.");
		} ಅನ್ಯಥಾ {
			warnx("Couldn’t create prompt for ssh-askpass: %s",
			    error->message);
		}

		ಪ್ರತ್ಯಾಗಮ 1;
	}

	gcr_prompt_set_message(prompt, "OpenSSH");
	gcr_prompt_set_description(prompt, state->message);

	/*
	 * XXX: Remove the Cancel button for PROMPT_NONE when GCR
	 * supports that.
	 */
	ಯದಿ (state->type == PROMPT_ENTRY) {
		gcr_prompt_password_async(prompt, ರಿಕ್ತ, prompt_password_done, state);
	} ಅನ್ಯಥಾ {
		gcr_prompt_confirm_async(prompt, ರಿಕ್ತ, prompt_confirm_done, state);
	}

	/* The exit status will be changed in the async callbacks. */
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	g_autoptr(GApplication) app = g_application_new(
	    "com.openssh.gnome-ssh-askpass4",
	    G_APPLICATION_HANDLES_COMMAND_ಸಾಲು);
	g_autofree ವರ್ಣ *message = ರಿಕ್ತ;

	ಯದಿ (argc > 1) {
		message = g_strjoinv(" ", argv + 1);
	} ಅನ್ಯಥಾ {
		message = g_strdup("Enter your OpenSSH passphrase:");
	}

	ಧ್ರುವ ವರ್ಣ *prompt_mode = getenv("SSH_ASKPASS_PROMPT");
	PromptType type = PROMPT_ENTRY;
	ಯದಿ (prompt_mode != ರಿಕ್ತ) {
		ಯದಿ (strcasecmp(prompt_mode, "confirm") == 0) {
			type = PROMPT_CONFIRM;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(prompt_mode, "none") == 0) {
			type = PROMPT_NONE;
		}
	}

	g_autoptr(PromptState) state = prompt_state_new(app, message, type);

	g_signal_connect(app, "command-line", G_CALLBACK(command_ಸಾಲು), state);

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
	(ಶೂನ್ಯ)(g_application_run(app, argc, argv));

	ಪ್ರತ್ಯಾಗಮ state->exit_status;
}
