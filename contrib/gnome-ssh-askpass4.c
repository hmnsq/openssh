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

#ವ್ಯಾಖ್ಯಾನಿಸು GCR_API_SUBJECT_ಗಮ್ಯ_CHANGE 1
#ಅನ್ತರ್ಭಾವ <gcr/gcr.h>

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಎಣಿಕೆ _PromptType {
	PROMPT_ನಮೂದು,
	PROMPT_CONFIRM,
	PROMPT_NONE,
} PromptType;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ _PromptState {
	GApplication *app;
	ಅಕ್ಷರ* ಸಂದೇಶ_2;
	PromptType type;
	ಪೂರ್ಣಾಂಕ exit_ಸ್ಥಿತಿ;
} PromptState;

ಸ್ಥಿರ PromptState *
prompt_state_new(GApplication *app, ಅಕ್ಷರ* ಸಂದೇಶ_2, PromptType type)
{
	PromptState *state = g_malloc(ಗಾತ್ರ(PromptState));
	state->app = g_object_ref(app);
	state->ಸಂದೇಶ_2 = g_strdup(ಸಂದೇಶ_2);
	state->type = type;
	state->exit_ಸ್ಥಿತಿ = -1;
	ಹಿಂತಿರುಗಿ state;
}

ಸ್ಥಿರ ಶೂನ್ಯ
prompt_state_free(PromptState *state)
{
	g_clear_object(&state->app);
	g_free(state->ಸಂದೇಶ_2);
	g_free(state);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PromptState, prompt_state_free)

ಸ್ಥಿರ ಶೂನ್ಯ
prompt_password_ಮುಗಿದ(GObject *ಮೂಲ_object, GAsync_ಫಲಿತಾಂಶ *res,
    gpointer user_ದತ್ತಾಂಶ)
{
	GcrPrompt *prompt = GCR_PROMPT(ಮೂಲ_object);
	PromptState *state = user_ದತ್ತಾಂಶ;
	g_autoptr(GError) error = ಖಾಲಿ;

	/*
	 * “The returned password is valid until the next time a method
	 * is called to display another prompt.”
	 */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pw = gcr_prompt_password_ಮುಕ್ತಾಯ(prompt, res, &error);

	ಆದರೆ ((!pw && !error) || (error && error->ಸಂಕೇತ_2 == G_IO_ERROR_CANCELLED)) {
		/* Operation was cancelled or timed out. */
		state->exit_ಸ್ಥಿತಿ = -1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (error) {
		warnx("Failed to prompt for ssh-askpass: %s", error->ಸಂದೇಶ_2);
		state->exit_ಸ್ಥಿತಿ = 1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Report passphrase if user selected Continue. */
		g_autofree ಅಕ್ಷರ *local = g_locale_from_utf8(pw, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pw),
		    ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ);

		ಆದರೆ (local != ಖಾಲಿ) {
			puts(local);
			memset(local, '\0', ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(local));
		} ಇಲ್ಲದಿದ್ದರೆ {
			puts(pw);
		}
		state->exit_ಸ್ಥಿತಿ = 0;
	}

	g_application_release(state->app);
}

ಸ್ಥಿರ ಶೂನ್ಯ
prompt_confirm_ಮುಗಿದ(GObject *ಮೂಲ_object, GAsync_ಫಲಿತಾಂಶ *res,
    gpointer user_ದತ್ತಾಂಶ)
{
	GcrPrompt *prompt = GCR_PROMPT(ಮೂಲ_object);
	PromptState *state = user_ದತ್ತಾಂಶ;
	g_autoptr(GError) error = ಖಾಲಿ;

	Gcr_Prompt_ಉತ್ತರ ಉತ್ತರ = gcr_prompt_confirm_ಮುಕ್ತಾಯ(prompt, res, &error);
	ಆದರೆ (error) {
		ಆದರೆ (error->ಸಂಕೇತ_2 == G_IO_ERROR_CANCELLED) {
			/* Operation was cancelled or timed out. */
			state->exit_ಸ್ಥಿತಿ = -1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			state->exit_ಸ್ಥಿತಿ = 1;
			warnx("Failed to prompt for ssh-askpass: %s",
			    error->ಸಂದೇಶ_2);
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಉತ್ತರ == GCR_PROMPT_ಉತ್ತರ_CONTINUE ||
	    state->type == PROMPT_NONE) {
		/*
		 * Since Gcr doesn’t yet support one button message
		 * boxes treat Cancel the same as Continue.
		 */
		state->exit_ಸ್ಥಿತಿ = 0;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* GCR_PROMPT_REPLY_CANCEL */
		state->exit_ಸ್ಥಿತಿ = -1;
	}

	g_application_release(state->app);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
command_ಸಾಲು(GApplication* app, G_GNUC_ಬಳಸದ GApplication_Command_ಸಾಲು *cmdline,
    gpointer user_ದತ್ತಾಂಶ)
{
	PromptState *state = user_ದತ್ತಾಂಶ;

	/* Prevent app from exiting while waiting for the async callback. */
	g_application_hold(app);

	/* Wait indefinitely. */
	ಪೂರ್ಣಾಂಕ timeout_seconds = -1;
	g_autoptr(GError) error = ಖಾಲಿ;
	GcrPrompt* prompt = gcr_system_prompt_open(timeout_seconds, ಖಾಲಿ, &error);

	ಆದರೆ (!prompt) {
		ಆದರೆ (error->ಸಂಕೇತ_2 == GCR_SYSTEM_PROMPT_ಒಳ_ಪ್ರಗತಿ) {
			/*
			 * This means the timeout elapsed, but no prompt
			 * was ever shown.
			 */
			warnx("Timeout: the Gcr system prompter was "
			    "already in use.");
		} ಇಲ್ಲದಿದ್ದರೆ {
			warnx("Couldn’t create prompt for ssh-askpass: %s",
			    error->ಸಂದೇಶ_2);
		}

		ಹಿಂತಿರುಗಿ 1;
	}

	gcr_prompt_ಗಣ_ಸಂದೇಶ(prompt, "OpenSSH");
	gcr_prompt_ಗಣ_description(prompt, state->ಸಂದೇಶ_2);

	/*
	 * XXX: Remove the Cancel button for PROMPT_NONE when GCR
	 * supports that.
	 */
	ಆದರೆ (state->type == PROMPT_ನಮೂದು) {
		gcr_prompt_password_async(prompt, ಖಾಲಿ, prompt_password_ಮುಗಿದ, state);
	} ಇಲ್ಲದಿದ್ದರೆ {
		gcr_prompt_confirm_async(prompt, ಖಾಲಿ, prompt_confirm_ಮುಗಿದ, state);
	}

	/* The exit status will be changed in the async callbacks. */
	ಹಿಂತಿರುಗಿ 1;
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	g_autoptr(GApplication) app = g_application_new(
	    "com.openssh.gnome-ssh-askpass4",
	    G_APPLICATION_HANDLES_COMMAND_ಸಾಲು);
	g_autofree ಅಕ್ಷರ *ಸಂದೇಶ_2 = ಖಾಲಿ;

	ಆದರೆ (argc > 1) {
		ಸಂದೇಶ_2 = g_strjoinv(" ", argv + 1);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಸಂದೇಶ_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *prompt_ಬಹುಲಕ = getenv("SSH_ASKPASS_PROMPT");
	PromptType type = PROMPT_ನಮೂದು;
	ಆದರೆ (prompt_ಬಹುಲಕ != ಖಾಲಿ) {
		ಆದರೆ (strcasecmp(prompt_ಬಹುಲಕ, "confirm") == 0) {
			type = PROMPT_CONFIRM;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(prompt_ಬಹುಲಕ, "none") == 0) {
			type = PROMPT_NONE;
		}
	}

	g_autoptr(PromptState) state = prompt_state_new(app, ಸಂದೇಶ_2, type);

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
	(ಶೂನ್ಯ)(g_application_ಸತತ(app, argc, argv));

	ಹಿಂತಿರುಗಿ state->exit_ಸ್ಥಿತಿ;
}
