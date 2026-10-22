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

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <err.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <gio/gio.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ GCR_API_SUBJECT_ਮੰਜ਼ਿਲ_CHANGE 1
#ਅਨ੍ਤਰ੍ਭਾਵ <gcr/gcr.h>

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਗਿਣਤੀ _PromptType {
	PROMPT_ਇੰਦਰਾਜ,
	PROMPT_CONFIRM,
	PROMPT_NONE,
} PromptType;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ _PromptState {
	GApplication *app;
	ਅੱਖਰ* ਸੁਨੇਹਾ_2;
	PromptType type;
	ਪੂਰਨ exit_ਸਥਿਤੀ;
} PromptState;

ਸਥਿਰ PromptState *
prompt_state_new(GApplication *app, ਅੱਖਰ* ਸੁਨੇਹਾ_2, PromptType type)
{
	PromptState *state = g_malloc(ਆਕਾਰ(PromptState));
	state->app = g_object_ref(app);
	state->ਸੁਨੇਹਾ_2 = g_strdup(ਸੁਨੇਹਾ_2);
	state->type = type;
	state->exit_ਸਥਿਤੀ = -1;
	ਵਾਪਸ state;
}

ਸਥਿਰ ਖਾਲੀ
prompt_state_free(PromptState *state)
{
	g_clear_object(&state->app);
	g_free(state->ਸੁਨੇਹਾ_2);
	g_free(state);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PromptState, prompt_state_free)

ਸਥਿਰ ਖਾਲੀ
prompt_password_ਪੂਰਾ(GObject *ਸਰੋਤ_object, GAsync_ਨਤੀਜਾ *res,
    gpointer user_ਅੰਕੜੇ)
{
	GcrPrompt *prompt = GCR_PROMPT(ਸਰੋਤ_object);
	PromptState *state = user_ਅੰਕੜੇ;
	g_autoptr(GError) error = ਨਿਰਾ;

	/*
	 * “The returned password is valid until the next time a method
	 * is called to display another prompt.”
	 */
	ਅਚਲ ਅੱਖਰ *pw = gcr_prompt_password_ਅੰਤ(prompt, res, &error);

	ਜੇ ((!pw && !error) || (error && error->ਕੋਡ == G_IO_ERROR_CANCELLED)) {
		/* Operation was cancelled or timed out. */
		state->exit_ਸਥਿਤੀ = -1;
	} ਨਹੀਂਤਾਂ ਜੇ (error) {
		warnx("Failed to prompt for ssh-askpass: %s", error->ਸੁਨੇਹਾ_2);
		state->exit_ਸਥਿਤੀ = 1;
	} ਨਹੀਂਤਾਂ {
		/* Report passphrase if user selected Continue. */
		g_autofree ਅੱਖਰ *local = g_locale_from_utf8(pw, ਲੜੀ_ਲੰਬਾਈ(pw),
		    ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ);

		ਜੇ (local != ਨਿਰਾ) {
			puts(local);
			memset(local, '\0', ਲੜੀ_ਲੰਬਾਈ(local));
		} ਨਹੀਂਤਾਂ {
			puts(pw);
		}
		state->exit_ਸਥਿਤੀ = 0;
	}

	g_application_release(state->app);
}

ਸਥਿਰ ਖਾਲੀ
prompt_confirm_ਪੂਰਾ(GObject *ਸਰੋਤ_object, GAsync_ਨਤੀਜਾ *res,
    gpointer user_ਅੰਕੜੇ)
{
	GcrPrompt *prompt = GCR_PROMPT(ਸਰੋਤ_object);
	PromptState *state = user_ਅੰਕੜੇ;
	g_autoptr(GError) error = ਨਿਰਾ;

	Gcr_Prompt_ਜਵਾਬ ਜਵਾਬ = gcr_prompt_confirm_ਅੰਤ(prompt, res, &error);
	ਜੇ (error) {
		ਜੇ (error->ਕੋਡ == G_IO_ERROR_CANCELLED) {
			/* Operation was cancelled or timed out. */
			state->exit_ਸਥਿਤੀ = -1;
		} ਨਹੀਂਤਾਂ {
			state->exit_ਸਥਿਤੀ = 1;
			warnx("Failed to prompt for ssh-askpass: %s",
			    error->ਸੁਨੇਹਾ_2);
		}
	} ਨਹੀਂਤਾਂ ਜੇ (ਜਵਾਬ == GCR_PROMPT_ਜਵਾਬ_CONTINUE ||
	    state->type == PROMPT_NONE) {
		/*
		 * Since Gcr doesn’t yet support one button message
		 * boxes treat Cancel the same as Continue.
		 */
		state->exit_ਸਥਿਤੀ = 0;
	} ਨਹੀਂਤਾਂ {
		/* GCR_PROMPT_REPLY_CANCEL */
		state->exit_ਸਥਿਤੀ = -1;
	}

	g_application_release(state->app);
}

ਸਥਿਰ ਪੂਰਨ
command_ਸਤਰ(GApplication* app, G_GNUC_ਅਣਵਰਤਿਆ GApplication_Command_ਸਤਰ *cmdline,
    gpointer user_ਅੰਕੜੇ)
{
	PromptState *state = user_ਅੰਕੜੇ;

	/* Prevent app from exiting while waiting for the async callback. */
	g_application_hold(app);

	/* Wait indefinitely. */
	ਪੂਰਨ timeout_seconds = -1;
	g_autoptr(GError) error = ਨਿਰਾ;
	GcrPrompt* prompt = gcr_system_prompt_open(timeout_seconds, ਨਿਰਾ, &error);

	ਜੇ (!prompt) {
		ਜੇ (error->ਕੋਡ == GCR_SYSTEM_PROMPT_ਵਿੱਚ_ਤਰੱਕੀ) {
			/*
			 * This means the timeout elapsed, but no prompt
			 * was ever shown.
			 */
			warnx("Timeout: the Gcr system prompter was "
			    "already in use.");
		} ਨਹੀਂਤਾਂ {
			warnx("Couldn’t create prompt for ssh-askpass: %s",
			    error->ਸੁਨੇਹਾ_2);
		}

		ਵਾਪਸ 1;
	}

	gcr_prompt_ਸੈੱਟ_ਸੁਨੇਹਾ(prompt, "OpenSSH");
	gcr_prompt_ਸੈੱਟ_description(prompt, state->ਸੁਨੇਹਾ_2);

	/*
	 * XXX: Remove the Cancel button for PROMPT_NONE when GCR
	 * supports that.
	 */
	ਜੇ (state->type == PROMPT_ਇੰਦਰਾਜ) {
		gcr_prompt_password_async(prompt, ਨਿਰਾ, prompt_password_ਪੂਰਾ, state);
	} ਨਹੀਂਤਾਂ {
		gcr_prompt_confirm_async(prompt, ਨਿਰਾ, prompt_confirm_ਪੂਰਾ, state);
	}

	/* The exit status will be changed in the async callbacks. */
	ਵਾਪਸ 1;
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	g_autoptr(GApplication) app = g_application_new(
	    "com.openssh.gnome-ssh-askpass4",
	    G_APPLICATION_HANDLES_COMMAND_ਸਤਰ);
	g_autofree ਅੱਖਰ *ਸੁਨੇਹਾ_2 = ਨਿਰਾ;

	ਜੇ (argc > 1) {
		ਸੁਨੇਹਾ_2 = g_strjoinv(" ", argv + 1);
	} ਨਹੀਂਤਾਂ {
		ਸੁਨੇਹਾ_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	ਅਚਲ ਅੱਖਰ *prompt_ਬਹੁਲਕ = getenv("SSH_ASKPASS_PROMPT");
	PromptType type = PROMPT_ਇੰਦਰਾਜ;
	ਜੇ (prompt_ਬਹੁਲਕ != ਨਿਰਾ) {
		ਜੇ (strcasecmp(prompt_ਬਹੁਲਕ, "confirm") == 0) {
			type = PROMPT_CONFIRM;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(prompt_ਬਹੁਲਕ, "none") == 0) {
			type = PROMPT_NONE;
		}
	}

	g_autoptr(PromptState) state = prompt_state_new(app, ਸੁਨੇਹਾ_2, type);

	g_signal_connect(app, "command-line", G_CALLBACK(command_ਸਤਰ), state);

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
	(ਖਾਲੀ)(g_application_ਲੜੀਵਾਰ(app, argc, argv));

	ਵਾਪਸ state->exit_ਸਥਿਤੀ;
}
