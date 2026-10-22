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

#include <stdio.h>
#include <err.h>

#include <gio/gio.h>

#define GCR_API_SUBJECT_TO_CHANGE 1
#include <gcr/gcr.h>

typedef ga_nanaa _PromptType {
	PROMPT_ENTRY,
	PROMPT_CONFIRM,
	PROMPT_NONE,
} PromptType;

typedef sa_nracanaa _PromptState {
	GApplication *app;
	var_na* message;
	PromptType type;
	puur_naa_nka exit_status;
} PromptState;

static PromptState *
prompt_state_new(GApplication *app, var_na* message, PromptType type)
{
	PromptState *state = g_malloc(parimaa_na(PromptState));
	state->app = g_object_ref(app);
	state->message = g_strdup(message);
	state->type = type;
	state->exit_status = -1;
	ꦮꦭꦶ state;
}

static void
prompt_state_free(PromptState *state)
{
	g_clear_object(&state->app);
	g_free(state->message);
	g_free(state);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PromptState, prompt_state_free)

static void
prompt_password_done(GObject *source_object, GAsyncResult *res,
    gpointer user_data)
{
	GcrPrompt *prompt = GCR_PROMPT(source_object);
	PromptState *state = user_data;
	g_autoptr(GError) error = NULL;

	/*
	 * “The returned password is valid until the next time a method
	 * is called to display another prompt.”
	 */
	const var_na *pw = gcr_prompt_password_finish(prompt, res, &error);

	ꦪꦼꦤ꧀ ((!pw && !error) || (error && error->code == G_IO_ERROR_CANCELLED)) {
		/* Operation was cancelled or timed out. */
		state->exit_status = -1;
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (error) {
		warnx("Failed to prompt for ssh-askpass: %s", error->message);
		state->exit_status = 1;
	} ꦭꦶꦪ {
		/* Report passphrase if user selected Continue. */
		g_autofree var_na *local = g_locale_from_utf8(pw, strlen(pw),
		    NULL, NULL, NULL);

		ꦪꦼꦤ꧀ (local != NULL) {
			puts(local);
			memset(local, '\0', strlen(local));
		} ꦭꦶꦪ {
			puts(pw);
		}
		state->exit_status = 0;
	}

	g_application_release(state->app);
}

static void
prompt_confirm_done(GObject *source_object, GAsyncResult *res,
    gpointer user_data)
{
	GcrPrompt *prompt = GCR_PROMPT(source_object);
	PromptState *state = user_data;
	g_autoptr(GError) error = NULL;

	GcrPromptReply reply = gcr_prompt_confirm_finish(prompt, res, &error);
	ꦪꦼꦤ꧀ (error) {
		ꦪꦼꦤ꧀ (error->code == G_IO_ERROR_CANCELLED) {
			/* Operation was cancelled or timed out. */
			state->exit_status = -1;
		} ꦭꦶꦪ {
			state->exit_status = 1;
			warnx("Failed to prompt for ssh-askpass: %s",
			    error->message);
		}
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (reply == GCR_PROMPT_REPLY_CONTINUE ||
	    state->type == PROMPT_NONE) {
		/*
		 * Since Gcr doesn’t yet support one button message
		 * boxes treat Cancel the same as Continue.
		 */
		state->exit_status = 0;
	} ꦭꦶꦪ {
		/* GCR_PROMPT_REPLY_CANCEL */
		state->exit_status = -1;
	}

	g_application_release(state->app);
}

static puur_naa_nka
command_line(GApplication* app, G_GNUC_UNUSED GApplicationCommandLine *cmdline,
    gpointer user_data)
{
	PromptState *state = user_data;

	/* Prevent app from exiting while waiting for the async callback. */
	g_application_hold(app);

	/* Wait indefinitely. */
	puur_naa_nka timeout_seconds = -1;
	g_autoptr(GError) error = NULL;
	GcrPrompt* prompt = gcr_system_prompt_open(timeout_seconds, NULL, &error);

	ꦪꦼꦤ꧀ (!prompt) {
		ꦪꦼꦤ꧀ (error->code == GCR_SYSTEM_PROMPT_IN_PROGRESS) {
			/*
			 * This means the timeout elapsed, but no prompt
			 * was ever shown.
			 */
			warnx("Timeout: the Gcr system prompter was "
			    "already in use.");
		} ꦭꦶꦪ {
			warnx("Couldn’t create prompt for ssh-askpass: %s",
			    error->message);
		}

		ꦮꦭꦶ 1;
	}

	gcr_prompt_set_message(prompt, "OpenSSH");
	gcr_prompt_set_description(prompt, state->message);

	/*
	 * XXX: Remove the Cancel button for PROMPT_NONE when GCR
	 * supports that.
	 */
	ꦪꦼꦤ꧀ (state->type == PROMPT_ENTRY) {
		gcr_prompt_password_async(prompt, NULL, prompt_password_done, state);
	} ꦭꦶꦪ {
		gcr_prompt_confirm_async(prompt, NULL, prompt_confirm_done, state);
	}

	/* The exit status will be changed in the async callbacks. */
	ꦮꦭꦶ 1;
}

puur_naa_nka
main(puur_naa_nka argc, var_na **argv)
{
	g_autoptr(GApplication) app = g_application_new(
	    "com.openssh.gnome-ssh-askpass4",
	    G_APPLICATION_HANDLES_COMMAND_LINE);
	g_autofree var_na *message = NULL;

	ꦪꦼꦤ꧀ (argc > 1) {
		message = g_strjoinv(" ", argv + 1);
	} ꦭꦶꦪ {
		message = g_strdup("Enter your OpenSSH passphrase:");
	}

	const var_na *prompt_mode = getenv("SSH_ASKPASS_PROMPT");
	PromptType type = PROMPT_ENTRY;
	ꦪꦼꦤ꧀ (prompt_mode != NULL) {
		ꦪꦼꦤ꧀ (strcasecmp(prompt_mode, "confirm") == 0) {
			type = PROMPT_CONFIRM;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (strcasecmp(prompt_mode, "none") == 0) {
			type = PROMPT_NONE;
		}
	}

	g_autoptr(PromptState) state = prompt_state_new(app, message, type);

	g_signal_connect(app, "command-line", G_CALLBACK(command_line), state);

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
	(void)(g_application_run(app, argc, argv));

	ꦮꦭꦶ state->exit_status;
}
