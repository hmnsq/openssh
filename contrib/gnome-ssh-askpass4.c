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

#ضمن <stdio.h>
#ضمن <err.h>

#ضمن <gio/gio.h>

#تعریف_کړه GCR_API_SUBJECT_منزل_CHANGE 1
#ضمن <gcr/gcr.h>

تعريفنوع تعداد _PromptType {
	PROMPT_ثبت,
	PROMPT_CONFIRM,
	PROMPT_NONE,
} PromptType;

تعريفنوع بنية _PromptState {
	GApplication *app;
	حرف* پیغام_2;
	PromptType type;
	صحيح exit_حالت;
} PromptState;

ساكن PromptState *
prompt_state_new(GApplication *app, حرف* پیغام_2, PromptType type)
{
	PromptState *state = g_malloc(حجم(PromptState));
	state->app = g_object_ref(app);
	state->پیغام_2 = g_strdup(پیغام_2);
	state->type = type;
	state->exit_حالت = -1;
	أرجع state;
}

ساكن فراغ
prompt_state_free(PromptState *state)
{
	g_clear_object(&state->app);
	g_free(state->پیغام_2);
	g_free(state);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PromptState, prompt_state_free)

ساكن فراغ
prompt_password_بشپړ(GObject *سرچینه_object, GAsync_پایله *res,
    gpointer user_معلومات)
{
	GcrPrompt *prompt = GCR_PROMPT(سرچینه_object);
	PromptState *state = user_معلومات;
	g_autoptr(GError) error = عدم;

	/*
	 * “The returned password is valid until the next time a method
	 * is called to display another prompt.”
	 */
	ثابت حرف *pw = gcr_prompt_password_پای(prompt, res, &error);

	إذا ((!pw && !error) || (error && error->کوډ == G_IO_ERROR_CANCELLED)) {
		/* Operation was cancelled or timed out. */
		state->exit_حالت = -1;
	} وإلا إذا (error) {
		warnx("Failed to prompt for ssh-askpass: %s", error->پیغام_2);
		state->exit_حالت = 1;
	} وإلا {
		/* Report passphrase if user selected Continue. */
		g_autofree حرف *local = g_locale_from_utf8(pw, مزي_اوږدوالی(pw),
		    عدم, عدم, عدم);

		إذا (local != عدم) {
			puts(local);
			memset(local, '\0', مزي_اوږدوالی(local));
		} وإلا {
			puts(pw);
		}
		state->exit_حالت = 0;
	}

	g_application_release(state->app);
}

ساكن فراغ
prompt_confirm_بشپړ(GObject *سرچینه_object, GAsync_پایله *res,
    gpointer user_معلومات)
{
	GcrPrompt *prompt = GCR_PROMPT(سرچینه_object);
	PromptState *state = user_معلومات;
	g_autoptr(GError) error = عدم;

	Gcr_Prompt_ځواب ځواب = gcr_prompt_confirm_پای(prompt, res, &error);
	إذا (error) {
		إذا (error->کوډ == G_IO_ERROR_CANCELLED) {
			/* Operation was cancelled or timed out. */
			state->exit_حالت = -1;
		} وإلا {
			state->exit_حالت = 1;
			warnx("Failed to prompt for ssh-askpass: %s",
			    error->پیغام_2);
		}
	} وإلا إذا (ځواب == GCR_PROMPT_ځواب_CONTINUE ||
	    state->type == PROMPT_NONE) {
		/*
		 * Since Gcr doesn’t yet support one button message
		 * boxes treat Cancel the same as Continue.
		 */
		state->exit_حالت = 0;
	} وإلا {
		/* GCR_PROMPT_REPLY_CANCEL */
		state->exit_حالت = -1;
	}

	g_application_release(state->app);
}

ساكن صحيح
command_کرښه(GApplication* app, G_GNUC_ناکارول_شوی GApplication_Command_کرښه *cmdline,
    gpointer user_معلومات)
{
	PromptState *state = user_معلومات;

	/* Prevent app from exiting while waiting for the async callback. */
	g_application_hold(app);

	/* Wait indefinitely. */
	صحيح timeout_seconds = -1;
	g_autoptr(GError) error = عدم;
	GcrPrompt* prompt = gcr_system_prompt_open(timeout_seconds, عدم, &error);

	إذا (!prompt) {
		إذا (error->کوډ == GCR_SYSTEM_PROMPT_دننه_پرمختګ) {
			/*
			 * This means the timeout elapsed, but no prompt
			 * was ever shown.
			 */
			warnx("Timeout: the Gcr system prompter was "
			    "already in use.");
		} وإلا {
			warnx("Couldn’t create prompt for ssh-askpass: %s",
			    error->پیغام_2);
		}

		أرجع 1;
	}

	gcr_prompt_سېټ_پیغام(prompt, "OpenSSH");
	gcr_prompt_سېټ_description(prompt, state->پیغام_2);

	/*
	 * XXX: Remove the Cancel button for PROMPT_NONE when GCR
	 * supports that.
	 */
	إذا (state->type == PROMPT_ثبت) {
		gcr_prompt_password_async(prompt, عدم, prompt_password_بشپړ, state);
	} وإلا {
		gcr_prompt_confirm_async(prompt, عدم, prompt_confirm_بشپړ, state);
	}

	/* The exit status will be changed in the async callbacks. */
	أرجع 1;
}

صحيح
اصلي(صحيح argc, حرف **argv)
{
	g_autoptr(GApplication) app = g_application_new(
	    "com.openssh.gnome-ssh-askpass4",
	    G_APPLICATION_HANDLES_COMMAND_کرښه);
	g_autofree حرف *پیغام_2 = عدم;

	إذا (argc > 1) {
		پیغام_2 = g_strjoinv(" ", argv + 1);
	} وإلا {
		پیغام_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	ثابت حرف *prompt_ډېرپېښ = getenv("SSH_ASKPASS_PROMPT");
	PromptType type = PROMPT_ثبت;
	إذا (prompt_ډېرپېښ != عدم) {
		إذا (strcasecmp(prompt_ډېرپېښ, "confirm") == 0) {
			type = PROMPT_CONFIRM;
		} وإلا إذا (strcasecmp(prompt_ډېرپېښ, "none") == 0) {
			type = PROMPT_NONE;
		}
	}

	g_autoptr(PromptState) state = prompt_state_new(app, پیغام_2, type);

	g_signal_connect(app, "command-line", G_CALLBACK(command_کرښه), state);

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
	(فراغ)(g_application_پرلپسې(app, argc, argv));

	أرجع state->exit_حالت;
}
