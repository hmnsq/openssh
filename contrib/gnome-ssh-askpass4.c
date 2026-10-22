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

#شامل <stdio.h>
#شامل <err.h>

#شامل <gio/gio.h>

#تعریف_کرو GCR_API_SUBJECT_مقصد_CHANGE 1
#شامل <gcr/gcr.h>

قسمتعریف شمار _PromptType {
	PROMPT_اندراج,
	PROMPT_CONFIRM,
	PROMPT_NONE,
} PromptType;

قسمتعریف ساخت _PromptState {
	GApplication *app;
	حرف* پیغام_2;
	PromptType type;
	صحیح exit_حالت;
} PromptState;

ساکن PromptState *
prompt_state_new(GApplication *app, حرف* پیغام_2, PromptType type)
{
	PromptState *state = g_malloc(حجم(PromptState));
	state->app = g_object_ref(app);
	state->پیغام_2 = g_strdup(پیغام_2);
	state->type = type;
	state->exit_حالت = -1;
	واپس state;
}

ساکن خالی
prompt_state_free(PromptState *state)
{
	g_clear_object(&state->app);
	g_free(state->پیغام_2);
	g_free(state);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PromptState, prompt_state_free)

ساکن خالی
prompt_password_مکمل(GObject *ماخذ_object, GAsync_نتیجہ *res,
    gpointer user_ڈیٹا)
{
	GcrPrompt *prompt = GCR_PROMPT(ماخذ_object);
	PromptState *state = user_ڈیٹا;
	g_autoptr(GError) error = تہی;

	/*
	 * “The returned password is valid until the next time a method
	 * is called to display another prompt.”
	 */
	ثابت حرف *pw = gcr_prompt_password_اختتام(prompt, res, &error);

	اگر ((!pw && !error) || (error && error->رمز == G_IO_ERROR_CANCELLED)) {
		/* Operation was cancelled or timed out. */
		state->exit_حالت = -1;
	} ورنہ اگر (error) {
		warnx("Failed to prompt for ssh-askpass: %s", error->پیغام_2);
		state->exit_حالت = 1;
	} ورنہ {
		/* Report passphrase if user selected Continue. */
		g_autofree حرف *local = g_locale_from_utf8(pw, لڑی_لمبائی(pw),
		    تہی, تہی, تہی);

		اگر (local != تہی) {
			puts(local);
			memset(local, '\0', لڑی_لمبائی(local));
		} ورنہ {
			puts(pw);
		}
		state->exit_حالت = 0;
	}

	g_application_release(state->app);
}

ساکن خالی
prompt_confirm_مکمل(GObject *ماخذ_object, GAsync_نتیجہ *res,
    gpointer user_ڈیٹا)
{
	GcrPrompt *prompt = GCR_PROMPT(ماخذ_object);
	PromptState *state = user_ڈیٹا;
	g_autoptr(GError) error = تہی;

	Gcr_Prompt_جواب جواب = gcr_prompt_confirm_اختتام(prompt, res, &error);
	اگر (error) {
		اگر (error->رمز == G_IO_ERROR_CANCELLED) {
			/* Operation was cancelled or timed out. */
			state->exit_حالت = -1;
		} ورنہ {
			state->exit_حالت = 1;
			warnx("Failed to prompt for ssh-askpass: %s",
			    error->پیغام_2);
		}
	} ورنہ اگر (جواب == GCR_PROMPT_جواب_CONTINUE ||
	    state->type == PROMPT_NONE) {
		/*
		 * Since Gcr doesn’t yet support one button message
		 * boxes treat Cancel the same as Continue.
		 */
		state->exit_حالت = 0;
	} ورنہ {
		/* GCR_PROMPT_REPLY_CANCEL */
		state->exit_حالت = -1;
	}

	g_application_release(state->app);
}

ساکن صحیح
command_سطر(GApplication* app, G_GNUC_غیر_مستعمل GApplication_Command_سطر *cmdline,
    gpointer user_ڈیٹا)
{
	PromptState *state = user_ڈیٹا;

	/* Prevent app from exiting while waiting for the async callback. */
	g_application_hold(app);

	/* Wait indefinitely. */
	صحیح timeout_seconds = -1;
	g_autoptr(GError) error = تہی;
	GcrPrompt* prompt = gcr_system_prompt_open(timeout_seconds, تہی, &error);

	اگر (!prompt) {
		اگر (error->رمز == GCR_SYSTEM_PROMPT_اندر_پیش_رفت) {
			/*
			 * This means the timeout elapsed, but no prompt
			 * was ever shown.
			 */
			warnx("Timeout: the Gcr system prompter was "
			    "already in use.");
		} ورنہ {
			warnx("Couldn’t create prompt for ssh-askpass: %s",
			    error->پیغام_2);
		}

		واپس 1;
	}

	gcr_prompt_سیٹ_پیغام(prompt, "OpenSSH");
	gcr_prompt_سیٹ_description(prompt, state->پیغام_2);

	/*
	 * XXX: Remove the Cancel button for PROMPT_NONE when GCR
	 * supports that.
	 */
	اگر (state->type == PROMPT_اندراج) {
		gcr_prompt_password_async(prompt, تہی, prompt_password_مکمل, state);
	} ورنہ {
		gcr_prompt_confirm_async(prompt, تہی, prompt_confirm_مکمل, state);
	}

	/* The exit status will be changed in the async callbacks. */
	واپس 1;
}

صحیح
مین(صحیح argc, حرف **argv)
{
	g_autoptr(GApplication) app = g_application_new(
	    "com.openssh.gnome-ssh-askpass4",
	    G_APPLICATION_HANDLES_COMMAND_سطر);
	g_autofree حرف *پیغام_2 = تہی;

	اگر (argc > 1) {
		پیغام_2 = g_strjoinv(" ", argv + 1);
	} ورنہ {
		پیغام_2 = g_strdup("Enter your OpenSSH passphrase:");
	}

	ثابت حرف *prompt_منوال = getenv("SSH_ASKPASS_PROMPT");
	PromptType type = PROMPT_اندراج;
	اگر (prompt_منوال != تہی) {
		اگر (strcasecmp(prompt_منوال, "confirm") == 0) {
			type = PROMPT_CONFIRM;
		} ورنہ اگر (strcasecmp(prompt_منوال, "none") == 0) {
			type = PROMPT_NONE;
		}
	}

	g_autoptr(PromptState) state = prompt_state_new(app, پیغام_2, type);

	g_signal_connect(app, "command-line", G_CALLBACK(command_سطر), state);

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
	(خالی)(g_application_تسلسل(app, argc, argv));

	واپس state->exit_حالت;
}
