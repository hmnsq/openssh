/*	$OpenBSD: readpassphrase.c,v 1.32 2026/10/15 16:40:50 millert Exp $	*/

/*
 * Copyright (c) 2000-2002, 2007, 2010
 *	Todd C. Miller <millert@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

/* OPENBSD ORIGINAL: lib/libc/gen/readpassphrase.c */

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ HAVE_READPASSPHRASE

#شامل <termios.h>
#شامل <signal.h>
#شامل <ctype.h>
#شامل <fcntl.h>
#شامل <readpassphrase.h>
#شامل <errno.h>
#شامل <string.h>
#شامل <unistd.h>

#اگر_غیر_تعریف_شدہ TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#اگر_ختم

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#اگر !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#اگر_ختم

ساکن متلون sig_atomic_t signo[_NSIG];

ساکن خالی handler(صحیح);

/* Like sigaction(2) but preserves SIG_IGN */
ساکن خالی
sigaction_except_ign(صحیح signum, ساخت sigaction *act, ساخت sigaction *old)
{
	ساخت sigaction sabuf;

	اگر (old == تہی)
		old = &sabuf;

	(خالی)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	اگر (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(خالی)sigaction(signum, old, تہی);
}

حرف *
readpassphrase(ثابت حرف *prompt, حرف *buf, سائز_t bufsiz, صحیح flags)
{
	ssize_t nr;
	صحیح داخلہ, output, save_errno, i, need_restart;
	حرف ch, *p, *انتہا;
	ساخت termios رکن, oterm;
	ساخت sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	ساخت sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	اگر (bufsiz == 0) {
		errno = EINVAL;
		واپس(تہی);
	}

restart:
	برائے (i = 0; i < _NSIG; i++)
		signo[i] = 0;
	nr = -1;
	save_errno = 0;
	need_restart = 0;
	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
#اگر_غیر_تعریف_شدہ O_CLOEXEC
# define O_CLOEXEC 0
#اگر_ختم
	اگر ((flags & RPP_STDIN) ||
	    (داخلہ = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		اگر (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			واپس(تہی);
		}
		داخلہ = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	اگر (داخلہ != STDIN_FILENO && tcgetattr(داخلہ, &oterm) == 0) {
		حافظہ_نقل(&رکن, &oterm, حجم(رکن));
		اگر (!(flags & RPP_ECHO_ON))
			رکن.c_lflag &= ~(ECHO | ECHONL);
#اگر_تعریف_شدہ VSTATUS
		اگر (رکن.c_cc[VSTATUS] != _POSIX_VDISABLE)
			رکن.c_cc[VSTATUS] = _POSIX_VDISABLE;
#اگر_ختم
		(خالی)tcsetattr(داخلہ, TCSAFLUSH|TCSASOFT, &رکن);
	} ورنہ {
		memset(&رکن, 0, حجم(رکن));
		رکن.c_lflag |= ECHO;
		memset(&oterm, 0, حجم(oterm));
		oterm.c_lflag |= ECHO;
	}

	/*
	 * Catch signals that would otherwise cause the user to end
	 * up with echo turned off in the shell.  Don't worry about
	 * things like SIGXCPU and SIGVTALRM for now.
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;		/* don't restart system calls */
	sa.sa_handler = handler;
	sigaction(SIGINT, &sa, &saveint);
	sigaction(SIGQUIT, &sa, &savequit);
	sigaction_except_ign(SIGALRM, &sa, &savealrm);
	sigaction_except_ign(SIGHUP, &sa, &savehup);
	sigaction_except_ign(SIGPIPE, &sa, &savepipe);
	sigaction_except_ign(SIGTERM, &sa, &saveterm);
	sigaction_except_ign(SIGTSTP, &sa, &savetstp);
	sigaction_except_ign(SIGTTIN, &sa, &savettin);
	sigaction_except_ign(SIGTTOU, &sa, &savettou);

	اگر (!(flags & RPP_STDIN))
		(خالی)اكتب(output, prompt, لڑی_لمبائی(prompt));
	انتہا = buf + bufsiz - 1;
	p = buf;
	جب ((nr = اقرأ(داخلہ, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		اگر (p < انتہا) {
			اگر ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			اگر (حرف_ہے((غیرعلامتی حرف)ch)) {
				اگر ((flags & RPP_FORCELOWER))
					ch = (حرف)tolower((غیرعلامتی حرف)ch);
				اگر ((flags & RPP_FORCEUPPER))
					ch = (حرف)بڑا_حرف((غیرعلامتی حرف)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	اگر (!(رکن.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(خالی)اكتب(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	اگر (memcmp(&رکن, &oterm, حجم(رکن)) != 0) {
		ثابت صحیح sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		جب (tcsetattr(داخلہ, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			جاری;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, تہی);
	sigaction(SIGQUIT, &savequit, تہی);
	sigaction_except_ign(SIGALRM, &savealrm, تہی);
	sigaction_except_ign(SIGHUP, &savehup, تہی);
	sigaction_except_ign(SIGPIPE, &savepipe, تہی);
	sigaction_except_ign(SIGTERM, &saveterm, تہی);
	sigaction_except_ign(SIGTSTP, &savetstp, تہی);
	sigaction_except_ign(SIGTTIN, &savettin, تہی);
	sigaction_except_ign(SIGTTOU, &savettou, تہی);
	اگر (داخلہ != STDIN_FILENO)
		(خالی)close(داخلہ);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	برائے (i = 0; i < _NSIG; i++) {
		اگر (signo[i]) {
			kill(getpid(), i);
			انتخاب (i) {
			حالت SIGTSTP:
			حالت SIGTTIN:
			حالت SIGTTOU:
				need_restart = 1;
			}
		}
	}
	اگر (need_restart)
		جاؤ restart;

	اگر (save_errno)
		errno = save_errno;
	واپس(nr == -1 ? تہی : buf);
}
DEF_WEAK(readpassphrase);

#اگر 0
حرف *
getpass(ثابت حرف *prompt)
{
	ساکن حرف buf[_PASSWORD_LEN + 1];

	واپس(readpassphrase(prompt, buf, حجم(buf), RPP_ECHO_OFF));
}
#اگر_ختم

ساکن خالی handler(صحیح s)
{

	signo[s] = 1;
}
#اگر_ختم /* HAVE_READPASSPHRASE */
