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

#ضمن "includes.h"

#جيڪڏهن_وصف_نه_ٿيل HAVE_READPASSPHRASE

#ضمن <termios.h>
#ضمن <signal.h>
#ضمن <ctype.h>
#ضمن <fcntl.h>
#ضمن <readpassphrase.h>
#ضمن <errno.h>
#ضمن <string.h>
#ضمن <unistd.h>

#جيڪڏهن_وصف_نه_ٿيل TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#جيڪڏهن_پورو

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#إذا !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#جيڪڏهن_پورو

ساكن متطاير sig_atomic_t signo[_NSIG];

ساكن فراغ handler(صحيح);

/* Like sigaction(2) but preserves SIG_IGN */
ساكن فراغ
sigaction_except_ign(صحيح signum, بنية sigaction *act, بنية sigaction *old)
{
	بنية sigaction sabuf;

	إذا (old == عدم)
		old = &sabuf;

	(فراغ)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	إذا (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(فراغ)sigaction(signum, old, عدم);
}

حرف *
readpassphrase(ثابت حرف *prompt, حرف *buf, سائيز_t bufsiz, صحيح flags)
{
	ssize_t nr;
	صحيح داخلا_2, output, save_errno, i, need_restart;
	حرف ch, *p, *پڇاڙي;
	بنية termios رڪن, oterm;
	بنية sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	بنية sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	إذا (bufsiz == 0) {
		errno = EINVAL;
		أرجع(عدم);
	}

restart:
	لكل (i = 0; i < _NSIG; i++)
		signo[i] = 0;
	nr = -1;
	save_errno = 0;
	need_restart = 0;
	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
#جيڪڏهن_وصف_نه_ٿيل O_CLOEXEC
# define O_CLOEXEC 0
#جيڪڏهن_پورو
	إذا ((flags & RPP_STDIN) ||
	    (داخلا_2 = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		إذا (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			أرجع(عدم);
		}
		داخلا_2 = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	إذا (داخلا_2 != STDIN_FILENO && tcgetattr(داخلا_2, &oterm) == 0) {
		يادگيري_نقل(&رڪن, &oterm, حجم(رڪن));
		إذا (!(flags & RPP_ECHO_ON))
			رڪن.c_lflag &= ~(ECHO | ECHONL);
#جيڪڏهن_وصف_ٿيل VSTATUS
		إذا (رڪن.c_cc[VSTATUS] != _POSIX_VDISABLE)
			رڪن.c_cc[VSTATUS] = _POSIX_VDISABLE;
#جيڪڏهن_پورو
		(فراغ)tcsetattr(داخلا_2, TCSAFLUSH|TCSASOFT, &رڪن);
	} وإلا {
		memset(&رڪن, 0, حجم(رڪن));
		رڪن.c_lflag |= ECHO;
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

	إذا (!(flags & RPP_STDIN))
		(فراغ)اكتب(output, prompt, لڙي_ڊيگهه(prompt));
	پڇاڙي = buf + bufsiz - 1;
	p = buf;
	طالما ((nr = اقرأ(داخلا_2, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		إذا (p < پڇاڙي) {
			إذا ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			إذا (اکر_آهي((بنانشان حرف)ch)) {
				إذا ((flags & RPP_FORCELOWER))
					ch = (حرف)tolower((بنانشان حرف)ch);
				إذا ((flags & RPP_FORCEUPPER))
					ch = (حرف)وڏو_اکر((بنانشان حرف)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	إذا (!(رڪن.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(فراغ)اكتب(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	إذا (memcmp(&رڪن, &oterm, حجم(رڪن)) != 0) {
		ثابت صحيح sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		طالما (tcsetattr(داخلا_2, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			استمر;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, عدم);
	sigaction(SIGQUIT, &savequit, عدم);
	sigaction_except_ign(SIGALRM, &savealrm, عدم);
	sigaction_except_ign(SIGHUP, &savehup, عدم);
	sigaction_except_ign(SIGPIPE, &savepipe, عدم);
	sigaction_except_ign(SIGTERM, &saveterm, عدم);
	sigaction_except_ign(SIGTSTP, &savetstp, عدم);
	sigaction_except_ign(SIGTTIN, &savettin, عدم);
	sigaction_except_ign(SIGTTOU, &savettou, عدم);
	إذا (داخلا_2 != STDIN_FILENO)
		(فراغ)close(داخلا_2);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	لكل (i = 0; i < _NSIG; i++) {
		إذا (signo[i]) {
			kill(getpid(), i);
			بدل (i) {
			حالة SIGTSTP:
			حالة SIGTTIN:
			حالة SIGTTOU:
				need_restart = 1;
			}
		}
	}
	إذا (need_restart)
		اذهب restart;

	إذا (save_errno)
		errno = save_errno;
	أرجع(nr == -1 ? عدم : buf);
}
DEF_WEAK(readpassphrase);

#إذا 0
حرف *
getpass(ثابت حرف *prompt)
{
	ساكن حرف buf[_PASSWORD_LEN + 1];

	أرجع(readpassphrase(prompt, buf, حجم(buf), RPP_ECHO_OFF));
}
#جيڪڏهن_پورو

ساكن فراغ handler(صحيح s)
{

	signo[s] = 1;
}
#جيڪڏهن_پورو /* HAVE_READPASSPHRASE */
