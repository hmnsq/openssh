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

#ifndef HAVE_READPASSPHRASE

#شامل <termios.h>
#شامل <signal.h>
#شامل <ctype.h>
#شامل <fcntl.h>
#شامل <readpassphrase.h>
#شامل <errno.h>
#شامل <string.h>
#شامل <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#اگر !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

ایستا فرار sig_atomic_t signo[_NSIG];

ایستا تهی handler(صحیح);

/* Like sigaction(2) but preserves SIG_IGN */
ایستا تهی
sigaction_except_ign(صحیح signum, ساختار sigaction *act, ساختار sigaction *old)
{
	ساختار sigaction sabuf;

	اگر (old == پوچ)
		old = &sabuf;

	(تهی)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	اگر (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(تهی)sigaction(signum, old, پوچ);
}

نویسه *
readpassphrase(ثابت نویسه *prompt, نویسه *buf, size_t bufsiz, صحیح flags)
{
	ssize_t nr;
	صحیح درون_داد, output, save_errno, i, need_restart;
	نویسه ch, *p, *end;
	ساختار termios term, oterm;
	ساختار sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	ساختار sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	اگر (bufsiz == 0) {
		errno = EINVAL;
		بازگشت(پوچ);
	}

restart:
	برای (i = 0; i < _NSIG; i++)
		signo[i] = 0;
	nr = -1;
	save_errno = 0;
	need_restart = 0;
	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
#ifndef O_CLOEXEC
# define O_CLOEXEC 0
#endif
	اگر ((flags & RPP_STDIN) ||
	    (درون_داد = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		اگر (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			بازگشت(پوچ);
		}
		درون_داد = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	اگر (درون_داد != STDIN_FILENO && tcgetattr(درون_داد, &oterm) == 0) {
		memcpy(&term, &oterm, اندازه(term));
		اگر (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		اگر (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(تهی)tcsetattr(درون_داد, TCSAFLUSH|TCSASOFT, &term);
	} وگرنه {
		memset(&term, 0, اندازه(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, اندازه(oterm));
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
		(تهی)اكتب(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	وقتی ((nr = اقرأ(درون_داد, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		اگر (p < end) {
			اگر ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			اگر (isalpha((unsigned نویسه)ch)) {
				اگر ((flags & RPP_FORCELOWER))
					ch = (نویسه)tolower((unsigned نویسه)ch);
				اگر ((flags & RPP_FORCEUPPER))
					ch = (نویسه)toupper((unsigned نویسه)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	اگر (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(تهی)اكتب(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	اگر (memcmp(&term, &oterm, اندازه(term)) != 0) {
		ثابت صحیح sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		وقتی (tcsetattr(درون_داد, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			ادامه;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, پوچ);
	sigaction(SIGQUIT, &savequit, پوچ);
	sigaction_except_ign(SIGALRM, &savealrm, پوچ);
	sigaction_except_ign(SIGHUP, &savehup, پوچ);
	sigaction_except_ign(SIGPIPE, &savepipe, پوچ);
	sigaction_except_ign(SIGTERM, &saveterm, پوچ);
	sigaction_except_ign(SIGTSTP, &savetstp, پوچ);
	sigaction_except_ign(SIGTTIN, &savettin, پوچ);
	sigaction_except_ign(SIGTTOU, &savettou, پوچ);
	اگر (درون_داد != STDIN_FILENO)
		(تهی)close(درون_داد);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	برای (i = 0; i < _NSIG; i++) {
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
		برو restart;

	اگر (save_errno)
		errno = save_errno;
	بازگشت(nr == -1 ? پوچ : buf);
}
DEF_WEAK(readpassphrase);

#اگر 0
نویسه *
getpass(ثابت نویسه *prompt)
{
	ایستا نویسه buf[_PASSWORD_LEN + 1];

	بازگشت(readpassphrase(prompt, buf, اندازه(buf), RPP_ECHO_OFF));
}
#endif

ایستا تهی handler(صحیح s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
