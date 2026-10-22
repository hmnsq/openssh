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

#অন্তর্ভাব "includes.h"

#ifndef HAVE_READPASSPHRASE

#অন্তর্ভাব <termios.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <readpassphrase.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#যদি !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

স্থির অস্থির sig_atomic_t signo[_NSIG];

স্থির শূন্য handler(পূর্ণসংখ্যা);

/* Like sigaction(2) but preserves SIG_IGN */
স্থির শূন্য
sigaction_except_ign(পূর্ণসংখ্যা signum, কাঠামো sigaction *act, কাঠামো sigaction *old)
{
	কাঠামো sigaction sabuf;

	যদি (old == ফাঁকা)
		old = &sabuf;

	(শূন্য)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	যদি (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(শূন্য)sigaction(signum, old, ফাঁকা);
}

অক্ষর *
readpassphrase(ধ্রুবক অক্ষর *prompt, অক্ষর *buf, আকার_t bufsiz, পূর্ণসংখ্যা flags)
{
	ssize_t nr;
	পূর্ণসংখ্যা প্রবেশ, output, save_errno, i, need_restart;
	অক্ষর ch, *p, *end;
	কাঠামো termios term, oterm;
	কাঠামো sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	কাঠামো sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	যদি (bufsiz == 0) {
		errno = EINVAL;
		ফেরত(ফাঁকা);
	}

restart:
	জন্য (i = 0; i < _NSIG; i++)
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
	যদি ((flags & RPP_STDIN) ||
	    (প্রবেশ = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		যদি (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			ফেরত(ফাঁকা);
		}
		প্রবেশ = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	যদি (প্রবেশ != STDIN_FILENO && tcgetattr(প্রবেশ, &oterm) == 0) {
		memcpy(&term, &oterm, আকার(term));
		যদি (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		যদি (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(শূন্য)tcsetattr(প্রবেশ, TCSAFLUSH|TCSASOFT, &term);
	} অন্যথা {
		memset(&term, 0, আকার(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, আকার(oterm));
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

	যদি (!(flags & RPP_STDIN))
		(শূন্য)লিখ(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	যখন ((nr = পঠ(প্রবেশ, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		যদি (p < end) {
			যদি ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			যদি (isalpha((unsigned অক্ষর)ch)) {
				যদি ((flags & RPP_FORCELOWER))
					ch = (অক্ষর)tolower((unsigned অক্ষর)ch);
				যদি ((flags & RPP_FORCEUPPER))
					ch = (অক্ষর)toupper((unsigned অক্ষর)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	যদি (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(শূন্য)লিখ(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	যদি (memcmp(&term, &oterm, আকার(term)) != 0) {
		ধ্রুবক পূর্ণসংখ্যা sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		যখন (tcsetattr(প্রবেশ, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			চালু;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, ফাঁকা);
	sigaction(SIGQUIT, &savequit, ফাঁকা);
	sigaction_except_ign(SIGALRM, &savealrm, ফাঁকা);
	sigaction_except_ign(SIGHUP, &savehup, ফাঁকা);
	sigaction_except_ign(SIGPIPE, &savepipe, ফাঁকা);
	sigaction_except_ign(SIGTERM, &saveterm, ফাঁকা);
	sigaction_except_ign(SIGTSTP, &savetstp, ফাঁকা);
	sigaction_except_ign(SIGTTIN, &savettin, ফাঁকা);
	sigaction_except_ign(SIGTTOU, &savettou, ফাঁকা);
	যদি (প্রবেশ != STDIN_FILENO)
		(শূন্য)close(প্রবেশ);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	জন্য (i = 0; i < _NSIG; i++) {
		যদি (signo[i]) {
			kill(getpid(), i);
			নির্বাচন (i) {
			ক্ষেত্র SIGTSTP:
			ক্ষেত্র SIGTTIN:
			ক্ষেত্র SIGTTOU:
				need_restart = 1;
			}
		}
	}
	যদি (need_restart)
		যাও restart;

	যদি (save_errno)
		errno = save_errno;
	ফেরত(nr == -1 ? ফাঁকা : buf);
}
DEF_WEAK(readpassphrase);

#যদি 0
অক্ষর *
getpass(ধ্রুবক অক্ষর *prompt)
{
	স্থির অক্ষর buf[_PASSWORD_LEN + 1];

	ফেরত(readpassphrase(prompt, buf, আকার(buf), RPP_ECHO_OFF));
}
#endif

স্থির শূন্য handler(পূর্ণসংখ্যা s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
