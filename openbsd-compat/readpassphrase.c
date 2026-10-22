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

#অন্তর্ভাৱ "includes.h"

#ifndef HAVE_READPASSPHRASE

#অন্তর্ভাৱ <termios.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <readpassphrase.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#যদি !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

স্থির চঞ্চল sig_atomic_t signo[_NSIG];

স্থির শূন্য handler(পূর্ণাঙ্ক);

/* Like sigaction(2) but preserves SIG_IGN */
স্থির শূন্য
sigaction_except_ign(পূর্ণাঙ্ক signum, সংরচনা sigaction *act, সংরচনা sigaction *old)
{
	সংরচনা sigaction sabuf;

	যদি (old == রিক্ত)
		old = &sabuf;

	(শূন্য)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	যদি (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(শূন্য)sigaction(signum, old, রিক্ত);
}

ৱর্ণ *
readpassphrase(ধ্রুৱ ৱর্ণ *prompt, ৱর্ণ *buf, size_t bufsiz, পূর্ণাঙ্ক flags)
{
	ssize_t nr;
	পূর্ণাঙ্ক প্ৰবেশ, output, save_errno, i, need_restart;
	ৱর্ণ ch, *p, *end;
	সংরচনা termios term, oterm;
	সংরচনা sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	সংরচনা sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	যদি (bufsiz == 0) {
		errno = EINVAL;
		ঘূৰাই(রিক্ত);
	}

restart:
	বাবে (i = 0; i < _NSIG; i++)
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
	    (প্ৰবেশ = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		যদি (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			ঘূৰাই(রিক্ত);
		}
		প্ৰবেশ = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	যদি (প্ৰবেশ != STDIN_FILENO && tcgetattr(প্ৰবেশ, &oterm) == 0) {
		memcpy(&term, &oterm, পরিমাণ(term));
		যদি (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		যদি (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(শূন্য)tcsetattr(প্ৰবেশ, TCSAFLUSH|TCSASOFT, &term);
	} অন্যথা {
		memset(&term, 0, পরিমাণ(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, পরিমাণ(oterm));
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
	যেতিয়ালৈ ((nr = পঠ(প্ৰবেশ, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		যদি (p < end) {
			যদি ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			যদি (isalpha((unsigned ৱর্ণ)ch)) {
				যদি ((flags & RPP_FORCELOWER))
					ch = (ৱর্ণ)tolower((unsigned ৱর্ণ)ch);
				যদি ((flags & RPP_FORCEUPPER))
					ch = (ৱর্ণ)toupper((unsigned ৱর্ণ)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	যদি (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(শূন্য)লিখ(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	যদি (memcmp(&term, &oterm, পরিমাণ(term)) != 0) {
		ধ্রুৱ পূর্ণাঙ্ক sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		যেতিয়ালৈ (tcsetattr(প্ৰবেশ, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			অনুৱর্ত;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, রিক্ত);
	sigaction(SIGQUIT, &savequit, রিক্ত);
	sigaction_except_ign(SIGALRM, &savealrm, রিক্ত);
	sigaction_except_ign(SIGHUP, &savehup, রিক্ত);
	sigaction_except_ign(SIGPIPE, &savepipe, রিক্ত);
	sigaction_except_ign(SIGTERM, &saveterm, রিক্ত);
	sigaction_except_ign(SIGTSTP, &savetstp, রিক্ত);
	sigaction_except_ign(SIGTTIN, &savettin, রিক্ত);
	sigaction_except_ign(SIGTTOU, &savettou, রিক্ত);
	যদি (প্ৰবেশ != STDIN_FILENO)
		(শূন্য)close(প্ৰবেশ);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	বাবে (i = 0; i < _NSIG; i++) {
		যদি (signo[i]) {
			kill(getpid(), i);
			ৱিকল্প (i) {
			পক্ষ SIGTSTP:
			পক্ষ SIGTTIN:
			পক্ষ SIGTTOU:
				need_restart = 1;
			}
		}
	}
	যদি (need_restart)
		গচ্ছ restart;

	যদি (save_errno)
		errno = save_errno;
	ঘূৰাই(nr == -1 ? রিক্ত : buf);
}
DEF_WEAK(readpassphrase);

#যদি 0
ৱর্ণ *
getpass(ধ্রুৱ ৱর্ণ *prompt)
{
	স্থির ৱর্ণ buf[_PASSWORD_LEN + 1];

	ঘূৰাই(readpassphrase(prompt, buf, পরিমাণ(buf), RPP_ECHO_OFF));
}
#endif

স্থির শূন্য handler(পূর্ণাঙ্ক s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
