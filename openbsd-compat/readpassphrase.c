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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_READPASSPHRASE

#ਅਨ੍ਤਰ੍ਭਾਵ <termios.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <readpassphrase.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#ਜੇ_ਅੰਤ

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#ਜੇ !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t signo[_NSIG];

ਸਥਿਰ ਖਾਲੀ handler(ਪੂਰਨ);

/* Like sigaction(2) but preserves SIG_IGN */
ਸਥਿਰ ਖਾਲੀ
sigaction_except_ign(ਪੂਰਨ signum, ਬਣਤਰ sigaction *act, ਬਣਤਰ sigaction *old)
{
	ਬਣਤਰ sigaction sabuf;

	ਜੇ (old == ਨਿਰਾ)
		old = &sabuf;

	(ਖਾਲੀ)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	ਜੇ (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(ਖਾਲੀ)sigaction(signum, old, ਨਿਰਾ);
}

ਅੱਖਰ *
readpassphrase(ਅਚਲ ਅੱਖਰ *prompt, ਅੱਖਰ *buf, ਮਾਪ_t bufsiz, ਪੂਰਨ flags)
{
	ssize_t nr;
	ਪੂਰਨ ਨਿਵੇਸ਼, output, save_errno, i, need_restart;
	ਅੱਖਰ ch, *p, *ਸਿਰਾ;
	ਬਣਤਰ termios ਪਦ, oterm;
	ਬਣਤਰ sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	ਬਣਤਰ sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	ਜੇ (bufsiz == 0) {
		errno = EINVAL;
		ਵਾਪਸ(ਨਿਰਾ);
	}

restart:
	ਲਈ (i = 0; i < _NSIG; i++)
		signo[i] = 0;
	nr = -1;
	save_errno = 0;
	need_restart = 0;
	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ O_CLOEXEC
# define O_CLOEXEC 0
#ਜੇ_ਅੰਤ
	ਜੇ ((flags & RPP_STDIN) ||
	    (ਨਿਵੇਸ਼ = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		ਜੇ (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			ਵਾਪਸ(ਨਿਰਾ);
		}
		ਨਿਵੇਸ਼ = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	ਜੇ (ਨਿਵੇਸ਼ != STDIN_FILENO && tcgetattr(ਨਿਵੇਸ਼, &oterm) == 0) {
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(&ਪਦ, &oterm, ਆਕਾਰ(ਪਦ));
		ਜੇ (!(flags & RPP_ECHO_ON))
			ਪਦ.c_lflag &= ~(ECHO | ECHONL);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ VSTATUS
		ਜੇ (ਪਦ.c_cc[VSTATUS] != _POSIX_VDISABLE)
			ਪਦ.c_cc[VSTATUS] = _POSIX_VDISABLE;
#ਜੇ_ਅੰਤ
		(ਖਾਲੀ)tcsetattr(ਨਿਵੇਸ਼, TCSAFLUSH|TCSASOFT, &ਪਦ);
	} ਨਹੀਂਤਾਂ {
		memset(&ਪਦ, 0, ਆਕਾਰ(ਪਦ));
		ਪਦ.c_lflag |= ECHO;
		memset(&oterm, 0, ਆਕਾਰ(oterm));
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

	ਜੇ (!(flags & RPP_STDIN))
		(ਖਾਲੀ)ਲਿਖ(output, prompt, ਲੜੀ_ਲੰਬਾਈ(prompt));
	ਸਿਰਾ = buf + bufsiz - 1;
	p = buf;
	ਜਦੋਂ ((nr = ਪਠ(ਨਿਵੇਸ਼, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		ਜੇ (p < ਸਿਰਾ) {
			ਜੇ ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			ਜੇ (ਅੱਖਰ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)ch)) {
				ਜੇ ((flags & RPP_FORCELOWER))
					ch = (ਅੱਖਰ)tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)ch);
				ਜੇ ((flags & RPP_FORCEUPPER))
					ch = (ਅੱਖਰ)ਵੱਡਾ_ਅੱਖਰ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	ਜੇ (!(ਪਦ.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(ਖਾਲੀ)ਲਿਖ(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	ਜੇ (memcmp(&ਪਦ, &oterm, ਆਕਾਰ(ਪਦ)) != 0) {
		ਅਚਲ ਪੂਰਨ sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		ਜਦੋਂ (tcsetattr(ਨਿਵੇਸ਼, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			ਜਾਰੀ;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, ਨਿਰਾ);
	sigaction(SIGQUIT, &savequit, ਨਿਰਾ);
	sigaction_except_ign(SIGALRM, &savealrm, ਨਿਰਾ);
	sigaction_except_ign(SIGHUP, &savehup, ਨਿਰਾ);
	sigaction_except_ign(SIGPIPE, &savepipe, ਨਿਰਾ);
	sigaction_except_ign(SIGTERM, &saveterm, ਨਿਰਾ);
	sigaction_except_ign(SIGTSTP, &savetstp, ਨਿਰਾ);
	sigaction_except_ign(SIGTTIN, &savettin, ਨਿਰਾ);
	sigaction_except_ign(SIGTTOU, &savettou, ਨਿਰਾ);
	ਜੇ (ਨਿਵੇਸ਼ != STDIN_FILENO)
		(ਖਾਲੀ)close(ਨਿਵੇਸ਼);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	ਲਈ (i = 0; i < _NSIG; i++) {
		ਜੇ (signo[i]) {
			kill(getpid(), i);
			ਚੋਣ (i) {
			ਹਾਲਤ SIGTSTP:
			ਹਾਲਤ SIGTTIN:
			ਹਾਲਤ SIGTTOU:
				need_restart = 1;
			}
		}
	}
	ਜੇ (need_restart)
		ਜਾਓ restart;

	ਜੇ (save_errno)
		errno = save_errno;
	ਵਾਪਸ(nr == -1 ? ਨਿਰਾ : buf);
}
DEF_WEAK(readpassphrase);

#ਜੇ 0
ਅੱਖਰ *
getpass(ਅਚਲ ਅੱਖਰ *prompt)
{
	ਸਥਿਰ ਅੱਖਰ buf[_PASSWORD_LEN + 1];

	ਵਾਪਸ(readpassphrase(prompt, buf, ਆਕਾਰ(buf), RPP_ECHO_OFF));
}
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਖਾਲੀ handler(ਪੂਰਨ s)
{

	signo[s] = 1;
}
#ਜੇ_ਅੰਤ /* HAVE_READPASSPHRASE */
