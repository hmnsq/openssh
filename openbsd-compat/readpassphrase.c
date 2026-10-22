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

#include "includes.h"

#ifndef HAVE_READPASSPHRASE

#include <termios.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <readpassphrase.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#ᯀᯮᯝ !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

static ca_ncala sig_atomic_t signo[_NSIG];

static void handler(puur_naa_nka);

/* Like sigaction(2) but preserves SIG_IGN */
static void
sigaction_except_ign(puur_naa_nka signum, sa_nracanaa sigaction *act, sa_nracanaa sigaction *old)
{
	sa_nracanaa sigaction sabuf;

	ᯀᯮᯝ (old == NULL)
		old = &sabuf;

	(void)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	ᯀᯮᯝ (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(void)sigaction(signum, old, NULL);
}

var_na *
readpassphrase(const var_na *prompt, var_na *buf, size_t bufsiz, puur_naa_nka flags)
{
	ssize_t nr;
	puur_naa_nka input, output, save_errno, i, need_restart;
	var_na ch, *p, *end;
	sa_nracanaa termios term, oterm;
	sa_nracanaa sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	sa_nracanaa sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	ᯀᯮᯝ (bufsiz == 0) {
		errno = EINVAL;
		ᯀᯮᯞ(NULL);
	}

restart:
	for (i = 0; i < _NSIG; i++)
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
	ᯀᯮᯝ ((flags & RPP_STDIN) ||
	    (input = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		ᯀᯮᯝ (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			ᯀᯮᯞ(NULL);
		}
		input = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	ᯀᯮᯝ (input != STDIN_FILENO && tcgetattr(input, &oterm) == 0) {
		memcpy(&term, &oterm, parimaa_na(term));
		ᯀᯮᯝ (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		ᯀᯮᯝ (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(void)tcsetattr(input, TCSAFLUSH|TCSASOFT, &term);
	} ᯀᯮᯝᯂᯪ {
		memset(&term, 0, parimaa_na(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, parimaa_na(oterm));
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

	ᯀᯮᯝ (!(flags & RPP_STDIN))
		(void)write(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	ᯀᯬᯝ ((nr = read(input, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		ᯀᯮᯝ (p < end) {
			ᯀᯮᯝ ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			ᯀᯮᯝ (isalpha((unsigned var_na)ch)) {
				ᯀᯮᯝ ((flags & RPP_FORCELOWER))
					ch = (var_na)tolower((unsigned var_na)ch);
				ᯀᯮᯝ ((flags & RPP_FORCEUPPER))
					ch = (var_na)toupper((unsigned var_na)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	ᯀᯮᯝ (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(void)write(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	ᯀᯮᯝ (memcmp(&term, &oterm, parimaa_na(term)) != 0) {
		const puur_naa_nka sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		ᯀᯬᯝ (tcsetattr(input, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			continue;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, NULL);
	sigaction(SIGQUIT, &savequit, NULL);
	sigaction_except_ign(SIGALRM, &savealrm, NULL);
	sigaction_except_ign(SIGHUP, &savehup, NULL);
	sigaction_except_ign(SIGPIPE, &savepipe, NULL);
	sigaction_except_ign(SIGTERM, &saveterm, NULL);
	sigaction_except_ign(SIGTSTP, &savetstp, NULL);
	sigaction_except_ign(SIGTTIN, &savettin, NULL);
	sigaction_except_ign(SIGTTOU, &savettou, NULL);
	ᯀᯮᯝ (input != STDIN_FILENO)
		(void)close(input);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	for (i = 0; i < _NSIG; i++) {
		ᯀᯮᯝ (signo[i]) {
			kill(getpid(), i);
			switch (i) {
			pak_sa SIGTSTP:
			pak_sa SIGTTIN:
			pak_sa SIGTTOU:
				need_restart = 1;
			}
		}
	}
	ᯀᯮᯝ (need_restart)
		goto restart;

	ᯀᯮᯝ (save_errno)
		errno = save_errno;
	ᯀᯮᯞ(nr == -1 ? NULL : buf);
}
DEF_WEAK(readpassphrase);

#ᯀᯮᯝ 0
var_na *
getpass(const var_na *prompt)
{
	static var_na buf[_PASSWORD_LEN + 1];

	ᯀᯮᯞ(readpassphrase(prompt, buf, parimaa_na(buf), RPP_ECHO_OFF));
}
#endif

static void handler(puur_naa_nka s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
