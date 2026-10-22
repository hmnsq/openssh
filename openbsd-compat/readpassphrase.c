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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_READPASSPHRASE

#ଅନ୍ତର୍ଭାଵ <termios.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <readpassphrase.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#ଯଦି !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

ସ୍ଥିର ଅସ୍ଥିର sig_atomic_t signo[_NSIG];

ସ୍ଥିର ଶୂନ୍ୟ handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* Like sigaction(2) but preserves SIG_IGN */
ସ୍ଥିର ଶୂନ୍ୟ
sigaction_except_ign(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signum, ସଂରଚନା sigaction *act, ସଂରଚନା sigaction *old)
{
	ସଂରଚନା sigaction sabuf;

	ଯଦି (old == ଖାଲି)
		old = &sabuf;

	(ଶୂନ୍ୟ)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	ଯଦି (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(ଶୂନ୍ୟ)sigaction(signum, old, ଖାଲି);
}

ଅକ୍ଷର *
readpassphrase(ଅଚଳ ଅକ୍ଷର *prompt, ଅକ୍ଷର *buf, size_t bufsiz, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ssize_t nr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ, output, save_errno, i, need_restart;
	ଅକ୍ଷର ch, *p, *end;
	ସଂରଚନା termios term, oterm;
	ସଂରଚନା sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	ସଂରଚନା sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	ଯଦି (bufsiz == 0) {
		errno = EINVAL;
		ଫେରନ୍ତୁ(ଖାଲି);
	}

restart:
	ପାଇଁ (i = 0; i < _NSIG; i++)
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
	ଯଦି ((flags & RPP_STDIN) ||
	    (ନିବେଶ = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		ଯଦି (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			ଫେରନ୍ତୁ(ଖାଲି);
		}
		ନିବେଶ = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	ଯଦି (ନିବେଶ != STDIN_FILENO && tcgetattr(ନିବେଶ, &oterm) == 0) {
		memcpy(&term, &oterm, ଆକାର(term));
		ଯଦି (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		ଯଦି (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(ଶୂନ୍ୟ)tcsetattr(ନିବେଶ, TCSAFLUSH|TCSASOFT, &term);
	} ଅନ୍ୟଥା {
		memset(&term, 0, ଆକାର(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, ଆକାର(oterm));
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

	ଯଦି (!(flags & RPP_STDIN))
		(ଶୂନ୍ୟ)ଲିଖ(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	ଯେତେବେଳେ ((nr = ପଠ(ନିବେଶ, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		ଯଦି (p < end) {
			ଯଦି ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			ଯଦି (isalpha((unsigned ଅକ୍ଷର)ch)) {
				ଯଦି ((flags & RPP_FORCELOWER))
					ch = (ଅକ୍ଷର)tolower((unsigned ଅକ୍ଷର)ch);
				ଯଦି ((flags & RPP_FORCEUPPER))
					ch = (ଅକ୍ଷର)toupper((unsigned ଅକ୍ଷର)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	ଯଦି (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(ଶୂନ୍ୟ)ଲିଖ(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	ଯଦି (memcmp(&term, &oterm, ଆକାର(term)) != 0) {
		ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		ଯେତେବେଳେ (tcsetattr(ନିବେଶ, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			ଜାରି;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, ଖାଲି);
	sigaction(SIGQUIT, &savequit, ଖାଲି);
	sigaction_except_ign(SIGALRM, &savealrm, ଖାଲି);
	sigaction_except_ign(SIGHUP, &savehup, ଖାଲି);
	sigaction_except_ign(SIGPIPE, &savepipe, ଖାଲି);
	sigaction_except_ign(SIGTERM, &saveterm, ଖାଲି);
	sigaction_except_ign(SIGTSTP, &savetstp, ଖାଲି);
	sigaction_except_ign(SIGTTIN, &savettin, ଖାଲି);
	sigaction_except_ign(SIGTTOU, &savettou, ଖାଲି);
	ଯଦି (ନିବେଶ != STDIN_FILENO)
		(ଶୂନ୍ୟ)close(ନିବେଶ);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	ପାଇଁ (i = 0; i < _NSIG; i++) {
		ଯଦି (signo[i]) {
			kill(getpid(), i);
			ବାଛ (i) {
			ସ୍ଥିତି SIGTSTP:
			ସ୍ଥିତି SIGTTIN:
			ସ୍ଥିତି SIGTTOU:
				need_restart = 1;
			}
		}
	}
	ଯଦି (need_restart)
		ଯାଅ restart;

	ଯଦି (save_errno)
		errno = save_errno;
	ଫେରନ୍ତୁ(nr == -1 ? ଖାଲି : buf);
}
DEF_WEAK(readpassphrase);

#ଯଦି 0
ଅକ୍ଷର *
getpass(ଅଚଳ ଅକ୍ଷର *prompt)
{
	ସ୍ଥିର ଅକ୍ଷର buf[_PASSWORD_LEN + 1];

	ଫେରନ୍ତୁ(readpassphrase(prompt, buf, ଆକାର(buf), RPP_ECHO_OFF));
}
#endif

ସ୍ଥିର ଶୂନ୍ୟ handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
