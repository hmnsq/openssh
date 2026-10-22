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

#અન્તર્ભાવ "includes.h"

#ifndef HAVE_READPASSPHRASE

#અન્તર્ભાવ <termios.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <readpassphrase.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#જો !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

સ્થિર અસ્થિર sig_atomic_t signo[_NSIG];

સ્થિર શૂન્ય handler(પૂર્ણાંક);

/* Like sigaction(2) but preserves SIG_IGN */
સ્થિર શૂન્ય
sigaction_except_ign(પૂર્ણાંક signum, સંરચના sigaction *act, સંરચના sigaction *old)
{
	સંરચના sigaction sabuf;

	જો (old == ખાલી)
		old = &sabuf;

	(શૂન્ય)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	જો (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(શૂન્ય)sigaction(signum, old, ખાલી);
}

અક્ષર *
readpassphrase(અચલ અક્ષર *prompt, અક્ષર *buf, size_t bufsiz, પૂર્ણાંક flags)
{
	ssize_t nr;
	પૂર્ણાંક આગત, output, save_errno, i, need_restart;
	અક્ષર ch, *p, *end;
	સંરચના termios term, oterm;
	સંરચના sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	સંરચના sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	જો (bufsiz == 0) {
		errno = EINVAL;
		પાછા(ખાલી);
	}

restart:
	માટે (i = 0; i < _NSIG; i++)
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
	જો ((flags & RPP_STDIN) ||
	    (આગત = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		જો (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			પાછા(ખાલી);
		}
		આગત = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	જો (આગત != STDIN_FILENO && tcgetattr(આગત, &oterm) == 0) {
		memcpy(&term, &oterm, કદ(term));
		જો (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		જો (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(શૂન્ય)tcsetattr(આગત, TCSAFLUSH|TCSASOFT, &term);
	} નહીંતર {
		memset(&term, 0, કદ(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, કદ(oterm));
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

	જો (!(flags & RPP_STDIN))
		(શૂન્ય)લિખ(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	જ્યારે ((nr = પઠ(આગત, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		જો (p < end) {
			જો ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			જો (isalpha((unsigned અક્ષર)ch)) {
				જો ((flags & RPP_FORCELOWER))
					ch = (અક્ષર)tolower((unsigned અક્ષર)ch);
				જો ((flags & RPP_FORCEUPPER))
					ch = (અક્ષર)toupper((unsigned અક્ષર)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	જો (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(શૂન્ય)લિખ(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	જો (memcmp(&term, &oterm, કદ(term)) != 0) {
		અચલ પૂર્ણાંક sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		જ્યારે (tcsetattr(આગત, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			ચાલુ;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, ખાલી);
	sigaction(SIGQUIT, &savequit, ખાલી);
	sigaction_except_ign(SIGALRM, &savealrm, ખાલી);
	sigaction_except_ign(SIGHUP, &savehup, ખાલી);
	sigaction_except_ign(SIGPIPE, &savepipe, ખાલી);
	sigaction_except_ign(SIGTERM, &saveterm, ખાલી);
	sigaction_except_ign(SIGTSTP, &savetstp, ખાલી);
	sigaction_except_ign(SIGTTIN, &savettin, ખાલી);
	sigaction_except_ign(SIGTTOU, &savettou, ખાલી);
	જો (આગત != STDIN_FILENO)
		(શૂન્ય)close(આગત);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	માટે (i = 0; i < _NSIG; i++) {
		જો (signo[i]) {
			kill(getpid(), i);
			પસંદગી (i) {
			સ્થિતિ SIGTSTP:
			સ્થિતિ SIGTTIN:
			સ્થિતિ SIGTTOU:
				need_restart = 1;
			}
		}
	}
	જો (need_restart)
		જાઓ restart;

	જો (save_errno)
		errno = save_errno;
	પાછા(nr == -1 ? ખાલી : buf);
}
DEF_WEAK(readpassphrase);

#જો 0
અક્ષર *
getpass(અચલ અક્ષર *prompt)
{
	સ્થિર અક્ષર buf[_PASSWORD_LEN + 1];

	પાછા(readpassphrase(prompt, buf, કદ(buf), RPP_ECHO_OFF));
}
#endif

સ્થિર શૂન્ય handler(પૂર્ણાંક s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
