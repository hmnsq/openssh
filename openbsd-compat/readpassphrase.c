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

#അന്തര്ഭാവ "includes.h"

#ifndef HAVE_READPASSPHRASE

#അന്തര്ഭാവ <termios.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <readpassphrase.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#എങ്കിൽ !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

സ്ഥിതം അസ്ഥിര sig_atomic_t signo[_NSIG];

സ്ഥിതം ശൂന്യം handler(പൂർണ്ണസംഖ്യ);

/* Like sigaction(2) but preserves SIG_IGN */
സ്ഥിതം ശൂന്യം
sigaction_except_ign(പൂർണ്ണസംഖ്യ signum, ഘടന sigaction *act, ഘടന sigaction *old)
{
	ഘടന sigaction sabuf;

	എങ്കിൽ (old == ശൂന്യ)
		old = &sabuf;

	(ശൂന്യം)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	എങ്കിൽ (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(ശൂന്യം)sigaction(signum, old, ശൂന്യ);
}

അക്ഷരം *
readpassphrase(സ്ഥിരം അക്ഷരം *prompt, അക്ഷരം *buf, size_t bufsiz, പൂർണ്ണസംഖ്യ flags)
{
	ssize_t nr;
	പൂർണ്ണസംഖ്യ നിവേശം, output, save_errno, i, need_restart;
	അക്ഷരം ch, *p, *end;
	ഘടന termios term, oterm;
	ഘടന sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	ഘടന sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	എങ്കിൽ (bufsiz == 0) {
		errno = EINVAL;
		തിരികെ(ശൂന്യ);
	}

restart:
	വേണ്ടി (i = 0; i < _NSIG; i++)
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
	എങ്കിൽ ((flags & RPP_STDIN) ||
	    (നിവേശം = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		എങ്കിൽ (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			തിരികെ(ശൂന്യ);
		}
		നിവേശം = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	എങ്കിൽ (നിവേശം != STDIN_FILENO && tcgetattr(നിവേശം, &oterm) == 0) {
		memcpy(&term, &oterm, വലുപ്പം(term));
		എങ്കിൽ (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		എങ്കിൽ (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(ശൂന്യം)tcsetattr(നിവേശം, TCSAFLUSH|TCSASOFT, &term);
	} അല്ലെങ്കിൽ {
		memset(&term, 0, വലുപ്പം(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, വലുപ്പം(oterm));
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

	എങ്കിൽ (!(flags & RPP_STDIN))
		(ശൂന്യം)ലിഖ(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	ആകുമ്പോൾ ((nr = പഠ(നിവേശം, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		എങ്കിൽ (p < end) {
			എങ്കിൽ ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			എങ്കിൽ (isalpha((unsigned അക്ഷരം)ch)) {
				എങ്കിൽ ((flags & RPP_FORCELOWER))
					ch = (അക്ഷരം)tolower((unsigned അക്ഷരം)ch);
				എങ്കിൽ ((flags & RPP_FORCEUPPER))
					ch = (അക്ഷരം)toupper((unsigned അക്ഷരം)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	എങ്കിൽ (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(ശൂന്യം)ലിഖ(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	എങ്കിൽ (memcmp(&term, &oterm, വലുപ്പം(term)) != 0) {
		സ്ഥിരം പൂർണ്ണസംഖ്യ sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		ആകുമ്പോൾ (tcsetattr(നിവേശം, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			തുടരുക;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, ശൂന്യ);
	sigaction(SIGQUIT, &savequit, ശൂന്യ);
	sigaction_except_ign(SIGALRM, &savealrm, ശൂന്യ);
	sigaction_except_ign(SIGHUP, &savehup, ശൂന്യ);
	sigaction_except_ign(SIGPIPE, &savepipe, ശൂന്യ);
	sigaction_except_ign(SIGTERM, &saveterm, ശൂന്യ);
	sigaction_except_ign(SIGTSTP, &savetstp, ശൂന്യ);
	sigaction_except_ign(SIGTTIN, &savettin, ശൂന്യ);
	sigaction_except_ign(SIGTTOU, &savettou, ശൂന്യ);
	എങ്കിൽ (നിവേശം != STDIN_FILENO)
		(ശൂന്യം)close(നിവേശം);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	വേണ്ടി (i = 0; i < _NSIG; i++) {
		എങ്കിൽ (signo[i]) {
			kill(getpid(), i);
			തിരഞ്ഞെടുപ്പ് (i) {
			അവസ്ഥ SIGTSTP:
			അവസ്ഥ SIGTTIN:
			അവസ്ഥ SIGTTOU:
				need_restart = 1;
			}
		}
	}
	എങ്കിൽ (need_restart)
		പോകുക restart;

	എങ്കിൽ (save_errno)
		errno = save_errno;
	തിരികെ(nr == -1 ? ശൂന്യ : buf);
}
DEF_WEAK(readpassphrase);

#എങ്കിൽ 0
അക്ഷരം *
getpass(സ്ഥിരം അക്ഷരം *prompt)
{
	സ്ഥിതം അക്ഷരം buf[_PASSWORD_LEN + 1];

	തിരികെ(readpassphrase(prompt, buf, വലുപ്പം(buf), RPP_ECHO_OFF));
}
#endif

സ്ഥിതം ശൂന്യം handler(പൂർണ്ണസംഖ്യ s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
