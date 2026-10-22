/* $OpenBSD: progressmeter.c,v 1.57 2026/03/29 01:08:13 djm Exp $ */
/*
 * Copyright (c) 2003 Nils Nordman.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/ioctl.h>
#അന്തര്ഭാവ <sys/uio.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "progressmeter.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
സ്ഥിതം പൂർണ്ണസംഖ്യ can_output(ശൂന്യം);

/* window resizing */
സ്ഥിതം ശൂന്യം sig_winch(പൂർണ്ണസംഖ്യ);
സ്ഥിതം ശൂന്യം setscreensize(ശൂന്യം);

/* signal handler for updating the progress meter */
സ്ഥിതം ശൂന്യം sig_alarm(പൂർണ്ണസംഖ്യ);

സ്ഥിതം ഇരട്ട start;		/* start progress */
സ്ഥിതം ഇരട്ട last_update;	/* last progress update */
സ്ഥിതം സ്ഥിരം അക്ഷരം *file;	/* name of the file being transferred */
സ്ഥിതം off_t start_pos;		/* initial position of transfer */
സ്ഥിതം off_t end_pos;		/* ending position of transfer */
സ്ഥിതം off_t cur_pos;		/* transfer position as of last refresh */
സ്ഥിതം അസ്ഥിര off_t *counter;	/* progress counter */
സ്ഥിതം long stalled;		/* how long we have been stalled */
സ്ഥിതം long long bytes_per_second; /* current speed in bytes per second */
സ്ഥിതം പൂർണ്ണസംഖ്യ win_size;		/* terminal window size */
സ്ഥിതം അസ്ഥിര sig_atomic_t win_resized; /* for window resizing */
സ്ഥിതം അസ്ഥിര sig_atomic_t alarm_fired;

/* units for format_size */
സ്ഥിതം സ്ഥിരം അക്ഷരം unit[] = " KMGT";

സ്ഥിതം പൂർണ്ണസംഖ്യ
can_output(ശൂന്യം)
{
	തിരികെ (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((വലുപ്പം(v) * 8 * 4) / 10) + 1)

സ്ഥിതം സ്ഥിരം അക്ഷരം *
format_rate(off_t bytes)
{
	പൂർണ്ണസംഖ്യ i;
	സ്ഥിതം അക്ഷരം buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	വേണ്ടി (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	എങ്കിൽ (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, വലുപ്പം(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	തിരികെ buf;
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
format_size(off_t bytes)
{
	പൂർണ്ണസംഖ്യ i;
	സ്ഥിതം അക്ഷരം buf[STRING_SIZE(bytes) + 16];

	വേണ്ടി (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, വലുപ്പം(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	തിരികെ buf;
}

ശൂന്യം
refresh_progress_meter(പൂർണ്ണസംഖ്യ force_update)
{
	അക്ഷരം *buf = ശൂന്യ, *obuf = ശൂന്യ;
	off_t transferred;
	ഇരട്ട elapsed, now;
	പൂർണ്ണസംഖ്യ percent;
	off_t bytes_ഇടത്;
	long long cur_speed;
	പൂർണ്ണസംഖ്യ hours, minutes, seconds;
	പൂർണ്ണസംഖ്യ file_len, cols;

	എങ്കിൽ (file == ശൂന്യ || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		തിരികെ;
	alarm_fired = 0;

	എങ്കിൽ (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_ഇടത് = end_pos - cur_pos;

	എങ്കിൽ (bytes_ഇടത് > 0)
		elapsed = now - last_update;
	അല്ലെങ്കിൽ {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	എങ്കിൽ (elapsed != 0)
		cur_speed = (transferred / elapsed);
	അല്ലെങ്കിൽ
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	എങ്കിൽ (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} അല്ലെങ്കിൽ
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	എങ്കിൽ (win_size < 4)
		തിരികെ;

	/* filename */
	file_len = cols = win_size - 36;
	എങ്കിൽ (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		എങ്കിൽ (cols < file_len)
			xextendf(&buf, ശൂന്യ, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	എങ്കിൽ (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	അല്ലെങ്കിൽ
		percent = ((ദശാംശം)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, ശൂന്യ, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	എങ്കിൽ (!transferred)
		stalled += elapsed;
	അല്ലെങ്കിൽ
		stalled = 0;

	എങ്കിൽ (stalled >= STALL_TIME)
		xextendf(&buf, ശൂന്യ, "- stalled -");
	അല്ലെങ്കിൽ എങ്കിൽ (bytes_per_second == 0 && bytes_ഇടത്)
		xextendf(&buf, ശൂന്യ, "  --:-- ETA");
	അല്ലെങ്കിൽ {
		എങ്കിൽ (bytes_ഇടത് > 0)
			seconds = bytes_ഇടത് / bytes_per_second;
		അല്ലെങ്കിൽ
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		എങ്കിൽ (hours != 0) {
			xextendf(&buf, ശൂന്യ, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} അല്ലെങ്കിൽ
			xextendf(&buf, ശൂന്യ, "  %02d:%02d", minutes, seconds);

		എങ്കിൽ (bytes_ഇടത് > 0)
			xextendf(&buf, ശൂന്യ, " ETA");
		അല്ലെങ്കിൽ
			xextendf(&buf, ശൂന്യ, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	എങ്കിൽ (obuf != ശൂന്യ) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
	}
	സ്വതന്ത്രം(buf);
	സ്വതന്ത്രം(obuf);
}

സ്ഥിതം ശൂന്യം
sig_alarm(പൂർണ്ണസംഖ്യ ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

ശൂന്യം
start_progress_meter(സ്ഥിരം അക്ഷരം *f, off_t filesize, off_t *ctr)
{
	start = last_update = monotime_double();
	file = f;
	start_pos = *ctr;
	end_pos = filesize;
	cur_pos = 0;
	counter = ctr;
	stalled = 0;
	bytes_per_second = 0;

	setscreensize();
	refresh_progress_meter(1);

	ssh_signal(SIGALRM, sig_alarm);
	ssh_signal(SIGWINCH, sig_winch);
	alarm(UPDATE_INTERVAL);
}

ശൂന്യം
stop_progress_meter(ശൂന്യം)
{
	alarm(0);

	എങ്കിൽ (!can_output())
		തിരികെ;

	/* Ensure we complete the progress */
	എങ്കിൽ (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = ശൂന്യ;
}

സ്ഥിതം ശൂന്യം
sig_winch(പൂർണ്ണസംഖ്യ sig)
{
	win_resized = 1;
}

സ്ഥിതം ശൂന്യം
setscreensize(ശൂന്യം)
{
	ഘടന winsize winsize;

	എങ്കിൽ (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		എങ്കിൽ (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		അല്ലെങ്കിൽ
			win_size = winsize.ws_col;
	} അല്ലെങ്കിൽ
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
