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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/ioctl.h>
#અન્તર્ભાવ <sys/uio.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "progressmeter.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
સ્થિર પૂર્ણાંક can_output(શૂન્ય);

/* window resizing */
સ્થિર શૂન્ય sig_winch(પૂર્ણાંક);
સ્થિર શૂન્ય setscreensize(શૂન્ય);

/* signal handler for updating the progress meter */
સ્થિર શૂન્ય sig_alarm(પૂર્ણાંક);

સ્થિર દ્વિગુણ start;		/* start progress */
સ્થિર દ્વિગુણ last_update;	/* last progress update */
સ્થિર અચલ અક્ષર *file;	/* name of the file being transferred */
સ્થિર off_t start_pos;		/* initial position of transfer */
સ્થિર off_t end_pos;		/* ending position of transfer */
સ્થિર off_t cur_pos;		/* transfer position as of last refresh */
સ્થિર અસ્થિર off_t *counter;	/* progress counter */
સ્થિર long stalled;		/* how long we have been stalled */
સ્થિર long long bytes_per_second; /* current speed in bytes per second */
સ્થિર પૂર્ણાંક win_size;		/* terminal window size */
સ્થિર અસ્થિર sig_atomic_t win_resized; /* for window resizing */
સ્થિર અસ્થિર sig_atomic_t alarm_fired;

/* units for format_size */
સ્થિર અચલ અક્ષર unit[] = " KMGT";

સ્થિર પૂર્ણાંક
can_output(શૂન્ય)
{
	પાછા (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((કદ(v) * 8 * 4) / 10) + 1)

સ્થિર અચલ અક્ષર *
format_rate(off_t bytes)
{
	પૂર્ણાંક i;
	સ્થિર અક્ષર buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	માટે (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	જો (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, કદ(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	પાછા buf;
}

સ્થિર અચલ અક્ષર *
format_size(off_t bytes)
{
	પૂર્ણાંક i;
	સ્થિર અક્ષર buf[STRING_SIZE(bytes) + 16];

	માટે (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, કદ(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	પાછા buf;
}

શૂન્ય
refresh_progress_meter(પૂર્ણાંક force_update)
{
	અક્ષર *buf = ખાલી, *obuf = ખાલી;
	off_t transferred;
	દ્વિગુણ elapsed, now;
	પૂર્ણાંક percent;
	off_t bytes_ડાબું;
	long long cur_speed;
	પૂર્ણાંક hours, minutes, seconds;
	પૂર્ણાંક file_len, cols;

	જો (file == ખાલી || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		પાછા;
	alarm_fired = 0;

	જો (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_ડાબું = end_pos - cur_pos;

	જો (bytes_ડાબું > 0)
		elapsed = now - last_update;
	નહીંતર {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	જો (elapsed != 0)
		cur_speed = (transferred / elapsed);
	નહીંતર
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	જો (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} નહીંતર
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	જો (win_size < 4)
		પાછા;

	/* filename */
	file_len = cols = win_size - 36;
	જો (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		જો (cols < file_len)
			xextendf(&buf, ખાલી, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	જો (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	નહીંતર
		percent = ((દશાંશ)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, ખાલી, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	જો (!transferred)
		stalled += elapsed;
	નહીંતર
		stalled = 0;

	જો (stalled >= STALL_TIME)
		xextendf(&buf, ખાલી, "- stalled -");
	નહીંતર જો (bytes_per_second == 0 && bytes_ડાબું)
		xextendf(&buf, ખાલી, "  --:-- ETA");
	નહીંતર {
		જો (bytes_ડાબું > 0)
			seconds = bytes_ડાબું / bytes_per_second;
		નહીંતર
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		જો (hours != 0) {
			xextendf(&buf, ખાલી, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} નહીંતર
			xextendf(&buf, ખાલી, "  %02d:%02d", minutes, seconds);

		જો (bytes_ડાબું > 0)
			xextendf(&buf, ખાલી, " ETA");
		નહીંતર
			xextendf(&buf, ખાલી, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	જો (obuf != ખાલી) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
	}
	મુક્ત(buf);
	મુક્ત(obuf);
}

સ્થિર શૂન્ય
sig_alarm(પૂર્ણાંક ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

શૂન્ય
start_progress_meter(અચલ અક્ષર *f, off_t filesize, off_t *ctr)
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

શૂન્ય
stop_progress_meter(શૂન્ય)
{
	alarm(0);

	જો (!can_output())
		પાછા;

	/* Ensure we complete the progress */
	જો (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = ખાલી;
}

સ્થિર શૂન્ય
sig_winch(પૂર્ણાંક sig)
{
	win_resized = 1;
}

સ્થિર શૂન્ય
setscreensize(શૂન્ય)
{
	સંરચના winsize winsize;

	જો (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		જો (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		નહીંતર
			win_size = winsize.ws_col;
	} નહીંતર
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
