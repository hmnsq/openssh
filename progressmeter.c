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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/uio.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "progressmeter.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ can_output(ಶೂನ್ಯ);

/* window resizing */
ಸ್ಥಿರ ಶೂನ್ಯ sig_winch(ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ ಶೂನ್ಯ setscreensize(ಶೂನ್ಯ);

/* signal handler for updating the progress meter */
ಸ್ಥಿರ ಶೂನ್ಯ sig_alarm(ಪೂರ್ಣಾಙ್ಕ);

ಸ್ಥಿರ ದ್ವಿಗುಣ start;		/* start progress */
ಸ್ಥಿರ ದ್ವಿಗುಣ last_update;	/* last progress update */
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *file;	/* name of the file being transferred */
ಸ್ಥಿರ off_t start_pos;		/* initial position of transfer */
ಸ್ಥಿರ off_t end_pos;		/* ending position of transfer */
ಸ್ಥಿರ off_t cur_pos;		/* transfer position as of last refresh */
ಸ್ಥಿರ ಚಞ್ಚಲ off_t *counter;	/* progress counter */
ಸ್ಥಿರ long stalled;		/* how long we have been stalled */
ಸ್ಥಿರ long long bytes_per_second; /* current speed in bytes per second */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ win_size;		/* terminal window size */
ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t win_resized; /* for window resizing */
ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t alarm_fired;

/* units for format_size */
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ unit[] = " KMGT";

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
can_output(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((ಪರಿಮಾಣ(v) * 8 * 4) / 10) + 1)

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
format_rate(off_t bytes)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಸ್ಥಿರ ವರ್ಣ buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	ಪ್ರತಿ (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	ಯದಿ (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, ಪರಿಮಾಣ(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	ಪ್ರತ್ಯಾಗಮ buf;
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
format_size(off_t bytes)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಸ್ಥಿರ ವರ್ಣ buf[STRING_SIZE(bytes) + 16];

	ಪ್ರತಿ (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, ಪರಿಮಾಣ(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	ಪ್ರತ್ಯಾಗಮ buf;
}

ಶೂನ್ಯ
refresh_progress_meter(ಪೂರ್ಣಾಙ್ಕ force_update)
{
	ವರ್ಣ *buf = ರಿಕ್ತ, *obuf = ರಿಕ್ತ;
	off_t transferred;
	ದ್ವಿಗುಣ elapsed, now;
	ಪೂರ್ಣಾಙ್ಕ percent;
	off_t bytes_ಎಡ;
	long long cur_speed;
	ಪೂರ್ಣಾಙ್ಕ hours, minutes, seconds;
	ಪೂರ್ಣಾಙ್ಕ file_len, cols;

	ಯದಿ (file == ರಿಕ್ತ || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		ಪ್ರತ್ಯಾಗಮ;
	alarm_fired = 0;

	ಯದಿ (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_ಎಡ = end_pos - cur_pos;

	ಯದಿ (bytes_ಎಡ > 0)
		elapsed = now - last_update;
	ಅನ್ಯಥಾ {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	ಯದಿ (elapsed != 0)
		cur_speed = (transferred / elapsed);
	ಅನ್ಯಥಾ
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	ಯದಿ (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} ಅನ್ಯಥಾ
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	ಯದಿ (win_size < 4)
		ಪ್ರತ್ಯಾಗಮ;

	/* filename */
	file_len = cols = win_size - 36;
	ಯದಿ (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		ಯದಿ (cols < file_len)
			xextendf(&buf, ರಿಕ್ತ, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	ಯದಿ (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	ಅನ್ಯಥಾ
		percent = ((ಭಿನ್ನ)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, ರಿಕ್ತ, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	ಯದಿ (!transferred)
		stalled += elapsed;
	ಅನ್ಯಥಾ
		stalled = 0;

	ಯದಿ (stalled >= STALL_TIME)
		xextendf(&buf, ರಿಕ್ತ, "- stalled -");
	ಅನ್ಯಥಾ ಯದಿ (bytes_per_second == 0 && bytes_ಎಡ)
		xextendf(&buf, ರಿಕ್ತ, "  --:-- ETA");
	ಅನ್ಯಥಾ {
		ಯದಿ (bytes_ಎಡ > 0)
			seconds = bytes_ಎಡ / bytes_per_second;
		ಅನ್ಯಥಾ
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		ಯದಿ (hours != 0) {
			xextendf(&buf, ರಿಕ್ತ, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} ಅನ್ಯಥಾ
			xextendf(&buf, ರಿಕ್ತ, "  %02d:%02d", minutes, seconds);

		ಯದಿ (bytes_ಎಡ > 0)
			xextendf(&buf, ರಿಕ್ತ, " ETA");
		ಅನ್ಯಥಾ
			xextendf(&buf, ರಿಕ್ತ, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	ಯದಿ (obuf != ರಿಕ್ತ) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
	}
	ಮುಕ್ತ(buf);
	ಮುಕ್ತ(obuf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sig_alarm(ಪೂರ್ಣಾಙ್ಕ ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

ಶೂನ್ಯ
start_progress_meter(ಧ್ರುವ ವರ್ಣ *f, off_t filesize, off_t *ctr)
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

ಶೂನ್ಯ
stop_progress_meter(ಶೂನ್ಯ)
{
	alarm(0);

	ಯದಿ (!can_output())
		ಪ್ರತ್ಯಾಗಮ;

	/* Ensure we complete the progress */
	ಯದಿ (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sig_winch(ಪೂರ್ಣಾಙ್ಕ sig)
{
	win_resized = 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
setscreensize(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ winsize winsize;

	ಯದಿ (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		ಯದಿ (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		ಅನ್ಯಥಾ
			win_size = winsize.ws_col;
	} ಅನ್ಯಥಾ
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
