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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/ioctl.h>
#অন্তর্ভাব <sys/uio.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "progressmeter.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
স্থির পূর্ণাঙ্ক can_output(শূন্য);

/* window resizing */
স্থির শূন্য sig_winch(পূর্ণাঙ্ক);
স্থির শূন্য setscreensize(শূন্য);

/* signal handler for updating the progress meter */
স্থির শূন্য sig_alarm(পূর্ণাঙ্ক);

স্থির দ্বিগুণ start;		/* start progress */
স্থির দ্বিগুণ last_update;	/* last progress update */
স্থির ধ্রুব বর্ণ *file;	/* name of the file being transferred */
স্থির off_t start_pos;		/* initial position of transfer */
স্থির off_t end_pos;		/* ending position of transfer */
স্থির off_t cur_pos;		/* transfer position as of last refresh */
স্থির চঞ্চল off_t *counter;	/* progress counter */
স্থির long stalled;		/* how long we have been stalled */
স্থির long long bytes_per_second; /* current speed in bytes per second */
স্থির পূর্ণাঙ্ক win_size;		/* terminal window size */
স্থির চঞ্চল sig_atomic_t win_resized; /* for window resizing */
স্থির চঞ্চল sig_atomic_t alarm_fired;

/* units for format_size */
স্থির ধ্রুব বর্ণ unit[] = " KMGT";

স্থির পূর্ণাঙ্ক
can_output(শূন্য)
{
	প্রত্যাগম (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((পরিমাণ(v) * 8 * 4) / 10) + 1)

স্থির ধ্রুব বর্ণ *
format_rate(off_t bytes)
{
	পূর্ণাঙ্ক i;
	স্থির বর্ণ buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	প্রতি (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	যদি (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, পরিমাণ(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	প্রত্যাগম buf;
}

স্থির ধ্রুব বর্ণ *
format_size(off_t bytes)
{
	পূর্ণাঙ্ক i;
	স্থির বর্ণ buf[STRING_SIZE(bytes) + 16];

	প্রতি (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, পরিমাণ(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	প্রত্যাগম buf;
}

শূন্য
refresh_progress_meter(পূর্ণাঙ্ক force_update)
{
	বর্ণ *buf = রিক্ত, *obuf = রিক্ত;
	off_t transferred;
	দ্বিগুণ elapsed, now;
	পূর্ণাঙ্ক percent;
	off_t bytes_বাম;
	long long cur_speed;
	পূর্ণাঙ্ক hours, minutes, seconds;
	পূর্ণাঙ্ক file_len, cols;

	যদি (file == রিক্ত || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		প্রত্যাগম;
	alarm_fired = 0;

	যদি (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_বাম = end_pos - cur_pos;

	যদি (bytes_বাম > 0)
		elapsed = now - last_update;
	অন্যথা {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	যদি (elapsed != 0)
		cur_speed = (transferred / elapsed);
	অন্যথা
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	যদি (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} অন্যথা
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	যদি (win_size < 4)
		প্রত্যাগম;

	/* filename */
	file_len = cols = win_size - 36;
	যদি (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		যদি (cols < file_len)
			xextendf(&buf, রিক্ত, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	যদি (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	অন্যথা
		percent = ((ভিন্ন)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, রিক্ত, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	যদি (!transferred)
		stalled += elapsed;
	অন্যথা
		stalled = 0;

	যদি (stalled >= STALL_TIME)
		xextendf(&buf, রিক্ত, "- stalled -");
	অন্যথা যদি (bytes_per_second == 0 && bytes_বাম)
		xextendf(&buf, রিক্ত, "  --:-- ETA");
	অন্যথা {
		যদি (bytes_বাম > 0)
			seconds = bytes_বাম / bytes_per_second;
		অন্যথা
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		যদি (hours != 0) {
			xextendf(&buf, রিক্ত, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} অন্যথা
			xextendf(&buf, রিক্ত, "  %02d:%02d", minutes, seconds);

		যদি (bytes_বাম > 0)
			xextendf(&buf, রিক্ত, " ETA");
		অন্যথা
			xextendf(&buf, রিক্ত, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	যদি (obuf != রিক্ত) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
	}
	মুক্ত(buf);
	মুক্ত(obuf);
}

স্থির শূন্য
sig_alarm(পূর্ণাঙ্ক ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

শূন্য
start_progress_meter(ধ্রুব বর্ণ *f, off_t filesize, off_t *ctr)
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

শূন্য
stop_progress_meter(শূন্য)
{
	alarm(0);

	যদি (!can_output())
		প্রত্যাগম;

	/* Ensure we complete the progress */
	যদি (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = রিক্ত;
}

স্থির শূন্য
sig_winch(পূর্ণাঙ্ক sig)
{
	win_resized = 1;
}

স্থির শূন্য
setscreensize(শূন্য)
{
	সংরচনা winsize winsize;

	যদি (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		যদি (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		অন্যথা
			win_size = winsize.ws_col;
	} অন্যথা
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
