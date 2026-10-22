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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>
#شامل <sys/uio.h>

#شامل <errno.h>
#شامل <limits.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>

#شامل "progressmeter.h"
#شامل "atomicio.h"
#شامل "misc.h"
#شامل "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
ایستا صحیح can_output(تهی);

/* window resizing */
ایستا تهی sig_winch(صحیح);
ایستا تهی setscreensize(تهی);

/* signal handler for updating the progress meter */
ایستا تهی sig_alarm(صحیح);

ایستا دوگانه start;		/* start progress */
ایستا دوگانه last_update;	/* last progress update */
ایستا ثابت نویسه *file;	/* name of the file being transferred */
ایستا off_t start_pos;		/* initial position of transfer */
ایستا off_t end_pos;		/* ending position of transfer */
ایستا off_t cur_pos;		/* transfer position as of last refresh */
ایستا فرار off_t *counter;	/* progress counter */
ایستا long stalled;		/* how long we have been stalled */
ایستا long long bytes_per_second; /* current speed in bytes per second */
ایستا صحیح win_size;		/* terminal window size */
ایستا فرار sig_atomic_t win_resized; /* for window resizing */
ایستا فرار sig_atomic_t alarm_fired;

/* units for format_size */
ایستا ثابت نویسه unit[] = " KMGT";

ایستا صحیح
can_output(تهی)
{
	بازگشت (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((اندازه(v) * 8 * 4) / 10) + 1)

ایستا ثابت نویسه *
format_rate(off_t bytes)
{
	صحیح i;
	ایستا نویسه buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	برای (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	اگر (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, اندازه(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	بازگشت buf;
}

ایستا ثابت نویسه *
format_size(off_t bytes)
{
	صحیح i;
	ایستا نویسه buf[STRING_SIZE(bytes) + 16];

	برای (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, اندازه(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	بازگشت buf;
}

تهی
refresh_progress_meter(صحیح force_update)
{
	نویسه *buf = پوچ, *obuf = پوچ;
	off_t transferred;
	دوگانه elapsed, now;
	صحیح percent;
	off_t bytes_چپ;
	long long cur_speed;
	صحیح hours, minutes, seconds;
	صحیح file_len, cols;

	اگر (file == پوچ || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		بازگشت;
	alarm_fired = 0;

	اگر (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_چپ = end_pos - cur_pos;

	اگر (bytes_چپ > 0)
		elapsed = now - last_update;
	وگرنه {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	اگر (elapsed != 0)
		cur_speed = (transferred / elapsed);
	وگرنه
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	اگر (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} وگرنه
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	اگر (win_size < 4)
		بازگشت;

	/* filename */
	file_len = cols = win_size - 36;
	اگر (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		اگر (cols < file_len)
			xextendf(&buf, پوچ, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	اگر (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	وگرنه
		percent = ((اعشاری)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, پوچ, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	اگر (!transferred)
		stalled += elapsed;
	وگرنه
		stalled = 0;

	اگر (stalled >= STALL_TIME)
		xextendf(&buf, پوچ, "- stalled -");
	وگرنه اگر (bytes_per_second == 0 && bytes_چپ)
		xextendf(&buf, پوچ, "  --:-- ETA");
	وگرنه {
		اگر (bytes_چپ > 0)
			seconds = bytes_چپ / bytes_per_second;
		وگرنه
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		اگر (hours != 0) {
			xextendf(&buf, پوچ, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} وگرنه
			xextendf(&buf, پوچ, "  %02d:%02d", minutes, seconds);

		اگر (bytes_چپ > 0)
			xextendf(&buf, پوچ, " ETA");
		وگرنه
			xextendf(&buf, پوچ, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	اگر (obuf != پوچ) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
	}
	آزاد(buf);
	آزاد(obuf);
}

ایستا تهی
sig_alarm(صحیح ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

تهی
start_progress_meter(ثابت نویسه *f, off_t filesize, off_t *ctr)
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

تهی
stop_progress_meter(تهی)
{
	alarm(0);

	اگر (!can_output())
		بازگشت;

	/* Ensure we complete the progress */
	اگر (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = پوچ;
}

ایستا تهی
sig_winch(صحیح sig)
{
	win_resized = 1;
}

ایستا تهی
setscreensize(تهی)
{
	ساختار winsize winsize;

	اگر (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		اگر (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		وگرنه
			win_size = winsize.ws_col;
	} وگرنه
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
