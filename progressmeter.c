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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/ioctl.h>
#ضمن <sys/uio.h>

#ضمن <errno.h>
#ضمن <limits.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>

#ضمن "progressmeter.h"
#ضمن "atomicio.h"
#ضمن "misc.h"
#ضمن "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
ساكن صحيح can_output(فراغ);

/* window resizing */
ساكن فراغ sig_winch(صحيح);
ساكن فراغ setscreensize(فراغ);

/* signal handler for updating the progress meter */
ساكن فراغ sig_alarm(صحيح);

ساكن مزدوج start;		/* start progress */
ساكن مزدوج last_update;	/* last progress update */
ساكن ثابت حرف *file;	/* name of the file being transferred */
ساكن off_t start_pos;		/* initial position of transfer */
ساكن off_t end_pos;		/* ending position of transfer */
ساكن off_t cur_pos;		/* transfer position as of last refresh */
ساكن متطاير off_t *counter;	/* progress counter */
ساكن long stalled;		/* how long we have been stalled */
ساكن long long bytes_per_second; /* current speed in bytes per second */
ساكن صحيح win_size;		/* terminal window size */
ساكن متطاير sig_atomic_t win_resized; /* for window resizing */
ساكن متطاير sig_atomic_t alarm_fired;

/* units for format_size */
ساكن ثابت حرف unit[] = " KMGT";

ساكن صحيح
can_output(فراغ)
{
	أرجع (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((حجم(v) * 8 * 4) / 10) + 1)

ساكن ثابت حرف *
format_rate(off_t bytes)
{
	صحيح i;
	ساكن حرف buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	لكل (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	إذا (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, حجم(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	أرجع buf;
}

ساكن ثابت حرف *
format_size(off_t bytes)
{
	صحيح i;
	ساكن حرف buf[STRING_SIZE(bytes) + 16];

	لكل (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, حجم(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	أرجع buf;
}

فراغ
refresh_progress_meter(صحيح force_update)
{
	حرف *buf = عدم, *obuf = عدم;
	off_t transferred;
	مزدوج elapsed, now;
	صحيح percent;
	off_t bytes_سول;
	long long cur_speed;
	صحيح hours, minutes, seconds;
	صحيح file_len, cols;

	إذا (file == عدم || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		أرجع;
	alarm_fired = 0;

	إذا (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_سول = end_pos - cur_pos;

	إذا (bytes_سول > 0)
		elapsed = now - last_update;
	وإلا {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	إذا (elapsed != 0)
		cur_speed = (transferred / elapsed);
	وإلا
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	إذا (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} وإلا
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	إذا (win_size < 4)
		أرجع;

	/* filename */
	file_len = cols = win_size - 36;
	إذا (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		إذا (cols < file_len)
			xextendf(&buf, عدم, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	إذا (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	وإلا
		percent = ((عائم)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, عدم, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	إذا (!transferred)
		stalled += elapsed;
	وإلا
		stalled = 0;

	إذا (stalled >= STALL_TIME)
		xextendf(&buf, عدم, "- stalled -");
	وإلا إذا (bytes_per_second == 0 && bytes_سول)
		xextendf(&buf, عدم, "  --:-- ETA");
	وإلا {
		إذا (bytes_سول > 0)
			seconds = bytes_سول / bytes_per_second;
		وإلا
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		إذا (hours != 0) {
			xextendf(&buf, عدم, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} وإلا
			xextendf(&buf, عدم, "  %02d:%02d", minutes, seconds);

		إذا (bytes_سول > 0)
			xextendf(&buf, عدم, " ETA");
		وإلا
			xextendf(&buf, عدم, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	إذا (obuf != عدم) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
	}
	حرر(buf);
	حرر(obuf);
}

ساكن فراغ
sig_alarm(صحيح ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

فراغ
start_progress_meter(ثابت حرف *f, off_t filesize, off_t *ctr)
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

فراغ
stop_progress_meter(فراغ)
{
	alarm(0);

	إذا (!can_output())
		أرجع;

	/* Ensure we complete the progress */
	إذا (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = عدم;
}

ساكن فراغ
sig_winch(صحيح sig)
{
	win_resized = 1;
}

ساكن فراغ
setscreensize(فراغ)
{
	بنية winsize winsize;

	إذا (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		إذا (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		وإلا
			win_size = winsize.ws_col;
	} وإلا
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
