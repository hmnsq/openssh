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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/ioctl.h>
#அந்தர்பாவ <sys/uio.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "progressmeter.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
நிலையான முழு can_output(வெறுமை);

/* window resizing */
நிலையான வெறுமை sig_winch(முழு);
நிலையான வெறுமை setscreensize(வெறுமை);

/* signal handler for updating the progress meter */
நிலையான வெறுமை sig_alarm(முழு);

நிலையான இரட்டை start;		/* start progress */
நிலையான இரட்டை last_update;	/* last progress update */
நிலையான மாறிலி எழுத்து *file;	/* name of the file being transferred */
நிலையான off_t start_pos;		/* initial position of transfer */
நிலையான off_t end_pos;		/* ending position of transfer */
நிலையான off_t cur_pos;		/* transfer position as of last refresh */
நிலையான நிலையற்ற off_t *counter;	/* progress counter */
நிலையான long stalled;		/* how long we have been stalled */
நிலையான long long bytes_per_second; /* current speed in bytes per second */
நிலையான முழு win_size;		/* terminal window size */
நிலையான நிலையற்ற sig_atomic_t win_resized; /* for window resizing */
நிலையான நிலையற்ற sig_atomic_t alarm_fired;

/* units for format_size */
நிலையான மாறிலி எழுத்து unit[] = " KMGT";

நிலையான முழு
can_output(வெறுமை)
{
	திரும்பு (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((அளவு(v) * 8 * 4) / 10) + 1)

நிலையான மாறிலி எழுத்து *
format_rate(off_t bytes)
{
	முழு i;
	நிலையான எழுத்து buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	க்கு (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	எனில் (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, அளவு(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	திரும்பு buf;
}

நிலையான மாறிலி எழுத்து *
format_size(off_t bytes)
{
	முழு i;
	நிலையான எழுத்து buf[STRING_SIZE(bytes) + 16];

	க்கு (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, அளவு(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	திரும்பு buf;
}

வெறுமை
refresh_progress_meter(முழு force_update)
{
	எழுத்து *buf = வெற்று, *obuf = வெற்று;
	off_t transferred;
	இரட்டை elapsed, now;
	முழு percent;
	off_t bytes_இடது;
	long long cur_speed;
	முழு hours, minutes, seconds;
	முழு file_len, cols;

	எனில் (file == வெற்று || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		திரும்பு;
	alarm_fired = 0;

	எனில் (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_இடது = end_pos - cur_pos;

	எனில் (bytes_இடது > 0)
		elapsed = now - last_update;
	இல்லையெனில் {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	எனில் (elapsed != 0)
		cur_speed = (transferred / elapsed);
	இல்லையெனில்
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	எனில் (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} இல்லையெனில்
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	எனில் (win_size < 4)
		திரும்பு;

	/* filename */
	file_len = cols = win_size - 36;
	எனில் (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		எனில் (cols < file_len)
			xextendf(&buf, வெற்று, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	எனில் (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	இல்லையெனில்
		percent = ((தசம)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, வெற்று, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	எனில் (!transferred)
		stalled += elapsed;
	இல்லையெனில்
		stalled = 0;

	எனில் (stalled >= STALL_TIME)
		xextendf(&buf, வெற்று, "- stalled -");
	இல்லையெனில் எனில் (bytes_per_second == 0 && bytes_இடது)
		xextendf(&buf, வெற்று, "  --:-- ETA");
	இல்லையெனில் {
		எனில் (bytes_இடது > 0)
			seconds = bytes_இடது / bytes_per_second;
		இல்லையெனில்
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		எனில் (hours != 0) {
			xextendf(&buf, வெற்று, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} இல்லையெனில்
			xextendf(&buf, வெற்று, "  %02d:%02d", minutes, seconds);

		எனில் (bytes_இடது > 0)
			xextendf(&buf, வெற்று, " ETA");
		இல்லையெனில்
			xextendf(&buf, வெற்று, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	எனில் (obuf != வெற்று) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
	}
	விடுவி(buf);
	விடுவி(obuf);
}

நிலையான வெறுமை
sig_alarm(முழு ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

வெறுமை
start_progress_meter(மாறிலி எழுத்து *f, off_t filesize, off_t *ctr)
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

வெறுமை
stop_progress_meter(வெறுமை)
{
	alarm(0);

	எனில் (!can_output())
		திரும்பு;

	/* Ensure we complete the progress */
	எனில் (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = வெற்று;
}

நிலையான வெறுமை
sig_winch(முழு sig)
{
	win_resized = 1;
}

நிலையான வெறுமை
setscreensize(வெறுமை)
{
	கட்டமைப்பு winsize winsize;

	எனில் (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		எனில் (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		இல்லையெனில்
			win_size = winsize.ws_col;
	} இல்லையெனில்
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
