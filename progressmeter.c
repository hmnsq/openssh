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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/ioctl.h>
#ଅନ୍ତର୍ଭାଵ <sys/uio.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "progressmeter.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା can_output(ଶୂନ୍ୟ);

/* window resizing */
ସ୍ଥିର ଶୂନ୍ୟ sig_winch(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର ଶୂନ୍ୟ setscreensize(ଶୂନ୍ୟ);

/* signal handler for updating the progress meter */
ସ୍ଥିର ଶୂନ୍ୟ sig_alarm(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ସ୍ଥିର ଦ୍ୱିଗୁଣ start;		/* start progress */
ସ୍ଥିର ଦ୍ୱିଗୁଣ last_update;	/* last progress update */
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *file;	/* name of the file being transferred */
ସ୍ଥିର off_t start_pos;		/* initial position of transfer */
ସ୍ଥିର off_t end_pos;		/* ending position of transfer */
ସ୍ଥିର off_t cur_pos;		/* transfer position as of last refresh */
ସ୍ଥିର ଅସ୍ଥିର off_t *counter;	/* progress counter */
ସ୍ଥିର long stalled;		/* how long we have been stalled */
ସ୍ଥିର long long bytes_per_second; /* current speed in bytes per second */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା win_size;		/* terminal window size */
ସ୍ଥିର ଅସ୍ଥିର sig_atomic_t win_resized; /* for window resizing */
ସ୍ଥିର ଅସ୍ଥିର sig_atomic_t alarm_fired;

/* units for format_size */
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର unit[] = " KMGT";

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
can_output(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((ଆକାର(v) * 8 * 4) / 10) + 1)

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
format_rate(off_t bytes)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ସ୍ଥିର ଅକ୍ଷର buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	ପାଇଁ (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	ଯଦି (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, ଆକାର(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	ଫେରନ୍ତୁ buf;
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
format_size(off_t bytes)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ସ୍ଥିର ଅକ୍ଷର buf[STRING_SIZE(bytes) + 16];

	ପାଇଁ (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, ଆକାର(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	ଫେରନ୍ତୁ buf;
}

ଶୂନ୍ୟ
refresh_progress_meter(ପୂର୍ଣ୍ଣସଂଖ୍ୟା force_update)
{
	ଅକ୍ଷର *buf = ଖାଲି, *obuf = ଖାଲି;
	off_t transferred;
	ଦ୍ୱିଗୁଣ elapsed, now;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା percent;
	off_t bytes_ବାମ;
	long long cur_speed;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hours, minutes, seconds;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା file_len, cols;

	ଯଦି (file == ଖାଲି || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		ଫେରନ୍ତୁ;
	alarm_fired = 0;

	ଯଦି (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_ବାମ = end_pos - cur_pos;

	ଯଦି (bytes_ବାମ > 0)
		elapsed = now - last_update;
	ଅନ୍ୟଥା {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	ଯଦି (elapsed != 0)
		cur_speed = (transferred / elapsed);
	ଅନ୍ୟଥା
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	ଯଦି (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} ଅନ୍ୟଥା
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	ଯଦି (win_size < 4)
		ଫେରନ୍ତୁ;

	/* filename */
	file_len = cols = win_size - 36;
	ଯଦି (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		ଯଦି (cols < file_len)
			xextendf(&buf, ଖାଲି, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	ଯଦି (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	ଅନ୍ୟଥା
		percent = ((ଦଶମିକ)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, ଖାଲି, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	ଯଦି (!transferred)
		stalled += elapsed;
	ଅନ୍ୟଥା
		stalled = 0;

	ଯଦି (stalled >= STALL_TIME)
		xextendf(&buf, ଖାଲି, "- stalled -");
	ଅନ୍ୟଥା ଯଦି (bytes_per_second == 0 && bytes_ବାମ)
		xextendf(&buf, ଖାଲି, "  --:-- ETA");
	ଅନ୍ୟଥା {
		ଯଦି (bytes_ବାମ > 0)
			seconds = bytes_ବାମ / bytes_per_second;
		ଅନ୍ୟଥା
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		ଯଦି (hours != 0) {
			xextendf(&buf, ଖାଲି, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} ଅନ୍ୟଥା
			xextendf(&buf, ଖାଲି, "  %02d:%02d", minutes, seconds);

		ଯଦି (bytes_ବାମ > 0)
			xextendf(&buf, ଖାଲି, " ETA");
		ଅନ୍ୟଥା
			xextendf(&buf, ଖାଲି, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	ଯଦି (obuf != ଖାଲି) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
	}
	ମୁକ୍ତ(buf);
	ମୁକ୍ତ(obuf);
}

ସ୍ଥିର ଶୂନ୍ୟ
sig_alarm(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

ଶୂନ୍ୟ
start_progress_meter(ଅଚଳ ଅକ୍ଷର *f, off_t filesize, off_t *ctr)
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

ଶୂନ୍ୟ
stop_progress_meter(ଶୂନ୍ୟ)
{
	alarm(0);

	ଯଦି (!can_output())
		ଫେରନ୍ତୁ;

	/* Ensure we complete the progress */
	ଯଦି (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = ଖାଲି;
}

ସ୍ଥିର ଶୂନ୍ୟ
sig_winch(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	win_resized = 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
setscreensize(ଶୂନ୍ୟ)
{
	ସଂରଚନା winsize winsize;

	ଯଦି (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		ଯଦି (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		ଅନ୍ୟଥା
			win_size = winsize.ws_col;
	} ଅନ୍ୟଥା
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
