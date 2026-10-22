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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/ioctl.h>
#అన్తర్భావ <sys/uio.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "progressmeter.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "utf8.h"

#నిర్వచించు DEFAULT_WINSIZE 80
#నిర్వచించు MAX_WINSIZE 512
#నిర్వచించు UPDATE_INTERVAL 1	/* update the progress meter every second */
#నిర్వచించు STALL_సమయం 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
స్థిర పూర్ణాంకం can_output(శూన్య);

/* window resizing */
స్థిర శూన్య sig_winch(పూర్ణాంకం);
స్థిర శూన్య setscreensize(శూన్య);

/* signal handler for updating the progress meter */
స్థిర శూన్య sig_alarm(పూర్ణాంకం);

స్థిర ద్విగుణ ప్రారంభం;		/* start progress */
స్థిర ద్విగుణ చివరి_update;	/* last progress update */
స్థిర స్థిరరాశి అక్షరం *file;	/* name of the file being transferred */
స్థిర off_t ప్రారంభం_pos;		/* initial position of transfer */
స్థిర off_t చివర_pos;		/* ending position of transfer */
స్థిర off_t cur_pos;		/* transfer position as of last refresh */
స్థిర అస్థిర off_t *counter;	/* progress counter */
స్థిర దీర్ఘ stalled;		/* how long we have been stalled */
స్థిర దీర్ఘ దీర్ఘ బైట్లు_చొప్పున_రెండవ; /* current speed in bytes per second */
స్థిర పూర్ణాంకం win_కొలత;		/* terminal window size */
స్థిర అస్థిర sig_atomic_t win_resized; /* for window resizing */
స్థిర అస్థిర sig_atomic_t alarm_fired;

/* units for format_size */
స్థిర స్థిరరాశి అక్షరం unit[] = " KMGT";

స్థిర పూర్ణాంకం
can_output(శూన్య)
{
	తిరిగి (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#నిర్వచించు STRING_కొలత(v) (((పరిమాణం(v) * 8 * 4) / 10) + 1)

స్థిర స్థిరరాశి అక్షరం *
format_రేటు(off_t బైట్లు)
{
	పూర్ణాంకం i;
	స్థిర అక్షరం buf[STRING_కొలత(బైట్లు) * 2 + 16];

	బైట్లు *= 100;
	కొరకు (i = 0; బైట్లు >= 100*1000 && unit[i] != 'T'; i++)
		బైట్లు = (బైట్లు + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	ఒకవేళ (i == 0) {
		i++;
		బైట్లు = (బైట్లు + 512) / 1024;
	}
	snprintf(buf, పరిమాణం(buf), "%3lld.%1lld%cB",
	    (దీర్ఘ దీర్ఘ) (బైట్లు + 5) / 100,
	    (దీర్ఘ దీర్ఘ) (బైట్లు + 5) / 10 % 10,
	    unit[i]);
	తిరిగి buf;
}

స్థిర స్థిరరాశి అక్షరం *
format_కొలత(off_t బైట్లు)
{
	పూర్ణాంకం i;
	స్థిర అక్షరం buf[STRING_కొలత(బైట్లు) + 16];

	కొరకు (i = 0; బైట్లు >= 10000 && unit[i] != 'T'; i++)
		బైట్లు = (బైట్లు + 512) / 1024;
	snprintf(buf, పరిమాణం(buf), "%4lld%c%s",
	    (దీర్ఘ దీర్ఘ) బైట్లు,
	    unit[i],
	    i ? "B" : " ");
	తిరిగి buf;
}

శూన్య
refresh_పురోగతి_meter(పూర్ణాంకం force_update)
{
	అక్షరం *buf = ఖాళీ, *obuf = ఖాళీ;
	off_t transferred;
	ద్విగుణ elapsed, now;
	పూర్ణాంకం percent;
	off_t బైట్లు_ఎడమ;
	దీర్ఘ దీర్ఘ cur_వేగం;
	పూర్ణాంకం hours, minutes, seconds;
	పూర్ణాంకం file_len, నిలువుల_సంఖ్య;

	ఒకవేళ (file == ఖాళీ || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		తిరిగి;
	alarm_fired = 0;

	ఒకవేళ (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : ప్రారంభం_pos);
	cur_pos = *counter;
	now = monotime_double();
	బైట్లు_ఎడమ = చివర_pos - cur_pos;

	ఒకవేళ (బైట్లు_ఎడమ > 0)
		elapsed = now - చివరి_update;
	లేకపోతే {
		elapsed = now - ప్రారంభం;
		/* Calculate true total speed when done */
		transferred = చివర_pos - ప్రారంభం_pos;
		బైట్లు_చొప్పున_రెండవ = 0;
	}

	/* calculate speed */
	ఒకవేళ (elapsed != 0)
		cur_వేగం = (transferred / elapsed);
	లేకపోతే
		cur_వేగం = transferred;

#నిర్వచించు AGE_గుణకం 0.9
	ఒకవేళ (బైట్లు_చొప్పున_రెండవ != 0) {
		బైట్లు_చొప్పున_రెండవ = (బైట్లు_చొప్పున_రెండవ * AGE_గుణకం) +
		    (cur_వేగం * (1.0 - AGE_గుణకం));
	} లేకపోతే
		బైట్లు_చొప్పున_రెండవ = cur_వేగం;

	చివరి_update = now;

	/* Don't bother if we can't even display the completion percentage */
	ఒకవేళ (win_కొలత < 4)
		తిరిగి;

	/* filename */
	file_len = నిలువుల_సంఖ్య = win_కొలత - 36;
	ఒకవేళ (file_len > 0) {
		asmprintf(&buf, గరిష్ఠ_పూర్ణాంకం, &నిలువుల_సంఖ్య, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		ఒకవేళ (నిలువుల_సంఖ్య < file_len)
			xextendf(&buf, ఖాళీ, "%*s", file_len - నిలువుల_సంఖ్య, "");
	}
	/* percent of transfer done */
	ఒకవేళ (చివర_pos == 0 || cur_pos == చివర_pos)
		percent = 100;
	లేకపోతే
		percent = ((దశాంశం)cur_pos / చివర_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, ఖాళీ, " %3d%% %s %s/s ", percent, format_కొలత(cur_pos),
	    format_రేటు((off_t)బైట్లు_చొప్పున_రెండవ));

	/* ETA */
	ఒకవేళ (!transferred)
		stalled += elapsed;
	లేకపోతే
		stalled = 0;

	ఒకవేళ (stalled >= STALL_సమయం)
		xextendf(&buf, ఖాళీ, "- stalled -");
	లేకపోతే ఒకవేళ (బైట్లు_చొప్పున_రెండవ == 0 && బైట్లు_ఎడమ)
		xextendf(&buf, ఖాళీ, "  --:-- ETA");
	లేకపోతే {
		ఒకవేళ (బైట్లు_ఎడమ > 0)
			seconds = బైట్లు_ఎడమ / బైట్లు_చొప్పున_రెండవ;
		లేకపోతే
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		ఒకవేళ (hours != 0) {
			xextendf(&buf, ఖాళీ, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} లేకపోతే
			xextendf(&buf, ఖాళీ, "  %02d:%02d", minutes, seconds);

		ఒకవేళ (బైట్లు_ఎడమ > 0)
			xextendf(&buf, ఖాళీ, " ETA");
		లేకపోతే
			xextendf(&buf, ఖాళీ, "    ");
	}

	/* Finally, truncate string at window width */
	నిలువుల_సంఖ్య = win_కొలత - 1;
	asmprintf(&obuf, గరిష్ఠ_పూర్ణాంకం, &నిలువుల_సంఖ్య, " %s", buf);
	ఒకవేళ (obuf != ఖాళీ) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, అక్షరశ్రేణి_పొడవు(obuf));
	}
	విడుదల(buf);
	విడుదల(obuf);
}

స్థిర శూన్య
sig_alarm(పూర్ణాంకం ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

శూన్య
ప్రారంభం_పురోగతి_meter(స్థిరరాశి అక్షరం *f, off_t filesize, off_t *ctr)
{
	ప్రారంభం = చివరి_update = monotime_double();
	file = f;
	ప్రారంభం_pos = *ctr;
	చివర_pos = filesize;
	cur_pos = 0;
	counter = ctr;
	stalled = 0;
	బైట్లు_చొప్పున_రెండవ = 0;

	setscreensize();
	refresh_పురోగతి_meter(1);

	ssh_signal(SIGALRM, sig_alarm);
	ssh_signal(SIGWINCH, sig_winch);
	alarm(UPDATE_INTERVAL);
}

శూన్య
stop_పురోగతి_meter(శూన్య)
{
	alarm(0);

	ఒకవేళ (!can_output())
		తిరిగి;

	/* Ensure we complete the progress */
	ఒకవేళ (cur_pos != చివర_pos)
		refresh_పురోగతి_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = ఖాళీ;
}

స్థిర శూన్య
sig_winch(పూర్ణాంకం sig)
{
	win_resized = 1;
}

స్థిర శూన్య
setscreensize(శూన్య)
{
	నిర్మాణం winsize winsize;

	ఒకవేళ (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_నిలువు != 0) {
		ఒకవేళ (winsize.ws_నిలువు > MAX_WINSIZE)
			win_కొలత = MAX_WINSIZE;
		లేకపోతే
			win_కొలత = winsize.ws_నిలువు;
	} లేకపోతే
		win_కొలత = DEFAULT_WINSIZE;
	win_కొలత += 1;					/* trailing \0 */
}
