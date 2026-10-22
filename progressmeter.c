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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "progressmeter.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "utf8.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_WINSIZE 80
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_WINSIZE 512
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ UPDATE_INTERVAL 1	/* update the progress meter every second */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ STALL_ਸਮਾਂ 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
ਸਥਿਰ ਪੂਰਨ can_output(ਖਾਲੀ);

/* window resizing */
ਸਥਿਰ ਖਾਲੀ sig_winch(ਪੂਰਨ);
ਸਥਿਰ ਖਾਲੀ setscreensize(ਖਾਲੀ);

/* signal handler for updating the progress meter */
ਸਥਿਰ ਖਾਲੀ sig_alarm(ਪੂਰਨ);

ਸਥਿਰ ਦੁੱਗਣਾ ਸ਼ੁਰੂ;		/* start progress */
ਸਥਿਰ ਦੁੱਗਣਾ ਆਖਰੀ_update;	/* last progress update */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *file;	/* name of the file being transferred */
ਸਥਿਰ off_t ਸ਼ੁਰੂ_pos;		/* initial position of transfer */
ਸਥਿਰ off_t ਸਿਰਾ_pos;		/* ending position of transfer */
ਸਥਿਰ off_t cur_pos;		/* transfer position as of last refresh */
ਸਥਿਰ ਅਸਥਿਰ off_t *counter;	/* progress counter */
ਸਥਿਰ ਲੰਮਾ stalled;		/* how long we have been stalled */
ਸਥਿਰ ਲੰਮਾ ਲੰਮਾ ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ; /* current speed in bytes per second */
ਸਥਿਰ ਪੂਰਨ win_ਮਾਪ;		/* terminal window size */
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t win_resized; /* for window resizing */
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t alarm_fired;

/* units for format_size */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ unit[] = " KMGT";

ਸਥਿਰ ਪੂਰਨ
can_output(ਖਾਲੀ)
{
	ਵਾਪਸ (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ STRING_ਮਾਪ(v) (((ਆਕਾਰ(v) * 8 * 4) / 10) + 1)

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
format_ਦਰ(off_t ਬਾਈਟਾਂ)
{
	ਪੂਰਨ i;
	ਸਥਿਰ ਅੱਖਰ buf[STRING_ਮਾਪ(ਬਾਈਟਾਂ) * 2 + 16];

	ਬਾਈਟਾਂ *= 100;
	ਲਈ (i = 0; ਬਾਈਟਾਂ >= 100*1000 && unit[i] != 'T'; i++)
		ਬਾਈਟਾਂ = (ਬਾਈਟਾਂ + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	ਜੇ (i == 0) {
		i++;
		ਬਾਈਟਾਂ = (ਬਾਈਟਾਂ + 512) / 1024;
	}
	snprintf(buf, ਆਕਾਰ(buf), "%3lld.%1lld%cB",
	    (ਲੰਮਾ ਲੰਮਾ) (ਬਾਈਟਾਂ + 5) / 100,
	    (ਲੰਮਾ ਲੰਮਾ) (ਬਾਈਟਾਂ + 5) / 10 % 10,
	    unit[i]);
	ਵਾਪਸ buf;
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
format_ਮਾਪ(off_t ਬਾਈਟਾਂ)
{
	ਪੂਰਨ i;
	ਸਥਿਰ ਅੱਖਰ buf[STRING_ਮਾਪ(ਬਾਈਟਾਂ) + 16];

	ਲਈ (i = 0; ਬਾਈਟਾਂ >= 10000 && unit[i] != 'T'; i++)
		ਬਾਈਟਾਂ = (ਬਾਈਟਾਂ + 512) / 1024;
	snprintf(buf, ਆਕਾਰ(buf), "%4lld%c%s",
	    (ਲੰਮਾ ਲੰਮਾ) ਬਾਈਟਾਂ,
	    unit[i],
	    i ? "B" : " ");
	ਵਾਪਸ buf;
}

ਖਾਲੀ
refresh_ਤਰੱਕੀ_meter(ਪੂਰਨ force_update)
{
	ਅੱਖਰ *buf = ਨਿਰਾ, *obuf = ਨਿਰਾ;
	off_t transferred;
	ਦੁੱਗਣਾ elapsed, now;
	ਪੂਰਨ percent;
	off_t ਬਾਈਟਾਂ_ਖੱਬਾ;
	ਲੰਮਾ ਲੰਮਾ cur_ਰਫਤਾਰ;
	ਪੂਰਨ hours, minutes, seconds;
	ਪੂਰਨ file_len, ਖਾਨੇ_ਗਿਣਤੀ;

	ਜੇ (file == ਨਿਰਾ || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		ਵਾਪਸ;
	alarm_fired = 0;

	ਜੇ (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : ਸ਼ੁਰੂ_pos);
	cur_pos = *counter;
	now = monotime_double();
	ਬਾਈਟਾਂ_ਖੱਬਾ = ਸਿਰਾ_pos - cur_pos;

	ਜੇ (ਬਾਈਟਾਂ_ਖੱਬਾ > 0)
		elapsed = now - ਆਖਰੀ_update;
	ਨਹੀਂਤਾਂ {
		elapsed = now - ਸ਼ੁਰੂ;
		/* Calculate true total speed when done */
		transferred = ਸਿਰਾ_pos - ਸ਼ੁਰੂ_pos;
		ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ = 0;
	}

	/* calculate speed */
	ਜੇ (elapsed != 0)
		cur_ਰਫਤਾਰ = (transferred / elapsed);
	ਨਹੀਂਤਾਂ
		cur_ਰਫਤਾਰ = transferred;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AGE_ਗੁਣਕ 0.9
	ਜੇ (ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ != 0) {
		ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ = (ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ * AGE_ਗੁਣਕ) +
		    (cur_ਰਫਤਾਰ * (1.0 - AGE_ਗੁਣਕ));
	} ਨਹੀਂਤਾਂ
		ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ = cur_ਰਫਤਾਰ;

	ਆਖਰੀ_update = now;

	/* Don't bother if we can't even display the completion percentage */
	ਜੇ (win_ਮਾਪ < 4)
		ਵਾਪਸ;

	/* filename */
	file_len = ਖਾਨੇ_ਗਿਣਤੀ = win_ਮਾਪ - 36;
	ਜੇ (file_len > 0) {
		asmprintf(&buf, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &ਖਾਨੇ_ਗਿਣਤੀ, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		ਜੇ (ਖਾਨੇ_ਗਿਣਤੀ < file_len)
			xextendf(&buf, ਨਿਰਾ, "%*s", file_len - ਖਾਨੇ_ਗਿਣਤੀ, "");
	}
	/* percent of transfer done */
	ਜੇ (ਸਿਰਾ_pos == 0 || cur_pos == ਸਿਰਾ_pos)
		percent = 100;
	ਨਹੀਂਤਾਂ
		percent = ((ਦਸ਼ਮਲਵ)cur_pos / ਸਿਰਾ_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, ਨਿਰਾ, " %3d%% %s %s/s ", percent, format_ਮਾਪ(cur_pos),
	    format_ਦਰ((off_t)ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ));

	/* ETA */
	ਜੇ (!transferred)
		stalled += elapsed;
	ਨਹੀਂਤਾਂ
		stalled = 0;

	ਜੇ (stalled >= STALL_ਸਮਾਂ)
		xextendf(&buf, ਨਿਰਾ, "- stalled -");
	ਨਹੀਂਤਾਂ ਜੇ (ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ == 0 && ਬਾਈਟਾਂ_ਖੱਬਾ)
		xextendf(&buf, ਨਿਰਾ, "  --:-- ETA");
	ਨਹੀਂਤਾਂ {
		ਜੇ (ਬਾਈਟਾਂ_ਖੱਬਾ > 0)
			seconds = ਬਾਈਟਾਂ_ਖੱਬਾ / ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ;
		ਨਹੀਂਤਾਂ
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		ਜੇ (hours != 0) {
			xextendf(&buf, ਨਿਰਾ, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} ਨਹੀਂਤਾਂ
			xextendf(&buf, ਨਿਰਾ, "  %02d:%02d", minutes, seconds);

		ਜੇ (ਬਾਈਟਾਂ_ਖੱਬਾ > 0)
			xextendf(&buf, ਨਿਰਾ, " ETA");
		ਨਹੀਂਤਾਂ
			xextendf(&buf, ਨਿਰਾ, "    ");
	}

	/* Finally, truncate string at window width */
	ਖਾਨੇ_ਗਿਣਤੀ = win_ਮਾਪ - 1;
	asmprintf(&obuf, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &ਖਾਨੇ_ਗਿਣਤੀ, " %s", buf);
	ਜੇ (obuf != ਨਿਰਾ) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, ਲੜੀ_ਲੰਬਾਈ(obuf));
	}
	ਮੁਕਤ(buf);
	ਮੁਕਤ(obuf);
}

ਸਥਿਰ ਖਾਲੀ
sig_alarm(ਪੂਰਨ ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

ਖਾਲੀ
ਸ਼ੁਰੂ_ਤਰੱਕੀ_meter(ਅਚਲ ਅੱਖਰ *f, off_t filesize, off_t *ctr)
{
	ਸ਼ੁਰੂ = ਆਖਰੀ_update = monotime_double();
	file = f;
	ਸ਼ੁਰੂ_pos = *ctr;
	ਸਿਰਾ_pos = filesize;
	cur_pos = 0;
	counter = ctr;
	stalled = 0;
	ਬਾਈਟਾਂ_ਪ੍ਰਤੀ_ਦੂਜਾ = 0;

	setscreensize();
	refresh_ਤਰੱਕੀ_meter(1);

	ssh_signal(SIGALRM, sig_alarm);
	ssh_signal(SIGWINCH, sig_winch);
	alarm(UPDATE_INTERVAL);
}

ਖਾਲੀ
stop_ਤਰੱਕੀ_meter(ਖਾਲੀ)
{
	alarm(0);

	ਜੇ (!can_output())
		ਵਾਪਸ;

	/* Ensure we complete the progress */
	ਜੇ (cur_pos != ਸਿਰਾ_pos)
		refresh_ਤਰੱਕੀ_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = ਨਿਰਾ;
}

ਸਥਿਰ ਖਾਲੀ
sig_winch(ਪੂਰਨ sig)
{
	win_resized = 1;
}

ਸਥਿਰ ਖਾਲੀ
setscreensize(ਖਾਲੀ)
{
	ਬਣਤਰ winsize winsize;

	ਜੇ (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_ਖਾਨਾ != 0) {
		ਜੇ (winsize.ws_ਖਾਨਾ > MAX_WINSIZE)
			win_ਮਾਪ = MAX_WINSIZE;
		ਨਹੀਂਤਾਂ
			win_ਮਾਪ = winsize.ws_ਖਾਨਾ;
	} ਨਹੀਂਤਾਂ
		win_ਮਾਪ = DEFAULT_WINSIZE;
	win_ਮਾਪ += 1;					/* trailing \0 */
}
