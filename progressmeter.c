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

#وصف_ڪريو DEFAULT_WINSIZE 80
#وصف_ڪريو MAX_WINSIZE 512
#وصف_ڪريو UPDATE_INTERVAL 1	/* update the progress meter every second */
#وصف_ڪريو STALL_وقت 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
ساكن صحيح can_output(فراغ);

/* window resizing */
ساكن فراغ sig_winch(صحيح);
ساكن فراغ setscreensize(فراغ);

/* signal handler for updating the progress meter */
ساكن فراغ sig_alarm(صحيح);

ساكن مزدوج شروعات;		/* start progress */
ساكن مزدوج آخري_update;	/* last progress update */
ساكن ثابت حرف *file;	/* name of the file being transferred */
ساكن off_t شروعات_pos;		/* initial position of transfer */
ساكن off_t پڇاڙي_pos;		/* ending position of transfer */
ساكن off_t cur_pos;		/* transfer position as of last refresh */
ساكن متطاير off_t *counter;	/* progress counter */
ساكن ڊگهو stalled;		/* how long we have been stalled */
ساكن ڊگهو ڊگهو بائيٽون_في_ٻيو; /* current speed in bytes per second */
ساكن صحيح win_سائيز;		/* terminal window size */
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
#وصف_ڪريو STRING_سائيز(v) (((حجم(v) * 8 * 4) / 10) + 1)

ساكن ثابت حرف *
format_شرح(off_t بائيٽون)
{
	صحيح i;
	ساكن حرف buf[STRING_سائيز(بائيٽون) * 2 + 16];

	بائيٽون *= 100;
	لكل (i = 0; بائيٽون >= 100*1000 && unit[i] != 'T'; i++)
		بائيٽون = (بائيٽون + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	إذا (i == 0) {
		i++;
		بائيٽون = (بائيٽون + 512) / 1024;
	}
	snprintf(buf, حجم(buf), "%3lld.%1lld%cB",
	    (ڊگهو ڊگهو) (بائيٽون + 5) / 100,
	    (ڊگهو ڊگهو) (بائيٽون + 5) / 10 % 10,
	    unit[i]);
	أرجع buf;
}

ساكن ثابت حرف *
format_سائيز(off_t بائيٽون)
{
	صحيح i;
	ساكن حرف buf[STRING_سائيز(بائيٽون) + 16];

	لكل (i = 0; بائيٽون >= 10000 && unit[i] != 'T'; i++)
		بائيٽون = (بائيٽون + 512) / 1024;
	snprintf(buf, حجم(buf), "%4lld%c%s",
	    (ڊگهو ڊگهو) بائيٽون,
	    unit[i],
	    i ? "B" : " ");
	أرجع buf;
}

فراغ
refresh_ترقي_meter(صحيح force_update)
{
	حرف *buf = عدم, *obuf = عدم;
	off_t transferred;
	مزدوج elapsed, now;
	صحيح percent;
	off_t بائيٽون_کاٻو;
	ڊگهو ڊگهو cur_رفتار;
	صحيح hours, minutes, seconds;
	صحيح file_len, کانن_ڳڻپ;

	إذا (file == عدم || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		أرجع;
	alarm_fired = 0;

	إذا (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : شروعات_pos);
	cur_pos = *counter;
	now = monotime_double();
	بائيٽون_کاٻو = پڇاڙي_pos - cur_pos;

	إذا (بائيٽون_کاٻو > 0)
		elapsed = now - آخري_update;
	وإلا {
		elapsed = now - شروعات;
		/* Calculate true total speed when done */
		transferred = پڇاڙي_pos - شروعات_pos;
		بائيٽون_في_ٻيو = 0;
	}

	/* calculate speed */
	إذا (elapsed != 0)
		cur_رفتار = (transferred / elapsed);
	وإلا
		cur_رفتار = transferred;

#وصف_ڪريو AGE_ضرب_ڪندڙ 0.9
	إذا (بائيٽون_في_ٻيو != 0) {
		بائيٽون_في_ٻيو = (بائيٽون_في_ٻيو * AGE_ضرب_ڪندڙ) +
		    (cur_رفتار * (1.0 - AGE_ضرب_ڪندڙ));
	} وإلا
		بائيٽون_في_ٻيو = cur_رفتار;

	آخري_update = now;

	/* Don't bother if we can't even display the completion percentage */
	إذا (win_سائيز < 4)
		أرجع;

	/* filename */
	file_len = کانن_ڳڻپ = win_سائيز - 36;
	إذا (file_len > 0) {
		asmprintf(&buf, وڌ_کان_وڌ_عدد, &کانن_ڳڻپ, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		إذا (کانن_ڳڻپ < file_len)
			xextendf(&buf, عدم, "%*s", file_len - کانن_ڳڻپ, "");
	}
	/* percent of transfer done */
	إذا (پڇاڙي_pos == 0 || cur_pos == پڇاڙي_pos)
		percent = 100;
	وإلا
		percent = ((عائم)cur_pos / پڇاڙي_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, عدم, " %3d%% %s %s/s ", percent, format_سائيز(cur_pos),
	    format_شرح((off_t)بائيٽون_في_ٻيو));

	/* ETA */
	إذا (!transferred)
		stalled += elapsed;
	وإلا
		stalled = 0;

	إذا (stalled >= STALL_وقت)
		xextendf(&buf, عدم, "- stalled -");
	وإلا إذا (بائيٽون_في_ٻيو == 0 && بائيٽون_کاٻو)
		xextendf(&buf, عدم, "  --:-- ETA");
	وإلا {
		إذا (بائيٽون_کاٻو > 0)
			seconds = بائيٽون_کاٻو / بائيٽون_في_ٻيو;
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

		إذا (بائيٽون_کاٻو > 0)
			xextendf(&buf, عدم, " ETA");
		وإلا
			xextendf(&buf, عدم, "    ");
	}

	/* Finally, truncate string at window width */
	کانن_ڳڻپ = win_سائيز - 1;
	asmprintf(&obuf, وڌ_کان_وڌ_عدد, &کانن_ڳڻپ, " %s", buf);
	إذا (obuf != عدم) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, لڙي_ڊيگهه(obuf));
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
شروعات_ترقي_meter(ثابت حرف *f, off_t filesize, off_t *ctr)
{
	شروعات = آخري_update = monotime_double();
	file = f;
	شروعات_pos = *ctr;
	پڇاڙي_pos = filesize;
	cur_pos = 0;
	counter = ctr;
	stalled = 0;
	بائيٽون_في_ٻيو = 0;

	setscreensize();
	refresh_ترقي_meter(1);

	ssh_signal(SIGALRM, sig_alarm);
	ssh_signal(SIGWINCH, sig_winch);
	alarm(UPDATE_INTERVAL);
}

فراغ
stop_ترقي_meter(فراغ)
{
	alarm(0);

	إذا (!can_output())
		أرجع;

	/* Ensure we complete the progress */
	إذا (cur_pos != پڇاڙي_pos)
		refresh_ترقي_meter(1);

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
	    winsize.ws_کانو != 0) {
		إذا (winsize.ws_کانو > MAX_WINSIZE)
			win_سائيز = MAX_WINSIZE;
		وإلا
			win_سائيز = winsize.ws_کانو;
	} وإلا
		win_سائيز = DEFAULT_WINSIZE;
	win_سائيز += 1;					/* trailing \0 */
}
