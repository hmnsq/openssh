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

#تعریف_کرو DEFAULT_WINSIZE 80
#تعریف_کرو MAX_WINSIZE 512
#تعریف_کرو UPDATE_INTERVAL 1	/* update the progress meter every second */
#تعریف_کرو STALL_وقت 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
ساکن صحیح can_output(خالی);

/* window resizing */
ساکن خالی sig_winch(صحیح);
ساکن خالی setscreensize(خالی);

/* signal handler for updating the progress meter */
ساکن خالی sig_alarm(صحیح);

ساکن دوہرا آغاز;		/* start progress */
ساکن دوہرا آخری_update;	/* last progress update */
ساکن ثابت حرف *file;	/* name of the file being transferred */
ساکن off_t آغاز_pos;		/* initial position of transfer */
ساکن off_t انتہا_pos;		/* ending position of transfer */
ساکن off_t cur_pos;		/* transfer position as of last refresh */
ساکن متلون off_t *شمار_2;	/* progress counter */
ساکن طویل stalled;		/* how long we have been stalled */
ساکن طویل طویل بائٹیں_فی_دوسرا; /* current speed in bytes per second */
ساکن صحیح win_سائز;		/* terminal window size */
ساکن متلون sig_atomic_t win_resized; /* for window resizing */
ساکن متلون sig_atomic_t alarm_fired;

/* units for format_size */
ساکن ثابت حرف unit[] = " KMGT";

ساکن صحیح
can_output(خالی)
{
	واپس (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#تعریف_کرو STRING_سائز(v) (((حجم(v) * 8 * 4) / 10) + 1)

ساکن ثابت حرف *
format_شرح(off_t بائٹیں)
{
	صحیح i;
	ساکن حرف buf[STRING_سائز(بائٹیں) * 2 + 16];

	بائٹیں *= 100;
	برائے (i = 0; بائٹیں >= 100*1000 && unit[i] != 'T'; i++)
		بائٹیں = (بائٹیں + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	اگر (i == 0) {
		i++;
		بائٹیں = (بائٹیں + 512) / 1024;
	}
	snprintf(buf, حجم(buf), "%3lld.%1lld%cB",
	    (طویل طویل) (بائٹیں + 5) / 100,
	    (طویل طویل) (بائٹیں + 5) / 10 % 10,
	    unit[i]);
	واپس buf;
}

ساکن ثابت حرف *
format_سائز(off_t بائٹیں)
{
	صحیح i;
	ساکن حرف buf[STRING_سائز(بائٹیں) + 16];

	برائے (i = 0; بائٹیں >= 10000 && unit[i] != 'T'; i++)
		بائٹیں = (بائٹیں + 512) / 1024;
	snprintf(buf, حجم(buf), "%4lld%c%s",
	    (طویل طویل) بائٹیں,
	    unit[i],
	    i ? "B" : " ");
	واپس buf;
}

خالی
refresh_پیش_رفت_meter(صحیح force_update)
{
	حرف *buf = تہی, *obuf = تہی;
	off_t transferred;
	دوہرا elapsed, now;
	صحیح percent;
	off_t بائٹیں_بایاں;
	طویل طویل cur_رفتار;
	صحیح hours, minutes, seconds;
	صحیح file_len, ستون_تعداد;

	اگر (file == تہی || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		واپس;
	alarm_fired = 0;

	اگر (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *شمار_2 - (cur_pos ? cur_pos : آغاز_pos);
	cur_pos = *شمار_2;
	now = monotime_double();
	بائٹیں_بایاں = انتہا_pos - cur_pos;

	اگر (بائٹیں_بایاں > 0)
		elapsed = now - آخری_update;
	ورنہ {
		elapsed = now - آغاز;
		/* Calculate true total speed when done */
		transferred = انتہا_pos - آغاز_pos;
		بائٹیں_فی_دوسرا = 0;
	}

	/* calculate speed */
	اگر (elapsed != 0)
		cur_رفتار = (transferred / elapsed);
	ورنہ
		cur_رفتار = transferred;

#تعریف_کرو AGE_ضربی_عدد 0.9
	اگر (بائٹیں_فی_دوسرا != 0) {
		بائٹیں_فی_دوسرا = (بائٹیں_فی_دوسرا * AGE_ضربی_عدد) +
		    (cur_رفتار * (1.0 - AGE_ضربی_عدد));
	} ورنہ
		بائٹیں_فی_دوسرا = cur_رفتار;

	آخری_update = now;

	/* Don't bother if we can't even display the completion percentage */
	اگر (win_سائز < 4)
		واپس;

	/* filename */
	file_len = ستون_تعداد = win_سائز - 36;
	اگر (file_len > 0) {
		asmprintf(&buf, زیادہ_سے_زیادہ_عدد, &ستون_تعداد, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		اگر (ستون_تعداد < file_len)
			xextendf(&buf, تہی, "%*s", file_len - ستون_تعداد, "");
	}
	/* percent of transfer done */
	اگر (انتہا_pos == 0 || cur_pos == انتہا_pos)
		percent = 100;
	ورنہ
		percent = ((اعشاری)cur_pos / انتہا_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, تہی, " %3d%% %s %s/s ", percent, format_سائز(cur_pos),
	    format_شرح((off_t)بائٹیں_فی_دوسرا));

	/* ETA */
	اگر (!transferred)
		stalled += elapsed;
	ورنہ
		stalled = 0;

	اگر (stalled >= STALL_وقت)
		xextendf(&buf, تہی, "- stalled -");
	ورنہ اگر (بائٹیں_فی_دوسرا == 0 && بائٹیں_بایاں)
		xextendf(&buf, تہی, "  --:-- ETA");
	ورنہ {
		اگر (بائٹیں_بایاں > 0)
			seconds = بائٹیں_بایاں / بائٹیں_فی_دوسرا;
		ورنہ
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		اگر (hours != 0) {
			xextendf(&buf, تہی, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} ورنہ
			xextendf(&buf, تہی, "  %02d:%02d", minutes, seconds);

		اگر (بائٹیں_بایاں > 0)
			xextendf(&buf, تہی, " ETA");
		ورنہ
			xextendf(&buf, تہی, "    ");
	}

	/* Finally, truncate string at window width */
	ستون_تعداد = win_سائز - 1;
	asmprintf(&obuf, زیادہ_سے_زیادہ_عدد, &ستون_تعداد, " %s", buf);
	اگر (obuf != تہی) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, لڑی_لمبائی(obuf));
	}
	آزاد(buf);
	آزاد(obuf);
}

ساکن خالی
sig_alarm(صحیح ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

خالی
آغاز_پیش_رفت_meter(ثابت حرف *f, off_t filesize, off_t *ctr)
{
	آغاز = آخری_update = monotime_double();
	file = f;
	آغاز_pos = *ctr;
	انتہا_pos = filesize;
	cur_pos = 0;
	شمار_2 = ctr;
	stalled = 0;
	بائٹیں_فی_دوسرا = 0;

	setscreensize();
	refresh_پیش_رفت_meter(1);

	ssh_signal(SIGALRM, sig_alarm);
	ssh_signal(SIGWINCH, sig_winch);
	alarm(UPDATE_INTERVAL);
}

خالی
stop_پیش_رفت_meter(خالی)
{
	alarm(0);

	اگر (!can_output())
		واپس;

	/* Ensure we complete the progress */
	اگر (cur_pos != انتہا_pos)
		refresh_پیش_رفت_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = تہی;
}

ساکن خالی
sig_winch(صحیح sig)
{
	win_resized = 1;
}

ساکن خالی
setscreensize(خالی)
{
	ساخت winsize winsize;

	اگر (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_ستون != 0) {
		اگر (winsize.ws_ستون > MAX_WINSIZE)
			win_سائز = MAX_WINSIZE;
		ورنہ
			win_سائز = winsize.ws_ستون;
	} ورنہ
		win_سائز = DEFAULT_WINSIZE;
	win_سائز += 1;					/* trailing \0 */
}
