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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>
#अन्तर्भाव <sys/uio.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "progressmeter.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
स्थिर पूर्णाङ्क can_output(शून्य);

/* window resizing */
स्थिर शून्य sig_winch(पूर्णाङ्क);
स्थिर शून्य setscreensize(शून्य);

/* signal handler for updating the progress meter */
स्थिर शून्य sig_alarm(पूर्णाङ्क);

स्थिर द्विगुण start;		/* start progress */
स्थिर द्विगुण last_update;	/* last progress update */
स्थिर ध्रुव वर्ण *file;	/* name of the file being transferred */
स्थिर off_t start_pos;		/* initial position of transfer */
स्थिर off_t end_pos;		/* ending position of transfer */
स्थिर off_t cur_pos;		/* transfer position as of last refresh */
स्थिर चञ्चल off_t *counter;	/* progress counter */
स्थिर long stalled;		/* how long we have been stalled */
स्थिर long long bytes_per_second; /* current speed in bytes per second */
स्थिर पूर्णाङ्क win_size;		/* terminal window size */
स्थिर चञ्चल sig_atomic_t win_resized; /* for window resizing */
स्थिर चञ्चल sig_atomic_t alarm_fired;

/* units for format_size */
स्थिर ध्रुव वर्ण unit[] = " KMGT";

स्थिर पूर्णाङ्क
can_output(शून्य)
{
	प्रत्यागम (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((परिमाण(v) * 8 * 4) / 10) + 1)

स्थिर ध्रुव वर्ण *
format_rate(off_t bytes)
{
	पूर्णाङ्क i;
	स्थिर वर्ण buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	प्रति (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	जइ (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, परिमाण(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	प्रत्यागम buf;
}

स्थिर ध्रुव वर्ण *
format_size(off_t bytes)
{
	पूर्णाङ्क i;
	स्थिर वर्ण buf[STRING_SIZE(bytes) + 16];

	प्रति (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, परिमाण(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	प्रत्यागम buf;
}

शून्य
refresh_progress_meter(पूर्णाङ्क force_update)
{
	वर्ण *buf = रिक्त, *obuf = रिक्त;
	off_t transferred;
	द्विगुण elapsed, now;
	पूर्णाङ्क percent;
	off_t bytes_वामः;
	long long cur_speed;
	पूर्णाङ्क hours, minutes, seconds;
	पूर्णाङ्क file_len, cols;

	जइ (file == रिक्त || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		प्रत्यागम;
	alarm_fired = 0;

	जइ (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_वामः = end_pos - cur_pos;

	जइ (bytes_वामः > 0)
		elapsed = now - last_update;
	अण्णहा {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	जइ (elapsed != 0)
		cur_speed = (transferred / elapsed);
	अण्णहा
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	जइ (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} अण्णहा
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	जइ (win_size < 4)
		प्रत्यागम;

	/* filename */
	file_len = cols = win_size - 36;
	जइ (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		जइ (cols < file_len)
			xextendf(&buf, रिक्त, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	जइ (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	अण्णहा
		percent = ((भिन्न)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, रिक्त, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	जइ (!transferred)
		stalled += elapsed;
	अण्णहा
		stalled = 0;

	जइ (stalled >= STALL_TIME)
		xextendf(&buf, रिक्त, "- stalled -");
	अण्णहा जइ (bytes_per_second == 0 && bytes_वामः)
		xextendf(&buf, रिक्त, "  --:-- ETA");
	अण्णहा {
		जइ (bytes_वामः > 0)
			seconds = bytes_वामः / bytes_per_second;
		अण्णहा
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		जइ (hours != 0) {
			xextendf(&buf, रिक्त, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} अण्णहा
			xextendf(&buf, रिक्त, "  %02d:%02d", minutes, seconds);

		जइ (bytes_वामः > 0)
			xextendf(&buf, रिक्त, " ETA");
		अण्णहा
			xextendf(&buf, रिक्त, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	जइ (obuf != रिक्त) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
	}
	मुक्त(buf);
	मुक्त(obuf);
}

स्थिर शून्य
sig_alarm(पूर्णाङ्क ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

शून्य
start_progress_meter(ध्रुव वर्ण *f, off_t filesize, off_t *ctr)
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

शून्य
stop_progress_meter(शून्य)
{
	alarm(0);

	जइ (!can_output())
		प्रत्यागम;

	/* Ensure we complete the progress */
	जइ (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = रिक्त;
}

स्थिर शून्य
sig_winch(पूर्णाङ्क sig)
{
	win_resized = 1;
}

स्थिर शून्य
setscreensize(शून्य)
{
	संरचना winsize winsize;

	जइ (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		जइ (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		अण्णहा
			win_size = winsize.ws_col;
	} अण्णहा
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
