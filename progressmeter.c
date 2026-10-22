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
स्थिर पूर्णांक can_output(शून्य);

/* window resizing */
स्थिर शून्य sig_winch(पूर्णांक);
स्थिर शून्य setscreensize(शून्य);

/* signal handler for updating the progress meter */
स्थिर शून्य sig_alarm(पूर्णांक);

स्थिर द्विगुण start;		/* start progress */
स्थिर द्विगुण last_update;	/* last progress update */
स्थिर स्थिरांक अक्षर *file;	/* name of the file being transferred */
स्थिर off_t start_pos;		/* initial position of transfer */
स्थिर off_t end_pos;		/* ending position of transfer */
स्थिर off_t cur_pos;		/* transfer position as of last refresh */
स्थिर अस्थिर off_t *counter;	/* progress counter */
स्थिर दीर्घ stalled;		/* how long we have been stalled */
स्थिर दीर्घ दीर्घ bytes_per_second; /* current speed in bytes per second */
स्थिर पूर्णांक win_size;		/* terminal window size */
स्थिर अस्थिर संक_पूर्ण_प्रकार win_resized; /* for window resizing */
स्थिर अस्थिर संक_पूर्ण_प्रकार alarm_fired;

/* units for format_size */
स्थिर स्थिरांक अक्षर unit[] = " KMGT";

स्थिर पूर्णांक
can_output(शून्य)
{
	परत (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((आकार(v) * 8 * 4) / 10) + 1)

स्थिर स्थिरांक अक्षर *
format_rate(off_t bytes)
{
	पूर्णांक i;
	स्थिर अक्षर buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	साठी (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	जर (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, आकार(buf), "%3lld.%1lld%cB",
	    (दीर्घ दीर्घ) (bytes + 5) / 100,
	    (दीर्घ दीर्घ) (bytes + 5) / 10 % 10,
	    unit[i]);
	परत buf;
}

स्थिर स्थिरांक अक्षर *
format_size(off_t bytes)
{
	पूर्णांक i;
	स्थिर अक्षर buf[STRING_SIZE(bytes) + 16];

	साठी (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, आकार(buf), "%4lld%c%s",
	    (दीर्घ दीर्घ) bytes,
	    unit[i],
	    i ? "B" : " ");
	परत buf;
}

शून्य
refresh_progress_meter(पूर्णांक force_update)
{
	अक्षर *buf = रिक्त, *obuf = रिक्त;
	off_t transferred;
	द्विगुण elapsed, now;
	पूर्णांक percent;
	off_t bytes_डावा;
	दीर्घ दीर्घ cur_speed;
	पूर्णांक hours, minutes, seconds;
	पूर्णांक file_len, cols;

	जर (file == रिक्त || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		परत;
	alarm_fired = 0;

	जर (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_डावा = end_pos - cur_pos;

	जर (bytes_डावा > 0)
		elapsed = now - last_update;
	अन्यथा {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	जर (elapsed != 0)
		cur_speed = (transferred / elapsed);
	अन्यथा
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	जर (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} अन्यथा
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	जर (win_size < 4)
		परत;

	/* filename */
	file_len = cols = win_size - 36;
	जर (file_len > 0) {
		asmprintf(&buf, पूर्णांक_उच्च, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		जर (cols < file_len)
			xextendf(&buf, रिक्त, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	जर (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	अन्यथा
		percent = ((दशांश)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, रिक्त, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	जर (!transferred)
		stalled += elapsed;
	अन्यथा
		stalled = 0;

	जर (stalled >= STALL_TIME)
		xextendf(&buf, रिक्त, "- stalled -");
	अन्यथा जर (bytes_per_second == 0 && bytes_डावा)
		xextendf(&buf, रिक्त, "  --:-- ETA");
	अन्यथा {
		जर (bytes_डावा > 0)
			seconds = bytes_डावा / bytes_per_second;
		अन्यथा
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		जर (hours != 0) {
			xextendf(&buf, रिक्त, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} अन्यथा
			xextendf(&buf, रिक्त, "  %02d:%02d", minutes, seconds);

		जर (bytes_डावा > 0)
			xextendf(&buf, रिक्त, " ETA");
		अन्यथा
			xextendf(&buf, रिक्त, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, पूर्णांक_उच्च, &cols, " %s", buf);
	जर (obuf != रिक्त) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, म_माप(obuf));
	}
	मुक्त(buf);
	मुक्त(obuf);
}

स्थिर शून्य
sig_alarm(पूर्णांक ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

शून्य
start_progress_meter(स्थिरांक अक्षर *f, off_t filesize, off_t *ctr)
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

	जर (!can_output())
		परत;

	/* Ensure we complete the progress */
	जर (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = रिक्त;
}

स्थिर शून्य
sig_winch(पूर्णांक sig)
{
	win_resized = 1;
}

स्थिर शून्य
setscreensize(शून्य)
{
	संरचना winsize winsize;

	जर (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		जर (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		अन्यथा
			win_size = winsize.ws_col;
	} अन्यथा
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
