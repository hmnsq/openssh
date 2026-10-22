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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/ioctl.h>
#समावेश <sys/uio.h>

#समावेश <errno.h>
#समावेश <limits.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>

#समावेश "progressmeter.h"
#समावेश "atomicio.h"
#समावेश "misc.h"
#समावेश "utf8.h"

#घोषणा DEFAULT_WINSIZE 80
#घोषणा MAX_WINSIZE 512
#घोषणा UPDATE_INTERVAL 1	/* update the progress meter every second */
#घोषणा STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
अटल पूर्णांक can_output(व्योम);

/* window resizing */
अटल व्योम sig_winch(पूर्णांक);
अटल व्योम setscreensize(व्योम);

/* signal handler for updating the progress meter */
अटल व्योम sig_alarm(पूर्णांक);

अटल द्विगुन start;		/* start progress */
अटल द्विगुन last_update;	/* last progress update */
अटल स्थिर अक्षर *file;	/* name of the file being transferred */
अटल off_t start_pos;		/* initial position of transfer */
अटल off_t end_pos;		/* ending position of transfer */
अटल off_t cur_pos;		/* transfer position as of last refresh */
अटल अस्थिर off_t *गणक;	/* progress counter */
अटल दीर्घ stalled;		/* how long we have been stalled */
अटल दीर्घ दीर्घ bytes_per_second; /* current speed in bytes per second */
अटल पूर्णांक win_आकार;		/* terminal window size */
अटल अस्थिर संक_पूर्ण_प्रकार win_resized; /* for window resizing */
अटल अस्थिर संक_पूर्ण_प्रकार alarm_fired;

/* units for format_size */
अटल स्थिर अक्षर unit[] = " KMGT";

अटल पूर्णांक
can_output(व्योम)
{
	वापस (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#घोषणा STRING_आकार(v) (((माप(v) * 8 * 4) / 10) + 1)

अटल स्थिर अक्षर *
format_rate(off_t bytes)
{
	पूर्णांक i;
	अटल अक्षर buf[STRING_आकार(bytes) * 2 + 16];

	bytes *= 100;
	क्रम (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	अगर (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, माप(buf), "%3lld.%1lld%cB",
	    (दीर्घ दीर्घ) (bytes + 5) / 100,
	    (दीर्घ दीर्घ) (bytes + 5) / 10 % 10,
	    unit[i]);
	वापस buf;
}

अटल स्थिर अक्षर *
format_आकार(off_t bytes)
{
	पूर्णांक i;
	अटल अक्षर buf[STRING_आकार(bytes) + 16];

	क्रम (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, माप(buf), "%4lld%c%s",
	    (दीर्घ दीर्घ) bytes,
	    unit[i],
	    i ? "B" : " ");
	वापस buf;
}

व्योम
refresh_progress_meter(पूर्णांक force_update)
{
	अक्षर *buf = शून्य, *obuf = शून्य;
	off_t transferred;
	द्विगुन elapsed, now;
	पूर्णांक percent;
	off_t bytes_बायाँ;
	दीर्घ दीर्घ cur_speed;
	पूर्णांक hours, minutes, seconds;
	पूर्णांक file_len, cols;

	अगर (file == शून्य || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		वापस;
	alarm_fired = 0;

	अगर (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *गणक - (cur_pos ? cur_pos : start_pos);
	cur_pos = *गणक;
	now = monotime_double();
	bytes_बायाँ = end_pos - cur_pos;

	अगर (bytes_बायाँ > 0)
		elapsed = now - last_update;
	अन्यथा {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	अगर (elapsed != 0)
		cur_speed = (transferred / elapsed);
	अन्यथा
		cur_speed = transferred;

#घोषणा AGE_FACTOR 0.9
	अगर (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} अन्यथा
		bytes_per_second = cur_speed;

	last_update = now;

	/* Don't bother if we can't even display the completion percentage */
	अगर (win_आकार < 4)
		वापस;

	/* filename */
	file_len = cols = win_आकार - 36;
	अगर (file_len > 0) {
		asmprintf(&buf, पूर्णांक_उच्च, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		अगर (cols < file_len)
			xextendf(&buf, शून्य, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	अगर (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	अन्यथा
		percent = ((भग्न)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, शून्य, " %3d%% %s %s/s ", percent, format_आकार(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* ETA */
	अगर (!transferred)
		stalled += elapsed;
	अन्यथा
		stalled = 0;

	अगर (stalled >= STALL_TIME)
		xextendf(&buf, शून्य, "- stalled -");
	अन्यथा अगर (bytes_per_second == 0 && bytes_बायाँ)
		xextendf(&buf, शून्य, "  --:-- ETA");
	अन्यथा {
		अगर (bytes_बायाँ > 0)
			seconds = bytes_बायाँ / bytes_per_second;
		अन्यथा
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		अगर (hours != 0) {
			xextendf(&buf, शून्य, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} अन्यथा
			xextendf(&buf, शून्य, "  %02d:%02d", minutes, seconds);

		अगर (bytes_बायाँ > 0)
			xextendf(&buf, शून्य, " ETA");
		अन्यथा
			xextendf(&buf, शून्य, "    ");
	}

	/* Finally, truncate string at window width */
	cols = win_आकार - 1;
	asmprintf(&obuf, पूर्णांक_उच्च, &cols, " %s", buf);
	अगर (obuf != शून्य) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, म_माप(obuf));
	}
	मुक्त(buf);
	मुक्त(obuf);
}

अटल व्योम
sig_alarm(पूर्णांक ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

व्योम
start_progress_meter(स्थिर अक्षर *f, off_t filesize, off_t *ctr)
{
	start = last_update = monotime_double();
	file = f;
	start_pos = *ctr;
	end_pos = filesize;
	cur_pos = 0;
	गणक = ctr;
	stalled = 0;
	bytes_per_second = 0;

	setscreensize();
	refresh_progress_meter(1);

	ssh_signal(SIGALRM, sig_alarm);
	ssh_signal(SIGWINCH, sig_winch);
	alarm(UPDATE_INTERVAL);
}

व्योम
stop_progress_meter(व्योम)
{
	alarm(0);

	अगर (!can_output())
		वापस;

	/* Ensure we complete the progress */
	अगर (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = शून्य;
}

अटल व्योम
sig_winch(पूर्णांक sig)
{
	win_resized = 1;
}

अटल व्योम
setscreensize(व्योम)
{
	काष्ठा winsize winsize;

	अगर (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		अगर (winsize.ws_col > MAX_WINSIZE)
			win_आकार = MAX_WINSIZE;
		अन्यथा
			win_आकार = winsize.ws_col;
	} अन्यथा
		win_आकार = DEFAULT_WINSIZE;
	win_आकार += 1;					/* trailing \0 */
}
