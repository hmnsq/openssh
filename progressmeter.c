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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/uio.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "progressmeter.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"

#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_WINSIZE 80
#ವ್ಯಾಖ್ಯಾನಿಸು MAX_WINSIZE 512
#ವ್ಯಾಖ್ಯಾನಿಸು UPDATE_INTERVAL 1	/* update the progress meter every second */
#ವ್ಯಾಖ್ಯಾನಿಸು STALL_ಸಮಯ 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ can_output(ಶೂನ್ಯ);

/* window resizing */
ಸ್ಥಿರ ಶೂನ್ಯ sig_winch(ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ ಶೂನ್ಯ setscreensize(ಶೂನ್ಯ);

/* signal handler for updating the progress meter */
ಸ್ಥಿರ ಶೂನ್ಯ sig_alarm(ಪೂರ್ಣಾಂಕ);

ಸ್ಥಿರ ದ್ವಿಗುಣ ಆರಂಭ;		/* start progress */
ಸ್ಥಿರ ದ್ವಿಗುಣ ಕೊನೆಯ_update;	/* last progress update */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file;	/* name of the file being transferred */
ಸ್ಥಿರ off_t ಆರಂಭ_pos;		/* initial position of transfer */
ಸ್ಥಿರ off_t ಕೊನೆ_pos;		/* ending position of transfer */
ಸ್ಥಿರ off_t cur_pos;		/* transfer position as of last refresh */
ಸ್ಥಿರ ಅಸ್ಥಿರ off_t *counter;	/* progress counter */
ಸ್ಥಿರ ದೀರ್ಘ stalled;		/* how long we have been stalled */
ಸ್ಥಿರ ದೀರ್ಘ ದೀರ್ಘ ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ; /* current speed in bytes per second */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ win_ಗಾತ್ರ;		/* terminal window size */
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t win_resized; /* for window resizing */
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t alarm_fired;

/* units for format_size */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ unit[] = " KMGT";

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
can_output(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#ವ್ಯಾಖ್ಯಾನಿಸು STRING_ಗಾತ್ರ(v) (((ಗಾತ್ರ(v) * 8 * 4) / 10) + 1)

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
format_ದರ(off_t ಬೈಟುಗಳು)
{
	ಪೂರ್ಣಾಂಕ i;
	ಸ್ಥಿರ ಅಕ್ಷರ buf[STRING_ಗಾತ್ರ(ಬೈಟುಗಳು) * 2 + 16];

	ಬೈಟುಗಳು *= 100;
	ಗಾಗಿ (i = 0; ಬೈಟುಗಳು >= 100*1000 && unit[i] != 'T'; i++)
		ಬೈಟುಗಳು = (ಬೈಟುಗಳು + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	ಆದರೆ (i == 0) {
		i++;
		ಬೈಟುಗಳು = (ಬೈಟುಗಳು + 512) / 1024;
	}
	snprintf(buf, ಗಾತ್ರ(buf), "%3lld.%1lld%cB",
	    (ದೀರ್ಘ ದೀರ್ಘ) (ಬೈಟುಗಳು + 5) / 100,
	    (ದೀರ್ಘ ದೀರ್ಘ) (ಬೈಟುಗಳು + 5) / 10 % 10,
	    unit[i]);
	ಹಿಂತಿರುಗಿ buf;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
format_ಗಾತ್ರ(off_t ಬೈಟುಗಳು)
{
	ಪೂರ್ಣಾಂಕ i;
	ಸ್ಥಿರ ಅಕ್ಷರ buf[STRING_ಗಾತ್ರ(ಬೈಟುಗಳು) + 16];

	ಗಾಗಿ (i = 0; ಬೈಟುಗಳು >= 10000 && unit[i] != 'T'; i++)
		ಬೈಟುಗಳು = (ಬೈಟುಗಳು + 512) / 1024;
	snprintf(buf, ಗಾತ್ರ(buf), "%4lld%c%s",
	    (ದೀರ್ಘ ದೀರ್ಘ) ಬೈಟುಗಳು,
	    unit[i],
	    i ? "B" : " ");
	ಹಿಂತಿರುಗಿ buf;
}

ಶೂನ್ಯ
refresh_ಪ್ರಗತಿ_meter(ಪೂರ್ಣಾಂಕ force_update)
{
	ಅಕ್ಷರ *buf = ಖಾಲಿ, *obuf = ಖಾಲಿ;
	off_t transferred;
	ದ್ವಿಗುಣ elapsed, now;
	ಪೂರ್ಣಾಂಕ percent;
	off_t ಬೈಟುಗಳು_ಎಡ;
	ದೀರ್ಘ ದೀರ್ಘ cur_ವೇಗ;
	ಪೂರ್ಣಾಂಕ hours, minutes, seconds;
	ಪೂರ್ಣಾಂಕ file_len, ಲಂಬಸಾಲು_ಸಂಖ್ಯೆ;

	ಆದರೆ (file == ಖಾಲಿ || (!force_update && !alarm_fired && !win_resized) ||
	    !can_output())
		ಹಿಂತಿರುಗಿ;
	alarm_fired = 0;

	ಆದರೆ (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : ಆರಂಭ_pos);
	cur_pos = *counter;
	now = monotime_double();
	ಬೈಟುಗಳು_ಎಡ = ಕೊನೆ_pos - cur_pos;

	ಆದರೆ (ಬೈಟುಗಳು_ಎಡ > 0)
		elapsed = now - ಕೊನೆಯ_update;
	ಇಲ್ಲದಿದ್ದರೆ {
		elapsed = now - ಆರಂಭ;
		/* Calculate true total speed when done */
		transferred = ಕೊನೆ_pos - ಆರಂಭ_pos;
		ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ = 0;
	}

	/* calculate speed */
	ಆದರೆ (elapsed != 0)
		cur_ವೇಗ = (transferred / elapsed);
	ಇಲ್ಲದಿದ್ದರೆ
		cur_ವೇಗ = transferred;

#ವ್ಯಾಖ್ಯಾನಿಸು AGE_ಗುಣಕ 0.9
	ಆದರೆ (ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ != 0) {
		ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ = (ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ * AGE_ಗುಣಕ) +
		    (cur_ವೇಗ * (1.0 - AGE_ಗುಣಕ));
	} ಇಲ್ಲದಿದ್ದರೆ
		ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ = cur_ವೇಗ;

	ಕೊನೆಯ_update = now;

	/* Don't bother if we can't even display the completion percentage */
	ಆದರೆ (win_ಗಾತ್ರ < 4)
		ಹಿಂತಿರುಗಿ;

	/* filename */
	file_len = ಲಂಬಸಾಲು_ಸಂಖ್ಯೆ = win_ಗಾತ್ರ - 36;
	ಆದರೆ (file_len > 0) {
		asmprintf(&buf, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &ಲಂಬಸಾಲು_ಸಂಖ್ಯೆ, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		ಆದರೆ (ಲಂಬಸಾಲು_ಸಂಖ್ಯೆ < file_len)
			xextendf(&buf, ಖಾಲಿ, "%*s", file_len - ಲಂಬಸಾಲು_ಸಂಖ್ಯೆ, "");
	}
	/* percent of transfer done */
	ಆದರೆ (ಕೊನೆ_pos == 0 || cur_pos == ಕೊನೆ_pos)
		percent = 100;
	ಇಲ್ಲದಿದ್ದರೆ
		percent = ((ದಶಮಾಂಶ)cur_pos / ಕೊನೆ_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, ಖಾಲಿ, " %3d%% %s %s/s ", percent, format_ಗಾತ್ರ(cur_pos),
	    format_ದರ((off_t)ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ));

	/* ETA */
	ಆದರೆ (!transferred)
		stalled += elapsed;
	ಇಲ್ಲದಿದ್ದರೆ
		stalled = 0;

	ಆದರೆ (stalled >= STALL_ಸಮಯ)
		xextendf(&buf, ಖಾಲಿ, "- stalled -");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ == 0 && ಬೈಟುಗಳು_ಎಡ)
		xextendf(&buf, ಖಾಲಿ, "  --:-- ETA");
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (ಬೈಟುಗಳು_ಎಡ > 0)
			seconds = ಬೈಟುಗಳು_ಎಡ / ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ;
		ಇಲ್ಲದಿದ್ದರೆ
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		ಆದರೆ (hours != 0) {
			xextendf(&buf, ಖಾಲಿ, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} ಇಲ್ಲದಿದ್ದರೆ
			xextendf(&buf, ಖಾಲಿ, "  %02d:%02d", minutes, seconds);

		ಆದರೆ (ಬೈಟುಗಳು_ಎಡ > 0)
			xextendf(&buf, ಖಾಲಿ, " ETA");
		ಇಲ್ಲದಿದ್ದರೆ
			xextendf(&buf, ಖಾಲಿ, "    ");
	}

	/* Finally, truncate string at window width */
	ಲಂಬಸಾಲು_ಸಂಖ್ಯೆ = win_ಗಾತ್ರ - 1;
	asmprintf(&obuf, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &ಲಂಬಸಾಲು_ಸಂಖ್ಯೆ, " %s", buf);
	ಆದರೆ (obuf != ಖಾಲಿ) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		atomicio(vwrite, STDOUT_FILENO, obuf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(obuf));
	}
	ಬಿಡುಗಡೆ(buf);
	ಬಿಡುಗಡೆ(obuf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sig_alarm(ಪೂರ್ಣಾಂಕ ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

ಶೂನ್ಯ
ಆರಂಭ_ಪ್ರಗತಿ_meter(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *f, off_t filesize, off_t *ctr)
{
	ಆರಂಭ = ಕೊನೆಯ_update = monotime_double();
	file = f;
	ಆರಂಭ_pos = *ctr;
	ಕೊನೆ_pos = filesize;
	cur_pos = 0;
	counter = ctr;
	stalled = 0;
	ಬೈಟುಗಳು_ಪ್ರತಿ_ಎರಡನೇ = 0;

	setscreensize();
	refresh_ಪ್ರಗತಿ_meter(1);

	ssh_signal(SIGALRM, sig_alarm);
	ssh_signal(SIGWINCH, sig_winch);
	alarm(UPDATE_INTERVAL);
}

ಶೂನ್ಯ
stop_ಪ್ರಗತಿ_meter(ಶೂನ್ಯ)
{
	alarm(0);

	ಆದರೆ (!can_output())
		ಹಿಂತಿರುಗಿ;

	/* Ensure we complete the progress */
	ಆದರೆ (cur_pos != ಕೊನೆ_pos)
		refresh_ಪ್ರಗತಿ_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = ಖಾಲಿ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sig_winch(ಪೂರ್ಣಾಂಕ sig)
{
	win_resized = 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
setscreensize(ಶೂನ್ಯ)
{
	ರಚನೆ winsize winsize;

	ಆದರೆ (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_ಲಂಬಸಾಲು != 0) {
		ಆದರೆ (winsize.ws_ಲಂಬಸಾಲು > MAX_WINSIZE)
			win_ಗಾತ್ರ = MAX_WINSIZE;
		ಇಲ್ಲದಿದ್ದರೆ
			win_ಗಾತ್ರ = winsize.ws_ಲಂಬಸಾಲು;
	} ಇಲ್ಲದಿದ್ದರೆ
		win_ಗಾತ್ರ = DEFAULT_WINSIZE;
	win_ಗಾತ್ರ += 1;					/* trailing \0 */
}
