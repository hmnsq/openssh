/* $OpenBSD: clientloop.c,v 1.427 2026/09/16 23:26:41 jsg Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The main loop for the interactive session (client side).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
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
 *
 *
 * SSH2 support added by Markus Friedl.
 * Copyright (c) 1999, 2000, 2001 Markus Friedl.  All rights reserved.
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
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"
#ಅನ್ತರ್ಭಾವ "clientloop.h"
#ಅನ್ತರ್ಭಾವ "sshconnect.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#ವ್ಯಾಖ್ಯಾನಿಸು HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEYSTROKE_TIMING_FUZZ 10

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

/* import options */
ಬಾಹ್ಯ Options options;

/* Control socket */
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
ಬಾಹ್ಯ ಅಕ್ಷರ *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
ಬಾಹ್ಯ ಅಕ್ಷರ *forward_agent_sock_ಮಾರ್ಗ;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t received_ಕಿಟಕಿ_change_signal = 0;
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t siginfo_received = 0;
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
ಸ್ಥಿರ time_t control_persist_exit_ಸಮಯ = 0;

/* Common data for the client loop code. */
ಅಸ್ಥಿರ sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಕೊನೆಯ_was_cr;		/* Last character was a newline. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ exit_ಸ್ಥಿತಿ;		/* Used to store the command exit status. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ connection_ಒಳ;	/* Connection to server (input). */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ connection_ಹೊರಹೋಗು;	/* Connection to server (output). */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ need_rekeying;	/* Set to non-zero if rekeying is requested. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ session_closed;	/* In SSH2: login session closed. */
ಸ್ಥಿರ time_t x11_refuse_ಸಮಯ;	/* If >0, refuse x11 opens after this time. */
ಸ್ಥಿರ time_t server_alive_ಸಮಯ;	/* Time to do server_alive_check */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ hostkeys_update_complete;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ session_ಸಿದ್ಧತೆ_complete;

ಸ್ಥಿರ ಶೂನ್ಯ client_init_dispatch(ರಚನೆ ssh *ssh);
ಪೂರ್ಣಾಂಕ	session_ident = -1;

/* Track escape per proto2 channel */
ರಚನೆ escape_filter_ctx {
	ಪೂರ್ಣಾಂಕ escape_pending;
	ಪೂರ್ಣಾಂಕ escape_char;
};

/* Context for channel confirmation replies */
ರಚನೆ channel_ಉತ್ತರ_ctx {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *request_type;
	ಪೂರ್ಣಾಂಕ id;
	ಎಣಿಕೆ confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
ರಚನೆ global_confirm {
	TAILQ_ENTRY(global_confirm) ನಮೂದು;
	global_confirm_cb *cb;
	ಶೂನ್ಯ *ctx;
	ಪೂರ್ಣಾಂಕ ref_ಎಣಿಕೆ;
};
TAILQ_HEAD(global_confirms, global_confirm);
ಸ್ಥಿರ ರಚನೆ global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

ಸ್ಥಿರ ಶೂನ್ಯ quit_ಸಂದೇಶ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
    __attribute__((__format__ (ಬರೆ, 1, 2)));

ಸ್ಥಿರ ಶೂನ್ಯ
quit_ಸಂದೇಶ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	ಅಕ್ಷರ *ಸಂದೇಶ, *fmt2;
	va_list ವಾದಗಳು;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(ವಾದಗಳು, fmt);
	xvasprintf(&ಸಂದೇಶ, fmt2, ವಾದಗಳು);
	va_end(ವಾದಗಳು);

	(ಶೂನ್ಯ)atomicio(vwrite, STDERR_FILENO, ಸಂದೇಶ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಂದೇಶ));
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);
	ಬಿಡುಗಡೆ(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
ಕಿಟಕಿ_change_handler(ಪೂರ್ಣಾಂಕ sig)
{
	received_ಕಿಟಕಿ_change_signal = 1;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
/* Signal handler for SIGINFO */
ಸ್ಥಿರ ಶೂನ್ಯ
siginfo_handler(ಪೂರ್ಣಾಂಕ sig)
{
	siginfo_received = 1;
}
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
signal_handler(ಪೂರ್ಣಾಂಕ sig)
{
	received_signal = sig;
	quit_pending = 1;
}

/*
 * Sets control_persist_exit_time to the absolute time when the
 * backgrounded control master should exit due to expiry of the
 * ControlPersist timeout.  Sets it to 0 if we are not a backgrounded
 * control master process, or if there is no ControlPersist timeout.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
ಗಣ_control_persist_exit_ಸಮಯ(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_ಸಮಯ = 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (channel_still_open(ssh)) {
		/* some client connections are still open */
		ಆದರೆ (control_persist_exit_ಸಮಯ > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_ಸಮಯ = 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (control_persist_exit_ಸಮಯ <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_ಸಮಯ = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
client_x11_display_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *display)
{
	ಗಾತ್ರ_t i, dlen;

	ಆದರೆ (display == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	dlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(display);
	ಗಾಗಿ (i = 0; i < dlen; i++) {
		ಆದರೆ (!ಅಕ್ಷರವೇ_ಅಂಕಿಯೇ((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == ಖಾಲಿ) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			ಹಿಂತಿರುಗಿ 0;
		}
	}
	ಹಿಂತಿರುಗಿ 1;
}

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#ವ್ಯಾಖ್ಯಾನಿಸು X11_TIMEOUT_SLACK	60
ಪೂರ್ಣಾಂಕ
client_x11_get_proto(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *display,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *xauth_ಮಾರ್ಗ, u_int trusted, u_int timeout,
    ಅಕ್ಷರ **_proto, ಅಕ್ಷರ **ದತ್ತಾಂಶ_2)
{
	ಅಕ್ಷರ *cmd, ಸಾಲು[512], xdisplay[512];
	ಅಕ್ಷರ xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	ಸ್ಥಿರ ಅಕ್ಷರ proto[512], ದತ್ತಾಂಶ[512];
	FILE *f;
	ಪೂರ್ಣಾಂಕ got_ದತ್ತಾಂಶ = 0, generated = 0, do_unlink = 0, r;
	ರಚನೆ stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*ದತ್ತಾಂಶ_2 = ದತ್ತಾಂಶ;
	proto[0] = ದತ್ತಾಂಶ[0] = xauthfile[0] = xauthdir[0] = '\0';

	ಆದರೆ (!client_x11_display_valid(display)) {
		ಆದರೆ (display != ಖಾಲಿ)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (xauth_ಮಾರ್ಗ != ಖಾಲಿ && stat(xauth_ಮಾರ್ಗ, &st) == -1) {
		debug("No xauth program.");
		xauth_ಮಾರ್ಗ = ಖಾಲಿ;
	}

	ಆದರೆ (xauth_ಮಾರ್ಗ != ಖಾಲಿ) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(display, "localhost:", 10) == 0) {
			ಆದರೆ ((r = snprintf(xdisplay, ಗಾತ್ರ(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (ಗಾತ್ರ_t)r >= ಗಾತ್ರ(xdisplay)) {
				error_f("display name too long");
				ಹಿಂತಿರುಗಿ -1;
			}
			display = xdisplay;
		}
		ಆದರೆ (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, ಗಾತ್ರ(xauthdir));
			ಆದರೆ (mkdtemp(xauthdir) == ಖಾಲಿ) {
				error_f("mkdtemp: %s", strerror(errno));
				ಹಿಂತಿರುಗಿ -1;
			}
			do_unlink = 1;
			ಆದರೆ ((r = snprintf(xauthfile, ಗಾತ್ರ(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (ಗಾತ್ರ_t)r >= ಗಾತ್ರ(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				ಹಿಂತಿರುಗಿ -1;
			}

			ಆದರೆ (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_ಮಾರ್ಗ, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} ಇಲ್ಲದಿದ್ದರೆ {
				/* Add some slack to requested expiry */
				ಆದರೆ (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				ಇಲ್ಲದಿದ್ದರೆ {
					/* Don't overflow on long timeouts */
					x11_timeout_real = UINT_MAX;
				}
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted timeout %u 2>%s",
				    xauth_ಮಾರ್ಗ, xauthfile, display,
				    SSH_X11_PROTO, x11_timeout_real,
				    _PATH_DEVNULL);
			}
			debug2_f("xauth command: %s", cmd);

			ಆದರೆ (timeout != 0 && x11_refuse_ಸಮಯ == 0) {
				now = monotime() + 1;
				ಆದರೆ (SSH_ಸಮಯ_T_MAX - timeout < now)
					x11_refuse_ಸಮಯ = SSH_ಸಮಯ_T_MAX;
				ಇಲ್ಲದಿದ್ದರೆ
					x11_refuse_ಸಮಯ = now + timeout;
				channel_ಗಣ_x11_refuse_ಸಮಯ(ssh,
				    x11_refuse_ಸಮಯ);
			}
			ಆದರೆ (system(cmd) == 0)
				generated = 1;
			ಬಿಡುಗಡೆ(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		ಆದರೆ (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_ಮಾರ್ಗ,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			ಆದರೆ (f && fgets(ಸಾಲು, ಗಾತ್ರ(ಸಾಲು), f) &&
			    ಅಕ್ಷರಸರಣಿ_ಓದು(ಸಾಲು, "%*s %511s %511s", proto, ದತ್ತಾಂಶ) == 2)
				got_ದತ್ತಾಂಶ = 1;
			ಆದರೆ (f)
				pclose(f);
			ಬಿಡುಗಡೆ(cmd);
		}
	}

	ಆದರೆ (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	ಆದರೆ (!trusted && !got_ದತ್ತಾಂಶ) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		ಹಿಂತಿರುಗಿ -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	ಆದರೆ (!got_ದತ್ತಾಂಶ) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, ಗಾತ್ರ proto);
		arc4random_buf(rnd, ಗಾತ್ರ(rnd));
		ಗಾಗಿ (i = 0; i < ಗಾತ್ರ(rnd); i++) {
			snprintf(ದತ್ತಾಂಶ + 2 * i, ಗಾತ್ರ ದತ್ತಾಂಶ - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

ಸ್ಥಿರ ಶೂನ್ಯ
client_check_ಕಿಟಕಿ_change(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (!received_ಕಿಟಕಿ_change_signal)
		ಹಿಂತಿರುಗಿ;
	received_ಕಿಟಕಿ_change_signal = 0;
	debug2_f("changed");
	channel_send_ಕಿಟಕಿ_changes(ssh);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
client_global_request_ಉತ್ತರ(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ global_confirm *gc;

	ಆದರೆ ((gc = TAILQ_FIRST(&global_confirms)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (gc->cb != ಖಾಲಿ)
		gc->cb(ssh, type, seq, gc->ctx);
	ಆದರೆ (--gc->ref_ಎಣಿಕೆ <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, ನಮೂದು);
		freezero(gc, ಗಾತ್ರ(*gc));
	}

	ssh_packet_ಗಣ_alive_timeouts(ssh, 0);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ವೇಳಾಪಟ್ಟಿ_server_alive_check(ಶೂನ್ಯ)
{
	ಆದರೆ (options.server_alive_interval > 0)
		server_alive_ಸಮಯ = monotime() + options.server_alive_interval;
}

ಸ್ಥಿರ ಶೂನ್ಯ
server_alive_check(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_ಎಣಿಕೆ_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_ರಿಜಿಸ್ಟರ್_global_confirm(ಖಾಲಿ, ಖಾಲಿ);
	ವೇಳಾಪಟ್ಟಿ_server_alive_check();
}

/* Try to send a dummy keystroke */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
send_chaff(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ssh->kex == ಖಾಲಿ || (ssh->kex->flags & KEX_HAS_PING) == 0)
		ಹಿಂತಿರುಗಿ 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ಹಿಂತಿರುಗಿ 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
ಸ್ಥಿರ ಶೂನ್ಯ
ಗಣ_ಮುಂದಿನ_interval(ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *now, ರಚನೆ timespec *ಮುಂದಿನ_interval,
    u_int interval_ms, ಪೂರ್ಣಾಂಕ starting)
{
	ರಚನೆ timespec tmp;
	ದೀರ್ಘ ದೀರ್ಘ interval_ns, fuzz_ns;
	ಸ್ಥಿರ ದೀರ್ಘ ದೀರ್ಘ ದರ_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	ಆದರೆ (fuzz_ns > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		fuzz_ns = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
	ಆದರೆ (fuzz_ns > interval_ns) {
		/* Shouldn't happen */
		fatal_f("internal error: fuzz %u%% %lldns > interval %lldns",
		    SSH_KEYSTROKE_TIMING_FUZZ, fuzz_ns, interval_ns);
	}
	/*
	 * Randomise the keystroke/chaff intervals in two ways:
	 * 1. Each interval has some random jitter applied to make the
	 *    interval-to-interval time unpredictable.
	 * 2. The overall interval rate is also randomly perturbed for each
	 *    chaffing session to make the average rate unpredictable.
	 */
	ಆದರೆ (starting)
		ದರ_fuzz = arc4random_ಏಕರೂಪ(fuzz_ns);
	interval_ns -= fuzz_ns;
	interval_ns += arc4random_ಏಕರೂಪ(fuzz_ns) + ದರ_fuzz;

	tmp.tv_sec = interval_ns / (1000 * 1000 * 1000);
	tmp.tv_nsec = interval_ns % (1000 * 1000 * 1000);

	timespecadd(now, &tmp, ಮುಂದಿನ_interval);
}

/*
 * Performs keystroke timing obfuscation. Returns non-zero if the
 * output fd should be polled.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
obfuscate_keystroke_timing(ರಚನೆ ssh *ssh, ರಚನೆ timespec *timeout,
    ಪೂರ್ಣಾಂಕ channel_did_ಸರತಿಗೆ_ಸೇರಿಸು)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಸಕ್ರಿಯ;
	ಸ್ಥಿರ ರಚನೆ timespec ಮುಂದಿನ_interval, chaff_until;
	ರಚನೆ timespec now, tmp;
	ಪೂರ್ಣಾಂಕ just_started = 0, had_keystroke = 0;
	ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ nchaff;
	ಅಕ್ಷರ *stop_reason = ಖಾಲಿ;
	ದೀರ್ಘ ದೀರ್ಘ n;

	monotime_ts(&now);

	ಆದರೆ (options.obscure_keystroke_timing_interval <= 0)
		ಹಿಂತಿರುಗಿ 1;	/* disabled in config */

	ಆದರೆ (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!ssh_packet_interactive_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh) &&
	    ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಸಕ್ರಿಯ && channel_did_ಸರತಿಗೆ_ಸೇರಿಸು &&
	    ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಸಕ್ರಿಯ) {
		ಆದರೆ (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (timespeccmp(&now, &ಮುಂದಿನ_interval, >=) &&
		    !ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			ಆದರೆ (send_chaff(ssh))
				nchaff++;
		}
	}

	ಆದರೆ (stop_reason != ಖಾಲಿ) {
		ಆದರೆ (ಸಕ್ರಿಯ) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			ಸಕ್ರಿಯ = 0;
		}
		ಹಿಂತಿರುಗಿ 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	ಆದರೆ (!ಸಕ್ರಿಯ && ssh_packet_interactive_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh) &&
	    channel_did_ಸರತಿಗೆ_ಸೇರಿಸು && ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = ಸಕ್ರಿಯ = 1;
		nchaff = 0;
		ಗಣ_ಮುಂದಿನ_interval(&now, &ಮುಂದಿನ_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	ಆದರೆ (!ಸಕ್ರಿಯ)
		ಹಿಂತಿರುಗಿ 1;

	ಆದರೆ (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_ಗಮ್ಯ_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_ಏಕರೂಪ(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &ಮುಂದಿನ_interval);

	ಆದರೆ (just_started)
		ಹಿಂತಿರುಗಿ 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	ಆದರೆ (timespeccmp(&now, &ಮುಂದಿನ_interval, <))
		/* ...unless there's x11 communication happening */
		ಹಿಂತಿರುಗಿ x11_channel_ಬಳಸಿದ_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - ಮುಂದಿನ_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - ಮುಂದಿನ_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	ಗಣ_ಮುಂದಿನ_interval(&now, &ಮುಂದಿನ_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
ಸ್ಥಿರ ಶೂನ್ಯ
client_wait_until_can_do_something(ರಚನೆ ssh *ssh, ರಚನೆ pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, ಪೂರ್ಣಾಂಕ channel_did_ಸರತಿಗೆ_ಸೇರಿಸು,
    sigset_t *sigsetp, ಪೂರ್ಣಾಂಕ *conn_ಒಳ_readyp, ಪೂರ್ಣಾಂಕ *conn_ಹೊರಹೋಗು_readyp)
{
	ರಚನೆ timespec timeout;
	ಪೂರ್ಣಾಂಕ ret, oready;
	u_int p;

	*conn_ಒಳ_readyp = *conn_ಹೊರಹೋಗು_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	ಆದರೆ (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	ಆದರೆ (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh)) {
		/* clear events since we did not call poll() */
		ಗಾಗಿ (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ಹಿಂತಿರುಗಿ;
	}

	oready = obfuscate_keystroke_timing(ssh, &timeout, channel_did_ಸರತಿಗೆ_ಸೇರಿಸು);

	/* Monitor server connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_ಒಳ;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_ಹೊರಹೋಗು;
	(*pfdp)[1].events = (oready && ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh)) ?
	    POLLOUT : 0;

	/*
	 * Wait for something to happen.  This will suspend the process until
	 * some polled descriptor can be read, written, or has some other
	 * event pending, or a timeout expires.
	 */
	ಗಣ_control_persist_exit_ಸಮಯ(ssh);
	ಆದರೆ (control_persist_exit_ಸಮಯ > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_ಸಮಯ);
	ಆದರೆ (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_ಸಮಯ);
	ಆದರೆ (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	ಆದರೆ (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		ಗಾಗಿ (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ಆದರೆ (errno == EINTR)
			ಹಿಂತಿರುಗಿ;
		/* Note: we might still have data in the buffers. */
		quit_ಸಂದೇಶ("poll: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ;
	}

	*conn_ಒಳ_readyp = (*pfdp)[0].revents != 0;
	*conn_ಹೊರಹೋಗು_readyp = (*pfdp)[1].revents != 0;

	ಆದರೆ (options.server_alive_interval > 0 && !*conn_ಒಳ_readyp &&
	    monotime() >= server_alive_ಸಮಯ) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_suspend_self(ರಚನೆ sshbuf *bin, ರಚನೆ sshbuf *bout, ರಚನೆ sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	ಆದರೆ (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	ಆದರೆ (sshbuf_len(berr) > 0)
		atomicio(vwrite, fileno(stderr), sshbuf_mutable_ptr(berr),
		    sshbuf_len(berr));

	leave_raw_ಬಹುಲಕ(options.request_tty == REQUEST_TTY_FORCE);

	sshbuf_reset(bin);
	sshbuf_reset(bout);
	sshbuf_reset(berr);

	/* Send the suspend signal to the program itself. */
	kill(getpid(), SIGTSTP);

	/* Reset window sizes in case they have changed */
	received_ಕಿಟಕಿ_change_signal = 1;

	enter_raw_ಬಹುಲಕ(options.request_tty == REQUEST_TTY_FORCE);
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_process_net_ಒಳಹರಿವು(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	ವೇಳಾಪಟ್ಟಿ_server_alive_check();
	ಆದರೆ ((r = ssh_packet_process_read(ssh, connection_ಒಳ)) == 0)
		ಹಿಂತಿರುಗಿ; /* success */
	ಆದರೆ (r == SSH_ERR_SYSTEM_ERROR) {
		ಆದರೆ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ಹಿಂತಿರುಗಿ;
		ಆದರೆ (errno == EPIPE) {
			quit_ಸಂದೇಶ("Connection to %s closed by remote host.",
			    host);
			ಹಿಂತಿರುಗಿ;
		}
	}
	quit_ಸಂದೇಶ("Read from remote host %s: %s", host, ssh_err(r));
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_ಸ್ಥಿತಿ_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ type, Channel *c, ಶೂನ್ಯ *ctx)
{
	ರಚನೆ channel_ಉತ್ತರ_ctx *cr = (ರಚನೆ channel_ಉತ್ತರ_ctx *)ctx;
	ಅಕ್ಷರ errmsg[256];
	ಪೂರ್ಣಾಂಕ r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	ಆದರೆ (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	ಆದರೆ (type == SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type == SSH2_ಸಂದೇಶ_CHANNEL_FAILURE) {
		ಆದರೆ (tochan) {
			snprintf(errmsg, ಗಾತ್ರ(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} ಇಲ್ಲದಿದ್ದರೆ {
			snprintf(errmsg, ಗಾತ್ರ(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		ಆದರೆ (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		ಆದರೆ (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			ಆದರೆ ((r = sshbuf_put(c->extended, errmsg,
			    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} ಇಲ್ಲದಿದ್ದರೆ
			error("%s", errmsg);
		ಆದರೆ (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			ಆದರೆ (c->self == session_ident)
				leave_raw_ಬಹುಲಕ(0);
			ಇಲ್ಲದಿದ್ದರೆ
				mux_tty_alloc_failed(ssh, c);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	ಬಿಡುಗಡೆ(cr);
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_abandon_ಸ್ಥಿತಿ_confirm(ರಚನೆ ssh *ssh, Channel *c, ಶೂನ್ಯ *ctx)
{
	ಬಿಡುಗಡೆ(ctx);
}

ಶೂನ್ಯ
client_expect_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *request,
    ಎಣಿಕೆ confirm_action action)
{
	ರಚನೆ channel_ಉತ್ತರ_ctx *cr = xcalloc(1, ಗಾತ್ರ(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_ರಿಜಿಸ್ಟರ್_ಸ್ಥಿತಿ_confirm(ssh, id, client_ಸ್ಥಿತಿ_confirm,
	    client_abandon_ಸ್ಥಿತಿ_confirm, cr);
}

ಶೂನ್ಯ
client_ರಿಜಿಸ್ಟರ್_global_confirm(global_confirm_cb *cb, ಶೂನ್ಯ *ctx)
{
	ರಚನೆ global_confirm *gc, *ಕೊನೆಯ_gc;

	/* Coalesce identical callbacks */
	ಕೊನೆಯ_gc = TAILQ_LAST(&global_confirms, global_confirms);
	ಆದರೆ (ಕೊನೆಯ_gc && ಕೊನೆಯ_gc->cb == cb && ಕೊನೆಯ_gc->ctx == ctx) {
		ಆದರೆ (++ಕೊನೆಯ_gc->ref_ಎಣಿಕೆ >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
			fatal_f("last_gc->ref_count = %d",
			    ಕೊನೆಯ_gc->ref_ಎಣಿಕೆ);
		ಹಿಂತಿರುಗಿ;
	}

	gc = xcalloc(1, ಗಾತ್ರ(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_ಎಣಿಕೆ = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, ನಮೂದು);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
can_update_hostkeys(ಶೂನ್ಯ)
{
	ಆದರೆ (hostkeys_update_complete)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_ಬಹುಲಕ)
		ಹಿಂತಿರುಗಿ 0; /* won't ask in batchmode, so don't even try */
	ಆದರೆ (!options.update_hostkeys || options.ಅಂಕೆ_user_hostfiles <= 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_repledge(ಶೂನ್ಯ)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	ಆದರೆ (options.control_master || options.control_ಮಾರ್ಗ != ಖಾಲಿ ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != ಖಾಲಿ || can_update_hostkeys() ||
	    (session_ident != -1 && !session_ಸಿದ್ಧತೆ_complete)) {
		/* Can't tighten */
		ಹಿಂತಿರುಗಿ;
	}
	/*
	 * LocalCommand and UpdateHostkeys have finished, so can get rid of
	 * filesystem.
	 *
	 * XXX protocol allows a server can to change hostkeys during the
	 *     connection at rekey time that could trigger a hostkeys update
	 *     but AFAIK no implementations support this. Could improve by
	 *     forcing known_hosts to be read-only or via unveil(2).
	 */
	ಆದರೆ (options.ಅಂಕೆ_local_forwards != 0 ||
	    options.ಅಂಕೆ_remote_forwards != 0 ||
	    options.ಅಂಕೆ_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		ಆದರೆ (pledge("stdio unix inet dns proc tty", ಖಾಲಿ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		ಆದರೆ (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", ಖಾಲಿ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("pledge: fork");
		ಆದರೆ (pledge(PLEDGE_EXTRA_INET "stdio proc tty", ಖಾಲಿ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	}
	/* XXX further things to do:
	 *
	 * - might be able to get rid of proc if we kill ~^Z
	 * - ssh -N (no session)
	 * - stdio forwarding
	 * - sessions without tty
	 */
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_cmdline(ರಚನೆ ssh *ssh)
{
	ಶೂನ್ಯ (*handler)(ಪೂರ್ಣಾಂಕ);
	ಅಕ್ಷರ *s, *cmd;
	ಪೂರ್ಣಾಂಕ ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	ರಚನೆ Forward fwd;

	memset(&fwd, 0, ಗಾತ್ರ(fwd));

	leave_raw_ಬಹುಲಕ(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	ಆದರೆ (s == ಖಾಲಿ)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆಗ (ಖಾಲಿಯೇ((u_char)*s))
		s++;
	ಆದರೆ (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	ಆದರೆ (*s == '\0')
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (*s == 'h' || *s == 'H' || *s == '?') {
		logit("Commands:");
		logit("      -L[bind_address:]port:host:hostport    "
		    "Request local forward");
		logit("      -R[bind_address:]port:host:hostport    "
		    "Request remote forward");
		logit("      -D[bind_address:]port                  "
		    "Request dynamic forward");
		logit("      -KL[bind_address:]port                 "
		    "Cancel local forward");
		logit("      -KR[bind_address:]port                 "
		    "Cancel remote forward");
		logit("      -KD[bind_address:]port                 "
		    "Cancel dynamic forward");
		ಆದರೆ (!options.permit_local_command)
			ಹೋಗು ಹೊರಹೋಗು;
		logit("      !args                                  "
		    "Execute local command");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (*s == 'K') {
		delete = 1;
		s++;
	}
	ಆದರೆ (*s == 'L')
		local = 1;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*s == 'R')
		remote = 1;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*s == 'D')
		dynamic = 1;
	ಇಲ್ಲದಿದ್ದರೆ {
		logit("Invalid command.");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆಗ (ಖಾಲಿಯೇ((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	ಆದರೆ (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		ಆದರೆ (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		ಇಲ್ಲದಿದ್ದರೆ
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_ಪೋರ್ಟ್_STATIC,
			    &options.fwd_opts) > 0;
		ಆದರೆ (!ok) {
			logit("Unknown port forwarding.");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		logit("Canceled forwarding.");
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* -R specs can be both dynamic or not, so check both. */
		ಆದರೆ (remote) {
			ಆದರೆ (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				ಹೋಗು ಹೊರಹೋಗು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (local || dynamic) {
			ಆದರೆ (!channel_ಸಿದ್ಧತೆ_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				ಹೋಗು ಹೊರಹೋಗು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				ಹೋಗು ಹೊರಹೋಗು;
			}
		}
		logit("Forwarding port.");
	}

ಹೊರಹೋಗು:
	ssh_signal(SIGINT, handler);
	enter_raw_ಬಹುಲಕ(options.request_tty == REQUEST_TTY_FORCE);
	ಬಿಡುಗಡೆ(cmd);
	ಬಿಡುಗಡೆ(fwd.listen_host);
	ಬಿಡುಗಡೆ(fwd.listen_ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(fwd.connect_host);
	ಬಿಡುಗಡೆ(fwd.connect_ಮಾರ್ಗ);
}

/* reasons to suppress output of an escape command in help output */
#ವ್ಯಾಖ್ಯಾನಿಸು SUPPRESS_NEVER		0	/* never suppress, always show */
#ವ್ಯಾಖ್ಯಾನಿಸು SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#ವ್ಯಾಖ್ಯಾನಿಸು SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#ವ್ಯಾಖ್ಯಾನಿಸು SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#ವ್ಯಾಖ್ಯಾನಿಸು SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
ರಚನೆ escape_help_ಪಠ್ಯ {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪಠ್ಯ;
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ flags;
};
ಸ್ಥಿರ ರಚನೆ escape_help_ಪಠ್ಯ esc_txt[] = {
    {".",  "terminate session", SUPPRESS_MUXMASTER},
    {".",  "terminate connection (and any multiplexed sessions)",
	SUPPRESS_MUXCLIENT},
    {"B",  "send a BREAK to the remote system", SUPPRESS_NEVER},
    {"C",  "open a command line", SUPPRESS_MUXCLIENT|SUPPRESS_NOCMDLINE},
    {"I",  "show connection information", SUPPRESS_NEVER},
    {"R",  "request rekey", SUPPRESS_NEVER},
    {"V/v",  "decrease/increase verbosity (LogLevel)", SUPPRESS_MUXCLIENT},
    {"^Z", "suspend ssh", SUPPRESS_MUXCLIENT},
    {"#",  "list forwarded connections", SUPPRESS_NEVER},
    {"&",  "background ssh (when waiting for connections to terminate)",
	SUPPRESS_MUXCLIENT},
    {"?", "this message", SUPPRESS_NEVER},
};

ಸ್ಥಿರ ಶೂನ್ಯ
print_escape_help(ರಚನೆ sshbuf *b, ಪೂರ್ಣಾಂಕ escape_char, ಪೂರ್ಣಾಂಕ mux_client,
    ಪೂರ್ಣಾಂಕ using_stderr)
{
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ i, suppress_flags;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	ಗಾಗಿ (i = 0; i < ಗಾತ್ರ(esc_txt)/ಗಾತ್ರ(esc_txt[0]); i++) {
		ಆದರೆ (esc_txt[i].flags & suppress_flags)
			ಮುಂದುವರಿ;
		ಆದರೆ ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].ಪಠ್ಯ)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	ಆದರೆ ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
process_escapes(ರಚನೆ ssh *ssh, Channel *c,
    ರಚನೆ sshbuf *bin, ರಚನೆ sshbuf *bout, ರಚನೆ sshbuf *berr,
    ಅಕ್ಷರ *buf, ಪೂರ್ಣಾಂಕ len)
{
	pid_t pid;
	ಪೂರ್ಣಾಂಕ r, ಬೈಟುಗಳು = 0;
	u_int i;
	u_char ch;
	ಅಕ್ಷರ *s;
	ರಚನೆ escape_filter_ctx *efc;

	ಆದರೆ (c == ಖಾಲಿ || c->filter_ctx == ಖಾಲಿ || len <= 0)
		ಹಿಂತಿರುಗಿ 0;

	efc = (ರಚನೆ escape_filter_ctx *)c->filter_ctx;

	ಗಾಗಿ (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		ಆದರೆ (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			ಆಯ್ಕೆ (ch) {
			ಸ್ಥಿತಿ '.':
				/* Terminate the connection. */
				ಆದರೆ ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				ಆದರೆ (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					ಹಿಂತಿರುಗಿ 0;
				} ಇಲ್ಲದಿದ್ದರೆ
					quit_pending = 1;
				ಹಿಂತಿರುಗಿ -1;

			ಸ್ಥಿತಿ 'Z' - 64:
				/* XXX support this for mux clients */
				ಆದರೆ (c && c->ctl_chan != -1) {
					ಅಕ್ಷರ b[16];
 noescape:
					ಆದರೆ (ch == 'Z' - 64)
						snprintf(b, ಗಾತ್ರ b, "^Z");
					ಇಲ್ಲದಿದ್ದರೆ
						snprintf(b, ಗಾತ್ರ b, "%c", ch);
					ಆದರೆ ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					ಮುಂದುವರಿ;
				}
				/* Suspend the program. Inform the user */
				ಆದರೆ ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				ಮುಂದುವರಿ;

			ಸ್ಥಿತಿ 'B':
				ಆದರೆ ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_ಆರಂಭ(ssh, c->self, "break", 0);
				ಆದರೆ ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				ಮುಂದುವರಿ;

			ಸ್ಥಿತಿ 'I':
				ಆದರೆ ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_ಸಂದೇಶ(ssh);
				ಆದರೆ ((r = sshbuf_put(berr, s, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				ಬಿಡುಗಡೆ(s);
				ಮುಂದುವರಿ;

			ಸ್ಥಿತಿ 'R':
				ಆದರೆ (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				ಇಲ್ಲದಿದ್ದರೆ
					need_rekeying = 1;
				ಮುಂದುವರಿ;

			ಸ್ಥಿತಿ 'V':
				/* FALLTHROUGH */
			ಸ್ಥಿತಿ 'v':
				ಆದರೆ (c && c->ctl_chan != -1)
					ಹೋಗು noescape;
				ಆದರೆ (!log_is_on_stderr()) {
					ಆದರೆ ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					ಮುಂದುವರಿ;
				}
				ಆದರೆ (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				ಆದರೆ (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				ಆದರೆ ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				ಮುಂದುವರಿ;

			ಸ್ಥಿತಿ '&':
				ಆದರೆ (c->ctl_chan != -1)
					ಹೋಗು noescape;
				/*
				 * Detach the program (continue to serve
				 * connections, but put in background and no
				 * more new connections).
				 */
				/* Restore tty modes. */
				leave_raw_ಬಹುಲಕ(
				    options.request_tty == REQUEST_TTY_FORCE);

				/* Stop listening for new connections. */
				channel_stop_listening(ssh);

				ಆದರೆ ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				ಆದರೆ (pid == -1) {
					error("fork: %.100s", strerror(errno));
					ಮುಂದುವರಿ;
				}
				ಆದರೆ (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					ನಿರ್ಗಮಿಸು(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				ಆದರೆ ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				ಹಿಂತಿರುಗಿ -1;
			ಸ್ಥಿತಿ '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				ಮುಂದುವರಿ;

			ಸ್ಥಿತಿ '#':
				ಆದರೆ ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_ಸಂದೇಶ(ssh);
				ಆದರೆ ((r = sshbuf_put(berr, s, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				ಬಿಡುಗಡೆ(s);
				ಮುಂದುವರಿ;

			ಸ್ಥಿತಿ 'C':
				ಆದರೆ (c && c->ctl_chan != -1)
					ಹೋಗು noescape;
				ಆದರೆ (options.enable_escape_commandline == 0) {
					ಆದರೆ ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					ಮುಂದುವರಿ;
				}
				process_cmdline(ssh);
				ಮುಂದುವರಿ;

			ಪೂರ್ವನಿಯೋಜಿತ:
				ಆದರೆ (ch != efc->escape_char) {
					ಆದರೆ ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					ಬೈಟುಗಳು++;
				}
				/* Escaped characters fall through here */
				ನಿಲ್ಲಿಸು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			ಆದರೆ (ಕೊನೆಯ_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				ಮುಂದುವರಿ;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		ಕೊನೆಯ_was_cr = (ch == '\r' || ch == '\n');
		ಆದರೆ ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		ಬೈಟುಗಳು++;
	}
	ಹಿಂತಿರುಗಿ ಬೈಟುಗಳು;
}

/*
 * Get packets from the connection input buffer, and process them as long as
 * there are packets available.
 *
 * Any unknown packets received during the actual
 * session cause the session to terminate.  This is
 * intended to make debugging easier since no
 * confirmations are sent.  Any compatible protocol
 * extensions must be negotiated during the
 * preparatory phase.
 */

ಸ್ಥಿರ ಶೂನ್ಯ
client_process_buffered_ಒಳಹರಿವು_packets(ರಚನೆ ssh *ssh)
{
	ssh_dispatch_ಸತತ_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
ಶೂನ್ಯ *
client_new_escape_filter_ctx(ಪೂರ್ಣಾಂಕ escape_char)
{
	ರಚನೆ escape_filter_ctx *ret;

	ret = xcalloc(1, ಗಾತ್ರ(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	ಹಿಂತಿರುಗಿ (ಶೂನ್ಯ *)ret;
}

/* Free the escape filter context on channel free */
ಶೂನ್ಯ
client_filter_cleanup(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ cid, ಶೂನ್ಯ *ctx)
{
	ಬಿಡುಗಡೆ(ctx);
}

ಪೂರ್ಣಾಂಕ
client_simple_escape_filter(ರಚನೆ ssh *ssh, Channel *c, ಅಕ್ಷರ *buf, ಪೂರ್ಣಾಂಕ len)
{
	ಆದರೆ (c->extended_usage != CHAN_EXTENDED_WRITE)
		ಹಿಂತಿರುಗಿ 0;

	ಹಿಂತಿರುಗಿ process_escapes(ssh, c, c->ಒಳಹರಿವು, c->output, c->extended,
	    buf, len);
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_channel_closed(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ force, ಶೂನ್ಯ *arg)
{
	channel_cancel_cleanup(ssh, id);
	session_closed = 1;
	leave_raw_ಬಹುಲಕ(options.request_tty == REQUEST_TTY_FORCE);
}

/*
 * Implements the interactive session with the server.  This is called after
 * the user has been authenticated, and a command has been started on the
 * remote host.  If escape_char != SSH_ESCAPECHAR_NONE, it is the character
 * used as an escape character for terminating or suspending the session.
 */
ಪೂರ್ಣಾಂಕ
client_loop(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ have_pty, ಪೂರ್ಣಾಂಕ escape_char_arg,
    ಪೂರ್ಣಾಂಕ ssh2_chan_id)
{
	ರಚನೆ pollfd *pfd = ಖಾಲಿ;
	u_int npfd_alloc = 0, npfd_ಸಕ್ರಿಯ = 0;
	ದ್ವಿಗುಣ ಆರಂಭ_ಸಮಯ, ಒಟ್ಟು_ಸಮಯ;
	ಪೂರ್ಣಾಂಕ interactive = -1, channel_did_ಸರತಿಗೆ_ಸೇರಿಸು = 0, r;
	uint64_t ibytes, obytes;
	ಪೂರ್ಣಾಂಕ conn_ಒಳ_ready, conn_ಹೊರಹೋಗು_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	ಆದರೆ (options.pkcs11_provider != ಖಾಲಿ)
		debug("pledge: disabled (PKCS11Provider active)");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.control_master &&
	    !option_clear_or_none(options.control_ಮಾರ್ಗ)) {
		debug("pledge: id");
		ಆದರೆ (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    ಖಾಲಿ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		ಆದರೆ (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    ಖಾಲಿ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.update_hostkeys) {
		debug("pledge: filesystem");
		ಆದರೆ (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    ಖಾಲಿ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		ಆದರೆ (pledge("stdio cpath unix inet dns proc tty", ಖಾಲಿ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("pledge: network");
		ಆದರೆ (pledge("stdio unix inet dns proc tty", ಖಾಲಿ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	}

	/* might be able to tighten now */
	client_repledge();

	ಆರಂಭ_ಸಮಯ = monotime_double();

	/* Initialize variables. */
	ಕೊನೆಯ_was_cr = 1;
	exit_ಸ್ಥಿತಿ = -1;
	connection_ಒಳ = ssh_packet_get_connection_ಒಳ(ssh);
	connection_ಹೊರಹೋಗು = ssh_packet_get_connection_ಹೊರಹೋಗು(ssh);

	quit_pending = 0;

	client_init_dispatch(ssh);

	/*
	 * Set signal handlers, (e.g. to restore non-blocking mode)
	 * but don't overwrite SIG_IGN, matches behaviour from rsh(1)
	 */
	ಆದರೆ (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	ಆದರೆ (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	ಆದರೆ (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	ಆದರೆ (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, ಕಿಟಕಿ_change_handler);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (have_pty)
		enter_raw_ಬಹುಲಕ(options.request_tty == REQUEST_TTY_FORCE);

	ಆದರೆ (session_ident != -1) {
		ಆದರೆ (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_ರಿಜಿಸ್ಟರ್_filter(ssh, session_ident,
			    client_simple_escape_filter, ಖಾಲಿ,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_ರಿಜಿಸ್ಟರ್_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	ವೇಳಾಪಟ್ಟಿ_server_alive_check();

	ಆದರೆ (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
	ಆದರೆ (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ

	/* Main loop of the client for the interactive session mode. */
	ಆಗ (!quit_pending) {
		channel_did_ಸರತಿಗೆ_ಸೇರಿಸು = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_ಒಳಹರಿವು_packets(ssh);

		ಆದರೆ (session_closed && !channel_still_open(ssh))
			ನಿಲ್ಲಿಸು;

		ಆದರೆ (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			ಆದರೆ ((r = kex_ಆರಂಭ_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} ಇಲ್ಲದಿದ್ದರೆ {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			ಆದರೆ (ssh_packet_not_very_much_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh))
				channel_did_ಸರತಿಗೆ_ಸೇರಿಸು = channel_output_poll(ssh);

			/*
			 * Check if the window size has changed, and buffer a
			 * message about it to the server if so.
			 */
			client_check_ಕಿಟಕಿ_change(ssh);
		}
		/*
		 * Wait until we have something to do (something becomes
		 * available on one of the descriptors).
		 */
		ಆದರೆ (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		ಆದರೆ (siginfo_received) {
			ಅಕ್ಷರ ident[256];

			sshpkt_fmt_connection_id(ssh, ident, ಗಾತ್ರ(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - ಆರಂಭ_ಸಮಯ);
			siginfo_received = 0;
		}
		ಆದರೆ (quit_pending)
			ನಿಲ್ಲಿಸು;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_ಸಕ್ರಿಯ, channel_did_ಸರತಿಗೆ_ಸೇರಿಸು, &osigset,
		    &conn_ಒಳ_ready, &conn_ಹೊರಹೋಗು_ready);
		ಆದರೆ (sigprocmask(SIG_SETMASK, &osigset, ಖಾಲಿ) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		ಆದರೆ (quit_pending)
			ನಿಲ್ಲಿಸು;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_ಸಕ್ರಿಯ);

		/* Buffer input from the connection.  */
		ಆದರೆ (conn_ಒಳ_ready)
			client_process_net_ಒಳಹರಿವು(ssh);

		ಆದರೆ (quit_pending)
			ನಿಲ್ಲಿಸು;

		/* A timeout may have triggered rekeying */
		ಆದರೆ ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		ಆದರೆ (conn_ಹೊರಹೋಗು_ready) {
			ಆದರೆ (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_ಗಣ_interactive(ssh, interactive);
			}
			ಆದರೆ ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		ಆದರೆ (control_persist_exit_ಸಮಯ > 0) {
			ಆದರೆ (monotime() >= control_persist_exit_ಸಮಯ) {
				debug("ControlPersist timeout expired");
				ನಿಲ್ಲಿಸು;
			}
		}
	}
	ಬಿಡುಗಡೆ(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	ಆದರೆ (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_ಸಂದೇಶ("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	ಆದರೆ (have_pty)
		leave_raw_ಬಹುಲಕ(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	ಆದರೆ (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_ಸ್ಥಿತಿ = 0;
	}

	ಆದರೆ (received_signal) {
		verbose("Killed by signal %d.", (ಪೂರ್ಣಾಂಕ) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	ಒಟ್ಟು_ಸಮಯ = monotime_double() - ಆರಂಭ_ಸಮಯ;
	ssh_packet_get_ಬೈಟುಗಳು(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)obytes, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ibytes, ಒಟ್ಟು_ಸಮಯ);
	ಆದರೆ (ಒಟ್ಟು_ಸಮಯ > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / ಒಟ್ಟು_ಸಮಯ, ibytes / ಒಟ್ಟು_ಸಮಯ);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_ಸ್ಥಿತಿ);
	ಹಿಂತಿರುಗಿ exit_ಸ್ಥಿತಿ;
}

/*********/

ಸ್ಥಿರ Channel *
client_request_forwarded_tcpip(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *request_type,
    ಪೂರ್ಣಾಂಕ rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = ಖಾಲಿ;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಅಕ್ಷರ *listen_ವಿಳಾಸ, *originator_ವಿಳಾಸ;
	u_int listen_ಪೋರ್ಟ್, originator_ಪೋರ್ಟ್;
	ಪೂರ್ಣಾಂಕ r;

	/* Get rest of the packet */
	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &listen_ವಿಳಾಸ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_ಪೋರ್ಟ್)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_ವಿಳಾಸ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_ಪೋರ್ಟ್)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_ವಿಳಾಸ, listen_ಪೋರ್ಟ್, originator_ವಿಳಾಸ, originator_ಪೋರ್ಟ್);

	ಆದರೆ (listen_ಪೋರ್ಟ್ > 0xffff)
		error_f("invalid listen port");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (originator_ಪೋರ್ಟ್ > 0xffff)
		error_f("invalid originator port");
	ಇಲ್ಲದಿದ್ದರೆ {
		c = channel_connect_by_listen_ವಿಳಾಸ(ssh,
		    listen_ವಿಳಾಸ, listen_ಪೋರ್ಟ್, "forwarded-tcpip",
		    originator_ವಿಳಾಸ);
	}

	ಆದರೆ (c != ಖಾಲಿ && c->type == SSH_CHANNEL_MUX_CLIENT) {
		ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
			error_f("alloc reply");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* reconstruct and send to muxclient */
		ಆದರೆ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_CHANNEL_OPEN)) != 0 ||
		    (r = sshbuf_put_cstring(b, request_type)) != 0 ||
		    (r = sshbuf_put_u32(b, rchan)) != 0 ||
		    (r = sshbuf_put_u32(b, rwindow)) != 0 ||
		    (r = sshbuf_put_u32(b, rmaxpack)) != 0 ||
		    (r = sshbuf_put_cstring(b, listen_ವಿಳಾಸ)) != 0 ||
		    (r = sshbuf_put_u32(b, listen_ಪೋರ್ಟ್)) != 0 ||
		    (r = sshbuf_put_cstring(b, originator_ವಿಳಾಸ)) != 0 ||
		    (r = sshbuf_put_u32(b, originator_ಪೋರ್ಟ್)) != 0 ||
		    (r = sshbuf_put_stringb(c->output, b)) != 0) {
			error_fr(r, "compose for muxclient");
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಬಿಡುಗಡೆ(originator_ವಿಳಾಸ);
	ಬಿಡುಗಡೆ(listen_ವಿಳಾಸ);
	ಹಿಂತಿರುಗಿ c;
}

ಸ್ಥಿರ Channel *
client_request_forwarded_streamlocal(ರಚನೆ ssh *ssh,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *request_type, ಪೂರ್ಣಾಂಕ rchan)
{
	Channel *c = ಖಾಲಿ;
	ಅಕ್ಷರ *listen_ಮಾರ್ಗ;
	ಪೂರ್ಣಾಂಕ r;

	/* Get the remote path. */
	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &listen_ಮಾರ್ಗ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_string(ssh, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_ಮಾರ್ಗ);

	c = channel_connect_by_listen_ಮಾರ್ಗ(ssh, listen_ಮಾರ್ಗ,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	ಬಿಡುಗಡೆ(listen_ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ c;
}

ಸ್ಥಿರ Channel *
client_request_x11(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *request_type, ಪೂರ್ಣಾಂಕ rchan)
{
	Channel *c = ಖಾಲಿ;
	ಅಕ್ಷರ *originator;
	u_int originator_ಪೋರ್ಟ್;
	ಪೂರ್ಣಾಂಕ r, sock;

	ಆದರೆ (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (x11_refuse_ಸಮಯ != 0 && monotime() >= x11_refuse_ಸಮಯ) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &originator, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_ಪೋರ್ಟ್)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_ಪೋರ್ಟ್);
	ಬಿಡುಗಡೆ(originator);
	sock = x11_connect_display(ssh);
	ಆದರೆ (sock < 0)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	ಹಿಂತಿರುಗಿ c;
}

ಸ್ಥಿರ Channel *
client_request_agent(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *request_type, ಪೂರ್ಣಾಂಕ rchan)
{
	Channel *c = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, sock;

	ಆದರೆ (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (forward_agent_sock_ಮಾರ್ಗ == ಖಾಲಿ) {
		r = ssh_get_authentication_socket(&sock);
	} ಇಲ್ಲದಿದ್ದರೆ {
		r = ssh_get_authentication_socket_ಮಾರ್ಗ(forward_agent_sock_ಮಾರ್ಗ, &sock);
	}
	ಆದರೆ (r != 0) {
		ಆದರೆ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	ಇಲ್ಲದಿದ್ದರೆ
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	ಹಿಂತಿರುಗಿ c;
}

ಅಕ್ಷರ *
client_request_tun_fwd(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ tun_ಬಹುಲಕ,
    ಪೂರ್ಣಾಂಕ local_tun, ಪೂರ್ಣಾಂಕ remote_tun, channel_open_fn *cb, ಶೂನ್ಯ *cbctx)
{
	Channel *c;
	ಪೂರ್ಣಾಂಕ r, fd;
	ಅಕ್ಷರ *ifname = ಖಾಲಿ;

	ಆದರೆ (tun_ಬಹುಲಕ == SSH_TUNMODE_NO)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_ಬಹುಲಕ);

	/* Open local tunnel device */
	ಆದರೆ ((fd = tun_open(local_tun, tun_ಬಹುಲಕ, &ifname)) == -1) {
		error("Tunnel device open failed.");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#ಆದರೆ defined(SSH_TUN_FILTER)
	ಆದರೆ (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_ರಿಜಿಸ್ಟರ್_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ಖಾಲಿ, ಖಾಲಿ);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (cb != ಖಾಲಿ)
		channel_ರಿಜಿಸ್ಟರ್_open_confirm(ssh, c->self, cb, cbctx);

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_ಕಿಟಕಿ_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_ಬಹುಲಕ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	ಹಿಂತಿರುಗಿ ifname;
}

/* XXXX move to generic input handler */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
client_ಒಳಹರಿವು_channel_open(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Channel *c = ಖಾಲಿ;
	ಅಕ್ಷರ *ctype = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;
	u_int rchan;
	ಗಾತ್ರ_t len;
	u_int rmaxpack, rwindow;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	ಆದರೆ (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	ಆದರೆ (c != ಖಾಲಿ && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c != ಖಾಲಿ) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_ಕಿಟಕಿ = rwindow;
		c->remote_maxpacket = rmaxpack;
		ಆದರೆ (c->type != SSH_CHANNEL_CONNECTING) {
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_ಕಿಟಕಿ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("failure %s", ctype);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ctype);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
client_ಒಳಹರಿವು_channel_req(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Channel *c = ಖಾಲಿ;
	ಅಕ್ಷರ *rtype = ಖಾಲಿ;
	u_char ಉತ್ತರ;
	u_int id, exitval;
	ಪೂರ್ಣಾಂಕ r, success = 0;

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &id)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (id <= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		c = channel_lookup(ssh, id);
	ಆದರೆ (channel_proxy_upstream(c, type, seq, ssh))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &rtype, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &ಉತ್ತರ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, ಉತ್ತರ);

	ಆದರೆ (c == ಖಾಲಿ) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "eow@openssh.com") == 0) {
		ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		chan_rcvd_eow(ssh, c);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "exit-status") == 0) {
		ಆದರೆ ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (c->ctl_chan != -1) {
			mux_exit_ಸಂದೇಶ(ssh, c, exitval);
			success = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಪೂರ್ಣಾಂಕ)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_ಸ್ಥಿತಿ = exitval;
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ಉತ್ತರ && c != ಖಾಲಿ && !(c->flags & CHAN_CLOSE_ಕಳುಹಿಸಿದ)) {
		ಆದರೆ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, success ?
		    SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS : SSH2_ಸಂದೇಶ_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(rtype);
	ಹಿಂತಿರುಗಿ r;
}

ರಚನೆ hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	ಅಕ್ಷರ *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	ರಚನೆ sshkey **ಕೀಲಿಗಳು;
	u_int *ಕೀಲಿಗಳು_ಹೊಂದಿಕೆ;	/* mask of HKF_MATCH_* from hostfile.h */
	ಪೂರ್ಣಾಂಕ *ಕೀಲಿಗಳು_verified;	/* flag for new keys verified by server */
	ಗಾತ್ರ_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	ರಚನೆ sshkey **old_ಕೀಲಿಗಳು;
	ಗಾತ್ರ_t nold;

	/* Various special cases. */
	ಪೂರ್ಣಾಂಕ complex_hostspec;	/* wildcard or manual pattern-list host name */
	ಪೂರ್ಣಾಂಕ ca_ಲಭ್ಯ;	/* saw CA key for this host */
	ಪೂರ್ಣಾಂಕ old_ಕೀಲಿ_ನೋಡಿದ;	/* saw old key with other name/addr */
	ಪೂರ್ಣಾಂಕ other_name_ನೋಡಿದ;	/* saw key with other name/addr */
};

ಸ್ಥಿರ ಶೂನ್ಯ
hostkeys_update_ctx_free(ರಚನೆ hostkeys_update_ctx *ctx)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (ctx == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->ಕೀಲಿಗಳು[i]);
	ಬಿಡುಗಡೆ(ctx->ಕೀಲಿಗಳು);
	ಬಿಡುಗಡೆ(ctx->ಕೀಲಿಗಳು_ಹೊಂದಿಕೆ);
	ಬಿಡುಗಡೆ(ctx->ಕೀಲಿಗಳು_verified);
	ಗಾಗಿ (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_ಕೀಲಿಗಳು[i]);
	ಬಿಡುಗಡೆ(ctx->old_ಕೀಲಿಗಳು);
	ಬಿಡುಗಡೆ(ctx->host_str);
	ಬಿಡುಗಡೆ(ctx->ip_str);
	ಬಿಡುಗಡೆ(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
hostspec_is_complex(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hosts)
{
	ಅಕ್ಷರ *cp;

	/* wildcard */
	ಆದರೆ (strchr(hosts, '*') != ಖಾಲಿ || strchr(hosts, '?') != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;
	/* single host/ip = ok */
	ಆದರೆ ((cp = strchr(hosts, ',')) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	/* more than two entries on the line */
	ಆದರೆ (strchr(cp + 1, ',') != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	ಹಿಂತಿರುಗಿ 0;
}

/* callback to search for ctx->keys in known_hosts */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
hostkeys_ಕಂಡುಹಿಡಿ(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ರಚನೆ hostkeys_update_ctx *ctx = (ರಚನೆ hostkeys_update_ctx *)_ctx;
	ಗಾತ್ರ_t i;
	ರಚನೆ sshkey **tmp;

	ಆದರೆ (l->ಕೀಲಿ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (l->ಸ್ಥಿತಿ_2 != HKF_ಸ್ಥಿತಿ_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		ಗಾಗಿ (i = 0; i < ctx->nkeys; i++) {
			ಆದರೆ (sshkey_equal(l->ಕೀಲಿ, ctx->ಕೀಲಿಗಳು[i])) {
				ctx->other_name_ನೋಡಿದ = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->ಕೀಲಿಗಳು[i]),
				    l->ಮಾರ್ಗ, l->linenum);
				ಹಿಂತಿರುಗಿ 0;
			}
		}
		ಹಿಂತಿರುಗಿ 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	ಆದರೆ (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->ಮಾರ್ಗ, l->linenum);
		ctx->complex_hostspec = 1;
		ಹಿಂತಿರುಗಿ 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	ಆದರೆ (ctx->ip_str != ಖಾಲಿ && strchr(l->hosts, ',') != ಖಾಲಿ) {
		ಆದರೆ ((l->ಹೊಂದಿಕೆ & HKF_ಹೊಂದಿಕೆ_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_ನೋಡಿದ = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->ಮಾರ್ಗ, l->linenum);
			ಹಿಂತಿರುಗಿ 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((l->ಹೊಂದಿಕೆ & HKF_ಹೊಂದಿಕೆ_IP) == 0) {
			/* Record if hostname matched a different address. */
			ctx->other_name_ನೋಡಿದ = 1;
			debug3_f("found hostname %s against different address "
			    "at %s:%ld", ctx->host_str, l->ಮಾರ್ಗ, l->linenum);
		}
	}

	/*
	 * UpdateHostkeys is skipped for wildcard host names and hostnames
	 * that contain more than two entries (ssh never writes these).
	 */
	ಆದರೆ (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->ಮಾರ್ಗ, l->linenum);
		ctx->complex_hostspec = 1;
		ಹಿಂತಿರುಗಿ 0;
	}

	/* Mark off keys we've already seen for this host */
	ಗಾಗಿ (i = 0; i < ctx->nkeys; i++) {
		ಆದರೆ (!sshkey_equal(l->ಕೀಲಿ, ctx->ಕೀಲಿಗಳು[i]))
			ಮುಂದುವರಿ;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->ಕೀಲಿಗಳು[i]), l->ಮಾರ್ಗ, l->linenum);
		ctx->ಕೀಲಿಗಳು_ಹೊಂದಿಕೆ[i] |= l->ಹೊಂದಿಕೆ;
		ಹಿಂತಿರುಗಿ 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->ಕೀಲಿ),
	    l->ಮಾರ್ಗ, l->linenum);
	ಆದರೆ ((tmp = recallocarray(ctx->old_ಕೀಲಿಗಳು, ctx->nold, ctx->nold + 1,
	    ಗಾತ್ರ(*ctx->old_ಕೀಲಿಗಳು))) == ಖಾಲಿ)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_ಕೀಲಿಗಳು = tmp;
	ctx->old_ಕೀಲಿಗಳು[ctx->nold++] = l->ಕೀಲಿ;
	l->ಕೀಲಿ = ಖಾಲಿ;

	ಹಿಂತಿರುಗಿ 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
hostkeys_check_old(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ರಚನೆ hostkeys_update_ctx *ctx = (ರಚನೆ hostkeys_update_ctx *)_ctx;
	ಗಾತ್ರ_t i;
	ಪೂರ್ಣಾಂಕ hashed;

	/* only care about lines that *don't* match the active host spec */
	ಆದರೆ (l->ಸ್ಥಿತಿ_2 == HKF_ಸ್ಥಿತಿ_MATCHED || l->ಕೀಲಿ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	hashed = l->ಹೊಂದಿಕೆ & (HKF_ಹೊಂದಿಕೆ_HOST_HASHED|HKF_ಹೊಂದಿಕೆ_IP_HASHED);
	ಗಾಗಿ (i = 0; i < ctx->nold; i++) {
		ಆದರೆ (!sshkey_equal(l->ಕೀಲಿ, ctx->old_ಕೀಲಿಗಳು[i]))
			ಮುಂದುವರಿ;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_ಕೀಲಿಗಳು[i]), l->ಮಾರ್ಗ, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_ಕೀಲಿ_ನೋಡಿದ = 1;
		ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_old_ಕೀಲಿಗಳು_othernames(ರಚನೆ hostkeys_update_ctx *ctx)
{
	ಗಾತ್ರ_t i;
	ಪೂರ್ಣಾಂಕ r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		ಆದರೆ ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_ಕೀಲಿ, 0)) != 0) {
			ಆದರೆ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				ಮುಂದುವರಿ;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

ಸ್ಥಿರ ಶೂನ್ಯ
update_ತಿಳಿದ_hosts(ರಚನೆ hostkeys_update_ctx *ctx)
{
	ಪೂರ್ಣಾಂಕ r, was_raw = 0, ಮೊದಲ = 1;
	ಪೂರ್ಣಾಂಕ asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	ಅಕ್ಷರ *fp, *response;
	ಗಾತ್ರ_t i;
	ರಚನೆ stat sb;

	ಗಾಗಿ (i = 0; i < ctx->nkeys; i++) {
		ಆದರೆ (!ctx->ಕೀಲಿಗಳು_verified[i])
			ಮುಂದುವರಿ;
		ಆದರೆ ((fp = sshkey_fingerprint(ctx->ಕೀಲಿಗಳು[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("sshkey_fingerprint failed");
		ಆದರೆ (ಮೊದಲ && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->ಕೀಲಿಗಳು[i]), fp);
		ಮೊದಲ = 0;
		ಬಿಡುಗಡೆ(fp);
	}
	ಗಾಗಿ (i = 0; i < ctx->nold; i++) {
		ಆದರೆ ((fp = sshkey_fingerprint(ctx->old_ಕೀಲಿಗಳು[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("sshkey_fingerprint failed");
		ಆದರೆ (ಮೊದಲ && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_ಕೀಲಿಗಳು[i]), fp);
		ಮೊದಲ = 0;
		ಬಿಡುಗಡೆ(fp);
	}
	ಆದರೆ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		ಆದರೆ (get_saved_tio() != ಖಾಲಿ) {
			leave_raw_ಬಹುಲಕ(1);
			was_raw = 1;
		}
		response = ಖಾಲಿ;
		ಗಾಗಿ (i = 0; !quit_pending && i < 3; i++) {
			ಬಿಡುಗಡೆ(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			ಆದರೆ (response != ಖಾಲಿ && strcasecmp(response, "yes") == 0)
				ನಿಲ್ಲಿಸು;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (quit_pending || response == ಖಾಲಿ ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				ನಿಲ್ಲಿಸು;
			} ಇಲ್ಲದಿದ್ದರೆ {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		ಆದರೆ (quit_pending || i >= 3 || response == ಖಾಲಿ)
			options.update_hostkeys = 0;
		ಬಿಡುಗಡೆ(response);
		ಆದರೆ (was_raw)
			enter_raw_ಬಹುಲಕ(1);
	}
	ಆದರೆ (options.update_hostkeys == 0)
		ಹಿಂತಿರುಗಿ;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		ಆದರೆ (stat(options.user_hostfiles[i], &sb) != 0) {
			ಆದರೆ (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} ಇಲ್ಲದಿದ್ದರೆ {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			ಮುಂದುವರಿ;
		}
		ಆದರೆ ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->ಕೀಲಿಗಳು : ಖಾಲಿ, i == 0 ? ctx->nkeys : 0,
		    options.hash_ತಿಳಿದ_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_global_hostkeys_prove_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ type,
    uint32_t seq, ಶೂನ್ಯ *_ctx)
{
	ರಚನೆ hostkeys_update_ctx *ctx = (ರಚನೆ hostkeys_update_ctx *)_ctx;
	ಗಾತ್ರ_t i, ndone;
	ರಚನೆ sshbuf *signdata;
	ಪೂರ್ಣಾಂಕ r, plaintype;
	ಸ್ಥಿರಾಂಕ u_char *sig;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rsa_kexalg = ಖಾಲಿ;
	ಅಕ್ಷರ *alg = ಖಾಲಿ;
	ಗಾತ್ರ_t siglen;

	ಆದರೆ (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	ಆದರೆ (type != SSH2_ಸಂದೇಶ_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == ಕೀಲಿ_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	ಆದರೆ ((signdata = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	ಗಾಗಿ (ndone = i = 0; i < ctx->nkeys; i++) {
		ಆದರೆ (ctx->ಕೀಲಿಗಳು_ಹೊಂದಿಕೆ[i])
			ಮುಂದುವರಿ;
		plaintype = sshkey_type_plain(ctx->ಕೀಲಿಗಳು[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		ಆದರೆ ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->ಕೀಲಿಗಳು[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		ಆದರೆ ((r = sshpkt_get_string_ನೇರ(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->ಕೀಲಿಗಳು[i]), i);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		ಆದರೆ (plaintype == ಕೀಲಿ_RSA && rsa_kexalg == ಖಾಲಿ &&
		    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			ಬಿಡುಗಡೆ(alg);
			/* zap the key from the list */
			sshkey_free(ctx->ಕೀಲಿಗಳು[i]);
			ctx->ಕೀಲಿಗಳು[i] = ಖಾಲಿ;
			ndone++;
			ಮುಂದುವರಿ;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->ಕೀಲಿಗಳು[i]), i, alg);
		ಬಿಡುಗಡೆ(alg);
		ಆದರೆ ((r = sshkey_verify(ctx->ಕೀಲಿಗಳು[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == ಕೀಲಿ_RSA ? rsa_kexalg : ಖಾಲಿ, 0, ಖಾಲಿ)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->ಕೀಲಿಗಳು[i]), i);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->ಕೀಲಿಗಳು_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	ಆದರೆ (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0) {
		error_f("protocol error");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Make the edits to known_hosts */
	update_ತಿಳಿದ_hosts(ctx);
 ಹೊರಹೋಗು:
	sshbuf_free(signdata);
	hostkeys_update_ctx_free(ctx);
	hostkeys_update_complete = 1;
	client_repledge();
}

/*
 * Handle hostkeys-00@openssh.com global request to inform the client of all
 * the server's hostkeys. The keys are checked against the user's
 * HostkeyAlgorithms preference before they are accepted.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
client_ಒಳಹರಿವು_hostkeys(ರಚನೆ ssh *ssh)
{
	ಸ್ಥಿರಾಂಕ u_char *blob = ಖಾಲಿ;
	ಗಾತ್ರ_t i, len = 0;
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ, **tmp;
	ಪೂರ್ಣಾಂಕ r, prove_ಕಳುಹಿಸಿದ = 0;
	ಅಕ್ಷರ *fp;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ hostkeys_ನೋಡಿದ = 0; /* XXX use struct ssh */
	ಬಾಹ್ಯ ರಚನೆ sockaddr_storage hostaddr; /* XXX from ssh.c */
	ರಚನೆ hostkeys_update_ctx *ctx = ಖಾಲಿ;
	u_int want;

	ಆದರೆ (hostkeys_ನೋಡಿದ)
		fatal_f("server already sent hostkeys");
	ಆದರೆ (!can_update_hostkeys())
		ಹಿಂತಿರುಗಿ 1;
	hostkeys_ನೋಡಿದ = 1;

	ctx = xcalloc(1, ಗಾತ್ರ(*ctx));
	ಆಗ (ssh_packet_ಉಳಿದ(ssh) > 0) {
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ಖಾಲಿ;
		ಆದರೆ ((r = sshpkt_get_string_ನೇರ(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshkey_from_blob(blob, len, &ಕೀಲಿ)) != 0) {
			do_log2_fr(r, r == SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			ಮುಂದುವರಿ;
		}
		fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(ಕೀಲಿ), fp);
		ಬಿಡುಗಡೆ(fp);

		ಆದರೆ (!hostkey_accepted_by_hostkeyalgs(ಕೀಲಿ)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(ಕೀಲಿ));
			ಮುಂದುವರಿ;
		}
		/* Skip certs */
		ಆದರೆ (sshkey_is_cert(ಕೀಲಿ)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(ಕೀಲಿ));
			ಮುಂದುವರಿ;
		}
		/* Ensure keys are unique */
		ಗಾಗಿ (i = 0; i < ctx->nkeys; i++) {
			ಆದರೆ (sshkey_equal(ಕೀಲಿ, ctx->ಕೀಲಿಗಳು[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(ಕೀಲಿ));
				ಹೋಗು ಹೊರಹೋಗು;
			}
		}
		/* Key is good, record it */
		ಆದರೆ ((tmp = recallocarray(ctx->ಕೀಲಿಗಳು, ctx->nkeys, ctx->nkeys + 1,
		    ಗಾತ್ರ(*ctx->ಕೀಲಿಗಳು))) == ಖಾಲಿ)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->ಕೀಲಿಗಳು = tmp;
		ctx->ಕೀಲಿಗಳು[ctx->nkeys++] = ಕೀಲಿ;
		ಕೀಲಿ = ಖಾಲಿ;
	}

	ಆದರೆ (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((ctx->ಕೀಲಿಗಳು_ಹೊಂದಿಕೆ = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(ctx->nkeys,
	    ಗಾತ್ರ(*ctx->ಕೀಲಿಗಳು_ಹೊಂದಿಕೆ))) == ಖಾಲಿ ||
	    (ctx->ಕೀಲಿಗಳು_verified = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(ctx->nkeys,
	    ಗಾತ್ರ(*ctx->ಕೀಲಿಗಳು_verified))) == ಖಾಲಿ)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (ರಚನೆ sockaddr *)&hostaddr : ಖಾಲಿ,
	    options.ಪೋರ್ಟ್, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : ಖಾಲಿ);

	/* Find which keys we already know about. */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		ಆದರೆ ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_ಕಂಡುಹಿಡಿ, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_ಕೀಲಿ, 0)) != 0) {
			ಆದರೆ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				ಮುಂದುವರಿ;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_ಹೊಂದಿಕೆ_HOST | ( options.check_host_ip ? HKF_ಹೊಂದಿಕೆ_IP : 0);
	ಗಾಗಿ (i = 0; i < ctx->nkeys; i++) {
		ಆದರೆ (ctx->ಕೀಲಿಗಳು_ಹೊಂದಿಕೆ[i] == 0)
			ctx->nnew++;
		ಆದರೆ ((ctx->ಕೀಲಿಗಳು_ಹೊಂದಿಕೆ[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	ಆದರೆ (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Various reasons why we cannot proceed with the update */
	ಆದರೆ (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ctx->other_name_ನೋಡಿದ) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	ಆದರೆ (ctx->nold != 0) {
		ಆದರೆ (check_old_ಕೀಲಿಗಳು_othernames(ctx) != 0)
			ಹೋಗು ಹೊರಹೋಗು; /* error already logged */
		ಆದರೆ (ctx->old_ಕೀಲಿ_ನೋಡಿದ) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == ಖಾಲಿ ? "" : ",",
			    ctx->ip_str == ಖಾಲಿ ? "" : ctx->ip_str);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	ಆದರೆ (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_ತಿಳಿದ_hosts(ctx);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಗಾಗಿ (i = 0; i < ctx->nkeys; i++) {
		ಆದರೆ (ctx->ಕೀಲಿಗಳು_ಹೊಂದಿಕೆ[i])
			ಮುಂದುವರಿ;
		sshbuf_reset(buf);
		ಆದರೆ ((r = sshkey_putb(ctx->ಕೀಲಿಗಳು[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_ರಿಜಿಸ್ಟರ್_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = ಖಾಲಿ;  /* will be freed in callback */
	prove_ಕಳುಹಿಸಿದ = 1;

	/* Success */
 ಹೊರಹೋಗು:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(buf);
	ಆದರೆ (!prove_ಕಳುಹಿಸಿದ) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
client_ಒಳಹರಿವು_global_request(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ *rtype;
	u_char want_ಉತ್ತರ;
	ಪೂರ್ಣಾಂಕ r, success = 0;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &rtype, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_ಉತ್ತರ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_ಉತ್ತರ);
	ಆದರೆ (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_ಒಳಹರಿವು_hostkeys(ssh);
	ಆದರೆ (want_ಉತ್ತರ) {
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, success ? SSH2_ಸಂದೇಶ_REQUEST_SUCCESS :
		    SSH2_ಸಂದೇಶ_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(rtype);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_send_env(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *val)
{
	ಪೂರ್ಣಾಂಕ r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_ಆರಂಭ(ssh, id, "env", 0);
	ಆದರೆ ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

ಶೂನ್ಯ
client_session2_ಸಿದ್ಧತೆ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ want_tty, ಪೂರ್ಣಾಂಕ want_subsystem,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪದ, ರಚನೆ termios *tiop, ಪೂರ್ಣಾಂಕ ಒಳ_fd, ರಚನೆ sshbuf *cmd,
    ಅಕ್ಷರ **env)
{
	ಗಾತ್ರ_t i, j, len;
	ಪೂರ್ಣಾಂಕ matched, r;
	ಅಕ್ಷರ *type = ಖಾಲಿ, *cmdstring = ಖಾಲಿ, *name, *val;
	Channel *c = ಖಾಲಿ;

	debug2_f("id %d", id);

	ಆದರೆ ((c = channel_lookup(ssh, id)) == ಖಾಲಿ)
		fatal_f("channel %d: unknown channel", id);

	ಆದರೆ (want_tty) {
		ರಚನೆ winsize ws;

		/* Store window size in the packet. */
		ಆದರೆ (ioctl(ಒಳ_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, ಗಾತ್ರ(ws));

		channel_request_ಆರಂಭ(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, ಪದ != ಖಾಲಿ ? ಪದ : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ಲಂಬಸಾಲು)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ಅಡ್ಡಸಾಲು)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		ಆದರೆ (tiop == ಖಾಲಿ)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	ಆದರೆ (options.ಅಂಕೆ_send_env != 0 && env != ಖಾಲಿ) {
		debug("Sending environment.");
		ಗಾಗಿ (i = 0; env[i] != ಖಾಲಿ; i++) {
			/*ವಿಭಜಿಸು*/
			name = xstrdup(env[i]);
			ಆದರೆ ((val = strchr(name, '=')) == ಖಾಲಿ) {
				ಬಿಡುಗಡೆ(name);
				ಮುಂದುವರಿ;
			}
			*val++ = '\0';

			matched = 0;
			ಗಾಗಿ (j = 0; j < options.ಅಂಕೆ_send_env; j++) {
				ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ(name, options.send_env[j])) {
					matched = 1;
					ನಿಲ್ಲಿಸು;
				}
			}
			ಆದರೆ (!matched) {
				debug3("Ignored env %s", name);
				ಬಿಡುಗಡೆ(name);
				ಮುಂದುವರಿ;
			}
			client_send_env(ssh, id, name, val);
			ಬಿಡುಗಡೆ(name);
		}
	}
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_setenv; i++) {
		/*ವಿಭಜಿಸು*/
		name = xstrdup(options.setenv[i]);
		ಆದರೆ ((val = strchr(name, '=')) == ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(name);
			ಮುಂದುವರಿ;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		ಬಿಡುಗಡೆ(name);
	}

	len = sshbuf_len(cmd);
	ಆದರೆ (len > 0) {
		ಆದರೆ ((cmdstring = sshbuf_dup_string(cmd)) == ಖಾಲಿ)
			fatal_f("sshbuf_dup_string failed");
		ಆದರೆ (len > 900)
			len = 900;
		ಆದರೆ (want_subsystem) {
			debug("Sending subsystem: %.*s", (ಪೂರ್ಣಾಂಕ)len, cmdstring);
			channel_request_ಆರಂಭ(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug("Sending command: %.*s", (ಪೂರ್ಣಾಂಕ)len, cmdstring);
			channel_request_ಆರಂಭ(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		ಆದರೆ ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} ಇಲ್ಲದಿದ್ದರೆ {
		channel_request_ಆರಂಭ(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_ಗಣ_xtype(ssh, id, type);
	ಬಿಡುಗಡೆ(cmdstring);
	ಬಿಡುಗಡೆ(type);

	session_ಸಿದ್ಧತೆ_complete = 1;
	client_repledge();
}

ಶೂನ್ಯ
client_channel_request_agent_forwarding(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *req = "auth-agent-req@openssh.com";
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ssh->kex != ಖಾಲಿ && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_ಆರಂಭ(ssh, id, req, 0);
	ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_init_dispatch(ರಚನೆ ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_CLOSE, &channel_ಒಳಹರಿವು_oclose);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ, &channel_ಒಳಹರಿವು_ದತ್ತಾಂಶ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EOF, &channel_ಒಳಹರಿವು_ieof);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_ದತ್ತಾಂಶ, &channel_ಒಳಹರಿವು_extended_ದತ್ತಾಂಶ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN, &client_ಒಳಹರಿವು_channel_open);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION, &channel_ಒಳಹರಿವು_open_confirmation);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE, &channel_ಒಳಹರಿವು_open_failure);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST, &client_ಒಳಹರಿವು_channel_req);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_ಕಿಟಕಿ_ADJUST, &channel_ಒಳಹರಿವು_ಕಿಟಕಿ_adjust);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS, &channel_ಒಳಹರಿವು_ಸ್ಥಿತಿ_confirm);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_FAILURE, &channel_ಒಳಹರಿವು_ಸ್ಥಿತಿ_confirm);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST, &client_ಒಳಹರಿವು_global_request);

	/* rekeying */
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEXINIT, &kex_ಒಳಹರಿವು_kexinit);

	/* global request reply messages */
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_REQUEST_FAILURE, &client_global_request_ಉತ್ತರ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_REQUEST_SUCCESS, &client_global_request_ಉತ್ತರ);
}

ಶೂನ್ಯ
client_stop_mux(ಶೂನ್ಯ)
{
	ಆದರೆ (options.control_ಮಾರ್ಗ != ಖಾಲಿ && muxserver_sock != -1)
		unlink(options.control_ಮಾರ್ಗ);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	ಆದರೆ (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ i)
{
	leave_raw_ಬಹುಲಕ(options.request_tty == REQUEST_TTY_FORCE);
	ಆದರೆ (options.control_ಮಾರ್ಗ != ಖಾಲಿ && muxserver_sock != -1)
		unlink(options.control_ಮಾರ್ಗ);
	ssh_kill_proxy_command();
	_exit(i);
}
