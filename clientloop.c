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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "clientloop.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshconnect.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshpty.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEYSTROKE_TIMING_FUZZ 10

ਬਾਹਰੀ ਅੱਖਰ *__progname;

/* import options */
ਬਾਹਰੀ Options options;

/* Control socket */
ਬਾਹਰੀ ਪੂਰਨ muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
ਬਾਹਰੀ ਅੱਖਰ *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
ਬਾਹਰੀ ਅੱਖਰ *forward_agent_sock_ਰਸਤਾ;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t received_ਖਿੜਕੀ_change_signal = 0;
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t siginfo_received = 0;
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
ਸਥਿਰ time_t control_persist_exit_ਸਮਾਂ = 0;

/* Common data for the client loop code. */
ਅਸਥਿਰ sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
ਸਥਿਰ ਪੂਰਨ ਆਖਰੀ_was_cr;		/* Last character was a newline. */
ਸਥਿਰ ਪੂਰਨ exit_ਸਥਿਤੀ;		/* Used to store the command exit status. */
ਸਥਿਰ ਪੂਰਨ connection_ਵਿੱਚ;	/* Connection to server (input). */
ਸਥਿਰ ਪੂਰਨ connection_ਬਾਹਰਲਾ;	/* Connection to server (output). */
ਸਥਿਰ ਪੂਰਨ need_rekeying;	/* Set to non-zero if rekeying is requested. */
ਸਥਿਰ ਪੂਰਨ session_closed;	/* In SSH2: login session closed. */
ਸਥਿਰ time_t x11_refuse_ਸਮਾਂ;	/* If >0, refuse x11 opens after this time. */
ਸਥਿਰ time_t server_alive_ਸਮਾਂ;	/* Time to do server_alive_check */
ਸਥਿਰ ਪੂਰਨ hostkeys_update_complete;
ਸਥਿਰ ਪੂਰਨ session_ਤਿਆਰੀ_complete;

ਸਥਿਰ ਖਾਲੀ client_init_dispatch(ਬਣਤਰ ssh *ssh);
ਪੂਰਨ	session_ident = -1;

/* Track escape per proto2 channel */
ਬਣਤਰ escape_filter_ctx {
	ਪੂਰਨ escape_pending;
	ਪੂਰਨ escape_char;
};

/* Context for channel confirmation replies */
ਬਣਤਰ channel_ਜਵਾਬ_ctx {
	ਅਚਲ ਅੱਖਰ *request_type;
	ਪੂਰਨ id;
	ਗਿਣਤੀ confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
ਬਣਤਰ global_confirm {
	TAILQ_ENTRY(global_confirm) ਇੰਦਰਾਜ;
	global_confirm_cb *cb;
	ਖਾਲੀ *ctx;
	ਪੂਰਨ ref_ਗਿਣਤੀ;
};
TAILQ_HEAD(global_confirms, global_confirm);
ਸਥਿਰ ਬਣਤਰ global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

ਸਥਿਰ ਖਾਲੀ quit_ਸੁਨੇਹਾ(ਅਚਲ ਅੱਖਰ *fmt, ...)
    __attribute__((__format__ (ਲਿਖੋ, 1, 2)));

ਸਥਿਰ ਖਾਲੀ
quit_ਸੁਨੇਹਾ(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ, *fmt2;
	va_list ਦਲੀਲਾਂ;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(ਦਲੀਲਾਂ, fmt);
	xvasprintf(&ਸੁਨੇਹਾ, fmt2, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);

	(ਖਾਲੀ)atomicio(vwrite, STDERR_FILENO, ਸੁਨੇਹਾ, ਲੜੀ_ਲੰਬਾਈ(ਸੁਨੇਹਾ));
	ਮੁਕਤ(ਸੁਨੇਹਾ);
	ਮੁਕਤ(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
ਸਥਿਰ ਖਾਲੀ
ਖਿੜਕੀ_change_handler(ਪੂਰਨ sig)
{
	received_ਖਿੜਕੀ_change_signal = 1;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
/* Signal handler for SIGINFO */
ਸਥਿਰ ਖਾਲੀ
siginfo_handler(ਪੂਰਨ sig)
{
	siginfo_received = 1;
}
#ਜੇ_ਅੰਤ

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
ਸਥਿਰ ਖਾਲੀ
signal_handler(ਪੂਰਨ sig)
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
ਸਥਿਰ ਖਾਲੀ
ਸੈੱਟ_control_persist_exit_ਸਮਾਂ(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_ਸਮਾਂ = 0;
	} ਨਹੀਂਤਾਂ ਜੇ (channel_still_open(ssh)) {
		/* some client connections are still open */
		ਜੇ (control_persist_exit_ਸਮਾਂ > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_ਸਮਾਂ = 0;
	} ਨਹੀਂਤਾਂ ਜੇ (control_persist_exit_ਸਮਾਂ <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_ਸਮਾਂ = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
ਸਥਿਰ ਪੂਰਨ
client_x11_display_valid(ਅਚਲ ਅੱਖਰ *display)
{
	ਮਾਪ_t i, dlen;

	ਜੇ (display == ਨਿਰਾ)
		ਵਾਪਸ 0;

	dlen = ਲੜੀ_ਲੰਬਾਈ(display);
	ਲਈ (i = 0; i < dlen; i++) {
		ਜੇ (!ਅੱਖਰ_ਜਾਂ_ਅੰਕ((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == ਨਿਰਾ) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			ਵਾਪਸ 0;
		}
	}
	ਵਾਪਸ 1;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ X11_TIMEOUT_SLACK	60
ਪੂਰਨ
client_x11_get_proto(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *display,
    ਅਚਲ ਅੱਖਰ *xauth_ਰਸਤਾ, u_int trusted, u_int timeout,
    ਅੱਖਰ **_proto, ਅੱਖਰ **ਅੰਕੜੇ_2)
{
	ਅੱਖਰ *cmd, ਸਤਰ[512], xdisplay[512];
	ਅੱਖਰ xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	ਸਥਿਰ ਅੱਖਰ proto[512], ਅੰਕੜੇ[512];
	FILE *f;
	ਪੂਰਨ got_ਅੰਕੜੇ = 0, generated = 0, do_unlink = 0, r;
	ਬਣਤਰ stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*ਅੰਕੜੇ_2 = ਅੰਕੜੇ;
	proto[0] = ਅੰਕੜੇ[0] = xauthfile[0] = xauthdir[0] = '\0';

	ਜੇ (!client_x11_display_valid(display)) {
		ਜੇ (display != ਨਿਰਾ)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		ਵਾਪਸ -1;
	}
	ਜੇ (xauth_ਰਸਤਾ != ਨਿਰਾ && stat(xauth_ਰਸਤਾ, &st) == -1) {
		debug("No xauth program.");
		xauth_ਰਸਤਾ = ਨਿਰਾ;
	}

	ਜੇ (xauth_ਰਸਤਾ != ਨਿਰਾ) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(display, "localhost:", 10) == 0) {
			ਜੇ ((r = snprintf(xdisplay, ਆਕਾਰ(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (ਮਾਪ_t)r >= ਆਕਾਰ(xdisplay)) {
				error_f("display name too long");
				ਵਾਪਸ -1;
			}
			display = xdisplay;
		}
		ਜੇ (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, ਆਕਾਰ(xauthdir));
			ਜੇ (mkdtemp(xauthdir) == ਨਿਰਾ) {
				error_f("mkdtemp: %s", strerror(errno));
				ਵਾਪਸ -1;
			}
			do_unlink = 1;
			ਜੇ ((r = snprintf(xauthfile, ਆਕਾਰ(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (ਮਾਪ_t)r >= ਆਕਾਰ(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				ਵਾਪਸ -1;
			}

			ਜੇ (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_ਰਸਤਾ, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} ਨਹੀਂਤਾਂ {
				/* Add some slack to requested expiry */
				ਜੇ (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				ਨਹੀਂਤਾਂ {
					/* Don't overflow on long timeouts */
					x11_timeout_real = UINT_MAX;
				}
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted timeout %u 2>%s",
				    xauth_ਰਸਤਾ, xauthfile, display,
				    SSH_X11_PROTO, x11_timeout_real,
				    _PATH_DEVNULL);
			}
			debug2_f("xauth command: %s", cmd);

			ਜੇ (timeout != 0 && x11_refuse_ਸਮਾਂ == 0) {
				now = monotime() + 1;
				ਜੇ (SSH_ਸਮਾਂ_T_MAX - timeout < now)
					x11_refuse_ਸਮਾਂ = SSH_ਸਮਾਂ_T_MAX;
				ਨਹੀਂਤਾਂ
					x11_refuse_ਸਮਾਂ = now + timeout;
				channel_ਸੈੱਟ_x11_refuse_ਸਮਾਂ(ssh,
				    x11_refuse_ਸਮਾਂ);
			}
			ਜੇ (system(cmd) == 0)
				generated = 1;
			ਮੁਕਤ(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		ਜੇ (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_ਰਸਤਾ,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			ਜੇ (f && fgets(ਸਤਰ, ਆਕਾਰ(ਸਤਰ), f) &&
			    ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(ਸਤਰ, "%*s %511s %511s", proto, ਅੰਕੜੇ) == 2)
				got_ਅੰਕੜੇ = 1;
			ਜੇ (f)
				pclose(f);
			ਮੁਕਤ(cmd);
		}
	}

	ਜੇ (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	ਜੇ (!trusted && !got_ਅੰਕੜੇ) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		ਵਾਪਸ -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	ਜੇ (!got_ਅੰਕੜੇ) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, ਆਕਾਰ proto);
		arc4random_buf(rnd, ਆਕਾਰ(rnd));
		ਲਈ (i = 0; i < ਆਕਾਰ(rnd); i++) {
			snprintf(ਅੰਕੜੇ + 2 * i, ਆਕਾਰ ਅੰਕੜੇ - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	ਵਾਪਸ 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

ਸਥਿਰ ਖਾਲੀ
client_check_ਖਿੜਕੀ_change(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (!received_ਖਿੜਕੀ_change_signal)
		ਵਾਪਸ;
	received_ਖਿੜਕੀ_change_signal = 0;
	debug2_f("changed");
	channel_send_ਖਿੜਕੀ_changes(ssh);
}

ਸਥਿਰ ਪੂਰਨ
client_global_request_ਜਵਾਬ(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ global_confirm *gc;

	ਜੇ ((gc = TAILQ_FIRST(&global_confirms)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (gc->cb != ਨਿਰਾ)
		gc->cb(ssh, type, seq, gc->ctx);
	ਜੇ (--gc->ref_ਗਿਣਤੀ <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, ਇੰਦਰਾਜ);
		freezero(gc, ਆਕਾਰ(*gc));
	}

	ssh_packet_ਸੈੱਟ_alive_timeouts(ssh, 0);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
ਸਮਾਂ_ਸਾਰਣੀ_server_alive_check(ਖਾਲੀ)
{
	ਜੇ (options.server_alive_interval > 0)
		server_alive_ਸਮਾਂ = monotime() + options.server_alive_interval;
}

ਸਥਿਰ ਖਾਲੀ
server_alive_check(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	ਜੇ (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_ਗਿਣਤੀ_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_ਰਜਿਸਟਰ_global_confirm(ਨਿਰਾ, ਨਿਰਾ);
	ਸਮਾਂ_ਸਾਰਣੀ_server_alive_check();
}

/* Try to send a dummy keystroke */
ਸਥਿਰ ਪੂਰਨ
send_chaff(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	ਜੇ (ssh->kex == ਨਿਰਾ || (ssh->kex->flags & KEX_HAS_PING) == 0)
		ਵਾਪਸ 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ਵਾਪਸ 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
ਸਥਿਰ ਖਾਲੀ
ਸੈੱਟ_ਅਗਲਾ_interval(ਅਚਲ ਬਣਤਰ timespec *now, ਬਣਤਰ timespec *ਅਗਲਾ_interval,
    u_int interval_ms, ਪੂਰਨ starting)
{
	ਬਣਤਰ timespec tmp;
	ਲੰਮਾ ਲੰਮਾ interval_ns, fuzz_ns;
	ਸਥਿਰ ਲੰਮਾ ਲੰਮਾ ਦਰ_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	ਜੇ (fuzz_ns > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		fuzz_ns = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
	ਜੇ (fuzz_ns > interval_ns) {
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
	ਜੇ (starting)
		ਦਰ_fuzz = arc4random_ਇਕਸਾਰ(fuzz_ns);
	interval_ns -= fuzz_ns;
	interval_ns += arc4random_ਇਕਸਾਰ(fuzz_ns) + ਦਰ_fuzz;

	tmp.tv_sec = interval_ns / (1000 * 1000 * 1000);
	tmp.tv_nsec = interval_ns % (1000 * 1000 * 1000);

	timespecadd(now, &tmp, ਅਗਲਾ_interval);
}

/*
 * Performs keystroke timing obfuscation. Returns non-zero if the
 * output fd should be polled.
 */
ਸਥਿਰ ਪੂਰਨ
obfuscate_keystroke_timing(ਬਣਤਰ ssh *ssh, ਬਣਤਰ timespec *timeout,
    ਪੂਰਨ channel_did_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ)
{
	ਸਥਿਰ ਪੂਰਨ ਸਰਗਰਮ;
	ਸਥਿਰ ਬਣਤਰ timespec ਅਗਲਾ_interval, chaff_until;
	ਬਣਤਰ timespec now, tmp;
	ਪੂਰਨ just_started = 0, had_keystroke = 0;
	ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ nchaff;
	ਅੱਖਰ *stop_reason = ਨਿਰਾ;
	ਲੰਮਾ ਲੰਮਾ n;

	monotime_ts(&now);

	ਜੇ (options.obscure_keystroke_timing_interval <= 0)
		ਵਾਪਸ 1;	/* disabled in config */

	ਜੇ (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} ਨਹੀਂਤਾਂ ਜੇ (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} ਨਹੀਂਤਾਂ ਜੇ (!ssh_packet_interactive_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh) &&
	    ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} ਨਹੀਂਤਾਂ ਜੇ (ਸਰਗਰਮ && channel_did_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ &&
	    ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} ਨਹੀਂਤਾਂ ਜੇ (ਸਰਗਰਮ) {
		ਜੇ (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} ਨਹੀਂਤਾਂ ਜੇ (timespeccmp(&now, &ਅਗਲਾ_interval, >=) &&
		    !ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			ਜੇ (send_chaff(ssh))
				nchaff++;
		}
	}

	ਜੇ (stop_reason != ਨਿਰਾ) {
		ਜੇ (ਸਰਗਰਮ) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			ਸਰਗਰਮ = 0;
		}
		ਵਾਪਸ 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	ਜੇ (!ਸਰਗਰਮ && ssh_packet_interactive_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh) &&
	    channel_did_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ && ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = ਸਰਗਰਮ = 1;
		nchaff = 0;
		ਸੈੱਟ_ਅਗਲਾ_interval(&now, &ਅਗਲਾ_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	ਜੇ (!ਸਰਗਰਮ)
		ਵਾਪਸ 1;

	ਜੇ (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_ਮੰਜ਼ਿਲ_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_ਇਕਸਾਰ(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &ਅਗਲਾ_interval);

	ਜੇ (just_started)
		ਵਾਪਸ 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	ਜੇ (timespeccmp(&now, &ਅਗਲਾ_interval, <))
		/* ...unless there's x11 communication happening */
		ਵਾਪਸ x11_channel_ਵਰਤਿਆ_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - ਅਗਲਾ_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - ਅਗਲਾ_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	ਸੈੱਟ_ਅਗਲਾ_interval(&now, &ਅਗਲਾ_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	ਵਾਪਸ 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
ਸਥਿਰ ਖਾਲੀ
client_wait_until_can_do_something(ਬਣਤਰ ssh *ssh, ਬਣਤਰ pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, ਪੂਰਨ channel_did_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ,
    sigset_t *sigsetp, ਪੂਰਨ *conn_ਵਿੱਚ_readyp, ਪੂਰਨ *conn_ਬਾਹਰਲਾ_readyp)
{
	ਬਣਤਰ timespec timeout;
	ਪੂਰਨ ret, oready;
	u_int p;

	*conn_ਵਿੱਚ_readyp = *conn_ਬਾਹਰਲਾ_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	ਜੇ (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	ਜੇ (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh)) {
		/* clear events since we did not call poll() */
		ਲਈ (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ਵਾਪਸ;
	}

	oready = obfuscate_keystroke_timing(ssh, &timeout, channel_did_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ);

	/* Monitor server connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_ਵਿੱਚ;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_ਬਾਹਰਲਾ;
	(*pfdp)[1].events = (oready && ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh)) ?
	    POLLOUT : 0;

	/*
	 * Wait for something to happen.  This will suspend the process until
	 * some polled descriptor can be read, written, or has some other
	 * event pending, or a timeout expires.
	 */
	ਸੈੱਟ_control_persist_exit_ਸਮਾਂ(ssh);
	ਜੇ (control_persist_exit_ਸਮਾਂ > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_ਸਮਾਂ);
	ਜੇ (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_ਸਮਾਂ);
	ਜੇ (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	ਜੇ (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		ਲਈ (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ਜੇ (errno == EINTR)
			ਵਾਪਸ;
		/* Note: we might still have data in the buffers. */
		quit_ਸੁਨੇਹਾ("poll: %s", strerror(errno));
		ਵਾਪਸ;
	}

	*conn_ਵਿੱਚ_readyp = (*pfdp)[0].revents != 0;
	*conn_ਬਾਹਰਲਾ_readyp = (*pfdp)[1].revents != 0;

	ਜੇ (options.server_alive_interval > 0 && !*conn_ਵਿੱਚ_readyp &&
	    monotime() >= server_alive_ਸਮਾਂ) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

ਸਥਿਰ ਖਾਲੀ
client_suspend_self(ਬਣਤਰ sshbuf *bin, ਬਣਤਰ sshbuf *bout, ਬਣਤਰ sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	ਜੇ (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	ਜੇ (sshbuf_len(berr) > 0)
		atomicio(vwrite, fileno(stderr), sshbuf_mutable_ptr(berr),
		    sshbuf_len(berr));

	leave_raw_ਬਹੁਲਕ(options.request_tty == REQUEST_TTY_FORCE);

	sshbuf_reset(bin);
	sshbuf_reset(bout);
	sshbuf_reset(berr);

	/* Send the suspend signal to the program itself. */
	kill(getpid(), SIGTSTP);

	/* Reset window sizes in case they have changed */
	received_ਖਿੜਕੀ_change_signal = 1;

	enter_raw_ਬਹੁਲਕ(options.request_tty == REQUEST_TTY_FORCE);
}

ਸਥਿਰ ਖਾਲੀ
client_process_net_ਨਿਵੇਸ਼(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	ਸਮਾਂ_ਸਾਰਣੀ_server_alive_check();
	ਜੇ ((r = ssh_packet_process_read(ssh, connection_ਵਿੱਚ)) == 0)
		ਵਾਪਸ; /* success */
	ਜੇ (r == SSH_ERR_SYSTEM_ERROR) {
		ਜੇ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ਵਾਪਸ;
		ਜੇ (errno == EPIPE) {
			quit_ਸੁਨੇਹਾ("Connection to %s closed by remote host.",
			    host);
			ਵਾਪਸ;
		}
	}
	quit_ਸੁਨੇਹਾ("Read from remote host %s: %s", host, ssh_err(r));
}

ਸਥਿਰ ਖਾਲੀ
client_ਸਥਿਤੀ_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ type, Channel *c, ਖਾਲੀ *ctx)
{
	ਬਣਤਰ channel_ਜਵਾਬ_ctx *cr = (ਬਣਤਰ channel_ਜਵਾਬ_ctx *)ctx;
	ਅੱਖਰ errmsg[256];
	ਪੂਰਨ r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	ਜੇ (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	ਜੇ (type == SSH2_ਸੁਨੇਹਾ_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} ਨਹੀਂਤਾਂ ਜੇ (type == SSH2_ਸੁਨੇਹਾ_CHANNEL_FAILURE) {
		ਜੇ (tochan) {
			snprintf(errmsg, ਆਕਾਰ(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} ਨਹੀਂਤਾਂ {
			snprintf(errmsg, ਆਕਾਰ(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		ਜੇ (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		ਜੇ (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			ਜੇ ((r = sshbuf_put(c->extended, errmsg,
			    ਲੜੀ_ਲੰਬਾਈ(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} ਨਹੀਂਤਾਂ
			error("%s", errmsg);
		ਜੇ (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			ਜੇ (c->self == session_ident)
				leave_raw_ਬਹੁਲਕ(0);
			ਨਹੀਂਤਾਂ
				mux_tty_alloc_failed(ssh, c);
		} ਨਹੀਂਤਾਂ ਜੇ (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	ਮੁਕਤ(cr);
}

ਸਥਿਰ ਖਾਲੀ
client_abandon_ਸਥਿਤੀ_confirm(ਬਣਤਰ ssh *ssh, Channel *c, ਖਾਲੀ *ctx)
{
	ਮੁਕਤ(ctx);
}

ਖਾਲੀ
client_expect_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਅਚਲ ਅੱਖਰ *request,
    ਗਿਣਤੀ confirm_action action)
{
	ਬਣਤਰ channel_ਜਵਾਬ_ctx *cr = xcalloc(1, ਆਕਾਰ(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_ਰਜਿਸਟਰ_ਸਥਿਤੀ_confirm(ssh, id, client_ਸਥਿਤੀ_confirm,
	    client_abandon_ਸਥਿਤੀ_confirm, cr);
}

ਖਾਲੀ
client_ਰਜਿਸਟਰ_global_confirm(global_confirm_cb *cb, ਖਾਲੀ *ctx)
{
	ਬਣਤਰ global_confirm *gc, *ਆਖਰੀ_gc;

	/* Coalesce identical callbacks */
	ਆਖਰੀ_gc = TAILQ_LAST(&global_confirms, global_confirms);
	ਜੇ (ਆਖਰੀ_gc && ਆਖਰੀ_gc->cb == cb && ਆਖਰੀ_gc->ctx == ctx) {
		ਜੇ (++ਆਖਰੀ_gc->ref_ਗਿਣਤੀ >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
			fatal_f("last_gc->ref_count = %d",
			    ਆਖਰੀ_gc->ref_ਗਿਣਤੀ);
		ਵਾਪਸ;
	}

	gc = xcalloc(1, ਆਕਾਰ(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_ਗਿਣਤੀ = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, ਇੰਦਰਾਜ);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
ਸਥਿਰ ਪੂਰਨ
can_update_hostkeys(ਖਾਲੀ)
{
	ਜੇ (hostkeys_update_complete)
		ਵਾਪਸ 0;
	ਜੇ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_ਬਹੁਲਕ)
		ਵਾਪਸ 0; /* won't ask in batchmode, so don't even try */
	ਜੇ (!options.update_hostkeys || options.ਅੰਕ_user_hostfiles <= 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
client_repledge(ਖਾਲੀ)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	ਜੇ (options.control_master || options.control_ਰਸਤਾ != ਨਿਰਾ ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != ਨਿਰਾ || can_update_hostkeys() ||
	    (session_ident != -1 && !session_ਤਿਆਰੀ_complete)) {
		/* Can't tighten */
		ਵਾਪਸ;
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
	ਜੇ (options.ਅੰਕ_local_forwards != 0 ||
	    options.ਅੰਕ_remote_forwards != 0 ||
	    options.ਅੰਕ_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		ਜੇ (pledge("stdio unix inet dns proc tty", ਨਿਰਾ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} ਨਹੀਂਤਾਂ ਜੇ (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		ਜੇ (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", ਨਿਰਾ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} ਨਹੀਂਤਾਂ {
		debug("pledge: fork");
		ਜੇ (pledge(PLEDGE_EXTRA_INET "stdio proc tty", ਨਿਰਾ) == -1)
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

ਸਥਿਰ ਖਾਲੀ
process_cmdline(ਬਣਤਰ ssh *ssh)
{
	ਖਾਲੀ (*handler)(ਪੂਰਨ);
	ਅੱਖਰ *s, *cmd;
	ਪੂਰਨ ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	ਬਣਤਰ Forward fwd;

	memset(&fwd, 0, ਆਕਾਰ(fwd));

	leave_raw_ਬਹੁਲਕ(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	ਜੇ (s == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜਦੋਂ (ਖਾਲੀ_ਥਾਂ_ਹੈ((u_char)*s))
		s++;
	ਜੇ (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	ਜੇ (*s == '\0')
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (*s == 'h' || *s == 'H' || *s == '?') {
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
		ਜੇ (!options.permit_local_command)
			ਜਾਓ ਬਾਹਰਲਾ;
		logit("      !args                                  "
		    "Execute local command");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (*s == 'K') {
		delete = 1;
		s++;
	}
	ਜੇ (*s == 'L')
		local = 1;
	ਨਹੀਂਤਾਂ ਜੇ (*s == 'R')
		remote = 1;
	ਨਹੀਂਤਾਂ ਜੇ (*s == 'D')
		dynamic = 1;
	ਨਹੀਂਤਾਂ {
		logit("Invalid command.");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜਦੋਂ (ਖਾਲੀ_ਥਾਂ_ਹੈ((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	ਜੇ (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		ਜੇ (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		ਨਹੀਂਤਾਂ ਜੇ (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		ਨਹੀਂਤਾਂ
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_ਪੋਰਟ_STATIC,
			    &options.fwd_opts) > 0;
		ਜੇ (!ok) {
			logit("Unknown port forwarding.");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		logit("Canceled forwarding.");
	} ਨਹੀਂਤਾਂ {
		/* -R specs can be both dynamic or not, so check both. */
		ਜੇ (remote) {
			ਜੇ (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (local || dynamic) {
			ਜੇ (!channel_ਤਿਆਰੀ_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		} ਨਹੀਂਤਾਂ {
			ਜੇ (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		}
		logit("Forwarding port.");
	}

ਬਾਹਰਲਾ:
	ssh_signal(SIGINT, handler);
	enter_raw_ਬਹੁਲਕ(options.request_tty == REQUEST_TTY_FORCE);
	ਮੁਕਤ(cmd);
	ਮੁਕਤ(fwd.listen_host);
	ਮੁਕਤ(fwd.listen_ਰਸਤਾ);
	ਮੁਕਤ(fwd.connect_host);
	ਮੁਕਤ(fwd.connect_ਰਸਤਾ);
}

/* reasons to suppress output of an escape command in help output */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUPPRESS_NEVER		0	/* never suppress, always show */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
ਬਣਤਰ escape_help_ਪਾਠ {
	ਅਚਲ ਅੱਖਰ *cmd;
	ਅਚਲ ਅੱਖਰ *ਪਾਠ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ flags;
};
ਸਥਿਰ ਬਣਤਰ escape_help_ਪਾਠ esc_txt[] = {
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

ਸਥਿਰ ਖਾਲੀ
print_escape_help(ਬਣਤਰ sshbuf *b, ਪੂਰਨ escape_char, ਪੂਰਨ mux_client,
    ਪੂਰਨ using_stderr)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ i, suppress_flags;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	ਲਈ (i = 0; i < ਆਕਾਰ(esc_txt)/ਆਕਾਰ(esc_txt[0]); i++) {
		ਜੇ (esc_txt[i].flags & suppress_flags)
			ਜਾਰੀ;
		ਜੇ ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].ਪਾਠ)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	ਜੇ ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
ਸਥਿਰ ਪੂਰਨ
process_escapes(ਬਣਤਰ ssh *ssh, Channel *c,
    ਬਣਤਰ sshbuf *bin, ਬਣਤਰ sshbuf *bout, ਬਣਤਰ sshbuf *berr,
    ਅੱਖਰ *buf, ਪੂਰਨ len)
{
	pid_t pid;
	ਪੂਰਨ r, ਬਾਈਟਾਂ = 0;
	u_int i;
	u_char ch;
	ਅੱਖਰ *s;
	ਬਣਤਰ escape_filter_ctx *efc;

	ਜੇ (c == ਨਿਰਾ || c->filter_ctx == ਨਿਰਾ || len <= 0)
		ਵਾਪਸ 0;

	efc = (ਬਣਤਰ escape_filter_ctx *)c->filter_ctx;

	ਲਈ (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		ਜੇ (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			ਚੋਣ (ch) {
			ਹਾਲਤ '.':
				/* Terminate the connection. */
				ਜੇ ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				ਜੇ (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					ਵਾਪਸ 0;
				} ਨਹੀਂਤਾਂ
					quit_pending = 1;
				ਵਾਪਸ -1;

			ਹਾਲਤ 'Z' - 64:
				/* XXX support this for mux clients */
				ਜੇ (c && c->ctl_chan != -1) {
					ਅੱਖਰ b[16];
 noescape:
					ਜੇ (ch == 'Z' - 64)
						snprintf(b, ਆਕਾਰ b, "^Z");
					ਨਹੀਂਤਾਂ
						snprintf(b, ਆਕਾਰ b, "%c", ch);
					ਜੇ ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					ਜਾਰੀ;
				}
				/* Suspend the program. Inform the user */
				ਜੇ ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				ਜਾਰੀ;

			ਹਾਲਤ 'B':
				ਜੇ ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_ਸ਼ੁਰੂ(ssh, c->self, "break", 0);
				ਜੇ ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				ਜਾਰੀ;

			ਹਾਲਤ 'I':
				ਜੇ ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_ਸੁਨੇਹਾ(ssh);
				ਜੇ ((r = sshbuf_put(berr, s, ਲੜੀ_ਲੰਬਾਈ(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				ਮੁਕਤ(s);
				ਜਾਰੀ;

			ਹਾਲਤ 'R':
				ਜੇ (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				ਨਹੀਂਤਾਂ
					need_rekeying = 1;
				ਜਾਰੀ;

			ਹਾਲਤ 'V':
				/* FALLTHROUGH */
			ਹਾਲਤ 'v':
				ਜੇ (c && c->ctl_chan != -1)
					ਜਾਓ noescape;
				ਜੇ (!log_is_on_stderr()) {
					ਜੇ ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					ਜਾਰੀ;
				}
				ਜੇ (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				ਜੇ (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				ਜੇ ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				ਜਾਰੀ;

			ਹਾਲਤ '&':
				ਜੇ (c->ctl_chan != -1)
					ਜਾਓ noescape;
				/*
				 * Detach the program (continue to serve
				 * connections, but put in background and no
				 * more new connections).
				 */
				/* Restore tty modes. */
				leave_raw_ਬਹੁਲਕ(
				    options.request_tty == REQUEST_TTY_FORCE);

				/* Stop listening for new connections. */
				channel_stop_listening(ssh);

				ਜੇ ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				ਜੇ (pid == -1) {
					error("fork: %.100s", strerror(errno));
					ਜਾਰੀ;
				}
				ਜੇ (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					ਬਾਹਰ_ਨਿਕਲੋ(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				ਜੇ ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				ਵਾਪਸ -1;
			ਹਾਲਤ '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				ਜਾਰੀ;

			ਹਾਲਤ '#':
				ਜੇ ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_ਸੁਨੇਹਾ(ssh);
				ਜੇ ((r = sshbuf_put(berr, s, ਲੜੀ_ਲੰਬਾਈ(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				ਮੁਕਤ(s);
				ਜਾਰੀ;

			ਹਾਲਤ 'C':
				ਜੇ (c && c->ctl_chan != -1)
					ਜਾਓ noescape;
				ਜੇ (options.enable_escape_commandline == 0) {
					ਜੇ ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					ਜਾਰੀ;
				}
				process_cmdline(ssh);
				ਜਾਰੀ;

			ਮੂਲ:
				ਜੇ (ch != efc->escape_char) {
					ਜੇ ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					ਬਾਈਟਾਂ++;
				}
				/* Escaped characters fall through here */
				ਰੋਕੋ;
			}
		} ਨਹੀਂਤਾਂ {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			ਜੇ (ਆਖਰੀ_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				ਜਾਰੀ;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		ਆਖਰੀ_was_cr = (ch == '\r' || ch == '\n');
		ਜੇ ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		ਬਾਈਟਾਂ++;
	}
	ਵਾਪਸ ਬਾਈਟਾਂ;
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

ਸਥਿਰ ਖਾਲੀ
client_process_buffered_ਨਿਵੇਸ਼_packets(ਬਣਤਰ ssh *ssh)
{
	ssh_dispatch_ਲੜੀਵਾਰ_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
ਖਾਲੀ *
client_new_escape_filter_ctx(ਪੂਰਨ escape_char)
{
	ਬਣਤਰ escape_filter_ctx *ret;

	ret = xcalloc(1, ਆਕਾਰ(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	ਵਾਪਸ (ਖਾਲੀ *)ret;
}

/* Free the escape filter context on channel free */
ਖਾਲੀ
client_filter_cleanup(ਬਣਤਰ ssh *ssh, ਪੂਰਨ cid, ਖਾਲੀ *ctx)
{
	ਮੁਕਤ(ctx);
}

ਪੂਰਨ
client_simple_escape_filter(ਬਣਤਰ ssh *ssh, Channel *c, ਅੱਖਰ *buf, ਪੂਰਨ len)
{
	ਜੇ (c->extended_usage != CHAN_EXTENDED_WRITE)
		ਵਾਪਸ 0;

	ਵਾਪਸ process_escapes(ssh, c, c->ਨਿਵੇਸ਼, c->output, c->extended,
	    buf, len);
}

ਸਥਿਰ ਖਾਲੀ
client_channel_closed(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ force, ਖਾਲੀ *arg)
{
	channel_cancel_cleanup(ssh, id);
	session_closed = 1;
	leave_raw_ਬਹੁਲਕ(options.request_tty == REQUEST_TTY_FORCE);
}

/*
 * Implements the interactive session with the server.  This is called after
 * the user has been authenticated, and a command has been started on the
 * remote host.  If escape_char != SSH_ESCAPECHAR_NONE, it is the character
 * used as an escape character for terminating or suspending the session.
 */
ਪੂਰਨ
client_loop(ਬਣਤਰ ssh *ssh, ਪੂਰਨ have_pty, ਪੂਰਨ escape_char_arg,
    ਪੂਰਨ ssh2_chan_id)
{
	ਬਣਤਰ pollfd *pfd = ਨਿਰਾ;
	u_int npfd_alloc = 0, npfd_ਸਰਗਰਮ = 0;
	ਦੁੱਗਣਾ ਸ਼ੁਰੂ_ਸਮਾਂ, ਕੁੱਲ_ਸਮਾਂ;
	ਪੂਰਨ interactive = -1, channel_did_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ = 0, r;
	uint64_t ibytes, obytes;
	ਪੂਰਨ conn_ਵਿੱਚ_ready, conn_ਬਾਹਰਲਾ_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	ਜੇ (options.pkcs11_provider != ਨਿਰਾ)
		debug("pledge: disabled (PKCS11Provider active)");
	ਨਹੀਂਤਾਂ ਜੇ (options.control_master &&
	    !option_clear_or_none(options.control_ਰਸਤਾ)) {
		debug("pledge: id");
		ਜੇ (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    ਨਿਰਾ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ਨਹੀਂਤਾਂ ਜੇ (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		ਜੇ (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    ਨਿਰਾ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ਨਹੀਂਤਾਂ ਜੇ (options.update_hostkeys) {
		debug("pledge: filesystem");
		ਜੇ (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    ਨਿਰਾ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ਨਹੀਂਤਾਂ ਜੇ (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		ਜੇ (pledge("stdio cpath unix inet dns proc tty", ਨਿਰਾ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ਨਹੀਂਤਾਂ {
		debug("pledge: network");
		ਜੇ (pledge("stdio unix inet dns proc tty", ਨਿਰਾ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	}

	/* might be able to tighten now */
	client_repledge();

	ਸ਼ੁਰੂ_ਸਮਾਂ = monotime_double();

	/* Initialize variables. */
	ਆਖਰੀ_was_cr = 1;
	exit_ਸਥਿਤੀ = -1;
	connection_ਵਿੱਚ = ssh_packet_get_connection_ਵਿੱਚ(ssh);
	connection_ਬਾਹਰਲਾ = ssh_packet_get_connection_ਬਾਹਰਲਾ(ssh);

	quit_pending = 0;

	client_init_dispatch(ssh);

	/*
	 * Set signal handlers, (e.g. to restore non-blocking mode)
	 * but don't overwrite SIG_IGN, matches behaviour from rsh(1)
	 */
	ਜੇ (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	ਜੇ (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	ਜੇ (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	ਜੇ (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, ਖਿੜਕੀ_change_handler);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#ਜੇ_ਅੰਤ

	ਜੇ (have_pty)
		enter_raw_ਬਹੁਲਕ(options.request_tty == REQUEST_TTY_FORCE);

	ਜੇ (session_ident != -1) {
		ਜੇ (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_ਰਜਿਸਟਰ_filter(ssh, session_ident,
			    client_simple_escape_filter, ਨਿਰਾ,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_ਰਜਿਸਟਰ_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	ਸਮਾਂ_ਸਾਰਣੀ_server_alive_check();

	ਜੇ (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
	ਜੇ (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ਜੇ_ਅੰਤ

	/* Main loop of the client for the interactive session mode. */
	ਜਦੋਂ (!quit_pending) {
		channel_did_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_ਨਿਵੇਸ਼_packets(ssh);

		ਜੇ (session_closed && !channel_still_open(ssh))
			ਰੋਕੋ;

		ਜੇ (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} ਨਹੀਂਤਾਂ ਜੇ (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			ਜੇ ((r = kex_ਸ਼ੁਰੂ_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} ਨਹੀਂਤਾਂ {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			ਜੇ (ssh_packet_not_very_much_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh))
				channel_did_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ = channel_output_poll(ssh);

			/*
			 * Check if the window size has changed, and buffer a
			 * message about it to the server if so.
			 */
			client_check_ਖਿੜਕੀ_change(ssh);
		}
		/*
		 * Wait until we have something to do (something becomes
		 * available on one of the descriptors).
		 */
		ਜੇ (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		ਜੇ (siginfo_received) {
			ਅੱਖਰ ident[256];

			sshpkt_fmt_connection_id(ssh, ident, ਆਕਾਰ(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - ਸ਼ੁਰੂ_ਸਮਾਂ);
			siginfo_received = 0;
		}
		ਜੇ (quit_pending)
			ਰੋਕੋ;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_ਸਰਗਰਮ, channel_did_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ, &osigset,
		    &conn_ਵਿੱਚ_ready, &conn_ਬਾਹਰਲਾ_ready);
		ਜੇ (sigprocmask(SIG_SETMASK, &osigset, ਨਿਰਾ) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		ਜੇ (quit_pending)
			ਰੋਕੋ;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_ਸਰਗਰਮ);

		/* Buffer input from the connection.  */
		ਜੇ (conn_ਵਿੱਚ_ready)
			client_process_net_ਨਿਵੇਸ਼(ssh);

		ਜੇ (quit_pending)
			ਰੋਕੋ;

		/* A timeout may have triggered rekeying */
		ਜੇ ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		ਜੇ (conn_ਬਾਹਰਲਾ_ready) {
			ਜੇ (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_ਸੈੱਟ_interactive(ssh, interactive);
			}
			ਜੇ ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		ਜੇ (control_persist_exit_ਸਮਾਂ > 0) {
			ਜੇ (monotime() >= control_persist_exit_ਸਮਾਂ) {
				debug("ControlPersist timeout expired");
				ਰੋਕੋ;
			}
		}
	}
	ਮੁਕਤ(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	ਜੇ (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_ਸੁਨੇਹਾ("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	ਜੇ (have_pty)
		leave_raw_ਬਹੁਲਕ(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	ਜੇ (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_ਸਥਿਤੀ = 0;
	}

	ਜੇ (received_signal) {
		verbose("Killed by signal %d.", (ਪੂਰਨ) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	ਕੁੱਲ_ਸਮਾਂ = monotime_double() - ਸ਼ੁਰੂ_ਸਮਾਂ;
	ssh_packet_get_ਬਾਈਟਾਂ(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)obytes, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ibytes, ਕੁੱਲ_ਸਮਾਂ);
	ਜੇ (ਕੁੱਲ_ਸਮਾਂ > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / ਕੁੱਲ_ਸਮਾਂ, ibytes / ਕੁੱਲ_ਸਮਾਂ);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_ਸਥਿਤੀ);
	ਵਾਪਸ exit_ਸਥਿਤੀ;
}

/*********/

ਸਥਿਰ Channel *
client_request_forwarded_tcpip(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *request_type,
    ਪੂਰਨ rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਅੱਖਰ *listen_ਪਤਾ, *originator_ਪਤਾ;
	u_int listen_ਪੋਰਟ, originator_ਪੋਰਟ;
	ਪੂਰਨ r;

	/* Get rest of the packet */
	ਜੇ ((r = sshpkt_get_cstring(ssh, &listen_ਪਤਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_ਪੋਰਟ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_ਪਤਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_ਪੋਰਟ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_ਪਤਾ, listen_ਪੋਰਟ, originator_ਪਤਾ, originator_ਪੋਰਟ);

	ਜੇ (listen_ਪੋਰਟ > 0xffff)
		error_f("invalid listen port");
	ਨਹੀਂਤਾਂ ਜੇ (originator_ਪੋਰਟ > 0xffff)
		error_f("invalid originator port");
	ਨਹੀਂਤਾਂ {
		c = channel_connect_by_listen_ਪਤਾ(ssh,
		    listen_ਪਤਾ, listen_ਪੋਰਟ, "forwarded-tcpip",
		    originator_ਪਤਾ);
	}

	ਜੇ (c != ਨਿਰਾ && c->type == SSH_CHANNEL_MUX_CLIENT) {
		ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
			error_f("alloc reply");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* reconstruct and send to muxclient */
		ਜੇ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN)) != 0 ||
		    (r = sshbuf_put_cstring(b, request_type)) != 0 ||
		    (r = sshbuf_put_u32(b, rchan)) != 0 ||
		    (r = sshbuf_put_u32(b, rwindow)) != 0 ||
		    (r = sshbuf_put_u32(b, rmaxpack)) != 0 ||
		    (r = sshbuf_put_cstring(b, listen_ਪਤਾ)) != 0 ||
		    (r = sshbuf_put_u32(b, listen_ਪੋਰਟ)) != 0 ||
		    (r = sshbuf_put_cstring(b, originator_ਪਤਾ)) != 0 ||
		    (r = sshbuf_put_u32(b, originator_ਪੋਰਟ)) != 0 ||
		    (r = sshbuf_put_stringb(c->output, b)) != 0) {
			error_fr(r, "compose for muxclient");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਮੁਕਤ(originator_ਪਤਾ);
	ਮੁਕਤ(listen_ਪਤਾ);
	ਵਾਪਸ c;
}

ਸਥਿਰ Channel *
client_request_forwarded_streamlocal(ਬਣਤਰ ssh *ssh,
    ਅਚਲ ਅੱਖਰ *request_type, ਪੂਰਨ rchan)
{
	Channel *c = ਨਿਰਾ;
	ਅੱਖਰ *listen_ਰਸਤਾ;
	ਪੂਰਨ r;

	/* Get the remote path. */
	ਜੇ ((r = sshpkt_get_cstring(ssh, &listen_ਰਸਤਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_string(ssh, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_ਰਸਤਾ);

	c = channel_connect_by_listen_ਰਸਤਾ(ssh, listen_ਰਸਤਾ,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	ਮੁਕਤ(listen_ਰਸਤਾ);
	ਵਾਪਸ c;
}

ਸਥਿਰ Channel *
client_request_x11(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *request_type, ਪੂਰਨ rchan)
{
	Channel *c = ਨਿਰਾ;
	ਅੱਖਰ *originator;
	u_int originator_ਪੋਰਟ;
	ਪੂਰਨ r, sock;

	ਜੇ (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (x11_refuse_ਸਮਾਂ != 0 && monotime() >= x11_refuse_ਸਮਾਂ) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((r = sshpkt_get_cstring(ssh, &originator, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_ਪੋਰਟ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_ਪੋਰਟ);
	ਮੁਕਤ(originator);
	sock = x11_connect_display(ssh);
	ਜੇ (sock < 0)
		ਵਾਪਸ ਨਿਰਾ;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	ਵਾਪਸ c;
}

ਸਥਿਰ Channel *
client_request_agent(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *request_type, ਪੂਰਨ rchan)
{
	Channel *c = ਨਿਰਾ;
	ਪੂਰਨ r, sock;

	ਜੇ (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (forward_agent_sock_ਰਸਤਾ == ਨਿਰਾ) {
		r = ssh_get_authentication_socket(&sock);
	} ਨਹੀਂਤਾਂ {
		r = ssh_get_authentication_socket_ਰਸਤਾ(forward_agent_sock_ਰਸਤਾ, &sock);
	}
	ਜੇ (r != 0) {
		ਜੇ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	ਨਹੀਂਤਾਂ
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	ਵਾਪਸ c;
}

ਅੱਖਰ *
client_request_tun_fwd(ਬਣਤਰ ssh *ssh, ਪੂਰਨ tun_ਬਹੁਲਕ,
    ਪੂਰਨ local_tun, ਪੂਰਨ remote_tun, channel_open_fn *cb, ਖਾਲੀ *cbctx)
{
	Channel *c;
	ਪੂਰਨ r, fd;
	ਅੱਖਰ *ifname = ਨਿਰਾ;

	ਜੇ (tun_ਬਹੁਲਕ == SSH_TUNMODE_NO)
		ਵਾਪਸ ਨਿਰਾ;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_ਬਹੁਲਕ);

	/* Open local tunnel device */
	ਜੇ ((fd = tun_open(local_tun, tun_ਬਹੁਲਕ, &ifname)) == -1) {
		error("Tunnel device open failed.");
		ਵਾਪਸ ਨਿਰਾ;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#ਜੇ defined(SSH_TUN_FILTER)
	ਜੇ (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_ਰਜਿਸਟਰ_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ਨਿਰਾ, ਨਿਰਾ);
#ਜੇ_ਅੰਤ

	ਜੇ (cb != ਨਿਰਾ)
		channel_ਰਜਿਸਟਰ_open_confirm(ssh, c->self, cb, cbctx);

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_ਖਿੜਕੀ_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_ਬਹੁਲਕ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	ਵਾਪਸ ifname;
}

/* XXXX move to generic input handler */
ਸਥਿਰ ਪੂਰਨ
client_ਨਿਵੇਸ਼_channel_open(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Channel *c = ਨਿਰਾ;
	ਅੱਖਰ *ctype = ਨਿਰਾ;
	ਪੂਰਨ r;
	u_int rchan;
	ਮਾਪ_t len;
	u_int rmaxpack, rwindow;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	ਜੇ (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	ਜੇ (c != ਨਿਰਾ && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} ਨਹੀਂਤਾਂ ਜੇ (c != ਨਿਰਾ) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_ਖਿੜਕੀ = rwindow;
		c->remote_maxpacket = rmaxpack;
		ਜੇ (c->type != SSH_CHANNEL_CONNECTING) {
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_ਖਿੜਕੀ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} ਨਹੀਂਤਾਂ {
		debug("failure %s", ctype);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ctype);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
client_ਨਿਵੇਸ਼_channel_req(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Channel *c = ਨਿਰਾ;
	ਅੱਖਰ *rtype = ਨਿਰਾ;
	u_char ਜਵਾਬ;
	u_int id, exitval;
	ਪੂਰਨ r, success = 0;

	ਜੇ ((r = sshpkt_get_u32(ssh, &id)) != 0)
		ਵਾਪਸ r;
	ਜੇ (id <= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		c = channel_lookup(ssh, id);
	ਜੇ (channel_proxy_upstream(c, type, seq, ssh))
		ਵਾਪਸ 0;
	ਜੇ ((r = sshpkt_get_cstring(ssh, &rtype, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &ਜਵਾਬ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, ਜਵਾਬ);

	ਜੇ (c == ਨਿਰਾ) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "eow@openssh.com") == 0) {
		ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		chan_rcvd_eow(ssh, c);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "exit-status") == 0) {
		ਜੇ ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (c->ctl_chan != -1) {
			mux_exit_ਸੁਨੇਹਾ(ssh, c, exitval);
			success = 1;
		} ਨਹੀਂਤਾਂ ਜੇ ((ਪੂਰਨ)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_ਸਥਿਤੀ = exitval;
		} ਨਹੀਂਤਾਂ {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ਜਵਾਬ && c != ਨਿਰਾ && !(c->flags & CHAN_CLOSE_ਭੇਜਿਆ)) {
		ਜੇ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, success ?
		    SSH2_ਸੁਨੇਹਾ_CHANNEL_SUCCESS : SSH2_ਸੁਨੇਹਾ_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(rtype);
	ਵਾਪਸ r;
}

ਬਣਤਰ hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	ਅੱਖਰ *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ;
	u_int *ਕੁੰਜੀਆਂ_ਮੇਲ;	/* mask of HKF_MATCH_* from hostfile.h */
	ਪੂਰਨ *ਕੁੰਜੀਆਂ_verified;	/* flag for new keys verified by server */
	ਮਾਪ_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	ਬਣਤਰ sshkey **old_ਕੁੰਜੀਆਂ;
	ਮਾਪ_t nold;

	/* Various special cases. */
	ਪੂਰਨ complex_hostspec;	/* wildcard or manual pattern-list host name */
	ਪੂਰਨ ca_ਉਪਲਬਧ;	/* saw CA key for this host */
	ਪੂਰਨ old_ਕੁੰਜੀ_ਵੇਖਿਆ;	/* saw old key with other name/addr */
	ਪੂਰਨ other_name_ਵੇਖਿਆ;	/* saw key with other name/addr */
};

ਸਥਿਰ ਖਾਲੀ
hostkeys_update_ctx_free(ਬਣਤਰ hostkeys_update_ctx *ctx)
{
	ਮਾਪ_t i;

	ਜੇ (ctx == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->ਕੁੰਜੀਆਂ[i]);
	ਮੁਕਤ(ctx->ਕੁੰਜੀਆਂ);
	ਮੁਕਤ(ctx->ਕੁੰਜੀਆਂ_ਮੇਲ);
	ਮੁਕਤ(ctx->ਕੁੰਜੀਆਂ_verified);
	ਲਈ (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_ਕੁੰਜੀਆਂ[i]);
	ਮੁਕਤ(ctx->old_ਕੁੰਜੀਆਂ);
	ਮੁਕਤ(ctx->host_str);
	ਮੁਕਤ(ctx->ip_str);
	ਮੁਕਤ(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
ਸਥਿਰ ਪੂਰਨ
hostspec_is_complex(ਅਚਲ ਅੱਖਰ *hosts)
{
	ਅੱਖਰ *cp;

	/* wildcard */
	ਜੇ (strchr(hosts, '*') != ਨਿਰਾ || strchr(hosts, '?') != ਨਿਰਾ)
		ਵਾਪਸ 1;
	/* single host/ip = ok */
	ਜੇ ((cp = strchr(hosts, ',')) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	/* more than two entries on the line */
	ਜੇ (strchr(cp + 1, ',') != ਨਿਰਾ)
		ਵਾਪਸ 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	ਵਾਪਸ 0;
}

/* callback to search for ctx->keys in known_hosts */
ਸਥਿਰ ਪੂਰਨ
hostkeys_ਲੱਭੋ(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *_ctx)
{
	ਬਣਤਰ hostkeys_update_ctx *ctx = (ਬਣਤਰ hostkeys_update_ctx *)_ctx;
	ਮਾਪ_t i;
	ਬਣਤਰ sshkey **tmp;

	ਜੇ (l->ਕੁੰਜੀ == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (l->ਸਥਿਤੀ != HKF_ਸਥਿਤੀ_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		ਲਈ (i = 0; i < ctx->nkeys; i++) {
			ਜੇ (sshkey_equal(l->ਕੁੰਜੀ, ctx->ਕੁੰਜੀਆਂ[i])) {
				ctx->other_name_ਵੇਖਿਆ = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->ਕੁੰਜੀਆਂ[i]),
				    l->ਰਸਤਾ, l->linenum);
				ਵਾਪਸ 0;
			}
		}
		ਵਾਪਸ 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	ਜੇ (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->ਰਸਤਾ, l->linenum);
		ctx->complex_hostspec = 1;
		ਵਾਪਸ 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	ਜੇ (ctx->ip_str != ਨਿਰਾ && strchr(l->hosts, ',') != ਨਿਰਾ) {
		ਜੇ ((l->ਮੇਲ & HKF_ਮੇਲ_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_ਵੇਖਿਆ = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->ਰਸਤਾ, l->linenum);
			ਵਾਪਸ 0;
		} ਨਹੀਂਤਾਂ ਜੇ ((l->ਮੇਲ & HKF_ਮੇਲ_IP) == 0) {
			/* Record if hostname matched a different address. */
			ctx->other_name_ਵੇਖਿਆ = 1;
			debug3_f("found hostname %s against different address "
			    "at %s:%ld", ctx->host_str, l->ਰਸਤਾ, l->linenum);
		}
	}

	/*
	 * UpdateHostkeys is skipped for wildcard host names and hostnames
	 * that contain more than two entries (ssh never writes these).
	 */
	ਜੇ (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->ਰਸਤਾ, l->linenum);
		ctx->complex_hostspec = 1;
		ਵਾਪਸ 0;
	}

	/* Mark off keys we've already seen for this host */
	ਲਈ (i = 0; i < ctx->nkeys; i++) {
		ਜੇ (!sshkey_equal(l->ਕੁੰਜੀ, ctx->ਕੁੰਜੀਆਂ[i]))
			ਜਾਰੀ;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->ਕੁੰਜੀਆਂ[i]), l->ਰਸਤਾ, l->linenum);
		ctx->ਕੁੰਜੀਆਂ_ਮੇਲ[i] |= l->ਮੇਲ;
		ਵਾਪਸ 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->ਕੁੰਜੀ),
	    l->ਰਸਤਾ, l->linenum);
	ਜੇ ((tmp = recallocarray(ctx->old_ਕੁੰਜੀਆਂ, ctx->nold, ctx->nold + 1,
	    ਆਕਾਰ(*ctx->old_ਕੁੰਜੀਆਂ))) == ਨਿਰਾ)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_ਕੁੰਜੀਆਂ = tmp;
	ctx->old_ਕੁੰਜੀਆਂ[ctx->nold++] = l->ਕੁੰਜੀ;
	l->ਕੁੰਜੀ = ਨਿਰਾ;

	ਵਾਪਸ 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
ਸਥਿਰ ਪੂਰਨ
hostkeys_check_old(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *_ctx)
{
	ਬਣਤਰ hostkeys_update_ctx *ctx = (ਬਣਤਰ hostkeys_update_ctx *)_ctx;
	ਮਾਪ_t i;
	ਪੂਰਨ hashed;

	/* only care about lines that *don't* match the active host spec */
	ਜੇ (l->ਸਥਿਤੀ == HKF_ਸਥਿਤੀ_MATCHED || l->ਕੁੰਜੀ == ਨਿਰਾ)
		ਵਾਪਸ 0;

	hashed = l->ਮੇਲ & (HKF_ਮੇਲ_HOST_HASHED|HKF_ਮੇਲ_IP_HASHED);
	ਲਈ (i = 0; i < ctx->nold; i++) {
		ਜੇ (!sshkey_equal(l->ਕੁੰਜੀ, ctx->old_ਕੁੰਜੀਆਂ[i]))
			ਜਾਰੀ;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_ਕੁੰਜੀਆਂ[i]), l->ਰਸਤਾ, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_ਕੁੰਜੀ_ਵੇਖਿਆ = 1;
		ਰੋਕੋ;
	}
	ਵਾਪਸ 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
ਸਥਿਰ ਪੂਰਨ
check_old_ਕੁੰਜੀਆਂ_othernames(ਬਣਤਰ hostkeys_update_ctx *ctx)
{
	ਮਾਪ_t i;
	ਪੂਰਨ r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	ਲਈ (i = 0; i < options.ਅੰਕ_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		ਜੇ ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_ਕੁੰਜੀ, 0)) != 0) {
			ਜੇ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				ਜਾਰੀ;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			ਵਾਪਸ -1;
		}
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

ਸਥਿਰ ਖਾਲੀ
update_ਗਿਆਤ_hosts(ਬਣਤਰ hostkeys_update_ctx *ctx)
{
	ਪੂਰਨ r, was_raw = 0, ਪਹਿਲਾ = 1;
	ਪੂਰਨ asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	ਅੱਖਰ *fp, *response;
	ਮਾਪ_t i;
	ਬਣਤਰ stat sb;

	ਲਈ (i = 0; i < ctx->nkeys; i++) {
		ਜੇ (!ctx->ਕੁੰਜੀਆਂ_verified[i])
			ਜਾਰੀ;
		ਜੇ ((fp = sshkey_fingerprint(ctx->ਕੁੰਜੀਆਂ[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("sshkey_fingerprint failed");
		ਜੇ (ਪਹਿਲਾ && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->ਕੁੰਜੀਆਂ[i]), fp);
		ਪਹਿਲਾ = 0;
		ਮੁਕਤ(fp);
	}
	ਲਈ (i = 0; i < ctx->nold; i++) {
		ਜੇ ((fp = sshkey_fingerprint(ctx->old_ਕੁੰਜੀਆਂ[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("sshkey_fingerprint failed");
		ਜੇ (ਪਹਿਲਾ && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_ਕੁੰਜੀਆਂ[i]), fp);
		ਪਹਿਲਾ = 0;
		ਮੁਕਤ(fp);
	}
	ਜੇ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		ਜੇ (get_saved_tio() != ਨਿਰਾ) {
			leave_raw_ਬਹੁਲਕ(1);
			was_raw = 1;
		}
		response = ਨਿਰਾ;
		ਲਈ (i = 0; !quit_pending && i < 3; i++) {
			ਮੁਕਤ(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			ਜੇ (response != ਨਿਰਾ && strcasecmp(response, "yes") == 0)
				ਰੋਕੋ;
			ਨਹੀਂਤਾਂ ਜੇ (quit_pending || response == ਨਿਰਾ ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				ਰੋਕੋ;
			} ਨਹੀਂਤਾਂ {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		ਜੇ (quit_pending || i >= 3 || response == ਨਿਰਾ)
			options.update_hostkeys = 0;
		ਮੁਕਤ(response);
		ਜੇ (was_raw)
			enter_raw_ਬਹੁਲਕ(1);
	}
	ਜੇ (options.update_hostkeys == 0)
		ਵਾਪਸ;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	ਲਈ (i = 0; i < options.ਅੰਕ_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		ਜੇ (stat(options.user_hostfiles[i], &sb) != 0) {
			ਜੇ (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} ਨਹੀਂਤਾਂ {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			ਜਾਰੀ;
		}
		ਜੇ ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->ਕੁੰਜੀਆਂ : ਨਿਰਾ, i == 0 ? ctx->nkeys : 0,
		    options.hash_ਗਿਆਤ_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

ਸਥਿਰ ਖਾਲੀ
client_global_hostkeys_prove_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ type,
    uint32_t seq, ਖਾਲੀ *_ctx)
{
	ਬਣਤਰ hostkeys_update_ctx *ctx = (ਬਣਤਰ hostkeys_update_ctx *)_ctx;
	ਮਾਪ_t i, ndone;
	ਬਣਤਰ sshbuf *signdata;
	ਪੂਰਨ r, plaintype;
	ਅਚਲ u_char *sig;
	ਅਚਲ ਅੱਖਰ *rsa_kexalg = ਨਿਰਾ;
	ਅੱਖਰ *alg = ਨਿਰਾ;
	ਮਾਪ_t siglen;

	ਜੇ (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	ਜੇ (type != SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		ਵਾਪਸ;
	}
	ਜੇ (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == ਕੁੰਜੀ_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	ਜੇ ((signdata = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	ਲਈ (ndone = i = 0; i < ctx->nkeys; i++) {
		ਜੇ (ctx->ਕੁੰਜੀਆਂ_ਮੇਲ[i])
			ਜਾਰੀ;
		plaintype = sshkey_type_plain(ctx->ਕੁੰਜੀਆਂ[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		ਜੇ ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->ਕੁੰਜੀਆਂ[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		ਜੇ ((r = sshpkt_get_string_ਸਿੱਧਾ(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->ਕੁੰਜੀਆਂ[i]), i);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		ਜੇ (plaintype == ਕੁੰਜੀ_RSA && rsa_kexalg == ਨਿਰਾ &&
		    ਮੇਲ_ਨਮੂਨਾ_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			ਮੁਕਤ(alg);
			/* zap the key from the list */
			sshkey_free(ctx->ਕੁੰਜੀਆਂ[i]);
			ctx->ਕੁੰਜੀਆਂ[i] = ਨਿਰਾ;
			ndone++;
			ਜਾਰੀ;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->ਕੁੰਜੀਆਂ[i]), i, alg);
		ਮੁਕਤ(alg);
		ਜੇ ((r = sshkey_verify(ctx->ਕੁੰਜੀਆਂ[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == ਕੁੰਜੀ_RSA ? rsa_kexalg : ਨਿਰਾ, 0, ਨਿਰਾ)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->ਕੁੰਜੀਆਂ[i]), i);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->ਕੁੰਜੀਆਂ_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	ਜੇ (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0) {
		error_f("protocol error");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Make the edits to known_hosts */
	update_ਗਿਆਤ_hosts(ctx);
 ਬਾਹਰਲਾ:
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
ਸਥਿਰ ਪੂਰਨ
client_ਨਿਵੇਸ਼_hostkeys(ਬਣਤਰ ssh *ssh)
{
	ਅਚਲ u_char *blob = ਨਿਰਾ;
	ਮਾਪ_t i, len = 0;
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ, **tmp;
	ਪੂਰਨ r, prove_ਭੇਜਿਆ = 0;
	ਅੱਖਰ *fp;
	ਸਥਿਰ ਪੂਰਨ hostkeys_ਵੇਖਿਆ = 0; /* XXX use struct ssh */
	ਬਾਹਰੀ ਬਣਤਰ sockaddr_storage hostaddr; /* XXX from ssh.c */
	ਬਣਤਰ hostkeys_update_ctx *ctx = ਨਿਰਾ;
	u_int want;

	ਜੇ (hostkeys_ਵੇਖਿਆ)
		fatal_f("server already sent hostkeys");
	ਜੇ (!can_update_hostkeys())
		ਵਾਪਸ 1;
	hostkeys_ਵੇਖਿਆ = 1;

	ctx = xcalloc(1, ਆਕਾਰ(*ctx));
	ਜਦੋਂ (ssh_packet_ਬਚਿਆ(ssh) > 0) {
		sshkey_free(ਕੁੰਜੀ);
		ਕੁੰਜੀ = ਨਿਰਾ;
		ਜੇ ((r = sshpkt_get_string_ਸਿੱਧਾ(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshkey_from_blob(blob, len, &ਕੁੰਜੀ)) != 0) {
			do_log2_fr(r, r == SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			ਜਾਰੀ;
		}
		fp = sshkey_fingerprint(ਕੁੰਜੀ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(ਕੁੰਜੀ), fp);
		ਮੁਕਤ(fp);

		ਜੇ (!hostkey_accepted_by_hostkeyalgs(ਕੁੰਜੀ)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(ਕੁੰਜੀ));
			ਜਾਰੀ;
		}
		/* Skip certs */
		ਜੇ (sshkey_is_cert(ਕੁੰਜੀ)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(ਕੁੰਜੀ));
			ਜਾਰੀ;
		}
		/* Ensure keys are unique */
		ਲਈ (i = 0; i < ctx->nkeys; i++) {
			ਜੇ (sshkey_equal(ਕੁੰਜੀ, ctx->ਕੁੰਜੀਆਂ[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(ਕੁੰਜੀ));
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		}
		/* Key is good, record it */
		ਜੇ ((tmp = recallocarray(ctx->ਕੁੰਜੀਆਂ, ctx->nkeys, ctx->nkeys + 1,
		    ਆਕਾਰ(*ctx->ਕੁੰਜੀਆਂ))) == ਨਿਰਾ)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->ਕੁੰਜੀਆਂ = tmp;
		ctx->ਕੁੰਜੀਆਂ[ctx->nkeys++] = ਕੁੰਜੀ;
		ਕੁੰਜੀ = ਨਿਰਾ;
	}

	ਜੇ (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((ctx->ਕੁੰਜੀਆਂ_ਮੇਲ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(ctx->nkeys,
	    ਆਕਾਰ(*ctx->ਕੁੰਜੀਆਂ_ਮੇਲ))) == ਨਿਰਾ ||
	    (ctx->ਕੁੰਜੀਆਂ_verified = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(ctx->nkeys,
	    ਆਕਾਰ(*ctx->ਕੁੰਜੀਆਂ_verified))) == ਨਿਰਾ)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (ਬਣਤਰ sockaddr *)&hostaddr : ਨਿਰਾ,
	    options.ਪੋਰਟ, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : ਨਿਰਾ);

	/* Find which keys we already know about. */
	ਲਈ (i = 0; i < options.ਅੰਕ_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		ਜੇ ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_ਲੱਭੋ, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_ਕੁੰਜੀ, 0)) != 0) {
			ਜੇ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				ਜਾਰੀ;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_ਮੇਲ_HOST | ( options.check_host_ip ? HKF_ਮੇਲ_IP : 0);
	ਲਈ (i = 0; i < ctx->nkeys; i++) {
		ਜੇ (ctx->ਕੁੰਜੀਆਂ_ਮੇਲ[i] == 0)
			ctx->nnew++;
		ਜੇ ((ctx->ਕੁੰਜੀਆਂ_ਮੇਲ[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	ਜੇ (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Various reasons why we cannot proceed with the update */
	ਜੇ (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ctx->other_name_ਵੇਖਿਆ) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	ਜੇ (ctx->nold != 0) {
		ਜੇ (check_old_ਕੁੰਜੀਆਂ_othernames(ctx) != 0)
			ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */
		ਜੇ (ctx->old_ਕੁੰਜੀ_ਵੇਖਿਆ) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == ਨਿਰਾ ? "" : ",",
			    ctx->ip_str == ਨਿਰਾ ? "" : ctx->ip_str);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	ਜੇ (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_ਗਿਆਤ_hosts(ctx);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਲਈ (i = 0; i < ctx->nkeys; i++) {
		ਜੇ (ctx->ਕੁੰਜੀਆਂ_ਮੇਲ[i])
			ਜਾਰੀ;
		sshbuf_reset(buf);
		ਜੇ ((r = sshkey_putb(ctx->ਕੁੰਜੀਆਂ[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	ਜੇ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_ਰਜਿਸਟਰ_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = ਨਿਰਾ;  /* will be freed in callback */
	prove_ਭੇਜਿਆ = 1;

	/* Success */
 ਬਾਹਰਲਾ:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(buf);
	ਜੇ (!prove_ਭੇਜਿਆ) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
client_ਨਿਵੇਸ਼_global_request(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ *rtype;
	u_char want_ਜਵਾਬ;
	ਪੂਰਨ r, success = 0;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &rtype, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_ਜਵਾਬ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_ਜਵਾਬ);
	ਜੇ (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_ਨਿਵੇਸ਼_hostkeys(ssh);
	ਜੇ (want_ਜਵਾਬ) {
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, success ? SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS :
		    SSH2_ਸੁਨੇਹਾ_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(rtype);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ
client_send_env(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਅਚਲ ਅੱਖਰ *name, ਅਚਲ ਅੱਖਰ *val)
{
	ਪੂਰਨ r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_ਸ਼ੁਰੂ(ssh, id, "env", 0);
	ਜੇ ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

ਖਾਲੀ
client_session2_ਤਿਆਰੀ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ want_tty, ਪੂਰਨ want_subsystem,
    ਅਚਲ ਅੱਖਰ *ਪਦ, ਬਣਤਰ termios *tiop, ਪੂਰਨ ਵਿੱਚ_fd, ਬਣਤਰ sshbuf *cmd,
    ਅੱਖਰ **env)
{
	ਮਾਪ_t i, j, len;
	ਪੂਰਨ matched, r;
	ਅੱਖਰ *type = ਨਿਰਾ, *cmdstring = ਨਿਰਾ, *name, *val;
	Channel *c = ਨਿਰਾ;

	debug2_f("id %d", id);

	ਜੇ ((c = channel_lookup(ssh, id)) == ਨਿਰਾ)
		fatal_f("channel %d: unknown channel", id);

	ਜੇ (want_tty) {
		ਬਣਤਰ winsize ws;

		/* Store window size in the packet. */
		ਜੇ (ioctl(ਵਿੱਚ_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, ਆਕਾਰ(ws));

		channel_request_ਸ਼ੁਰੂ(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		ਜੇ ((r = sshpkt_put_cstring(ssh, ਪਦ != ਨਿਰਾ ? ਪਦ : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ਖਾਨਾ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ਪੰਕਤੀ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		ਜੇ (tiop == ਨਿਰਾ)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		ਜੇ ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	ਜੇ (options.ਅੰਕ_send_env != 0 && env != ਨਿਰਾ) {
		debug("Sending environment.");
		ਲਈ (i = 0; env[i] != ਨਿਰਾ; i++) {
			/*ਵੰਡੋ*/
			name = xstrdup(env[i]);
			ਜੇ ((val = strchr(name, '=')) == ਨਿਰਾ) {
				ਮੁਕਤ(name);
				ਜਾਰੀ;
			}
			*val++ = '\0';

			matched = 0;
			ਲਈ (j = 0; j < options.ਅੰਕ_send_env; j++) {
				ਜੇ (ਮੇਲ_ਨਮੂਨਾ(name, options.send_env[j])) {
					matched = 1;
					ਰੋਕੋ;
				}
			}
			ਜੇ (!matched) {
				debug3("Ignored env %s", name);
				ਮੁਕਤ(name);
				ਜਾਰੀ;
			}
			client_send_env(ssh, id, name, val);
			ਮੁਕਤ(name);
		}
	}
	ਲਈ (i = 0; i < options.ਅੰਕ_setenv; i++) {
		/*ਵੰਡੋ*/
		name = xstrdup(options.setenv[i]);
		ਜੇ ((val = strchr(name, '=')) == ਨਿਰਾ) {
			ਮੁਕਤ(name);
			ਜਾਰੀ;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		ਮੁਕਤ(name);
	}

	len = sshbuf_len(cmd);
	ਜੇ (len > 0) {
		ਜੇ ((cmdstring = sshbuf_dup_string(cmd)) == ਨਿਰਾ)
			fatal_f("sshbuf_dup_string failed");
		ਜੇ (len > 900)
			len = 900;
		ਜੇ (want_subsystem) {
			debug("Sending subsystem: %.*s", (ਪੂਰਨ)len, cmdstring);
			channel_request_ਸ਼ੁਰੂ(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} ਨਹੀਂਤਾਂ {
			debug("Sending command: %.*s", (ਪੂਰਨ)len, cmdstring);
			channel_request_ਸ਼ੁਰੂ(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		ਜੇ ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} ਨਹੀਂਤਾਂ {
		channel_request_ਸ਼ੁਰੂ(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		ਜੇ ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_ਸੈੱਟ_xtype(ssh, id, type);
	ਮੁਕਤ(cmdstring);
	ਮੁਕਤ(type);

	session_ਤਿਆਰੀ_complete = 1;
	client_repledge();
}

ਖਾਲੀ
client_channel_request_agent_forwarding(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id)
{
	ਅਚਲ ਅੱਖਰ *req = "auth-agent-req@openssh.com";
	ਪੂਰਨ r;

	ਜੇ (ssh->kex != ਨਿਰਾ && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_ਸ਼ੁਰੂ(ssh, id, req, 0);
	ਜੇ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

ਸਥਿਰ ਖਾਲੀ
client_init_dispatch(ਬਣਤਰ ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_CLOSE, &channel_ਨਿਵੇਸ਼_oclose);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ, &channel_ਨਿਵੇਸ਼_ਅੰਕੜੇ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_EOF, &channel_ਨਿਵੇਸ਼_ieof);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_EXTENDED_ਅੰਕੜੇ, &channel_ਨਿਵੇਸ਼_extended_ਅੰਕੜੇ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN, &client_ਨਿਵੇਸ਼_channel_open);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION, &channel_ਨਿਵੇਸ਼_open_confirmation);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_FAILURE, &channel_ਨਿਵੇਸ਼_open_failure);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_REQUEST, &client_ਨਿਵੇਸ਼_channel_req);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਖਿੜਕੀ_ADJUST, &channel_ਨਿਵੇਸ਼_ਖਿੜਕੀ_adjust);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_SUCCESS, &channel_ਨਿਵੇਸ਼_ਸਥਿਤੀ_confirm);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_FAILURE, &channel_ਨਿਵੇਸ਼_ਸਥਿਤੀ_confirm);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST, &client_ਨਿਵੇਸ਼_global_request);

	/* rekeying */
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEXINIT, &kex_ਨਿਵੇਸ਼_kexinit);

	/* global request reply messages */
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_REQUEST_FAILURE, &client_global_request_ਜਵਾਬ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS, &client_global_request_ਜਵਾਬ);
}

ਖਾਲੀ
client_stop_mux(ਖਾਲੀ)
{
	ਜੇ (options.control_ਰਸਤਾ != ਨਿਰਾ && muxserver_sock != -1)
		unlink(options.control_ਰਸਤਾ);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	ਜੇ (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
ਖਾਲੀ
cleanup_exit(ਪੂਰਨ i)
{
	leave_raw_ਬਹੁਲਕ(options.request_tty == REQUEST_TTY_FORCE);
	ਜੇ (options.control_ਰਸਤਾ != ਨਿਰਾ && muxserver_sock != -1)
		unlink(options.control_ਰਸਤਾ);
	ssh_kill_proxy_command();
	_exit(i);
}
