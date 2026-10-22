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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/ioctl.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "readconf.h"
#അന്തര്ഭാവ "clientloop.h"
#അന്തര്ഭാവ "sshconnect.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "sshpty.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#define HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#define SSH_KEYSTROKE_TIMING_FUZZ 10

ബാഹ്യ അക്ഷരം *__progname;

/* import options */
ബാഹ്യ Options options;

/* Control socket */
ബാഹ്യ പൂർണ്ണസംഖ്യ muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
ബാഹ്യ അക്ഷരം *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
ബാഹ്യ അക്ഷരം *forward_agent_sock_path;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
സ്ഥിതം അസ്ഥിര sig_atomic_t received_window_change_signal = 0;
സ്ഥിതം അസ്ഥിര sig_atomic_t siginfo_received = 0;
സ്ഥിതം അസ്ഥിര sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
സ്ഥിതം time_t control_persist_exit_time = 0;

/* Common data for the client loop code. */
അസ്ഥിര sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
സ്ഥിതം പൂർണ്ണസംഖ്യ last_was_cr;		/* Last character was a newline. */
സ്ഥിതം പൂർണ്ണസംഖ്യ exit_status;		/* Used to store the command exit status. */
സ്ഥിതം പൂർണ്ണസംഖ്യ connection_in;	/* Connection to server (input). */
സ്ഥിതം പൂർണ്ണസംഖ്യ connection_out;	/* Connection to server (output). */
സ്ഥിതം പൂർണ്ണസംഖ്യ need_rekeying;	/* Set to non-zero if rekeying is requested. */
സ്ഥിതം പൂർണ്ണസംഖ്യ session_closed;	/* In SSH2: login session closed. */
സ്ഥിതം time_t x11_refuse_time;	/* If >0, refuse x11 opens after this time. */
സ്ഥിതം time_t server_alive_time;	/* Time to do server_alive_check */
സ്ഥിതം പൂർണ്ണസംഖ്യ hostkeys_update_complete;
സ്ഥിതം പൂർണ്ണസംഖ്യ session_setup_complete;

സ്ഥിതം ശൂന്യം client_init_dispatch(ഘടന ssh *ssh);
പൂർണ്ണസംഖ്യ	session_ident = -1;

/* Track escape per proto2 channel */
ഘടന escape_filter_ctx {
	പൂർണ്ണസംഖ്യ escape_pending;
	പൂർണ്ണസംഖ്യ escape_char;
};

/* Context for channel confirmation replies */
ഘടന channel_reply_ctx {
	സ്ഥിരം അക്ഷരം *request_type;
	പൂർണ്ണസംഖ്യ id;
	എണ്ണൽ confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
ഘടന global_confirm {
	TAILQ_ENTRY(global_confirm) entry;
	global_confirm_cb *cb;
	ശൂന്യം *ctx;
	പൂർണ്ണസംഖ്യ ref_എണ്ണം;
};
TAILQ_HEAD(global_confirms, global_confirm);
സ്ഥിതം ഘടന global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

സ്ഥിതം ശൂന്യം quit_message(സ്ഥിരം അക്ഷരം *fmt, ...)
    __attribute__((__format__ (printf, 1, 2)));

സ്ഥിതം ശൂന്യം
quit_message(സ്ഥിരം അക്ഷരം *fmt, ...)
{
	അക്ഷരം *സന്ദേശം, *fmt2;
	va_list args;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(args, fmt);
	xvasprintf(&സന്ദേശം, fmt2, args);
	va_end(args);

	(ശൂന്യം)atomicio(vwrite, STDERR_FILENO, സന്ദേശം, strlen(സന്ദേശം));
	സ്വതന്ത്രം(സന്ദേശം);
	സ്വതന്ത്രം(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
സ്ഥിതം ശൂന്യം
window_change_handler(പൂർണ്ണസംഖ്യ sig)
{
	received_window_change_signal = 1;
}

#ifdef SIGINFO
/* Signal handler for SIGINFO */
സ്ഥിതം ശൂന്യം
siginfo_handler(പൂർണ്ണസംഖ്യ sig)
{
	siginfo_received = 1;
}
#endif

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
സ്ഥിതം ശൂന്യം
signal_handler(പൂർണ്ണസംഖ്യ sig)
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
സ്ഥിതം ശൂന്യം
set_control_persist_exit_time(ഘടന ssh *ssh)
{
	എങ്കിൽ (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (channel_still_open(ssh)) {
		/* some client connections are still open */
		എങ്കിൽ (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#define SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
സ്ഥിതം പൂർണ്ണസംഖ്യ
client_x11_display_valid(സ്ഥിരം അക്ഷരം *display)
{
	size_t i, dlen;

	എങ്കിൽ (display == ശൂന്യ)
		തിരികെ 0;

	dlen = strlen(display);
	വേണ്ടി (i = 0; i < dlen; i++) {
		എങ്കിൽ (!isalnum((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == ശൂന്യ) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			തിരികെ 0;
		}
	}
	തിരികെ 1;
}

#define SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#define X11_TIMEOUT_SLACK	60
പൂർണ്ണസംഖ്യ
client_x11_get_proto(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *display,
    സ്ഥിരം അക്ഷരം *xauth_path, u_int trusted, u_int timeout,
    അക്ഷരം **_proto, അക്ഷരം **_data)
{
	അക്ഷരം *cmd, വരി[512], xdisplay[512];
	അക്ഷരം xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	സ്ഥിതം അക്ഷരം proto[512], data[512];
	FILE *f;
	പൂർണ്ണസംഖ്യ got_data = 0, generated = 0, do_unlink = 0, r;
	ഘടന stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*_data = data;
	proto[0] = data[0] = xauthfile[0] = xauthdir[0] = '\0';

	എങ്കിൽ (!client_x11_display_valid(display)) {
		എങ്കിൽ (display != ശൂന്യ)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		തിരികെ -1;
	}
	എങ്കിൽ (xauth_path != ശൂന്യ && stat(xauth_path, &st) == -1) {
		debug("No xauth program.");
		xauth_path = ശൂന്യ;
	}

	എങ്കിൽ (xauth_path != ശൂന്യ) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		എങ്കിൽ (strncmp(display, "localhost:", 10) == 0) {
			എങ്കിൽ ((r = snprintf(xdisplay, വലുപ്പം(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (size_t)r >= വലുപ്പം(xdisplay)) {
				error_f("display name too long");
				തിരികെ -1;
			}
			display = xdisplay;
		}
		എങ്കിൽ (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, വലുപ്പം(xauthdir));
			എങ്കിൽ (mkdtemp(xauthdir) == ശൂന്യ) {
				error_f("mkdtemp: %s", strerror(errno));
				തിരികെ -1;
			}
			do_unlink = 1;
			എങ്കിൽ ((r = snprintf(xauthfile, വലുപ്പം(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (size_t)r >= വലുപ്പം(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				തിരികെ -1;
			}

			എങ്കിൽ (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} അല്ലെങ്കിൽ {
				/* Add some slack to requested expiry */
				എങ്കിൽ (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				അല്ലെങ്കിൽ {
					/* Don't overflow on long timeouts */
					x11_timeout_real = UINT_MAX;
				}
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted timeout %u 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, x11_timeout_real,
				    _PATH_DEVNULL);
			}
			debug2_f("xauth command: %s", cmd);

			എങ്കിൽ (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				എങ്കിൽ (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				അല്ലെങ്കിൽ
					x11_refuse_time = now + timeout;
				channel_set_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			എങ്കിൽ (system(cmd) == 0)
				generated = 1;
			സ്വതന്ത്രം(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		എങ്കിൽ (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_path,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			എങ്കിൽ (f && fgets(വരി, വലുപ്പം(വരി), f) &&
			    sscanf(വരി, "%*s %511s %511s", proto, data) == 2)
				got_data = 1;
			എങ്കിൽ (f)
				pclose(f);
			സ്വതന്ത്രം(cmd);
		}
	}

	എങ്കിൽ (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	എങ്കിൽ (!trusted && !got_data) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		തിരികെ -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	എങ്കിൽ (!got_data) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, വലുപ്പം proto);
		arc4random_buf(rnd, വലുപ്പം(rnd));
		വേണ്ടി (i = 0; i < വലുപ്പം(rnd); i++) {
			snprintf(data + 2 * i, വലുപ്പം data - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	തിരികെ 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

സ്ഥിതം ശൂന്യം
client_check_window_change(ഘടന ssh *ssh)
{
	എങ്കിൽ (!received_window_change_signal)
		തിരികെ;
	received_window_change_signal = 0;
	debug2_f("changed");
	channel_send_window_changes(ssh);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
client_global_request_reply(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന global_confirm *gc;

	എങ്കിൽ ((gc = TAILQ_FIRST(&global_confirms)) == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (gc->cb != ശൂന്യ)
		gc->cb(ssh, type, seq, gc->ctx);
	എങ്കിൽ (--gc->ref_എണ്ണം <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, entry);
		freezero(gc, വലുപ്പം(*gc));
	}

	ssh_packet_set_alive_timeouts(ssh, 0);
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
schedule_server_alive_check(ശൂന്യം)
{
	എങ്കിൽ (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

സ്ഥിതം ശൂന്യം
server_alive_check(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_എണ്ണം_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_register_global_confirm(ശൂന്യ, ശൂന്യ);
	schedule_server_alive_check();
}

/* Try to send a dummy keystroke */
സ്ഥിതം പൂർണ്ണസംഖ്യ
send_chaff(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (ssh->kex == ശൂന്യ || (ssh->kex->flags & KEX_HAS_PING) == 0)
		തിരികെ 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	തിരികെ 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
സ്ഥിതം ശൂന്യം
set_next_interval(സ്ഥിരം ഘടന timespec *now, ഘടന timespec *next_interval,
    u_int interval_ms, പൂർണ്ണസംഖ്യ starting)
{
	ഘടന timespec tmp;
	long long interval_ns, fuzz_ns;
	സ്ഥിതം long long rate_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	എങ്കിൽ (fuzz_ns > INT_MAX)
		fuzz_ns = INT_MAX;
	എങ്കിൽ (fuzz_ns > interval_ns) {
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
	എങ്കിൽ (starting)
		rate_fuzz = arc4random_uniform(fuzz_ns);
	interval_ns -= fuzz_ns;
	interval_ns += arc4random_uniform(fuzz_ns) + rate_fuzz;

	tmp.tv_sec = interval_ns / (1000 * 1000 * 1000);
	tmp.tv_nsec = interval_ns % (1000 * 1000 * 1000);

	timespecadd(now, &tmp, next_interval);
}

/*
 * Performs keystroke timing obfuscation. Returns non-zero if the
 * output fd should be polled.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
obfuscate_keystroke_timing(ഘടന ssh *ssh, ഘടന timespec *timeout,
    പൂർണ്ണസംഖ്യ channel_did_enqueue)
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ active;
	സ്ഥിതം ഘടന timespec next_interval, chaff_until;
	ഘടന timespec now, tmp;
	പൂർണ്ണസംഖ്യ just_started = 0, had_keystroke = 0;
	സ്ഥിതം unsigned long long nchaff;
	അക്ഷരം *stop_reason = ശൂന്യ;
	long long n;

	monotime_ts(&now);

	എങ്കിൽ (options.obscure_keystroke_timing_interval <= 0)
		തിരികെ 1;	/* disabled in config */

	എങ്കിൽ (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} അല്ലെങ്കിൽ എങ്കിൽ (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} അല്ലെങ്കിൽ എങ്കിൽ (!ssh_packet_interactive_data_to_write(ssh) &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} അല്ലെങ്കിൽ എങ്കിൽ (active && channel_did_enqueue &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} അല്ലെങ്കിൽ എങ്കിൽ (active) {
		എങ്കിൽ (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} അല്ലെങ്കിൽ എങ്കിൽ (timespeccmp(&now, &next_interval, >=) &&
		    !ssh_packet_have_data_to_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			എങ്കിൽ (send_chaff(ssh))
				nchaff++;
		}
	}

	എങ്കിൽ (stop_reason != ശൂന്യ) {
		എങ്കിൽ (active) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			active = 0;
		}
		തിരികെ 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	എങ്കിൽ (!active && ssh_packet_interactive_data_to_write(ssh) &&
	    channel_did_enqueue && ssh_packet_have_data_to_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = active = 1;
		nchaff = 0;
		set_next_interval(&now, &next_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	എങ്കിൽ (!active)
		തിരികെ 1;

	എങ്കിൽ (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_to_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_uniform(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &next_interval);

	എങ്കിൽ (just_started)
		തിരികെ 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	എങ്കിൽ (timespeccmp(&now, &next_interval, <))
		/* ...unless there's x11 communication happening */
		തിരികെ x11_channel_used_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - next_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - next_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	set_next_interval(&now, &next_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	തിരികെ 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
സ്ഥിതം ശൂന്യം
client_wait_until_can_do_something(ഘടന ssh *ssh, ഘടന pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, പൂർണ്ണസംഖ്യ channel_did_enqueue,
    sigset_t *sigsetp, പൂർണ്ണസംഖ്യ *conn_in_readyp, പൂർണ്ണസംഖ്യ *conn_out_readyp)
{
	ഘടന timespec timeout;
	പൂർണ്ണസംഖ്യ ret, oready;
	u_int p;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	എങ്കിൽ (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	എങ്കിൽ (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_data_to_write(ssh)) {
		/* clear events since we did not call poll() */
		വേണ്ടി (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		തിരികെ;
	}

	oready = obfuscate_keystroke_timing(ssh, &timeout, channel_did_enqueue);

	/* Monitor server connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_in;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_out;
	(*pfdp)[1].events = (oready && ssh_packet_have_data_to_write(ssh)) ?
	    POLLOUT : 0;

	/*
	 * Wait for something to happen.  This will suspend the process until
	 * some polled descriptor can be read, written, or has some other
	 * event pending, or a timeout expires.
	 */
	set_control_persist_exit_time(ssh);
	എങ്കിൽ (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	എങ്കിൽ (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	എങ്കിൽ (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	എങ്കിൽ (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		വേണ്ടി (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		എങ്കിൽ (errno == EINTR)
			തിരികെ;
		/* Note: we might still have data in the buffers. */
		quit_message("poll: %s", strerror(errno));
		തിരികെ;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	എങ്കിൽ (options.server_alive_interval > 0 && !*conn_in_readyp &&
	    monotime() >= server_alive_time) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

സ്ഥിതം ശൂന്യം
client_suspend_self(ഘടന sshbuf *bin, ഘടന sshbuf *bout, ഘടന sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	എങ്കിൽ (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	എങ്കിൽ (sshbuf_len(berr) > 0)
		atomicio(vwrite, fileno(stderr), sshbuf_mutable_ptr(berr),
		    sshbuf_len(berr));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	sshbuf_reset(bin);
	sshbuf_reset(bout);
	sshbuf_reset(berr);

	/* Send the suspend signal to the program itself. */
	kill(getpid(), SIGTSTP);

	/* Reset window sizes in case they have changed */
	received_window_change_signal = 1;

	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
}

സ്ഥിതം ശൂന്യം
client_process_net_നിവേശം(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	schedule_server_alive_check();
	എങ്കിൽ ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		തിരികെ; /* success */
	എങ്കിൽ (r == SSH_ERR_SYSTEM_ERROR) {
		എങ്കിൽ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			തിരികെ;
		എങ്കിൽ (errno == EPIPE) {
			quit_message("Connection to %s closed by remote host.",
			    host);
			തിരികെ;
		}
	}
	quit_message("Read from remote host %s: %s", host, ssh_err(r));
}

സ്ഥിതം ശൂന്യം
client_status_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ type, Channel *c, ശൂന്യം *ctx)
{
	ഘടന channel_reply_ctx *cr = (ഘടന channel_reply_ctx *)ctx;
	അക്ഷരം errmsg[256];
	പൂർണ്ണസംഖ്യ r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	എങ്കിൽ (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	എങ്കിൽ (type == SSH2_സന്ദേശം_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} അല്ലെങ്കിൽ എങ്കിൽ (type == SSH2_സന്ദേശം_CHANNEL_FAILURE) {
		എങ്കിൽ (tochan) {
			snprintf(errmsg, വലുപ്പം(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} അല്ലെങ്കിൽ {
			snprintf(errmsg, വലുപ്പം(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		എങ്കിൽ (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		എങ്കിൽ (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			എങ്കിൽ ((r = sshbuf_put(c->extended, errmsg,
			    strlen(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} അല്ലെങ്കിൽ
			error("%s", errmsg);
		എങ്കിൽ (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			എങ്കിൽ (c->self == session_ident)
				leave_raw_mode(0);
			അല്ലെങ്കിൽ
				mux_tty_alloc_failed(ssh, c);
		} അല്ലെങ്കിൽ എങ്കിൽ (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	സ്വതന്ത്രം(cr);
}

സ്ഥിതം ശൂന്യം
client_abandon_status_confirm(ഘടന ssh *ssh, Channel *c, ശൂന്യം *ctx)
{
	സ്വതന്ത്രം(ctx);
}

ശൂന്യം
client_expect_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, സ്ഥിരം അക്ഷരം *request,
    എണ്ണൽ confirm_action action)
{
	ഘടന channel_reply_ctx *cr = xcalloc(1, വലുപ്പം(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_register_status_confirm(ssh, id, client_status_confirm,
	    client_abandon_status_confirm, cr);
}

ശൂന്യം
client_register_global_confirm(global_confirm_cb *cb, ശൂന്യം *ctx)
{
	ഘടന global_confirm *gc, *last_gc;

	/* Coalesce identical callbacks */
	last_gc = TAILQ_LAST(&global_confirms, global_confirms);
	എങ്കിൽ (last_gc && last_gc->cb == cb && last_gc->ctx == ctx) {
		എങ്കിൽ (++last_gc->ref_എണ്ണം >= INT_MAX)
			fatal_f("last_gc->ref_count = %d",
			    last_gc->ref_എണ്ണം);
		തിരികെ;
	}

	gc = xcalloc(1, വലുപ്പം(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_എണ്ണം = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, entry);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
can_update_hostkeys(ശൂന്യം)
{
	എങ്കിൽ (hostkeys_update_complete)
		തിരികെ 0;
	എങ്കിൽ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_mode)
		തിരികെ 0; /* won't ask in batchmode, so don't even try */
	എങ്കിൽ (!options.update_hostkeys || options.അക്കം_user_hostfiles <= 0)
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
client_repledge(ശൂന്യം)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	എങ്കിൽ (options.control_master || options.control_path != ശൂന്യ ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != ശൂന്യ || can_update_hostkeys() ||
	    (session_ident != -1 && !session_setup_complete)) {
		/* Can't tighten */
		തിരികെ;
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
	എങ്കിൽ (options.അക്കം_local_forwards != 0 ||
	    options.അക്കം_remote_forwards != 0 ||
	    options.അക്കം_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		എങ്കിൽ (pledge("stdio unix inet dns proc tty", ശൂന്യ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} അല്ലെങ്കിൽ എങ്കിൽ (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		എങ്കിൽ (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", ശൂന്യ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} അല്ലെങ്കിൽ {
		debug("pledge: fork");
		എങ്കിൽ (pledge(PLEDGE_EXTRA_INET "stdio proc tty", ശൂന്യ) == -1)
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

സ്ഥിതം ശൂന്യം
process_cmdline(ഘടന ssh *ssh)
{
	ശൂന്യം (*handler)(പൂർണ്ണസംഖ്യ);
	അക്ഷരം *s, *cmd;
	പൂർണ്ണസംഖ്യ ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	ഘടന Forward fwd;

	memset(&fwd, 0, വലുപ്പം(fwd));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	എങ്കിൽ (s == ശൂന്യ)
		പോകുക out;
	ആകുമ്പോൾ (isspace((u_char)*s))
		s++;
	എങ്കിൽ (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	എങ്കിൽ (*s == '\0')
		പോകുക out;

	എങ്കിൽ (*s == 'h' || *s == 'H' || *s == '?') {
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
		എങ്കിൽ (!options.permit_local_command)
			പോകുക out;
		logit("      !args                                  "
		    "Execute local command");
		പോകുക out;
	}

	എങ്കിൽ (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		പോകുക out;
	}

	എങ്കിൽ (*s == 'K') {
		delete = 1;
		s++;
	}
	എങ്കിൽ (*s == 'L')
		local = 1;
	അല്ലെങ്കിൽ എങ്കിൽ (*s == 'R')
		remote = 1;
	അല്ലെങ്കിൽ എങ്കിൽ (*s == 'D')
		dynamic = 1;
	അല്ലെങ്കിൽ {
		logit("Invalid command.");
		പോകുക out;
	}

	ആകുമ്പോൾ (isspace((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	എങ്കിൽ (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		എങ്കിൽ (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			പോകുക out;
		}
		എങ്കിൽ (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		അല്ലെങ്കിൽ എങ്കിൽ (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		അല്ലെങ്കിൽ
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_PORT_STATIC,
			    &options.fwd_opts) > 0;
		എങ്കിൽ (!ok) {
			logit("Unknown port forwarding.");
			പോകുക out;
		}
		logit("Canceled forwarding.");
	} അല്ലെങ്കിൽ {
		/* -R specs can be both dynamic or not, so check both. */
		എങ്കിൽ (remote) {
			എങ്കിൽ (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				പോകുക out;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			പോകുക out;
		}
		എങ്കിൽ (local || dynamic) {
			എങ്കിൽ (!channel_setup_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				പോകുക out;
			}
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				പോകുക out;
			}
		}
		logit("Forwarding port.");
	}

out:
	ssh_signal(SIGINT, handler);
	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	സ്വതന്ത്രം(cmd);
	സ്വതന്ത്രം(fwd.listen_host);
	സ്വതന്ത്രം(fwd.listen_path);
	സ്വതന്ത്രം(fwd.connect_host);
	സ്വതന്ത്രം(fwd.connect_path);
}

/* reasons to suppress output of an escape command in help output */
#define SUPPRESS_NEVER		0	/* never suppress, always show */
#define SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#define SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#define SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#define SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
ഘടന escape_help_text {
	സ്ഥിരം അക്ഷരം *cmd;
	സ്ഥിരം അക്ഷരം *text;
	unsigned പൂർണ്ണസംഖ്യ flags;
};
സ്ഥിതം ഘടന escape_help_text esc_txt[] = {
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

സ്ഥിതം ശൂന്യം
print_escape_help(ഘടന sshbuf *b, പൂർണ്ണസംഖ്യ escape_char, പൂർണ്ണസംഖ്യ mux_client,
    പൂർണ്ണസംഖ്യ using_stderr)
{
	unsigned പൂർണ്ണസംഖ്യ i, suppress_flags;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	വേണ്ടി (i = 0; i < വലുപ്പം(esc_txt)/വലുപ്പം(esc_txt[0]); i++) {
		എങ്കിൽ (esc_txt[i].flags & suppress_flags)
			തുടരുക;
		എങ്കിൽ ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	എങ്കിൽ ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
process_escapes(ഘടന ssh *ssh, Channel *c,
    ഘടന sshbuf *bin, ഘടന sshbuf *bout, ഘടന sshbuf *berr,
    അക്ഷരം *buf, പൂർണ്ണസംഖ്യ len)
{
	pid_t pid;
	പൂർണ്ണസംഖ്യ r, bytes = 0;
	u_int i;
	u_char ch;
	അക്ഷരം *s;
	ഘടന escape_filter_ctx *efc;

	എങ്കിൽ (c == ശൂന്യ || c->filter_ctx == ശൂന്യ || len <= 0)
		തിരികെ 0;

	efc = (ഘടന escape_filter_ctx *)c->filter_ctx;

	വേണ്ടി (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		എങ്കിൽ (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			തിരഞ്ഞെടുപ്പ് (ch) {
			അവസ്ഥ '.':
				/* Terminate the connection. */
				എങ്കിൽ ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				എങ്കിൽ (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					തിരികെ 0;
				} അല്ലെങ്കിൽ
					quit_pending = 1;
				തിരികെ -1;

			അവസ്ഥ 'Z' - 64:
				/* XXX support this for mux clients */
				എങ്കിൽ (c && c->ctl_chan != -1) {
					അക്ഷരം b[16];
 noescape:
					എങ്കിൽ (ch == 'Z' - 64)
						snprintf(b, വലുപ്പം b, "^Z");
					അല്ലെങ്കിൽ
						snprintf(b, വലുപ്പം b, "%c", ch);
					എങ്കിൽ ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					തുടരുക;
				}
				/* Suspend the program. Inform the user */
				എങ്കിൽ ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				തുടരുക;

			അവസ്ഥ 'B':
				എങ്കിൽ ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				എങ്കിൽ ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				തുടരുക;

			അവസ്ഥ 'I':
				എങ്കിൽ ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_message(ssh);
				എങ്കിൽ ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				സ്വതന്ത്രം(s);
				തുടരുക;

			അവസ്ഥ 'R':
				എങ്കിൽ (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				അല്ലെങ്കിൽ
					need_rekeying = 1;
				തുടരുക;

			അവസ്ഥ 'V':
				/* FALLTHROUGH */
			അവസ്ഥ 'v':
				എങ്കിൽ (c && c->ctl_chan != -1)
					പോകുക noescape;
				എങ്കിൽ (!log_is_on_stderr()) {
					എങ്കിൽ ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					തുടരുക;
				}
				എങ്കിൽ (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				എങ്കിൽ (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				എങ്കിൽ ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				തുടരുക;

			അവസ്ഥ '&':
				എങ്കിൽ (c->ctl_chan != -1)
					പോകുക noescape;
				/*
				 * Detach the program (continue to serve
				 * connections, but put in background and no
				 * more new connections).
				 */
				/* Restore tty modes. */
				leave_raw_mode(
				    options.request_tty == REQUEST_TTY_FORCE);

				/* Stop listening for new connections. */
				channel_stop_listening(ssh);

				എങ്കിൽ ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				എങ്കിൽ (pid == -1) {
					error("fork: %.100s", strerror(errno));
					തുടരുക;
				}
				എങ്കിൽ (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					exit(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				എങ്കിൽ ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				തിരികെ -1;
			അവസ്ഥ '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				തുടരുക;

			അവസ്ഥ '#':
				എങ്കിൽ ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_message(ssh);
				എങ്കിൽ ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				സ്വതന്ത്രം(s);
				തുടരുക;

			അവസ്ഥ 'C':
				എങ്കിൽ (c && c->ctl_chan != -1)
					പോകുക noescape;
				എങ്കിൽ (options.enable_escape_commandline == 0) {
					എങ്കിൽ ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					തുടരുക;
				}
				process_cmdline(ssh);
				തുടരുക;

			സ്ഥിരസ്ഥിതി:
				എങ്കിൽ (ch != efc->escape_char) {
					എങ്കിൽ ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					bytes++;
				}
				/* Escaped characters fall through here */
				നിർത്തുക;
			}
		} അല്ലെങ്കിൽ {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			എങ്കിൽ (last_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				തുടരുക;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		last_was_cr = (ch == '\r' || ch == '\n');
		എങ്കിൽ ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		bytes++;
	}
	തിരികെ bytes;
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

സ്ഥിതം ശൂന്യം
client_process_buffered_നിവേശം_packets(ഘടന ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
ശൂന്യം *
client_new_escape_filter_ctx(പൂർണ്ണസംഖ്യ escape_char)
{
	ഘടന escape_filter_ctx *ret;

	ret = xcalloc(1, വലുപ്പം(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	തിരികെ (ശൂന്യം *)ret;
}

/* Free the escape filter context on channel free */
ശൂന്യം
client_filter_cleanup(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ cid, ശൂന്യം *ctx)
{
	സ്വതന്ത്രം(ctx);
}

പൂർണ്ണസംഖ്യ
client_simple_escape_filter(ഘടന ssh *ssh, Channel *c, അക്ഷരം *buf, പൂർണ്ണസംഖ്യ len)
{
	എങ്കിൽ (c->extended_usage != CHAN_EXTENDED_WRITE)
		തിരികെ 0;

	തിരികെ process_escapes(ssh, c, c->നിവേശം, c->output, c->extended,
	    buf, len);
}

സ്ഥിതം ശൂന്യം
client_channel_closed(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ force, ശൂന്യം *arg)
{
	channel_cancel_cleanup(ssh, id);
	session_closed = 1;
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
}

/*
 * Implements the interactive session with the server.  This is called after
 * the user has been authenticated, and a command has been started on the
 * remote host.  If escape_char != SSH_ESCAPECHAR_NONE, it is the character
 * used as an escape character for terminating or suspending the session.
 */
പൂർണ്ണസംഖ്യ
client_loop(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ have_pty, പൂർണ്ണസംഖ്യ escape_char_arg,
    പൂർണ്ണസംഖ്യ ssh2_chan_id)
{
	ഘടന pollfd *pfd = ശൂന്യ;
	u_int npfd_alloc = 0, npfd_active = 0;
	ഇരട്ട start_time, total_time;
	പൂർണ്ണസംഖ്യ interactive = -1, channel_did_enqueue = 0, r;
	uint64_t ibytes, obytes;
	പൂർണ്ണസംഖ്യ conn_in_ready, conn_out_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	എങ്കിൽ (options.pkcs11_provider != ശൂന്യ)
		debug("pledge: disabled (PKCS11Provider active)");
	അല്ലെങ്കിൽ എങ്കിൽ (options.control_master &&
	    !option_clear_or_none(options.control_path)) {
		debug("pledge: id");
		എങ്കിൽ (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    ശൂന്യ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} അല്ലെങ്കിൽ എങ്കിൽ (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		എങ്കിൽ (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    ശൂന്യ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} അല്ലെങ്കിൽ എങ്കിൽ (options.update_hostkeys) {
		debug("pledge: filesystem");
		എങ്കിൽ (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    ശൂന്യ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} അല്ലെങ്കിൽ എങ്കിൽ (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		എങ്കിൽ (pledge("stdio cpath unix inet dns proc tty", ശൂന്യ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} അല്ലെങ്കിൽ {
		debug("pledge: network");
		എങ്കിൽ (pledge("stdio unix inet dns proc tty", ശൂന്യ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	}

	/* might be able to tighten now */
	client_repledge();

	start_time = monotime_double();

	/* Initialize variables. */
	last_was_cr = 1;
	exit_status = -1;
	connection_in = ssh_packet_get_connection_in(ssh);
	connection_out = ssh_packet_get_connection_out(ssh);

	quit_pending = 0;

	client_init_dispatch(ssh);

	/*
	 * Set signal handlers, (e.g. to restore non-blocking mode)
	 * but don't overwrite SIG_IGN, matches behaviour from rsh(1)
	 */
	എങ്കിൽ (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	എങ്കിൽ (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	എങ്കിൽ (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	എങ്കിൽ (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, window_change_handler);
#ifdef SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#endif

	എങ്കിൽ (have_pty)
		enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	എങ്കിൽ (session_ident != -1) {
		എങ്കിൽ (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, ശൂന്യ,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_register_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	schedule_server_alive_check();

	എങ്കിൽ (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ifdef SIGINFO
	എങ്കിൽ (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#endif

	/* Main loop of the client for the interactive session mode. */
	ആകുമ്പോൾ (!quit_pending) {
		channel_did_enqueue = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_നിവേശം_packets(ssh);

		എങ്കിൽ (session_closed && !channel_still_open(ssh))
			നിർത്തുക;

		എങ്കിൽ (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} അല്ലെങ്കിൽ എങ്കിൽ (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			എങ്കിൽ ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} അല്ലെങ്കിൽ {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			എങ്കിൽ (ssh_packet_not_very_much_data_to_write(ssh))
				channel_did_enqueue = channel_output_poll(ssh);

			/*
			 * Check if the window size has changed, and buffer a
			 * message about it to the server if so.
			 */
			client_check_window_change(ssh);
		}
		/*
		 * Wait until we have something to do (something becomes
		 * available on one of the descriptors).
		 */
		എങ്കിൽ (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		എങ്കിൽ (siginfo_received) {
			അക്ഷരം ident[256];

			sshpkt_fmt_connection_id(ssh, ident, വലുപ്പം(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - start_time);
			siginfo_received = 0;
		}
		എങ്കിൽ (quit_pending)
			നിർത്തുക;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_active, channel_did_enqueue, &osigset,
		    &conn_in_ready, &conn_out_ready);
		എങ്കിൽ (sigprocmask(SIG_SETMASK, &osigset, ശൂന്യ) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		എങ്കിൽ (quit_pending)
			നിർത്തുക;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_active);

		/* Buffer input from the connection.  */
		എങ്കിൽ (conn_in_ready)
			client_process_net_നിവേശം(ssh);

		എങ്കിൽ (quit_pending)
			നിർത്തുക;

		/* A timeout may have triggered rekeying */
		എങ്കിൽ ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		എങ്കിൽ (conn_out_ready) {
			എങ്കിൽ (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_set_interactive(ssh, interactive);
			}
			എങ്കിൽ ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		എങ്കിൽ (control_persist_exit_time > 0) {
			എങ്കിൽ (monotime() >= control_persist_exit_time) {
				debug("ControlPersist timeout expired");
				നിർത്തുക;
			}
		}
	}
	സ്വതന്ത്രം(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	എങ്കിൽ (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_message("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	എങ്കിൽ (have_pty)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	എങ്കിൽ (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_status = 0;
	}

	എങ്കിൽ (received_signal) {
		verbose("Killed by signal %d.", (പൂർണ്ണസംഖ്യ) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	total_time = monotime_double() - start_time;
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (unsigned long long)obytes, (unsigned long long)ibytes, total_time);
	എങ്കിൽ (total_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / total_time, ibytes / total_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	തിരികെ exit_status;
}

/*********/

സ്ഥിതം Channel *
client_request_forwarded_tcpip(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *request_type,
    പൂർണ്ണസംഖ്യ rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = ശൂന്യ;
	ഘടന sshbuf *b = ശൂന്യ;
	അക്ഷരം *listen_address, *originator_address;
	u_int listen_port, originator_port;
	പൂർണ്ണസംഖ്യ r;

	/* Get rest of the packet */
	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &listen_address, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_address, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_address, listen_port, originator_address, originator_port);

	എങ്കിൽ (listen_port > 0xffff)
		error_f("invalid listen port");
	അല്ലെങ്കിൽ എങ്കിൽ (originator_port > 0xffff)
		error_f("invalid originator port");
	അല്ലെങ്കിൽ {
		c = channel_connect_by_listen_address(ssh,
		    listen_address, listen_port, "forwarded-tcpip",
		    originator_address);
	}

	എങ്കിൽ (c != ശൂന്യ && c->type == SSH_CHANNEL_MUX_CLIENT) {
		എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
			error_f("alloc reply");
			പോകുക out;
		}
		/* reconstruct and send to muxclient */
		എങ്കിൽ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_സന്ദേശം_CHANNEL_OPEN)) != 0 ||
		    (r = sshbuf_put_cstring(b, request_type)) != 0 ||
		    (r = sshbuf_put_u32(b, rchan)) != 0 ||
		    (r = sshbuf_put_u32(b, rwindow)) != 0 ||
		    (r = sshbuf_put_u32(b, rmaxpack)) != 0 ||
		    (r = sshbuf_put_cstring(b, listen_address)) != 0 ||
		    (r = sshbuf_put_u32(b, listen_port)) != 0 ||
		    (r = sshbuf_put_cstring(b, originator_address)) != 0 ||
		    (r = sshbuf_put_u32(b, originator_port)) != 0 ||
		    (r = sshbuf_put_stringb(c->output, b)) != 0) {
			error_fr(r, "compose for muxclient");
			പോകുക out;
		}
	}

 out:
	sshbuf_free(b);
	സ്വതന്ത്രം(originator_address);
	സ്വതന്ത്രം(listen_address);
	തിരികെ c;
}

സ്ഥിതം Channel *
client_request_forwarded_streamlocal(ഘടന ssh *ssh,
    സ്ഥിരം അക്ഷരം *request_type, പൂർണ്ണസംഖ്യ rchan)
{
	Channel *c = ശൂന്യ;
	അക്ഷരം *listen_path;
	പൂർണ്ണസംഖ്യ r;

	/* Get the remote path. */
	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &listen_path, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_string(ssh, ശൂന്യ, ശൂന്യ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_path);

	c = channel_connect_by_listen_path(ssh, listen_path,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	സ്വതന്ത്രം(listen_path);
	തിരികെ c;
}

സ്ഥിതം Channel *
client_request_x11(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *request_type, പൂർണ്ണസംഖ്യ rchan)
{
	Channel *c = ശൂന്യ;
	അക്ഷരം *originator;
	u_int originator_port;
	പൂർണ്ണസംഖ്യ r, sock;

	എങ്കിൽ (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &originator, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_port);
	സ്വതന്ത്രം(originator);
	sock = x11_connect_display(ssh);
	എങ്കിൽ (sock < 0)
		തിരികെ ശൂന്യ;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	തിരികെ c;
}

സ്ഥിതം Channel *
client_request_agent(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *request_type, പൂർണ്ണസംഖ്യ rchan)
{
	Channel *c = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, sock;

	എങ്കിൽ (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (forward_agent_sock_path == ശൂന്യ) {
		r = ssh_get_authentication_socket(&sock);
	} അല്ലെങ്കിൽ {
		r = ssh_get_authentication_socket_path(forward_agent_sock_path, &sock);
	}
	എങ്കിൽ (r != 0) {
		എങ്കിൽ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	അല്ലെങ്കിൽ
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	തിരികെ c;
}

അക്ഷരം *
client_request_tun_fwd(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ tun_mode,
    പൂർണ്ണസംഖ്യ local_tun, പൂർണ്ണസംഖ്യ remote_tun, channel_open_fn *cb, ശൂന്യം *cbctx)
{
	Channel *c;
	പൂർണ്ണസംഖ്യ r, fd;
	അക്ഷരം *ifname = ശൂന്യ;

	എങ്കിൽ (tun_mode == SSH_TUNMODE_NO)
		തിരികെ ശൂന്യ;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	എങ്കിൽ ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		തിരികെ ശൂന്യ;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#എങ്കിൽ defined(SSH_TUN_FILTER)
	എങ്കിൽ (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ശൂന്യ, ശൂന്യ);
#endif

	എങ്കിൽ (cb != ശൂന്യ)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	തിരികെ ifname;
}

/* XXXX move to generic input handler */
സ്ഥിതം പൂർണ്ണസംഖ്യ
client_നിവേശം_channel_open(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Channel *c = ശൂന്യ;
	അക്ഷരം *ctype = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;
	u_int rchan;
	size_t len;
	u_int rmaxpack, rwindow;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		പോകുക out;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	എങ്കിൽ (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	എങ്കിൽ (c != ശൂന്യ && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} അല്ലെങ്കിൽ എങ്കിൽ (c != ശൂന്യ) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		എങ്കിൽ (c->type != SSH_CHANNEL_CONNECTING) {
			എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} അല്ലെങ്കിൽ {
		debug("failure %s", ctype);
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	സ്വതന്ത്രം(ctype);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
client_നിവേശം_channel_req(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Channel *c = ശൂന്യ;
	അക്ഷരം *rtype = ശൂന്യ;
	u_char reply;
	u_int id, exitval;
	പൂർണ്ണസംഖ്യ r, success = 0;

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &id)) != 0)
		തിരികെ r;
	എങ്കിൽ (id <= INT_MAX)
		c = channel_lookup(ssh, id);
	എങ്കിൽ (channel_proxy_upstream(c, type, seq, ssh))
		തിരികെ 0;
	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &rtype, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &reply)) != 0)
		പോകുക out;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, reply);

	എങ്കിൽ (c == ശൂന്യ) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "eow@openssh.com") == 0) {
		എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
			പോകുക out;
		chan_rcvd_eow(ssh, c);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "exit-status") == 0) {
		എങ്കിൽ ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			പോകുക out;
		എങ്കിൽ (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ ((പൂർണ്ണസംഖ്യ)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} അല്ലെങ്കിൽ {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
			പോകുക out;
	}
	എങ്കിൽ (reply && c != ശൂന്യ && !(c->flags & CHAN_CLOSE_SENT)) {
		എങ്കിൽ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		എങ്കിൽ ((r = sshpkt_start(ssh, success ?
		    SSH2_സന്ദേശം_CHANNEL_SUCCESS : SSH2_സന്ദേശം_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	സ്വതന്ത്രം(rtype);
	തിരികെ r;
}

ഘടന hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	അക്ഷരം *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	ഘടന sshkey **താക്കോലുകൾ;
	u_int *താക്കോലുകൾ_match;	/* mask of HKF_MATCH_* from hostfile.h */
	പൂർണ്ണസംഖ്യ *താക്കോലുകൾ_verified;	/* flag for new keys verified by server */
	size_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	ഘടന sshkey **old_താക്കോലുകൾ;
	size_t nold;

	/* Various special cases. */
	പൂർണ്ണസംഖ്യ complex_hostspec;	/* wildcard or manual pattern-list host name */
	പൂർണ്ണസംഖ്യ ca_available;	/* saw CA key for this host */
	പൂർണ്ണസംഖ്യ old_താക്കോൽ_seen;	/* saw old key with other name/addr */
	പൂർണ്ണസംഖ്യ other_name_seen;	/* saw key with other name/addr */
};

സ്ഥിതം ശൂന്യം
hostkeys_update_ctx_free(ഘടന hostkeys_update_ctx *ctx)
{
	size_t i;

	എങ്കിൽ (ctx == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->താക്കോലുകൾ[i]);
	സ്വതന്ത്രം(ctx->താക്കോലുകൾ);
	സ്വതന്ത്രം(ctx->താക്കോലുകൾ_match);
	സ്വതന്ത്രം(ctx->താക്കോലുകൾ_verified);
	വേണ്ടി (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_താക്കോലുകൾ[i]);
	സ്വതന്ത്രം(ctx->old_താക്കോലുകൾ);
	സ്വതന്ത്രം(ctx->host_str);
	സ്വതന്ത്രം(ctx->ip_str);
	സ്വതന്ത്രം(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
hostspec_is_complex(സ്ഥിരം അക്ഷരം *hosts)
{
	അക്ഷരം *cp;

	/* wildcard */
	എങ്കിൽ (strchr(hosts, '*') != ശൂന്യ || strchr(hosts, '?') != ശൂന്യ)
		തിരികെ 1;
	/* single host/ip = ok */
	എങ്കിൽ ((cp = strchr(hosts, ',')) == ശൂന്യ)
		തിരികെ 0;
	/* more than two entries on the line */
	എങ്കിൽ (strchr(cp + 1, ',') != ശൂന്യ)
		തിരികെ 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	തിരികെ 0;
}

/* callback to search for ctx->keys in known_hosts */
സ്ഥിതം പൂർണ്ണസംഖ്യ
hostkeys_find(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *_ctx)
{
	ഘടന hostkeys_update_ctx *ctx = (ഘടന hostkeys_update_ctx *)_ctx;
	size_t i;
	ഘടന sshkey **tmp;

	എങ്കിൽ (l->താക്കോൽ == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (l->status != HKF_STATUS_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		വേണ്ടി (i = 0; i < ctx->nkeys; i++) {
			എങ്കിൽ (sshkey_equal(l->താക്കോൽ, ctx->താക്കോലുകൾ[i])) {
				ctx->other_name_seen = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->താക്കോലുകൾ[i]),
				    l->path, l->linenum);
				തിരികെ 0;
			}
		}
		തിരികെ 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	എങ്കിൽ (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		തിരികെ 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	എങ്കിൽ (ctx->ip_str != ശൂന്യ && strchr(l->hosts, ',') != ശൂന്യ) {
		എങ്കിൽ ((l->match & HKF_MATCH_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_seen = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->path, l->linenum);
			തിരികെ 0;
		} അല്ലെങ്കിൽ എങ്കിൽ ((l->match & HKF_MATCH_IP) == 0) {
			/* Record if hostname matched a different address. */
			ctx->other_name_seen = 1;
			debug3_f("found hostname %s against different address "
			    "at %s:%ld", ctx->host_str, l->path, l->linenum);
		}
	}

	/*
	 * UpdateHostkeys is skipped for wildcard host names and hostnames
	 * that contain more than two entries (ssh never writes these).
	 */
	എങ്കിൽ (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		തിരികെ 0;
	}

	/* Mark off keys we've already seen for this host */
	വേണ്ടി (i = 0; i < ctx->nkeys; i++) {
		എങ്കിൽ (!sshkey_equal(l->താക്കോൽ, ctx->താക്കോലുകൾ[i]))
			തുടരുക;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->താക്കോലുകൾ[i]), l->path, l->linenum);
		ctx->താക്കോലുകൾ_match[i] |= l->match;
		തിരികെ 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->താക്കോൽ),
	    l->path, l->linenum);
	എങ്കിൽ ((tmp = recallocarray(ctx->old_താക്കോലുകൾ, ctx->nold, ctx->nold + 1,
	    വലുപ്പം(*ctx->old_താക്കോലുകൾ))) == ശൂന്യ)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_താക്കോലുകൾ = tmp;
	ctx->old_താക്കോലുകൾ[ctx->nold++] = l->താക്കോൽ;
	l->താക്കോൽ = ശൂന്യ;

	തിരികെ 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
സ്ഥിതം പൂർണ്ണസംഖ്യ
hostkeys_check_old(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *_ctx)
{
	ഘടന hostkeys_update_ctx *ctx = (ഘടന hostkeys_update_ctx *)_ctx;
	size_t i;
	പൂർണ്ണസംഖ്യ hashed;

	/* only care about lines that *don't* match the active host spec */
	എങ്കിൽ (l->status == HKF_STATUS_MATCHED || l->താക്കോൽ == ശൂന്യ)
		തിരികെ 0;

	hashed = l->match & (HKF_MATCH_HOST_HASHED|HKF_MATCH_IP_HASHED);
	വേണ്ടി (i = 0; i < ctx->nold; i++) {
		എങ്കിൽ (!sshkey_equal(l->താക്കോൽ, ctx->old_താക്കോലുകൾ[i]))
			തുടരുക;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_താക്കോലുകൾ[i]), l->path, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_താക്കോൽ_seen = 1;
		നിർത്തുക;
	}
	തിരികെ 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
check_old_താക്കോലുകൾ_othernames(ഘടന hostkeys_update_ctx *ctx)
{
	size_t i;
	പൂർണ്ണസംഖ്യ r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	വേണ്ടി (i = 0; i < options.അക്കം_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		എങ്കിൽ ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_താക്കോൽ, 0)) != 0) {
			എങ്കിൽ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				തുടരുക;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			തിരികെ -1;
		}
	}
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

സ്ഥിതം ശൂന്യം
update_known_hosts(ഘടന hostkeys_update_ctx *ctx)
{
	പൂർണ്ണസംഖ്യ r, was_raw = 0, first = 1;
	പൂർണ്ണസംഖ്യ asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	അക്ഷരം *fp, *response;
	size_t i;
	ഘടന stat sb;

	വേണ്ടി (i = 0; i < ctx->nkeys; i++) {
		എങ്കിൽ (!ctx->താക്കോലുകൾ_verified[i])
			തുടരുക;
		എങ്കിൽ ((fp = sshkey_fingerprint(ctx->താക്കോലുകൾ[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("sshkey_fingerprint failed");
		എങ്കിൽ (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->താക്കോലുകൾ[i]), fp);
		first = 0;
		സ്വതന്ത്രം(fp);
	}
	വേണ്ടി (i = 0; i < ctx->nold; i++) {
		എങ്കിൽ ((fp = sshkey_fingerprint(ctx->old_താക്കോലുകൾ[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("sshkey_fingerprint failed");
		എങ്കിൽ (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_താക്കോലുകൾ[i]), fp);
		first = 0;
		സ്വതന്ത്രം(fp);
	}
	എങ്കിൽ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		എങ്കിൽ (get_saved_tio() != ശൂന്യ) {
			leave_raw_mode(1);
			was_raw = 1;
		}
		response = ശൂന്യ;
		വേണ്ടി (i = 0; !quit_pending && i < 3; i++) {
			സ്വതന്ത്രം(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			എങ്കിൽ (response != ശൂന്യ && strcasecmp(response, "yes") == 0)
				നിർത്തുക;
			അല്ലെങ്കിൽ എങ്കിൽ (quit_pending || response == ശൂന്യ ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				നിർത്തുക;
			} അല്ലെങ്കിൽ {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		എങ്കിൽ (quit_pending || i >= 3 || response == ശൂന്യ)
			options.update_hostkeys = 0;
		സ്വതന്ത്രം(response);
		എങ്കിൽ (was_raw)
			enter_raw_mode(1);
	}
	എങ്കിൽ (options.update_hostkeys == 0)
		തിരികെ;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	വേണ്ടി (i = 0; i < options.അക്കം_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		എങ്കിൽ (stat(options.user_hostfiles[i], &sb) != 0) {
			എങ്കിൽ (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} അല്ലെങ്കിൽ {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			തുടരുക;
		}
		എങ്കിൽ ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->താക്കോലുകൾ : ശൂന്യ, i == 0 ? ctx->nkeys : 0,
		    options.hash_known_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

സ്ഥിതം ശൂന്യം
client_global_hostkeys_prove_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ type,
    uint32_t seq, ശൂന്യം *_ctx)
{
	ഘടന hostkeys_update_ctx *ctx = (ഘടന hostkeys_update_ctx *)_ctx;
	size_t i, ndone;
	ഘടന sshbuf *signdata;
	പൂർണ്ണസംഖ്യ r, plaintype;
	സ്ഥിരം u_char *sig;
	സ്ഥിരം അക്ഷരം *rsa_kexalg = ശൂന്യ;
	അക്ഷരം *alg = ശൂന്യ;
	size_t siglen;

	എങ്കിൽ (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	എങ്കിൽ (type != SSH2_സന്ദേശം_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		തിരികെ;
	}
	എങ്കിൽ (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == താക്കോൽ_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	എങ്കിൽ ((signdata = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	വേണ്ടി (ndone = i = 0; i < ctx->nkeys; i++) {
		എങ്കിൽ (ctx->താക്കോലുകൾ_match[i])
			തുടരുക;
		plaintype = sshkey_type_plain(ctx->താക്കോലുകൾ[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		എങ്കിൽ ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->താക്കോലുകൾ[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		എങ്കിൽ ((r = sshpkt_get_string_direct(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			പോകുക out;
		}
		എങ്കിൽ ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->താക്കോലുകൾ[i]), i);
			പോകുക out;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		എങ്കിൽ (plaintype == താക്കോൽ_RSA && rsa_kexalg == ശൂന്യ &&
		    match_pattern_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			സ്വതന്ത്രം(alg);
			/* zap the key from the list */
			sshkey_free(ctx->താക്കോലുകൾ[i]);
			ctx->താക്കോലുകൾ[i] = ശൂന്യ;
			ndone++;
			തുടരുക;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->താക്കോലുകൾ[i]), i, alg);
		സ്വതന്ത്രം(alg);
		എങ്കിൽ ((r = sshkey_verify(ctx->താക്കോലുകൾ[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == താക്കോൽ_RSA ? rsa_kexalg : ശൂന്യ, 0, ശൂന്യ)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->താക്കോലുകൾ[i]), i);
			പോകുക out;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->താക്കോലുകൾ_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	എങ്കിൽ (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0) {
		error_f("protocol error");
		പോകുക out;
	}

	/* Make the edits to known_hosts */
	update_known_hosts(ctx);
 out:
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
client_നിവേശം_hostkeys(ഘടന ssh *ssh)
{
	സ്ഥിരം u_char *blob = ശൂന്യ;
	size_t i, len = 0;
	ഘടന sshbuf *buf = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ, **tmp;
	പൂർണ്ണസംഖ്യ r, prove_sent = 0;
	അക്ഷരം *fp;
	സ്ഥിതം പൂർണ്ണസംഖ്യ hostkeys_seen = 0; /* XXX use struct ssh */
	ബാഹ്യ ഘടന sockaddr_storage hostaddr; /* XXX from ssh.c */
	ഘടന hostkeys_update_ctx *ctx = ശൂന്യ;
	u_int want;

	എങ്കിൽ (hostkeys_seen)
		fatal_f("server already sent hostkeys");
	എങ്കിൽ (!can_update_hostkeys())
		തിരികെ 1;
	hostkeys_seen = 1;

	ctx = xcalloc(1, വലുപ്പം(*ctx));
	ആകുമ്പോൾ (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(താക്കോൽ);
		താക്കോൽ = ശൂന്യ;
		എങ്കിൽ ((r = sshpkt_get_string_direct(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			പോകുക out;
		}
		എങ്കിൽ ((r = sshkey_from_blob(blob, len, &താക്കോൽ)) != 0) {
			do_log2_fr(r, r == SSH_ERR_താക്കോൽ_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			തുടരുക;
		}
		fp = sshkey_fingerprint(താക്കോൽ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(താക്കോൽ), fp);
		സ്വതന്ത്രം(fp);

		എങ്കിൽ (!hostkey_accepted_by_hostkeyalgs(താക്കോൽ)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(താക്കോൽ));
			തുടരുക;
		}
		/* Skip certs */
		എങ്കിൽ (sshkey_is_cert(താക്കോൽ)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(താക്കോൽ));
			തുടരുക;
		}
		/* Ensure keys are unique */
		വേണ്ടി (i = 0; i < ctx->nkeys; i++) {
			എങ്കിൽ (sshkey_equal(താക്കോൽ, ctx->താക്കോലുകൾ[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(താക്കോൽ));
				പോകുക out;
			}
		}
		/* Key is good, record it */
		എങ്കിൽ ((tmp = recallocarray(ctx->താക്കോലുകൾ, ctx->nkeys, ctx->nkeys + 1,
		    വലുപ്പം(*ctx->താക്കോലുകൾ))) == ശൂന്യ)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->താക്കോലുകൾ = tmp;
		ctx->താക്കോലുകൾ[ctx->nkeys++] = താക്കോൽ;
		താക്കോൽ = ശൂന്യ;
	}

	എങ്കിൽ (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		പോകുക out;
	}

	എങ്കിൽ ((ctx->താക്കോലുകൾ_match = calloc(ctx->nkeys,
	    വലുപ്പം(*ctx->താക്കോലുകൾ_match))) == ശൂന്യ ||
	    (ctx->താക്കോലുകൾ_verified = calloc(ctx->nkeys,
	    വലുപ്പം(*ctx->താക്കോലുകൾ_verified))) == ശൂന്യ)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (ഘടന sockaddr *)&hostaddr : ശൂന്യ,
	    options.port, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : ശൂന്യ);

	/* Find which keys we already know about. */
	വേണ്ടി (i = 0; i < options.അക്കം_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		എങ്കിൽ ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_താക്കോൽ, 0)) != 0) {
			എങ്കിൽ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				തുടരുക;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			പോകുക out;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_MATCH_HOST | ( options.check_host_ip ? HKF_MATCH_IP : 0);
	വേണ്ടി (i = 0; i < ctx->nkeys; i++) {
		എങ്കിൽ (ctx->താക്കോലുകൾ_match[i] == 0)
			ctx->nnew++;
		എങ്കിൽ ((ctx->താക്കോലുകൾ_match[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	എങ്കിൽ (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		പോകുക out;
	}

	/* Various reasons why we cannot proceed with the update */
	എങ്കിൽ (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		പോകുക out;
	}
	എങ്കിൽ (ctx->other_name_seen) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		പോകുക out;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	എങ്കിൽ (ctx->nold != 0) {
		എങ്കിൽ (check_old_താക്കോലുകൾ_othernames(ctx) != 0)
			പോകുക out; /* error already logged */
		എങ്കിൽ (ctx->old_താക്കോൽ_seen) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == ശൂന്യ ? "" : ",",
			    ctx->ip_str == ശൂന്യ ? "" : ctx->ip_str);
			പോകുക out;
		}
	}

	എങ്കിൽ (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_known_hosts(ctx);
		പോകുക out;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	വേണ്ടി (i = 0; i < ctx->nkeys; i++) {
		എങ്കിൽ (ctx->താക്കോലുകൾ_match[i])
			തുടരുക;
		sshbuf_reset(buf);
		എങ്കിൽ ((r = sshkey_putb(ctx->താക്കോലുകൾ[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_register_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = ശൂന്യ;  /* will be freed in callback */
	prove_sent = 1;

	/* Success */
 out:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(താക്കോൽ);
	sshbuf_free(buf);
	എങ്കിൽ (!prove_sent) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
client_നിവേശം_global_request(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	അക്ഷരം *rtype;
	u_char want_reply;
	പൂർണ്ണസംഖ്യ r, success = 0;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &rtype, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		പോകുക out;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_reply);
	എങ്കിൽ (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_നിവേശം_hostkeys(ssh);
	എങ്കിൽ (want_reply) {
		എങ്കിൽ ((r = sshpkt_start(ssh, success ? SSH2_സന്ദേശം_REQUEST_SUCCESS :
		    SSH2_സന്ദേശം_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			പോകുക out;
	}
	r = 0;
 out:
	സ്വതന്ത്രം(rtype);
	തിരികെ r;
}

സ്ഥിതം ശൂന്യം
client_send_env(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, സ്ഥിരം അക്ഷരം *name, സ്ഥിരം അക്ഷരം *val)
{
	പൂർണ്ണസംഖ്യ r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	എങ്കിൽ ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

ശൂന്യം
client_session2_setup(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ want_tty, പൂർണ്ണസംഖ്യ want_subsystem,
    സ്ഥിരം അക്ഷരം *term, ഘടന termios *tiop, പൂർണ്ണസംഖ്യ in_fd, ഘടന sshbuf *cmd,
    അക്ഷരം **env)
{
	size_t i, j, len;
	പൂർണ്ണസംഖ്യ matched, r;
	അക്ഷരം *type = ശൂന്യ, *cmdstring = ശൂന്യ, *name, *val;
	Channel *c = ശൂന്യ;

	debug2_f("id %d", id);

	എങ്കിൽ ((c = channel_lookup(ssh, id)) == ശൂന്യ)
		fatal_f("channel %d: unknown channel", id);

	എങ്കിൽ (want_tty) {
		ഘടന winsize ws;

		/* Store window size in the packet. */
		എങ്കിൽ (ioctl(in_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, വലുപ്പം(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, term != ശൂന്യ ? term : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		എങ്കിൽ (tiop == ശൂന്യ)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	എങ്കിൽ (options.അക്കം_send_env != 0 && env != ശൂന്യ) {
		debug("Sending environment.");
		വേണ്ടി (i = 0; env[i] != ശൂന്യ; i++) {
			/* Split */
			name = xstrdup(env[i]);
			എങ്കിൽ ((val = strchr(name, '=')) == ശൂന്യ) {
				സ്വതന്ത്രം(name);
				തുടരുക;
			}
			*val++ = '\0';

			matched = 0;
			വേണ്ടി (j = 0; j < options.അക്കം_send_env; j++) {
				എങ്കിൽ (match_pattern(name, options.send_env[j])) {
					matched = 1;
					നിർത്തുക;
				}
			}
			എങ്കിൽ (!matched) {
				debug3("Ignored env %s", name);
				സ്വതന്ത്രം(name);
				തുടരുക;
			}
			client_send_env(ssh, id, name, val);
			സ്വതന്ത്രം(name);
		}
	}
	വേണ്ടി (i = 0; i < options.അക്കം_setenv; i++) {
		/* Split */
		name = xstrdup(options.setenv[i]);
		എങ്കിൽ ((val = strchr(name, '=')) == ശൂന്യ) {
			സ്വതന്ത്രം(name);
			തുടരുക;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		സ്വതന്ത്രം(name);
	}

	len = sshbuf_len(cmd);
	എങ്കിൽ (len > 0) {
		എങ്കിൽ ((cmdstring = sshbuf_dup_string(cmd)) == ശൂന്യ)
			fatal_f("sshbuf_dup_string failed");
		എങ്കിൽ (len > 900)
			len = 900;
		എങ്കിൽ (want_subsystem) {
			debug("Sending subsystem: %.*s", (പൂർണ്ണസംഖ്യ)len, cmdstring);
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} അല്ലെങ്കിൽ {
			debug("Sending command: %.*s", (പൂർണ്ണസംഖ്യ)len, cmdstring);
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		എങ്കിൽ ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} അല്ലെങ്കിൽ {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_set_xtype(ssh, id, type);
	സ്വതന്ത്രം(cmdstring);
	സ്വതന്ത്രം(type);

	session_setup_complete = 1;
	client_repledge();
}

ശൂന്യം
client_channel_request_agent_forwarding(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id)
{
	സ്ഥിരം അക്ഷരം *req = "auth-agent-req@openssh.com";
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (ssh->kex != ശൂന്യ && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_start(ssh, id, req, 0);
	എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

സ്ഥിതം ശൂന്യം
client_init_dispatch(ഘടന ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_CLOSE, &channel_നിവേശം_oclose);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_DATA, &channel_നിവേശം_data);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_EOF, &channel_നിവേശം_ieof);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_EXTENDED_DATA, &channel_നിവേശം_extended_data);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN, &client_നിവേശം_channel_open);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION, &channel_നിവേശം_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN_FAILURE, &channel_നിവേശം_open_failure);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_REQUEST, &client_നിവേശം_channel_req);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_WINDOW_ADJUST, &channel_നിവേശം_window_adjust);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_SUCCESS, &channel_നിവേശം_status_confirm);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_CHANNEL_FAILURE, &channel_നിവേശം_status_confirm);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST, &client_നിവേശം_global_request);

	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEXINIT, &kex_നിവേശം_kexinit);

	/* global request reply messages */
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_REQUEST_FAILURE, &client_global_request_reply);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_REQUEST_SUCCESS, &client_global_request_reply);
}

ശൂന്യം
client_stop_mux(ശൂന്യം)
{
	എങ്കിൽ (options.control_path != ശൂന്യ && muxserver_sock != -1)
		unlink(options.control_path);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	എങ്കിൽ (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ i)
{
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	എങ്കിൽ (options.control_path != ശൂന്യ && muxserver_sock != -1)
		unlink(options.control_path);
	ssh_kill_proxy_command();
	_exit(i);
}
