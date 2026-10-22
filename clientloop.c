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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/ioctl.h>
#ضمن <sys/stat.h>
#ضمن <sys/time.h>
#ضمن <sys/queue.h>

#ضمن <ctype.h>
#ضمن <errno.h>
#ضمن <paths.h>
#ضمن <poll.h>
#ضمن <signal.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>
#ضمن <limits.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "packet.h"
#ضمن "sshbuf.h"
#ضمن "compat.h"
#ضمن "channels.h"
#ضمن "dispatch.h"
#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "readconf.h"
#ضمن "clientloop.h"
#ضمن "sshconnect.h"
#ضمن "authfd.h"
#ضمن "atomicio.h"
#ضمن "sshpty.h"
#ضمن "match.h"
#ضمن "ssherr.h"
#ضمن "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#define HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#define SSH_KEYSTROKE_TIMING_FUZZ 10

خارجي حرف *__progname;

/* import options */
خارجي Options options;

/* Control socket */
خارجي صحيح muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
خارجي حرف *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
خارجي حرف *forward_agent_sock_path;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
ساكن متطاير sig_atomic_t received_window_change_signal = 0;
ساكن متطاير sig_atomic_t siginfo_received = 0;
ساكن متطاير sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
ساكن time_t control_persist_exit_time = 0;

/* Common data for the client loop code. */
متطاير sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
ساكن صحيح last_was_cr;		/* Last character was a newline. */
ساكن صحيح exit_status;		/* Used to store the command exit status. */
ساكن صحيح connection_in;	/* Connection to server (input). */
ساكن صحيح connection_out;	/* Connection to server (output). */
ساكن صحيح need_rekeying;	/* Set to non-zero if rekeying is requested. */
ساكن صحيح session_closed;	/* In SSH2: login session closed. */
ساكن time_t x11_refuse_time;	/* If >0, refuse x11 opens after this time. */
ساكن time_t server_alive_time;	/* Time to do server_alive_check */
ساكن صحيح hostkeys_update_complete;
ساكن صحيح session_setup_complete;

ساكن فراغ client_init_dispatch(بنية ssh *ssh);
صحيح	session_ident = -1;

/* Track escape per proto2 channel */
بنية escape_filter_ctx {
	صحيح escape_pending;
	صحيح escape_char;
};

/* Context for channel confirmation replies */
بنية channel_reply_ctx {
	ثابت حرف *request_type;
	صحيح id;
	تعداد confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
بنية global_confirm {
	TAILQ_ENTRY(global_confirm) entry;
	global_confirm_cb *cb;
	فراغ *ctx;
	صحيح ref_سانى;
};
TAILQ_HEAD(global_confirms, global_confirm);
ساكن بنية global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

ساكن فراغ quit_message(ثابت حرف *fmt, ...)
    __attribute__((__format__ (printf, 1, 2)));

ساكن فراغ
quit_message(ثابت حرف *fmt, ...)
{
	حرف *ئۇچۇر, *fmt2;
	va_list args;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(args, fmt);
	xvasprintf(&ئۇچۇر, fmt2, args);
	va_end(args);

	(فراغ)atomicio(vwrite, STDERR_FILENO, ئۇچۇر, strlen(ئۇچۇر));
	حرر(ئۇچۇر);
	حرر(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
ساكن فراغ
window_change_handler(صحيح sig)
{
	received_window_change_signal = 1;
}

#ifdef SIGINFO
/* Signal handler for SIGINFO */
ساكن فراغ
siginfo_handler(صحيح sig)
{
	siginfo_received = 1;
}
#endif

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
ساكن فراغ
signal_handler(صحيح sig)
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
ساكن فراغ
set_control_persist_exit_time(بنية ssh *ssh)
{
	إذا (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} وإلا إذا (channel_still_open(ssh)) {
		/* some client connections are still open */
		إذا (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} وإلا إذا (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#define SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
ساكن صحيح
client_x11_display_valid(ثابت حرف *display)
{
	size_t i, dlen;

	إذا (display == عدم)
		أرجع 0;

	dlen = strlen(display);
	لكل (i = 0; i < dlen; i++) {
		إذا (!isalnum((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == عدم) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			أرجع 0;
		}
	}
	أرجع 1;
}

#define SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#define X11_TIMEOUT_SLACK	60
صحيح
client_x11_get_proto(بنية ssh *ssh, ثابت حرف *display,
    ثابت حرف *xauth_path, u_int trusted, u_int timeout,
    حرف **_proto, حرف **_data)
{
	حرف *cmd, قۇر[512], xdisplay[512];
	حرف xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	ساكن حرف proto[512], data[512];
	FILE *f;
	صحيح got_data = 0, generated = 0, do_unlink = 0, r;
	بنية stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*_data = data;
	proto[0] = data[0] = xauthfile[0] = xauthdir[0] = '\0';

	إذا (!client_x11_display_valid(display)) {
		إذا (display != عدم)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		أرجع -1;
	}
	إذا (xauth_path != عدم && stat(xauth_path, &st) == -1) {
		debug("No xauth program.");
		xauth_path = عدم;
	}

	إذا (xauth_path != عدم) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		إذا (strncmp(display, "localhost:", 10) == 0) {
			إذا ((r = snprintf(xdisplay, حجم(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (size_t)r >= حجم(xdisplay)) {
				error_f("display name too long");
				أرجع -1;
			}
			display = xdisplay;
		}
		إذا (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, حجم(xauthdir));
			إذا (mkdtemp(xauthdir) == عدم) {
				error_f("mkdtemp: %s", strerror(errno));
				أرجع -1;
			}
			do_unlink = 1;
			إذا ((r = snprintf(xauthfile, حجم(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (size_t)r >= حجم(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				أرجع -1;
			}

			إذا (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} وإلا {
				/* Add some slack to requested expiry */
				إذا (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				وإلا {
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

			إذا (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				إذا (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				وإلا
					x11_refuse_time = now + timeout;
				channel_set_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			إذا (system(cmd) == 0)
				generated = 1;
			حرر(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		إذا (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_path,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			إذا (f && fgets(قۇر, حجم(قۇر), f) &&
			    sscanf(قۇر, "%*s %511s %511s", proto, data) == 2)
				got_data = 1;
			إذا (f)
				pclose(f);
			حرر(cmd);
		}
	}

	إذا (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	إذا (!trusted && !got_data) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		أرجع -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	إذا (!got_data) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, حجم proto);
		arc4random_buf(rnd, حجم(rnd));
		لكل (i = 0; i < حجم(rnd); i++) {
			snprintf(data + 2 * i, حجم data - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	أرجع 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

ساكن فراغ
client_check_window_change(بنية ssh *ssh)
{
	إذا (!received_window_change_signal)
		أرجع;
	received_window_change_signal = 0;
	debug2_f("changed");
	channel_send_window_changes(ssh);
}

ساكن صحيح
client_global_request_reply(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية global_confirm *gc;

	إذا ((gc = TAILQ_FIRST(&global_confirms)) == عدم)
		أرجع 0;
	إذا (gc->cb != عدم)
		gc->cb(ssh, type, seq, gc->ctx);
	إذا (--gc->ref_سانى <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, entry);
		freezero(gc, حجم(*gc));
	}

	ssh_packet_set_alive_timeouts(ssh, 0);
	أرجع 0;
}

ساكن فراغ
schedule_server_alive_check(فراغ)
{
	إذا (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

ساكن فراغ
server_alive_check(بنية ssh *ssh)
{
	صحيح r;

	إذا (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_سانى_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_register_global_confirm(عدم, عدم);
	schedule_server_alive_check();
}

/* Try to send a dummy keystroke */
ساكن صحيح
send_chaff(بنية ssh *ssh)
{
	صحيح r;

	إذا (ssh->kex == عدم || (ssh->kex->flags & KEX_HAS_PING) == 0)
		أرجع 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	أرجع 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
ساكن فراغ
set_next_interval(ثابت بنية timespec *now, بنية timespec *next_interval,
    u_int interval_ms, صحيح starting)
{
	بنية timespec tmp;
	long long interval_ns, fuzz_ns;
	ساكن long long rate_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	إذا (fuzz_ns > INT_MAX)
		fuzz_ns = INT_MAX;
	إذا (fuzz_ns > interval_ns) {
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
	إذا (starting)
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
ساكن صحيح
obfuscate_keystroke_timing(بنية ssh *ssh, بنية timespec *timeout,
    صحيح channel_did_enqueue)
{
	ساكن صحيح active;
	ساكن بنية timespec next_interval, chaff_until;
	بنية timespec now, tmp;
	صحيح just_started = 0, had_keystroke = 0;
	ساكن unsigned long long nchaff;
	حرف *stop_reason = عدم;
	long long n;

	monotime_ts(&now);

	إذا (options.obscure_keystroke_timing_interval <= 0)
		أرجع 1;	/* disabled in config */

	إذا (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} وإلا إذا (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} وإلا إذا (!ssh_packet_interactive_data_to_write(ssh) &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} وإلا إذا (active && channel_did_enqueue &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} وإلا إذا (active) {
		إذا (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} وإلا إذا (timespeccmp(&now, &next_interval, >=) &&
		    !ssh_packet_have_data_to_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			إذا (send_chaff(ssh))
				nchaff++;
		}
	}

	إذا (stop_reason != عدم) {
		إذا (active) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			active = 0;
		}
		أرجع 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	إذا (!active && ssh_packet_interactive_data_to_write(ssh) &&
	    channel_did_enqueue && ssh_packet_have_data_to_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = active = 1;
		nchaff = 0;
		set_next_interval(&now, &next_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	إذا (!active)
		أرجع 1;

	إذا (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_to_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_uniform(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &next_interval);

	إذا (just_started)
		أرجع 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	إذا (timespeccmp(&now, &next_interval, <))
		/* ...unless there's x11 communication happening */
		أرجع x11_channel_used_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - next_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - next_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	set_next_interval(&now, &next_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	أرجع 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
ساكن فراغ
client_wait_until_can_do_something(بنية ssh *ssh, بنية pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, صحيح channel_did_enqueue,
    sigset_t *sigsetp, صحيح *conn_in_readyp, صحيح *conn_out_readyp)
{
	بنية timespec timeout;
	صحيح ret, oready;
	u_int p;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	إذا (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	إذا (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_data_to_write(ssh)) {
		/* clear events since we did not call poll() */
		لكل (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		أرجع;
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
	إذا (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	إذا (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	إذا (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	إذا (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		لكل (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		إذا (errno == EINTR)
			أرجع;
		/* Note: we might still have data in the buffers. */
		quit_message("poll: %s", strerror(errno));
		أرجع;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	إذا (options.server_alive_interval > 0 && !*conn_in_readyp &&
	    monotime() >= server_alive_time) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

ساكن فراغ
client_suspend_self(بنية sshbuf *bin, بنية sshbuf *bout, بنية sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	إذا (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	إذا (sshbuf_len(berr) > 0)
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

ساكن فراغ
client_process_net_كىرگۈزۈش(بنية ssh *ssh)
{
	صحيح r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	schedule_server_alive_check();
	إذا ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		أرجع; /* success */
	إذا (r == SSH_ERR_SYSTEM_ERROR) {
		إذا (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			أرجع;
		إذا (errno == EPIPE) {
			quit_message("Connection to %s closed by remote host.",
			    host);
			أرجع;
		}
	}
	quit_message("Read from remote host %s: %s", host, ssh_err(r));
}

ساكن فراغ
client_status_confirm(بنية ssh *ssh, صحيح type, Channel *c, فراغ *ctx)
{
	بنية channel_reply_ctx *cr = (بنية channel_reply_ctx *)ctx;
	حرف errmsg[256];
	صحيح r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	إذا (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	إذا (type == SSH2_ئۇچۇر_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} وإلا إذا (type == SSH2_ئۇچۇر_CHANNEL_FAILURE) {
		إذا (tochan) {
			snprintf(errmsg, حجم(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} وإلا {
			snprintf(errmsg, حجم(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		إذا (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		إذا (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			إذا ((r = sshbuf_put(c->extended, errmsg,
			    strlen(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} وإلا
			error("%s", errmsg);
		إذا (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			إذا (c->self == session_ident)
				leave_raw_mode(0);
			وإلا
				mux_tty_alloc_failed(ssh, c);
		} وإلا إذا (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	حرر(cr);
}

ساكن فراغ
client_abandon_status_confirm(بنية ssh *ssh, Channel *c, فراغ *ctx)
{
	حرر(ctx);
}

فراغ
client_expect_confirm(بنية ssh *ssh, صحيح id, ثابت حرف *request,
    تعداد confirm_action action)
{
	بنية channel_reply_ctx *cr = xcalloc(1, حجم(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_register_status_confirm(ssh, id, client_status_confirm,
	    client_abandon_status_confirm, cr);
}

فراغ
client_register_global_confirm(global_confirm_cb *cb, فراغ *ctx)
{
	بنية global_confirm *gc, *last_gc;

	/* Coalesce identical callbacks */
	last_gc = TAILQ_LAST(&global_confirms, global_confirms);
	إذا (last_gc && last_gc->cb == cb && last_gc->ctx == ctx) {
		إذا (++last_gc->ref_سانى >= INT_MAX)
			fatal_f("last_gc->ref_count = %d",
			    last_gc->ref_سانى);
		أرجع;
	}

	gc = xcalloc(1, حجم(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_سانى = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, entry);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
ساكن صحيح
can_update_hostkeys(فراغ)
{
	إذا (hostkeys_update_complete)
		أرجع 0;
	إذا (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_mode)
		أرجع 0; /* won't ask in batchmode, so don't even try */
	إذا (!options.update_hostkeys || options.رەقەم_user_hostfiles <= 0)
		أرجع 0;
	أرجع 1;
}

ساكن فراغ
client_repledge(فراغ)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	إذا (options.control_master || options.control_path != عدم ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != عدم || can_update_hostkeys() ||
	    (session_ident != -1 && !session_setup_complete)) {
		/* Can't tighten */
		أرجع;
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
	إذا (options.رەقەم_local_forwards != 0 ||
	    options.رەقەم_remote_forwards != 0 ||
	    options.رەقەم_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		إذا (pledge("stdio unix inet dns proc tty", عدم) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} وإلا إذا (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		إذا (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", عدم) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} وإلا {
		debug("pledge: fork");
		إذا (pledge(PLEDGE_EXTRA_INET "stdio proc tty", عدم) == -1)
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

ساكن فراغ
process_cmdline(بنية ssh *ssh)
{
	فراغ (*handler)(صحيح);
	حرف *s, *cmd;
	صحيح ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	بنية Forward fwd;

	memset(&fwd, 0, حجم(fwd));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	إذا (s == عدم)
		اذهب out;
	طالما (isspace((u_char)*s))
		s++;
	إذا (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	إذا (*s == '\0')
		اذهب out;

	إذا (*s == 'h' || *s == 'H' || *s == '?') {
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
		إذا (!options.permit_local_command)
			اذهب out;
		logit("      !args                                  "
		    "Execute local command");
		اذهب out;
	}

	إذا (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		اذهب out;
	}

	إذا (*s == 'K') {
		delete = 1;
		s++;
	}
	إذا (*s == 'L')
		local = 1;
	وإلا إذا (*s == 'R')
		remote = 1;
	وإلا إذا (*s == 'D')
		dynamic = 1;
	وإلا {
		logit("Invalid command.");
		اذهب out;
	}

	طالما (isspace((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	إذا (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		إذا (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			اذهب out;
		}
		إذا (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		وإلا إذا (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		وإلا
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_PORT_STATIC,
			    &options.fwd_opts) > 0;
		إذا (!ok) {
			logit("Unknown port forwarding.");
			اذهب out;
		}
		logit("Canceled forwarding.");
	} وإلا {
		/* -R specs can be both dynamic or not, so check both. */
		إذا (remote) {
			إذا (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				اذهب out;
			}
		} وإلا إذا (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			اذهب out;
		}
		إذا (local || dynamic) {
			إذا (!channel_setup_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				اذهب out;
			}
		} وإلا {
			إذا (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				اذهب out;
			}
		}
		logit("Forwarding port.");
	}

out:
	ssh_signal(SIGINT, handler);
	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	حرر(cmd);
	حرر(fwd.listen_host);
	حرر(fwd.listen_path);
	حرر(fwd.connect_host);
	حرر(fwd.connect_path);
}

/* reasons to suppress output of an escape command in help output */
#define SUPPRESS_NEVER		0	/* never suppress, always show */
#define SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#define SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#define SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#define SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
بنية escape_help_text {
	ثابت حرف *cmd;
	ثابت حرف *text;
	unsigned صحيح flags;
};
ساكن بنية escape_help_text esc_txt[] = {
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

ساكن فراغ
print_escape_help(بنية sshbuf *b, صحيح escape_char, صحيح mux_client,
    صحيح using_stderr)
{
	unsigned صحيح i, suppress_flags;
	صحيح r;

	إذا ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	لكل (i = 0; i < حجم(esc_txt)/حجم(esc_txt[0]); i++) {
		إذا (esc_txt[i].flags & suppress_flags)
			استمر;
		إذا ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	إذا ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
ساكن صحيح
process_escapes(بنية ssh *ssh, Channel *c,
    بنية sshbuf *bin, بنية sshbuf *bout, بنية sshbuf *berr,
    حرف *buf, صحيح len)
{
	pid_t pid;
	صحيح r, bytes = 0;
	u_int i;
	u_char ch;
	حرف *s;
	بنية escape_filter_ctx *efc;

	إذا (c == عدم || c->filter_ctx == عدم || len <= 0)
		أرجع 0;

	efc = (بنية escape_filter_ctx *)c->filter_ctx;

	لكل (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		إذا (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			بدل (ch) {
			حالة '.':
				/* Terminate the connection. */
				إذا ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				إذا (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					أرجع 0;
				} وإلا
					quit_pending = 1;
				أرجع -1;

			حالة 'Z' - 64:
				/* XXX support this for mux clients */
				إذا (c && c->ctl_chan != -1) {
					حرف b[16];
 noescape:
					إذا (ch == 'Z' - 64)
						snprintf(b, حجم b, "^Z");
					وإلا
						snprintf(b, حجم b, "%c", ch);
					إذا ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					استمر;
				}
				/* Suspend the program. Inform the user */
				إذا ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				استمر;

			حالة 'B':
				إذا ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				إذا ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				استمر;

			حالة 'I':
				إذا ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_message(ssh);
				إذا ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				حرر(s);
				استمر;

			حالة 'R':
				إذا (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				وإلا
					need_rekeying = 1;
				استمر;

			حالة 'V':
				/* FALLTHROUGH */
			حالة 'v':
				إذا (c && c->ctl_chan != -1)
					اذهب noescape;
				إذا (!log_is_on_stderr()) {
					إذا ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					استمر;
				}
				إذا (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				إذا (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				إذا ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				استمر;

			حالة '&':
				إذا (c->ctl_chan != -1)
					اذهب noescape;
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

				إذا ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				إذا (pid == -1) {
					error("fork: %.100s", strerror(errno));
					استمر;
				}
				إذا (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					exit(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				إذا ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				أرجع -1;
			حالة '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				استمر;

			حالة '#':
				إذا ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_message(ssh);
				إذا ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				حرر(s);
				استمر;

			حالة 'C':
				إذا (c && c->ctl_chan != -1)
					اذهب noescape;
				إذا (options.enable_escape_commandline == 0) {
					إذا ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					استمر;
				}
				process_cmdline(ssh);
				استمر;

			افتراضي:
				إذا (ch != efc->escape_char) {
					إذا ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					bytes++;
				}
				/* Escaped characters fall through here */
				اكسر;
			}
		} وإلا {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			إذا (last_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				استمر;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		last_was_cr = (ch == '\r' || ch == '\n');
		إذا ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		bytes++;
	}
	أرجع bytes;
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

ساكن فراغ
client_process_buffered_كىرگۈزۈش_packets(بنية ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
فراغ *
client_new_escape_filter_ctx(صحيح escape_char)
{
	بنية escape_filter_ctx *ret;

	ret = xcalloc(1, حجم(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	أرجع (فراغ *)ret;
}

/* Free the escape filter context on channel free */
فراغ
client_filter_cleanup(بنية ssh *ssh, صحيح cid, فراغ *ctx)
{
	حرر(ctx);
}

صحيح
client_simple_escape_filter(بنية ssh *ssh, Channel *c, حرف *buf, صحيح len)
{
	إذا (c->extended_usage != CHAN_EXTENDED_WRITE)
		أرجع 0;

	أرجع process_escapes(ssh, c, c->كىرگۈزۈش, c->output, c->extended,
	    buf, len);
}

ساكن فراغ
client_channel_closed(بنية ssh *ssh, صحيح id, صحيح force, فراغ *arg)
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
صحيح
client_loop(بنية ssh *ssh, صحيح have_pty, صحيح escape_char_arg,
    صحيح ssh2_chan_id)
{
	بنية pollfd *pfd = عدم;
	u_int npfd_alloc = 0, npfd_active = 0;
	مزدوج start_time, total_time;
	صحيح interactive = -1, channel_did_enqueue = 0, r;
	uint64_t ibytes, obytes;
	صحيح conn_in_ready, conn_out_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	إذا (options.pkcs11_provider != عدم)
		debug("pledge: disabled (PKCS11Provider active)");
	وإلا إذا (options.control_master &&
	    !option_clear_or_none(options.control_path)) {
		debug("pledge: id");
		إذا (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    عدم) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} وإلا إذا (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		إذا (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    عدم) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} وإلا إذا (options.update_hostkeys) {
		debug("pledge: filesystem");
		إذا (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    عدم) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} وإلا إذا (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		إذا (pledge("stdio cpath unix inet dns proc tty", عدم) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} وإلا {
		debug("pledge: network");
		إذا (pledge("stdio unix inet dns proc tty", عدم) == -1)
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
	إذا (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	إذا (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	إذا (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	إذا (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, window_change_handler);
#ifdef SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#endif

	إذا (have_pty)
		enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	إذا (session_ident != -1) {
		إذا (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, عدم,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_register_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	schedule_server_alive_check();

	إذا (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ifdef SIGINFO
	إذا (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#endif

	/* Main loop of the client for the interactive session mode. */
	طالما (!quit_pending) {
		channel_did_enqueue = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_كىرگۈزۈش_packets(ssh);

		إذا (session_closed && !channel_still_open(ssh))
			اكسر;

		إذا (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} وإلا إذا (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			إذا ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} وإلا {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			إذا (ssh_packet_not_very_much_data_to_write(ssh))
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
		إذا (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		إذا (siginfo_received) {
			حرف ident[256];

			sshpkt_fmt_connection_id(ssh, ident, حجم(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - start_time);
			siginfo_received = 0;
		}
		إذا (quit_pending)
			اكسر;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_active, channel_did_enqueue, &osigset,
		    &conn_in_ready, &conn_out_ready);
		إذا (sigprocmask(SIG_SETMASK, &osigset, عدم) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		إذا (quit_pending)
			اكسر;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_active);

		/* Buffer input from the connection.  */
		إذا (conn_in_ready)
			client_process_net_كىرگۈزۈش(ssh);

		إذا (quit_pending)
			اكسر;

		/* A timeout may have triggered rekeying */
		إذا ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		إذا (conn_out_ready) {
			إذا (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_set_interactive(ssh, interactive);
			}
			إذا ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		إذا (control_persist_exit_time > 0) {
			إذا (monotime() >= control_persist_exit_time) {
				debug("ControlPersist timeout expired");
				اكسر;
			}
		}
	}
	حرر(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	إذا (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_message("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	إذا (have_pty)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	إذا (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_status = 0;
	}

	إذا (received_signal) {
		verbose("Killed by signal %d.", (صحيح) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	total_time = monotime_double() - start_time;
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (unsigned long long)obytes, (unsigned long long)ibytes, total_time);
	إذا (total_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / total_time, ibytes / total_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	أرجع exit_status;
}

/*********/

ساكن Channel *
client_request_forwarded_tcpip(بنية ssh *ssh, ثابت حرف *request_type,
    صحيح rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = عدم;
	بنية sshbuf *b = عدم;
	حرف *listen_address, *originator_address;
	u_int listen_port, originator_port;
	صحيح r;

	/* Get rest of the packet */
	إذا ((r = sshpkt_get_cstring(ssh, &listen_address, عدم)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_address, عدم)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_address, listen_port, originator_address, originator_port);

	إذا (listen_port > 0xffff)
		error_f("invalid listen port");
	وإلا إذا (originator_port > 0xffff)
		error_f("invalid originator port");
	وإلا {
		c = channel_connect_by_listen_address(ssh,
		    listen_address, listen_port, "forwarded-tcpip",
		    originator_address);
	}

	إذا (c != عدم && c->type == SSH_CHANNEL_MUX_CLIENT) {
		إذا ((b = sshbuf_new()) == عدم) {
			error_f("alloc reply");
			اذهب out;
		}
		/* reconstruct and send to muxclient */
		إذا ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_ئۇچۇر_CHANNEL_OPEN)) != 0 ||
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
			اذهب out;
		}
	}

 out:
	sshbuf_free(b);
	حرر(originator_address);
	حرر(listen_address);
	أرجع c;
}

ساكن Channel *
client_request_forwarded_streamlocal(بنية ssh *ssh,
    ثابت حرف *request_type, صحيح rchan)
{
	Channel *c = عدم;
	حرف *listen_path;
	صحيح r;

	/* Get the remote path. */
	إذا ((r = sshpkt_get_cstring(ssh, &listen_path, عدم)) != 0 ||
	    (r = sshpkt_get_string(ssh, عدم, عدم)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_path);

	c = channel_connect_by_listen_path(ssh, listen_path,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	حرر(listen_path);
	أرجع c;
}

ساكن Channel *
client_request_x11(بنية ssh *ssh, ثابت حرف *request_type, صحيح rchan)
{
	Channel *c = عدم;
	حرف *originator;
	u_int originator_port;
	صحيح r, sock;

	إذا (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		أرجع عدم;
	}
	إذا (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		أرجع عدم;
	}
	إذا ((r = sshpkt_get_cstring(ssh, &originator, عدم)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_port);
	حرر(originator);
	sock = x11_connect_display(ssh);
	إذا (sock < 0)
		أرجع عدم;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	أرجع c;
}

ساكن Channel *
client_request_agent(بنية ssh *ssh, ثابت حرف *request_type, صحيح rchan)
{
	Channel *c = عدم;
	صحيح r, sock;

	إذا (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		أرجع عدم;
	}
	إذا (forward_agent_sock_path == عدم) {
		r = ssh_get_authentication_socket(&sock);
	} وإلا {
		r = ssh_get_authentication_socket_path(forward_agent_sock_path, &sock);
	}
	إذا (r != 0) {
		إذا (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		أرجع عدم;
	}
	إذا ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	وإلا
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	أرجع c;
}

حرف *
client_request_tun_fwd(بنية ssh *ssh, صحيح tun_mode,
    صحيح local_tun, صحيح remote_tun, channel_open_fn *cb, فراغ *cbctx)
{
	Channel *c;
	صحيح r, fd;
	حرف *ifname = عدم;

	إذا (tun_mode == SSH_TUNMODE_NO)
		أرجع عدم;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	إذا ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		أرجع عدم;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#إذا defined(SSH_TUN_FILTER)
	إذا (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, عدم, عدم);
#endif

	إذا (cb != عدم)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	أرجع ifname;
}

/* XXXX move to generic input handler */
ساكن صحيح
client_كىرگۈزۈش_channel_open(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Channel *c = عدم;
	حرف *ctype = عدم;
	صحيح r;
	u_int rchan;
	size_t len;
	u_int rmaxpack, rwindow;

	إذا ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		اذهب out;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	إذا (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} وإلا إذا (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} وإلا إذا (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} وإلا إذا (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	إذا (c != عدم && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} وإلا إذا (c != عدم) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		إذا (c->type != SSH_CHANNEL_CONNECTING) {
			إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} وإلا {
		debug("failure %s", ctype);
		إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	حرر(ctype);
	أرجع r;
}

ساكن صحيح
client_كىرگۈزۈش_channel_req(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Channel *c = عدم;
	حرف *rtype = عدم;
	u_char reply;
	u_int id, exitval;
	صحيح r, success = 0;

	إذا ((r = sshpkt_get_u32(ssh, &id)) != 0)
		أرجع r;
	إذا (id <= INT_MAX)
		c = channel_lookup(ssh, id);
	إذا (channel_proxy_upstream(c, type, seq, ssh))
		أرجع 0;
	إذا ((r = sshpkt_get_cstring(ssh, &rtype, عدم)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &reply)) != 0)
		اذهب out;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, reply);

	إذا (c == عدم) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} وإلا إذا (strcmp(rtype, "eow@openssh.com") == 0) {
		إذا ((r = sshpkt_get_end(ssh)) != 0)
			اذهب out;
		chan_rcvd_eow(ssh, c);
	} وإلا إذا (strcmp(rtype, "exit-status") == 0) {
		إذا ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			اذهب out;
		إذا (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} وإلا إذا ((صحيح)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} وإلا {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		إذا ((r = sshpkt_get_end(ssh)) != 0)
			اذهب out;
	}
	إذا (reply && c != عدم && !(c->flags & CHAN_CLOSE_SENT)) {
		إذا (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		إذا ((r = sshpkt_start(ssh, success ?
		    SSH2_ئۇچۇر_CHANNEL_SUCCESS : SSH2_ئۇچۇر_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	حرر(rtype);
	أرجع r;
}

بنية hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	حرف *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	بنية sshkey **ئاچقۇچلار;
	u_int *ئاچقۇچلار_match;	/* mask of HKF_MATCH_* from hostfile.h */
	صحيح *ئاچقۇچلار_verified;	/* flag for new keys verified by server */
	size_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	بنية sshkey **old_ئاچقۇچلار;
	size_t nold;

	/* Various special cases. */
	صحيح complex_hostspec;	/* wildcard or manual pattern-list host name */
	صحيح ca_available;	/* saw CA key for this host */
	صحيح old_ئاچقۇچ_seen;	/* saw old key with other name/addr */
	صحيح other_name_seen;	/* saw key with other name/addr */
};

ساكن فراغ
hostkeys_update_ctx_free(بنية hostkeys_update_ctx *ctx)
{
	size_t i;

	إذا (ctx == عدم)
		أرجع;
	لكل (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->ئاچقۇچلار[i]);
	حرر(ctx->ئاچقۇچلار);
	حرر(ctx->ئاچقۇچلار_match);
	حرر(ctx->ئاچقۇچلار_verified);
	لكل (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_ئاچقۇچلار[i]);
	حرر(ctx->old_ئاچقۇچلار);
	حرر(ctx->host_str);
	حرر(ctx->ip_str);
	حرر(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
ساكن صحيح
hostspec_is_complex(ثابت حرف *hosts)
{
	حرف *cp;

	/* wildcard */
	إذا (strchr(hosts, '*') != عدم || strchr(hosts, '?') != عدم)
		أرجع 1;
	/* single host/ip = ok */
	إذا ((cp = strchr(hosts, ',')) == عدم)
		أرجع 0;
	/* more than two entries on the line */
	إذا (strchr(cp + 1, ',') != عدم)
		أرجع 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	أرجع 0;
}

/* callback to search for ctx->keys in known_hosts */
ساكن صحيح
hostkeys_find(بنية hostkey_foreach_قۇر *l, فراغ *_ctx)
{
	بنية hostkeys_update_ctx *ctx = (بنية hostkeys_update_ctx *)_ctx;
	size_t i;
	بنية sshkey **tmp;

	إذا (l->ئاچقۇچ == عدم)
		أرجع 0;
	إذا (l->status != HKF_STATUS_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		لكل (i = 0; i < ctx->nkeys; i++) {
			إذا (sshkey_equal(l->ئاچقۇچ, ctx->ئاچقۇچلار[i])) {
				ctx->other_name_seen = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->ئاچقۇچلار[i]),
				    l->path, l->linenum);
				أرجع 0;
			}
		}
		أرجع 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	إذا (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		أرجع 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	إذا (ctx->ip_str != عدم && strchr(l->hosts, ',') != عدم) {
		إذا ((l->match & HKF_MATCH_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_seen = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->path, l->linenum);
			أرجع 0;
		} وإلا إذا ((l->match & HKF_MATCH_IP) == 0) {
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
	إذا (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		أرجع 0;
	}

	/* Mark off keys we've already seen for this host */
	لكل (i = 0; i < ctx->nkeys; i++) {
		إذا (!sshkey_equal(l->ئاچقۇچ, ctx->ئاچقۇچلار[i]))
			استمر;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->ئاچقۇچلار[i]), l->path, l->linenum);
		ctx->ئاچقۇچلار_match[i] |= l->match;
		أرجع 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->ئاچقۇچ),
	    l->path, l->linenum);
	إذا ((tmp = recallocarray(ctx->old_ئاچقۇچلار, ctx->nold, ctx->nold + 1,
	    حجم(*ctx->old_ئاچقۇچلار))) == عدم)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_ئاچقۇچلار = tmp;
	ctx->old_ئاچقۇچلار[ctx->nold++] = l->ئاچقۇچ;
	l->ئاچقۇچ = عدم;

	أرجع 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
ساكن صحيح
hostkeys_check_old(بنية hostkey_foreach_قۇر *l, فراغ *_ctx)
{
	بنية hostkeys_update_ctx *ctx = (بنية hostkeys_update_ctx *)_ctx;
	size_t i;
	صحيح hashed;

	/* only care about lines that *don't* match the active host spec */
	إذا (l->status == HKF_STATUS_MATCHED || l->ئاچقۇچ == عدم)
		أرجع 0;

	hashed = l->match & (HKF_MATCH_HOST_HASHED|HKF_MATCH_IP_HASHED);
	لكل (i = 0; i < ctx->nold; i++) {
		إذا (!sshkey_equal(l->ئاچقۇچ, ctx->old_ئاچقۇچلار[i]))
			استمر;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_ئاچقۇچلار[i]), l->path, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_ئاچقۇچ_seen = 1;
		اكسر;
	}
	أرجع 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
ساكن صحيح
check_old_ئاچقۇچلار_othernames(بنية hostkeys_update_ctx *ctx)
{
	size_t i;
	صحيح r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	لكل (i = 0; i < options.رەقەم_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		إذا ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_ئاچقۇچ, 0)) != 0) {
			إذا (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				استمر;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			أرجع -1;
		}
	}
	أرجع 0;
}

ساكن فراغ
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

ساكن فراغ
update_known_hosts(بنية hostkeys_update_ctx *ctx)
{
	صحيح r, was_raw = 0, first = 1;
	صحيح asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	حرف *fp, *response;
	size_t i;
	بنية stat sb;

	لكل (i = 0; i < ctx->nkeys; i++) {
		إذا (!ctx->ئاچقۇچلار_verified[i])
			استمر;
		إذا ((fp = sshkey_fingerprint(ctx->ئاچقۇچلار[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
			fatal_f("sshkey_fingerprint failed");
		إذا (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->ئاچقۇچلار[i]), fp);
		first = 0;
		حرر(fp);
	}
	لكل (i = 0; i < ctx->nold; i++) {
		إذا ((fp = sshkey_fingerprint(ctx->old_ئاچقۇچلار[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
			fatal_f("sshkey_fingerprint failed");
		إذا (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_ئاچقۇچلار[i]), fp);
		first = 0;
		حرر(fp);
	}
	إذا (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		إذا (get_saved_tio() != عدم) {
			leave_raw_mode(1);
			was_raw = 1;
		}
		response = عدم;
		لكل (i = 0; !quit_pending && i < 3; i++) {
			حرر(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			إذا (response != عدم && strcasecmp(response, "yes") == 0)
				اكسر;
			وإلا إذا (quit_pending || response == عدم ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				اكسر;
			} وإلا {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		إذا (quit_pending || i >= 3 || response == عدم)
			options.update_hostkeys = 0;
		حرر(response);
		إذا (was_raw)
			enter_raw_mode(1);
	}
	إذا (options.update_hostkeys == 0)
		أرجع;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	لكل (i = 0; i < options.رەقەم_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		إذا (stat(options.user_hostfiles[i], &sb) != 0) {
			إذا (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} وإلا {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			استمر;
		}
		إذا ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->ئاچقۇچلار : عدم, i == 0 ? ctx->nkeys : 0,
		    options.hash_known_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

ساكن فراغ
client_global_hostkeys_prove_confirm(بنية ssh *ssh, صحيح type,
    uint32_t seq, فراغ *_ctx)
{
	بنية hostkeys_update_ctx *ctx = (بنية hostkeys_update_ctx *)_ctx;
	size_t i, ndone;
	بنية sshbuf *signdata;
	صحيح r, plaintype;
	ثابت u_char *sig;
	ثابت حرف *rsa_kexalg = عدم;
	حرف *alg = عدم;
	size_t siglen;

	إذا (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	إذا (type != SSH2_ئۇچۇر_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		أرجع;
	}
	إذا (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == ئاچقۇچ_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	إذا ((signdata = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	لكل (ndone = i = 0; i < ctx->nkeys; i++) {
		إذا (ctx->ئاچقۇچلار_match[i])
			استمر;
		plaintype = sshkey_type_plain(ctx->ئاچقۇچلار[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		إذا ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->ئاچقۇچلار[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		إذا ((r = sshpkt_get_string_direct(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			اذهب out;
		}
		إذا ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->ئاچقۇچلار[i]), i);
			اذهب out;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		إذا (plaintype == ئاچقۇچ_RSA && rsa_kexalg == عدم &&
		    match_pattern_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			حرر(alg);
			/* zap the key from the list */
			sshkey_free(ctx->ئاچقۇچلار[i]);
			ctx->ئاچقۇچلار[i] = عدم;
			ndone++;
			استمر;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->ئاچقۇچلار[i]), i, alg);
		حرر(alg);
		إذا ((r = sshkey_verify(ctx->ئاچقۇچلار[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == ئاچقۇچ_RSA ? rsa_kexalg : عدم, 0, عدم)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->ئاچقۇچلار[i]), i);
			اذهب out;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->ئاچقۇچلار_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	إذا (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	إذا ((r = sshpkt_get_end(ssh)) != 0) {
		error_f("protocol error");
		اذهب out;
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
ساكن صحيح
client_كىرگۈزۈش_hostkeys(بنية ssh *ssh)
{
	ثابت u_char *blob = عدم;
	size_t i, len = 0;
	بنية sshbuf *buf = عدم;
	بنية sshkey *ئاچقۇچ = عدم, **tmp;
	صحيح r, prove_sent = 0;
	حرف *fp;
	ساكن صحيح hostkeys_seen = 0; /* XXX use struct ssh */
	خارجي بنية sockaddr_storage hostaddr; /* XXX from ssh.c */
	بنية hostkeys_update_ctx *ctx = عدم;
	u_int want;

	إذا (hostkeys_seen)
		fatal_f("server already sent hostkeys");
	إذا (!can_update_hostkeys())
		أرجع 1;
	hostkeys_seen = 1;

	ctx = xcalloc(1, حجم(*ctx));
	طالما (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(ئاچقۇچ);
		ئاچقۇچ = عدم;
		إذا ((r = sshpkt_get_string_direct(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			اذهب out;
		}
		إذا ((r = sshkey_from_blob(blob, len, &ئاچقۇچ)) != 0) {
			do_log2_fr(r, r == SSH_ERR_ئاچقۇچ_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			استمر;
		}
		fp = sshkey_fingerprint(ئاچقۇچ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(ئاچقۇچ), fp);
		حرر(fp);

		إذا (!hostkey_accepted_by_hostkeyalgs(ئاچقۇچ)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(ئاچقۇچ));
			استمر;
		}
		/* Skip certs */
		إذا (sshkey_is_cert(ئاچقۇچ)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(ئاچقۇچ));
			استمر;
		}
		/* Ensure keys are unique */
		لكل (i = 0; i < ctx->nkeys; i++) {
			إذا (sshkey_equal(ئاچقۇچ, ctx->ئاچقۇچلار[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(ئاچقۇچ));
				اذهب out;
			}
		}
		/* Key is good, record it */
		إذا ((tmp = recallocarray(ctx->ئاچقۇچلار, ctx->nkeys, ctx->nkeys + 1,
		    حجم(*ctx->ئاچقۇچلار))) == عدم)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->ئاچقۇچلار = tmp;
		ctx->ئاچقۇچلار[ctx->nkeys++] = ئاچقۇچ;
		ئاچقۇچ = عدم;
	}

	إذا (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		اذهب out;
	}

	إذا ((ctx->ئاچقۇچلار_match = calloc(ctx->nkeys,
	    حجم(*ctx->ئاچقۇچلار_match))) == عدم ||
	    (ctx->ئاچقۇچلار_verified = calloc(ctx->nkeys,
	    حجم(*ctx->ئاچقۇچلار_verified))) == عدم)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (بنية sockaddr *)&hostaddr : عدم,
	    options.port, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : عدم);

	/* Find which keys we already know about. */
	لكل (i = 0; i < options.رەقەم_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		إذا ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_ئاچقۇچ, 0)) != 0) {
			إذا (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				استمر;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			اذهب out;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_MATCH_HOST | ( options.check_host_ip ? HKF_MATCH_IP : 0);
	لكل (i = 0; i < ctx->nkeys; i++) {
		إذا (ctx->ئاچقۇچلار_match[i] == 0)
			ctx->nnew++;
		إذا ((ctx->ئاچقۇچلار_match[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	إذا (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		اذهب out;
	}

	/* Various reasons why we cannot proceed with the update */
	إذا (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		اذهب out;
	}
	إذا (ctx->other_name_seen) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		اذهب out;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	إذا (ctx->nold != 0) {
		إذا (check_old_ئاچقۇچلار_othernames(ctx) != 0)
			اذهب out; /* error already logged */
		إذا (ctx->old_ئاچقۇچ_seen) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == عدم ? "" : ",",
			    ctx->ip_str == عدم ? "" : ctx->ip_str);
			اذهب out;
		}
	}

	إذا (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_known_hosts(ctx);
		اذهب out;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	إذا ((buf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	لكل (i = 0; i < ctx->nkeys; i++) {
		إذا (ctx->ئاچقۇچلار_match[i])
			استمر;
		sshbuf_reset(buf);
		إذا ((r = sshkey_putb(ctx->ئاچقۇچلار[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	إذا ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_register_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = عدم;  /* will be freed in callback */
	prove_sent = 1;

	/* Success */
 out:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(ئاچقۇچ);
	sshbuf_free(buf);
	إذا (!prove_sent) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	أرجع 1;
}

ساكن صحيح
client_كىرگۈزۈش_global_request(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	حرف *rtype;
	u_char want_reply;
	صحيح r, success = 0;

	إذا ((r = sshpkt_get_cstring(ssh, &rtype, عدم)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		اذهب out;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_reply);
	إذا (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_كىرگۈزۈش_hostkeys(ssh);
	إذا (want_reply) {
		إذا ((r = sshpkt_start(ssh, success ? SSH2_ئۇچۇر_REQUEST_SUCCESS :
		    SSH2_ئۇچۇر_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			اذهب out;
	}
	r = 0;
 out:
	حرر(rtype);
	أرجع r;
}

ساكن فراغ
client_send_env(بنية ssh *ssh, صحيح id, ثابت حرف *name, ثابت حرف *val)
{
	صحيح r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	إذا ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

فراغ
client_session2_setup(بنية ssh *ssh, صحيح id, صحيح want_tty, صحيح want_subsystem,
    ثابت حرف *term, بنية termios *tiop, صحيح in_fd, بنية sshbuf *cmd,
    حرف **env)
{
	size_t i, j, len;
	صحيح matched, r;
	حرف *type = عدم, *cmdstring = عدم, *name, *val;
	Channel *c = عدم;

	debug2_f("id %d", id);

	إذا ((c = channel_lookup(ssh, id)) == عدم)
		fatal_f("channel %d: unknown channel", id);

	إذا (want_tty) {
		بنية winsize ws;

		/* Store window size in the packet. */
		إذا (ioctl(in_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, حجم(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		إذا ((r = sshpkt_put_cstring(ssh, term != عدم ? term : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		إذا (tiop == عدم)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		إذا ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	إذا (options.رەقەم_send_env != 0 && env != عدم) {
		debug("Sending environment.");
		لكل (i = 0; env[i] != عدم; i++) {
			/* Split */
			name = xstrdup(env[i]);
			إذا ((val = strchr(name, '=')) == عدم) {
				حرر(name);
				استمر;
			}
			*val++ = '\0';

			matched = 0;
			لكل (j = 0; j < options.رەقەم_send_env; j++) {
				إذا (match_pattern(name, options.send_env[j])) {
					matched = 1;
					اكسر;
				}
			}
			إذا (!matched) {
				debug3("Ignored env %s", name);
				حرر(name);
				استمر;
			}
			client_send_env(ssh, id, name, val);
			حرر(name);
		}
	}
	لكل (i = 0; i < options.رەقەم_setenv; i++) {
		/* Split */
		name = xstrdup(options.setenv[i]);
		إذا ((val = strchr(name, '=')) == عدم) {
			حرر(name);
			استمر;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		حرر(name);
	}

	len = sshbuf_len(cmd);
	إذا (len > 0) {
		إذا ((cmdstring = sshbuf_dup_string(cmd)) == عدم)
			fatal_f("sshbuf_dup_string failed");
		إذا (len > 900)
			len = 900;
		إذا (want_subsystem) {
			debug("Sending subsystem: %.*s", (صحيح)len, cmdstring);
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} وإلا {
			debug("Sending command: %.*s", (صحيح)len, cmdstring);
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		إذا ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} وإلا {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		إذا ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_set_xtype(ssh, id, type);
	حرر(cmdstring);
	حرر(type);

	session_setup_complete = 1;
	client_repledge();
}

فراغ
client_channel_request_agent_forwarding(بنية ssh *ssh, صحيح id)
{
	ثابت حرف *req = "auth-agent-req@openssh.com";
	صحيح r;

	إذا (ssh->kex != عدم && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_start(ssh, id, req, 0);
	إذا ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

ساكن فراغ
client_init_dispatch(بنية ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_CLOSE, &channel_كىرگۈزۈش_oclose);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_DATA, &channel_كىرگۈزۈش_data);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_EOF, &channel_كىرگۈزۈش_ieof);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_EXTENDED_DATA, &channel_كىرگۈزۈش_extended_data);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_OPEN, &client_كىرگۈزۈش_channel_open);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_OPEN_CONFIRMATION, &channel_كىرگۈزۈش_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_OPEN_FAILURE, &channel_كىرگۈزۈش_open_failure);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_REQUEST, &client_كىرگۈزۈش_channel_req);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_WINDOW_ADJUST, &channel_كىرگۈزۈش_window_adjust);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_SUCCESS, &channel_كىرگۈزۈش_status_confirm);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_CHANNEL_FAILURE, &channel_كىرگۈزۈش_status_confirm);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_GLOBAL_REQUEST, &client_كىرگۈزۈش_global_request);

	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_KEXINIT, &kex_كىرگۈزۈش_kexinit);

	/* global request reply messages */
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_REQUEST_FAILURE, &client_global_request_reply);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_REQUEST_SUCCESS, &client_global_request_reply);
}

فراغ
client_stop_mux(فراغ)
{
	إذا (options.control_path != عدم && muxserver_sock != -1)
		unlink(options.control_path);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	إذا (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
فراغ
cleanup_exit(صحيح i)
{
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	إذا (options.control_path != عدم && muxserver_sock != -1)
		unlink(options.control_path);
	ssh_kill_proxy_command();
	_exit(i);
}
