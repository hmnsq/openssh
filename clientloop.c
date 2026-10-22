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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/ioctl.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <sys/time.h>
#অন্তর্ভাৱ <sys/queue.h>

#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <paths.h>
#অন্তর্ভাৱ <poll.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <limits.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "compat.h"
#অন্তর্ভাৱ "channels.h"
#অন্তর্ভাৱ "dispatch.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "kex.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "readconf.h"
#অন্তর্ভাৱ "clientloop.h"
#অন্তর্ভাৱ "sshconnect.h"
#অন্তর্ভাৱ "authfd.h"
#অন্তর্ভাৱ "atomicio.h"
#অন্তর্ভাৱ "sshpty.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#define HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#define SSH_KEYSTROKE_TIMING_FUZZ 10

বাহ্য ৱর্ণ *__progname;

/* import options */
বাহ্য Options options;

/* Control socket */
বাহ্য পূর্ণাঙ্ক muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
বাহ্য ৱর্ণ *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
বাহ্য ৱর্ণ *forward_agent_sock_path;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
স্থির চঞ্চল sig_atomic_t received_window_change_signal = 0;
স্থির চঞ্চল sig_atomic_t siginfo_received = 0;
স্থির চঞ্চল sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
স্থির time_t control_persist_exit_time = 0;

/* Common data for the client loop code. */
চঞ্চল sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
স্থির পূর্ণাঙ্ক last_was_cr;		/* Last character was a newline. */
স্থির পূর্ণাঙ্ক exit_status;		/* Used to store the command exit status. */
স্থির পূর্ণাঙ্ক connection_in;	/* Connection to server (input). */
স্থির পূর্ণাঙ্ক connection_out;	/* Connection to server (output). */
স্থির পূর্ণাঙ্ক need_rekeying;	/* Set to non-zero if rekeying is requested. */
স্থির পূর্ণাঙ্ক session_closed;	/* In SSH2: login session closed. */
স্থির time_t x11_refuse_time;	/* If >0, refuse x11 opens after this time. */
স্থির time_t server_alive_time;	/* Time to do server_alive_check */
স্থির পূর্ণাঙ্ক hostkeys_update_complete;
স্থির পূর্ণাঙ্ক session_setup_complete;

স্থির শূন্য client_init_dispatch(সংরচনা ssh *ssh);
পূর্ণাঙ্ক	session_ident = -1;

/* Track escape per proto2 channel */
সংরচনা escape_filter_ctx {
	পূর্ণাঙ্ক escape_pending;
	পূর্ণাঙ্ক escape_char;
};

/* Context for channel confirmation replies */
সংরচনা channel_reply_ctx {
	ধ্রুৱ ৱর্ণ *request_type;
	পূর্ণাঙ্ক id;
	গণনা confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
সংরচনা global_confirm {
	TAILQ_ENTRY(global_confirm) entry;
	global_confirm_cb *cb;
	শূন্য *ctx;
	পূর্ণাঙ্ক ref_গুনতি;
};
TAILQ_HEAD(global_confirms, global_confirm);
স্থির সংরচনা global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

স্থির শূন্য quit_message(ধ্রুৱ ৱর্ণ *fmt, ...)
    __attribute__((__format__ (printf, 1, 2)));

স্থির শূন্য
quit_message(ধ্রুৱ ৱর্ণ *fmt, ...)
{
	ৱর্ণ *বাৰ্তা, *fmt2;
	va_list args;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(args, fmt);
	xvasprintf(&বাৰ্তা, fmt2, args);
	va_end(args);

	(শূন্য)atomicio(vwrite, STDERR_FILENO, বাৰ্তা, strlen(বাৰ্তা));
	মুক্ত(বাৰ্তা);
	মুক্ত(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
স্থির শূন্য
window_change_handler(পূর্ণাঙ্ক sig)
{
	received_window_change_signal = 1;
}

#ifdef SIGINFO
/* Signal handler for SIGINFO */
স্থির শূন্য
siginfo_handler(পূর্ণাঙ্ক sig)
{
	siginfo_received = 1;
}
#endif

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
স্থির শূন্য
signal_handler(পূর্ণাঙ্ক sig)
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
স্থির শূন্য
set_control_persist_exit_time(সংরচনা ssh *ssh)
{
	যদি (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} অন্যথা যদি (channel_still_open(ssh)) {
		/* some client connections are still open */
		যদি (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} অন্যথা যদি (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#define SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
স্থির পূর্ণাঙ্ক
client_x11_display_valid(ধ্রুৱ ৱর্ণ *display)
{
	size_t i, dlen;

	যদি (display == রিক্ত)
		ঘূৰাই 0;

	dlen = strlen(display);
	বাবে (i = 0; i < dlen; i++) {
		যদি (!isalnum((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == রিক্ত) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			ঘূৰাই 0;
		}
	}
	ঘূৰাই 1;
}

#define SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#define X11_TIMEOUT_SLACK	60
পূর্ণাঙ্ক
client_x11_get_proto(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *display,
    ধ্রুৱ ৱর্ণ *xauth_path, u_int trusted, u_int timeout,
    ৱর্ণ **_proto, ৱর্ণ **_data)
{
	ৱর্ণ *cmd, সাৰি[512], xdisplay[512];
	ৱর্ণ xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	স্থির ৱর্ণ proto[512], data[512];
	FILE *f;
	পূর্ণাঙ্ক got_data = 0, generated = 0, do_unlink = 0, r;
	সংরচনা stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*_data = data;
	proto[0] = data[0] = xauthfile[0] = xauthdir[0] = '\0';

	যদি (!client_x11_display_valid(display)) {
		যদি (display != রিক্ত)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		ঘূৰাই -1;
	}
	যদি (xauth_path != রিক্ত && stat(xauth_path, &st) == -1) {
		debug("No xauth program.");
		xauth_path = রিক্ত;
	}

	যদি (xauth_path != রিক্ত) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		যদি (strncmp(display, "localhost:", 10) == 0) {
			যদি ((r = snprintf(xdisplay, পরিমাণ(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (size_t)r >= পরিমাণ(xdisplay)) {
				error_f("display name too long");
				ঘূৰাই -1;
			}
			display = xdisplay;
		}
		যদি (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, পরিমাণ(xauthdir));
			যদি (mkdtemp(xauthdir) == রিক্ত) {
				error_f("mkdtemp: %s", strerror(errno));
				ঘূৰাই -1;
			}
			do_unlink = 1;
			যদি ((r = snprintf(xauthfile, পরিমাণ(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (size_t)r >= পরিমাণ(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				ঘূৰাই -1;
			}

			যদি (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} অন্যথা {
				/* Add some slack to requested expiry */
				যদি (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				অন্যথা {
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

			যদি (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				যদি (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				অন্যথা
					x11_refuse_time = now + timeout;
				channel_set_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			যদি (system(cmd) == 0)
				generated = 1;
			মুক্ত(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		যদি (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_path,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			যদি (f && fgets(সাৰি, পরিমাণ(সাৰি), f) &&
			    sscanf(সাৰি, "%*s %511s %511s", proto, data) == 2)
				got_data = 1;
			যদি (f)
				pclose(f);
			মুক্ত(cmd);
		}
	}

	যদি (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	যদি (!trusted && !got_data) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		ঘূৰাই -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	যদি (!got_data) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, পরিমাণ proto);
		arc4random_buf(rnd, পরিমাণ(rnd));
		বাবে (i = 0; i < পরিমাণ(rnd); i++) {
			snprintf(data + 2 * i, পরিমাণ data - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	ঘূৰাই 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

স্থির শূন্য
client_check_window_change(সংরচনা ssh *ssh)
{
	যদি (!received_window_change_signal)
		ঘূৰাই;
	received_window_change_signal = 0;
	debug2_f("changed");
	channel_send_window_changes(ssh);
}

স্থির পূর্ণাঙ্ক
client_global_request_reply(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	সংরচনা global_confirm *gc;

	যদি ((gc = TAILQ_FIRST(&global_confirms)) == রিক্ত)
		ঘূৰাই 0;
	যদি (gc->cb != রিক্ত)
		gc->cb(ssh, type, seq, gc->ctx);
	যদি (--gc->ref_গুনতি <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, entry);
		freezero(gc, পরিমাণ(*gc));
	}

	ssh_packet_set_alive_timeouts(ssh, 0);
	ঘূৰাই 0;
}

স্থির শূন্য
schedule_server_alive_check(শূন্য)
{
	যদি (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

স্থির শূন্য
server_alive_check(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;

	যদি (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_গুনতি_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_register_global_confirm(রিক্ত, রিক্ত);
	schedule_server_alive_check();
}

/* Try to send a dummy keystroke */
স্থির পূর্ণাঙ্ক
send_chaff(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;

	যদি (ssh->kex == রিক্ত || (ssh->kex->flags & KEX_HAS_PING) == 0)
		ঘূৰাই 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ঘূৰাই 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
স্থির শূন্য
set_next_interval(ধ্রুৱ সংরচনা timespec *now, সংরচনা timespec *next_interval,
    u_int interval_ms, পূর্ণাঙ্ক starting)
{
	সংরচনা timespec tmp;
	long long interval_ns, fuzz_ns;
	স্থির long long rate_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	যদি (fuzz_ns > INT_MAX)
		fuzz_ns = INT_MAX;
	যদি (fuzz_ns > interval_ns) {
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
	যদি (starting)
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
স্থির পূর্ণাঙ্ক
obfuscate_keystroke_timing(সংরচনা ssh *ssh, সংরচনা timespec *timeout,
    পূর্ণাঙ্ক channel_did_enqueue)
{
	স্থির পূর্ণাঙ্ক active;
	স্থির সংরচনা timespec next_interval, chaff_until;
	সংরচনা timespec now, tmp;
	পূর্ণাঙ্ক just_started = 0, had_keystroke = 0;
	স্থির unsigned long long nchaff;
	ৱর্ণ *stop_reason = রিক্ত;
	long long n;

	monotime_ts(&now);

	যদি (options.obscure_keystroke_timing_interval <= 0)
		ঘূৰাই 1;	/* disabled in config */

	যদি (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} অন্যথা যদি (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} অন্যথা যদি (!ssh_packet_interactive_data_to_write(ssh) &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} অন্যথা যদি (active && channel_did_enqueue &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} অন্যথা যদি (active) {
		যদি (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} অন্যথা যদি (timespeccmp(&now, &next_interval, >=) &&
		    !ssh_packet_have_data_to_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			যদি (send_chaff(ssh))
				nchaff++;
		}
	}

	যদি (stop_reason != রিক্ত) {
		যদি (active) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			active = 0;
		}
		ঘূৰাই 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	যদি (!active && ssh_packet_interactive_data_to_write(ssh) &&
	    channel_did_enqueue && ssh_packet_have_data_to_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = active = 1;
		nchaff = 0;
		set_next_interval(&now, &next_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	যদি (!active)
		ঘূৰাই 1;

	যদি (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_to_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_uniform(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &next_interval);

	যদি (just_started)
		ঘূৰাই 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	যদি (timespeccmp(&now, &next_interval, <))
		/* ...unless there's x11 communication happening */
		ঘূৰাই x11_channel_used_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - next_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - next_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	set_next_interval(&now, &next_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	ঘূৰাই 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
স্থির শূন্য
client_wait_until_can_do_something(সংরচনা ssh *ssh, সংরচনা pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, পূর্ণাঙ্ক channel_did_enqueue,
    sigset_t *sigsetp, পূর্ণাঙ্ক *conn_in_readyp, পূর্ণাঙ্ক *conn_out_readyp)
{
	সংরচনা timespec timeout;
	পূর্ণাঙ্ক ret, oready;
	u_int p;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	যদি (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	যদি (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_data_to_write(ssh)) {
		/* clear events since we did not call poll() */
		বাবে (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ঘূৰাই;
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
	যদি (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	যদি (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	যদি (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	যদি (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		বাবে (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		যদি (errno == EINTR)
			ঘূৰাই;
		/* Note: we might still have data in the buffers. */
		quit_message("poll: %s", strerror(errno));
		ঘূৰাই;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	যদি (options.server_alive_interval > 0 && !*conn_in_readyp &&
	    monotime() >= server_alive_time) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

স্থির শূন্য
client_suspend_self(সংরচনা sshbuf *bin, সংরচনা sshbuf *bout, সংরচনা sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	যদি (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	যদি (sshbuf_len(berr) > 0)
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

স্থির শূন্য
client_process_net_প্ৰবেশ(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	schedule_server_alive_check();
	যদি ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		ঘূৰাই; /* success */
	যদি (r == SSH_ERR_SYSTEM_ERROR) {
		যদি (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			ঘূৰাই;
		যদি (errno == EPIPE) {
			quit_message("Connection to %s closed by remote host.",
			    host);
			ঘূৰাই;
		}
	}
	quit_message("Read from remote host %s: %s", host, ssh_err(r));
}

স্থির শূন্য
client_status_confirm(সংরচনা ssh *ssh, পূর্ণাঙ্ক type, Channel *c, শূন্য *ctx)
{
	সংরচনা channel_reply_ctx *cr = (সংরচনা channel_reply_ctx *)ctx;
	ৱর্ণ errmsg[256];
	পূর্ণাঙ্ক r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	যদি (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	যদি (type == SSH2_বাৰ্তা_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} অন্যথা যদি (type == SSH2_বাৰ্তা_CHANNEL_FAILURE) {
		যদি (tochan) {
			snprintf(errmsg, পরিমাণ(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} অন্যথা {
			snprintf(errmsg, পরিমাণ(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		যদি (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		যদি (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			যদি ((r = sshbuf_put(c->extended, errmsg,
			    strlen(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} অন্যথা
			error("%s", errmsg);
		যদি (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			যদি (c->self == session_ident)
				leave_raw_mode(0);
			অন্যথা
				mux_tty_alloc_failed(ssh, c);
		} অন্যথা যদি (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	মুক্ত(cr);
}

স্থির শূন্য
client_abandon_status_confirm(সংরচনা ssh *ssh, Channel *c, শূন্য *ctx)
{
	মুক্ত(ctx);
}

শূন্য
client_expect_confirm(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, ধ্রুৱ ৱর্ণ *request,
    গণনা confirm_action action)
{
	সংরচনা channel_reply_ctx *cr = xcalloc(1, পরিমাণ(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_register_status_confirm(ssh, id, client_status_confirm,
	    client_abandon_status_confirm, cr);
}

শূন্য
client_register_global_confirm(global_confirm_cb *cb, শূন্য *ctx)
{
	সংরচনা global_confirm *gc, *last_gc;

	/* Coalesce identical callbacks */
	last_gc = TAILQ_LAST(&global_confirms, global_confirms);
	যদি (last_gc && last_gc->cb == cb && last_gc->ctx == ctx) {
		যদি (++last_gc->ref_গুনতি >= INT_MAX)
			fatal_f("last_gc->ref_count = %d",
			    last_gc->ref_গুনতি);
		ঘূৰাই;
	}

	gc = xcalloc(1, পরিমাণ(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_গুনতি = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, entry);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
স্থির পূর্ণাঙ্ক
can_update_hostkeys(শূন্য)
{
	যদি (hostkeys_update_complete)
		ঘূৰাই 0;
	যদি (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_mode)
		ঘূৰাই 0; /* won't ask in batchmode, so don't even try */
	যদি (!options.update_hostkeys || options.অঙ্ক_user_hostfiles <= 0)
		ঘূৰাই 0;
	ঘূৰাই 1;
}

স্থির শূন্য
client_repledge(শূন্য)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	যদি (options.control_master || options.control_path != রিক্ত ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != রিক্ত || can_update_hostkeys() ||
	    (session_ident != -1 && !session_setup_complete)) {
		/* Can't tighten */
		ঘূৰাই;
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
	যদি (options.অঙ্ক_local_forwards != 0 ||
	    options.অঙ্ক_remote_forwards != 0 ||
	    options.অঙ্ক_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		যদি (pledge("stdio unix inet dns proc tty", রিক্ত) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} অন্যথা যদি (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		যদি (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", রিক্ত) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} অন্যথা {
		debug("pledge: fork");
		যদি (pledge(PLEDGE_EXTRA_INET "stdio proc tty", রিক্ত) == -1)
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

স্থির শূন্য
process_cmdline(সংরচনা ssh *ssh)
{
	শূন্য (*handler)(পূর্ণাঙ্ক);
	ৱর্ণ *s, *cmd;
	পূর্ণাঙ্ক ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	সংরচনা Forward fwd;

	memset(&fwd, 0, পরিমাণ(fwd));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	যদি (s == রিক্ত)
		গচ্ছ out;
	যেতিয়ালৈ (isspace((u_char)*s))
		s++;
	যদি (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	যদি (*s == '\0')
		গচ্ছ out;

	যদি (*s == 'h' || *s == 'H' || *s == '?') {
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
		যদি (!options.permit_local_command)
			গচ্ছ out;
		logit("      !args                                  "
		    "Execute local command");
		গচ্ছ out;
	}

	যদি (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		গচ্ছ out;
	}

	যদি (*s == 'K') {
		delete = 1;
		s++;
	}
	যদি (*s == 'L')
		local = 1;
	অন্যথা যদি (*s == 'R')
		remote = 1;
	অন্যথা যদি (*s == 'D')
		dynamic = 1;
	অন্যথা {
		logit("Invalid command.");
		গচ্ছ out;
	}

	যেতিয়ালৈ (isspace((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	যদি (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		যদি (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			গচ্ছ out;
		}
		যদি (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		অন্যথা যদি (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		অন্যথা
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_PORT_STATIC,
			    &options.fwd_opts) > 0;
		যদি (!ok) {
			logit("Unknown port forwarding.");
			গচ্ছ out;
		}
		logit("Canceled forwarding.");
	} অন্যথা {
		/* -R specs can be both dynamic or not, so check both. */
		যদি (remote) {
			যদি (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				গচ্ছ out;
			}
		} অন্যথা যদি (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			গচ্ছ out;
		}
		যদি (local || dynamic) {
			যদি (!channel_setup_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				গচ্ছ out;
			}
		} অন্যথা {
			যদি (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				গচ্ছ out;
			}
		}
		logit("Forwarding port.");
	}

out:
	ssh_signal(SIGINT, handler);
	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	মুক্ত(cmd);
	মুক্ত(fwd.listen_host);
	মুক্ত(fwd.listen_path);
	মুক্ত(fwd.connect_host);
	মুক্ত(fwd.connect_path);
}

/* reasons to suppress output of an escape command in help output */
#define SUPPRESS_NEVER		0	/* never suppress, always show */
#define SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#define SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#define SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#define SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
সংরচনা escape_help_text {
	ধ্রুৱ ৱর্ণ *cmd;
	ধ্রুৱ ৱর্ণ *text;
	unsigned পূর্ণাঙ্ক flags;
};
স্থির সংরচনা escape_help_text esc_txt[] = {
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

স্থির শূন্য
print_escape_help(সংরচনা sshbuf *b, পূর্ণাঙ্ক escape_char, পূর্ণাঙ্ক mux_client,
    পূর্ণাঙ্ক using_stderr)
{
	unsigned পূর্ণাঙ্ক i, suppress_flags;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	বাবে (i = 0; i < পরিমাণ(esc_txt)/পরিমাণ(esc_txt[0]); i++) {
		যদি (esc_txt[i].flags & suppress_flags)
			অনুৱর্ত;
		যদি ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	যদি ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
স্থির পূর্ণাঙ্ক
process_escapes(সংরচনা ssh *ssh, Channel *c,
    সংরচনা sshbuf *bin, সংরচনা sshbuf *bout, সংরচনা sshbuf *berr,
    ৱর্ণ *buf, পূর্ণাঙ্ক len)
{
	pid_t pid;
	পূর্ণাঙ্ক r, bytes = 0;
	u_int i;
	u_char ch;
	ৱর্ণ *s;
	সংরচনা escape_filter_ctx *efc;

	যদি (c == রিক্ত || c->filter_ctx == রিক্ত || len <= 0)
		ঘূৰাই 0;

	efc = (সংরচনা escape_filter_ctx *)c->filter_ctx;

	বাবে (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		যদি (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			ৱিকল্প (ch) {
			পক্ষ '.':
				/* Terminate the connection. */
				যদি ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				যদি (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					ঘূৰাই 0;
				} অন্যথা
					quit_pending = 1;
				ঘূৰাই -1;

			পক্ষ 'Z' - 64:
				/* XXX support this for mux clients */
				যদি (c && c->ctl_chan != -1) {
					ৱর্ণ b[16];
 noescape:
					যদি (ch == 'Z' - 64)
						snprintf(b, পরিমাণ b, "^Z");
					অন্যথা
						snprintf(b, পরিমাণ b, "%c", ch);
					যদি ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					অনুৱর্ত;
				}
				/* Suspend the program. Inform the user */
				যদি ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				অনুৱর্ত;

			পক্ষ 'B':
				যদি ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				যদি ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				অনুৱর্ত;

			পক্ষ 'I':
				যদি ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_message(ssh);
				যদি ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				মুক্ত(s);
				অনুৱর্ত;

			পক্ষ 'R':
				যদি (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				অন্যথা
					need_rekeying = 1;
				অনুৱর্ত;

			পক্ষ 'V':
				/* FALLTHROUGH */
			পক্ষ 'v':
				যদি (c && c->ctl_chan != -1)
					গচ্ছ noescape;
				যদি (!log_is_on_stderr()) {
					যদি ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					অনুৱর্ত;
				}
				যদি (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				যদি (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				যদি ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				অনুৱর্ত;

			পক্ষ '&':
				যদি (c->ctl_chan != -1)
					গচ্ছ noescape;
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

				যদি ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				যদি (pid == -1) {
					error("fork: %.100s", strerror(errno));
					অনুৱর্ত;
				}
				যদি (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					exit(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				যদি ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				ঘূৰাই -1;
			পক্ষ '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				অনুৱর্ত;

			পক্ষ '#':
				যদি ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_message(ssh);
				যদি ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				মুক্ত(s);
				অনুৱর্ত;

			পক্ষ 'C':
				যদি (c && c->ctl_chan != -1)
					গচ্ছ noescape;
				যদি (options.enable_escape_commandline == 0) {
					যদি ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					অনুৱর্ত;
				}
				process_cmdline(ssh);
				অনুৱর্ত;

			স্ৱভাৱ:
				যদি (ch != efc->escape_char) {
					যদি ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					bytes++;
				}
				/* Escaped characters fall through here */
				ভঙ্গ;
			}
		} অন্যথা {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			যদি (last_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				অনুৱর্ত;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		last_was_cr = (ch == '\r' || ch == '\n');
		যদি ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		bytes++;
	}
	ঘূৰাই bytes;
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

স্থির শূন্য
client_process_buffered_প্ৰবেশ_packets(সংরচনা ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
শূন্য *
client_new_escape_filter_ctx(পূর্ণাঙ্ক escape_char)
{
	সংরচনা escape_filter_ctx *ret;

	ret = xcalloc(1, পরিমাণ(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	ঘূৰাই (শূন্য *)ret;
}

/* Free the escape filter context on channel free */
শূন্য
client_filter_cleanup(সংরচনা ssh *ssh, পূর্ণাঙ্ক cid, শূন্য *ctx)
{
	মুক্ত(ctx);
}

পূর্ণাঙ্ক
client_simple_escape_filter(সংরচনা ssh *ssh, Channel *c, ৱর্ণ *buf, পূর্ণাঙ্ক len)
{
	যদি (c->extended_usage != CHAN_EXTENDED_WRITE)
		ঘূৰাই 0;

	ঘূৰাই process_escapes(ssh, c, c->প্ৰবেশ, c->output, c->extended,
	    buf, len);
}

স্থির শূন্য
client_channel_closed(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, পূর্ণাঙ্ক force, শূন্য *arg)
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
পূর্ণাঙ্ক
client_loop(সংরচনা ssh *ssh, পূর্ণাঙ্ক have_pty, পূর্ণাঙ্ক escape_char_arg,
    পূর্ণাঙ্ক ssh2_chan_id)
{
	সংরচনা pollfd *pfd = রিক্ত;
	u_int npfd_alloc = 0, npfd_active = 0;
	দ্ৱিগুণ start_time, total_time;
	পূর্ণাঙ্ক interactive = -1, channel_did_enqueue = 0, r;
	uint64_t ibytes, obytes;
	পূর্ণাঙ্ক conn_in_ready, conn_out_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	যদি (options.pkcs11_provider != রিক্ত)
		debug("pledge: disabled (PKCS11Provider active)");
	অন্যথা যদি (options.control_master &&
	    !option_clear_or_none(options.control_path)) {
		debug("pledge: id");
		যদি (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    রিক্ত) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} অন্যথা যদি (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		যদি (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    রিক্ত) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} অন্যথা যদি (options.update_hostkeys) {
		debug("pledge: filesystem");
		যদি (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    রিক্ত) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} অন্যথা যদি (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		যদি (pledge("stdio cpath unix inet dns proc tty", রিক্ত) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} অন্যথা {
		debug("pledge: network");
		যদি (pledge("stdio unix inet dns proc tty", রিক্ত) == -1)
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
	যদি (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	যদি (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	যদি (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	যদি (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, window_change_handler);
#ifdef SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#endif

	যদি (have_pty)
		enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	যদি (session_ident != -1) {
		যদি (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, রিক্ত,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_register_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	schedule_server_alive_check();

	যদি (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ifdef SIGINFO
	যদি (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#endif

	/* Main loop of the client for the interactive session mode. */
	যেতিয়ালৈ (!quit_pending) {
		channel_did_enqueue = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_প্ৰবেশ_packets(ssh);

		যদি (session_closed && !channel_still_open(ssh))
			ভঙ্গ;

		যদি (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} অন্যথা যদি (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			যদি ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} অন্যথা {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			যদি (ssh_packet_not_very_much_data_to_write(ssh))
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
		যদি (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		যদি (siginfo_received) {
			ৱর্ণ ident[256];

			sshpkt_fmt_connection_id(ssh, ident, পরিমাণ(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - start_time);
			siginfo_received = 0;
		}
		যদি (quit_pending)
			ভঙ্গ;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_active, channel_did_enqueue, &osigset,
		    &conn_in_ready, &conn_out_ready);
		যদি (sigprocmask(SIG_SETMASK, &osigset, রিক্ত) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		যদি (quit_pending)
			ভঙ্গ;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_active);

		/* Buffer input from the connection.  */
		যদি (conn_in_ready)
			client_process_net_প্ৰবেশ(ssh);

		যদি (quit_pending)
			ভঙ্গ;

		/* A timeout may have triggered rekeying */
		যদি ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		যদি (conn_out_ready) {
			যদি (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_set_interactive(ssh, interactive);
			}
			যদি ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		যদি (control_persist_exit_time > 0) {
			যদি (monotime() >= control_persist_exit_time) {
				debug("ControlPersist timeout expired");
				ভঙ্গ;
			}
		}
	}
	মুক্ত(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	যদি (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_message("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	যদি (have_pty)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	যদি (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_status = 0;
	}

	যদি (received_signal) {
		verbose("Killed by signal %d.", (পূর্ণাঙ্ক) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	total_time = monotime_double() - start_time;
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (unsigned long long)obytes, (unsigned long long)ibytes, total_time);
	যদি (total_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / total_time, ibytes / total_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	ঘূৰাই exit_status;
}

/*********/

স্থির Channel *
client_request_forwarded_tcpip(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *request_type,
    পূর্ণাঙ্ক rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = রিক্ত;
	সংরচনা sshbuf *b = রিক্ত;
	ৱর্ণ *listen_address, *originator_address;
	u_int listen_port, originator_port;
	পূর্ণাঙ্ক r;

	/* Get rest of the packet */
	যদি ((r = sshpkt_get_cstring(ssh, &listen_address, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_address, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_address, listen_port, originator_address, originator_port);

	যদি (listen_port > 0xffff)
		error_f("invalid listen port");
	অন্যথা যদি (originator_port > 0xffff)
		error_f("invalid originator port");
	অন্যথা {
		c = channel_connect_by_listen_address(ssh,
		    listen_address, listen_port, "forwarded-tcpip",
		    originator_address);
	}

	যদি (c != রিক্ত && c->type == SSH_CHANNEL_MUX_CLIENT) {
		যদি ((b = sshbuf_new()) == রিক্ত) {
			error_f("alloc reply");
			গচ্ছ out;
		}
		/* reconstruct and send to muxclient */
		যদি ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_বাৰ্তা_CHANNEL_OPEN)) != 0 ||
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
			গচ্ছ out;
		}
	}

 out:
	sshbuf_free(b);
	মুক্ত(originator_address);
	মুক্ত(listen_address);
	ঘূৰাই c;
}

স্থির Channel *
client_request_forwarded_streamlocal(সংরচনা ssh *ssh,
    ধ্রুৱ ৱর্ণ *request_type, পূর্ণাঙ্ক rchan)
{
	Channel *c = রিক্ত;
	ৱর্ণ *listen_path;
	পূর্ণাঙ্ক r;

	/* Get the remote path. */
	যদি ((r = sshpkt_get_cstring(ssh, &listen_path, রিক্ত)) != 0 ||
	    (r = sshpkt_get_string(ssh, রিক্ত, রিক্ত)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_path);

	c = channel_connect_by_listen_path(ssh, listen_path,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	মুক্ত(listen_path);
	ঘূৰাই c;
}

স্থির Channel *
client_request_x11(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *request_type, পূর্ণাঙ্ক rchan)
{
	Channel *c = রিক্ত;
	ৱর্ণ *originator;
	u_int originator_port;
	পূর্ণাঙ্ক r, sock;

	যদি (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		ঘূৰাই রিক্ত;
	}
	যদি (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		ঘূৰাই রিক্ত;
	}
	যদি ((r = sshpkt_get_cstring(ssh, &originator, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_port);
	মুক্ত(originator);
	sock = x11_connect_display(ssh);
	যদি (sock < 0)
		ঘূৰাই রিক্ত;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	ঘূৰাই c;
}

স্থির Channel *
client_request_agent(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *request_type, পূর্ণাঙ্ক rchan)
{
	Channel *c = রিক্ত;
	পূর্ণাঙ্ক r, sock;

	যদি (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		ঘূৰাই রিক্ত;
	}
	যদি (forward_agent_sock_path == রিক্ত) {
		r = ssh_get_authentication_socket(&sock);
	} অন্যথা {
		r = ssh_get_authentication_socket_path(forward_agent_sock_path, &sock);
	}
	যদি (r != 0) {
		যদি (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		ঘূৰাই রিক্ত;
	}
	যদি ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	অন্যথা
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	ঘূৰাই c;
}

ৱর্ণ *
client_request_tun_fwd(সংরচনা ssh *ssh, পূর্ণাঙ্ক tun_mode,
    পূর্ণাঙ্ক local_tun, পূর্ণাঙ্ক remote_tun, channel_open_fn *cb, শূন্য *cbctx)
{
	Channel *c;
	পূর্ণাঙ্ক r, fd;
	ৱর্ণ *ifname = রিক্ত;

	যদি (tun_mode == SSH_TUNMODE_NO)
		ঘূৰাই রিক্ত;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	যদি ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		ঘূৰাই রিক্ত;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#যদি defined(SSH_TUN_FILTER)
	যদি (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, রিক্ত, রিক্ত);
#endif

	যদি (cb != রিক্ত)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	ঘূৰাই ifname;
}

/* XXXX move to generic input handler */
স্থির পূর্ণাঙ্ক
client_প্ৰবেশ_channel_open(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Channel *c = রিক্ত;
	ৱর্ণ *ctype = রিক্ত;
	পূর্ণাঙ্ক r;
	u_int rchan;
	size_t len;
	u_int rmaxpack, rwindow;

	যদি ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		গচ্ছ out;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	যদি (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} অন্যথা যদি (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} অন্যথা যদি (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} অন্যথা যদি (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	যদি (c != রিক্ত && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} অন্যথা যদি (c != রিক্ত) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		যদি (c->type != SSH_CHANNEL_CONNECTING) {
			যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} অন্যথা {
		debug("failure %s", ctype);
		যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	মুক্ত(ctype);
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
client_প্ৰবেশ_channel_req(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Channel *c = রিক্ত;
	ৱর্ণ *rtype = রিক্ত;
	u_char reply;
	u_int id, exitval;
	পূর্ণাঙ্ক r, success = 0;

	যদি ((r = sshpkt_get_u32(ssh, &id)) != 0)
		ঘূৰাই r;
	যদি (id <= INT_MAX)
		c = channel_lookup(ssh, id);
	যদি (channel_proxy_upstream(c, type, seq, ssh))
		ঘূৰাই 0;
	যদি ((r = sshpkt_get_cstring(ssh, &rtype, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &reply)) != 0)
		গচ্ছ out;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, reply);

	যদি (c == রিক্ত) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} অন্যথা যদি (strcmp(rtype, "eow@openssh.com") == 0) {
		যদি ((r = sshpkt_get_end(ssh)) != 0)
			গচ্ছ out;
		chan_rcvd_eow(ssh, c);
	} অন্যথা যদি (strcmp(rtype, "exit-status") == 0) {
		যদি ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			গচ্ছ out;
		যদি (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} অন্যথা যদি ((পূর্ণাঙ্ক)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} অন্যথা {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		যদি ((r = sshpkt_get_end(ssh)) != 0)
			গচ্ছ out;
	}
	যদি (reply && c != রিক্ত && !(c->flags & CHAN_CLOSE_SENT)) {
		যদি (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		যদি ((r = sshpkt_start(ssh, success ?
		    SSH2_বাৰ্তা_CHANNEL_SUCCESS : SSH2_বাৰ্তা_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	মুক্ত(rtype);
	ঘূৰাই r;
}

সংরচনা hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	ৱর্ণ *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	সংরচনা sshkey **চাবিগুলি;
	u_int *চাবিগুলি_match;	/* mask of HKF_MATCH_* from hostfile.h */
	পূর্ণাঙ্ক *চাবিগুলি_verified;	/* flag for new keys verified by server */
	size_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	সংরচনা sshkey **old_চাবিগুলি;
	size_t nold;

	/* Various special cases. */
	পূর্ণাঙ্ক complex_hostspec;	/* wildcard or manual pattern-list host name */
	পূর্ণাঙ্ক ca_available;	/* saw CA key for this host */
	পূর্ণাঙ্ক old_চাবি_seen;	/* saw old key with other name/addr */
	পূর্ণাঙ্ক other_name_seen;	/* saw key with other name/addr */
};

স্থির শূন্য
hostkeys_update_ctx_free(সংরচনা hostkeys_update_ctx *ctx)
{
	size_t i;

	যদি (ctx == রিক্ত)
		ঘূৰাই;
	বাবে (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->চাবিগুলি[i]);
	মুক্ত(ctx->চাবিগুলি);
	মুক্ত(ctx->চাবিগুলি_match);
	মুক্ত(ctx->চাবিগুলি_verified);
	বাবে (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_চাবিগুলি[i]);
	মুক্ত(ctx->old_চাবিগুলি);
	মুক্ত(ctx->host_str);
	মুক্ত(ctx->ip_str);
	মুক্ত(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
স্থির পূর্ণাঙ্ক
hostspec_is_complex(ধ্রুৱ ৱর্ণ *hosts)
{
	ৱর্ণ *cp;

	/* wildcard */
	যদি (strchr(hosts, '*') != রিক্ত || strchr(hosts, '?') != রিক্ত)
		ঘূৰাই 1;
	/* single host/ip = ok */
	যদি ((cp = strchr(hosts, ',')) == রিক্ত)
		ঘূৰাই 0;
	/* more than two entries on the line */
	যদি (strchr(cp + 1, ',') != রিক্ত)
		ঘূৰাই 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	ঘূৰাই 0;
}

/* callback to search for ctx->keys in known_hosts */
স্থির পূর্ণাঙ্ক
hostkeys_find(সংরচনা hostkey_foreach_সাৰি *l, শূন্য *_ctx)
{
	সংরচনা hostkeys_update_ctx *ctx = (সংরচনা hostkeys_update_ctx *)_ctx;
	size_t i;
	সংরচনা sshkey **tmp;

	যদি (l->চাবি == রিক্ত)
		ঘূৰাই 0;
	যদি (l->status != HKF_STATUS_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		বাবে (i = 0; i < ctx->nkeys; i++) {
			যদি (sshkey_equal(l->চাবি, ctx->চাবিগুলি[i])) {
				ctx->other_name_seen = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->চাবিগুলি[i]),
				    l->path, l->linenum);
				ঘূৰাই 0;
			}
		}
		ঘূৰাই 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	যদি (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		ঘূৰাই 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	যদি (ctx->ip_str != রিক্ত && strchr(l->hosts, ',') != রিক্ত) {
		যদি ((l->match & HKF_MATCH_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_seen = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->path, l->linenum);
			ঘূৰাই 0;
		} অন্যথা যদি ((l->match & HKF_MATCH_IP) == 0) {
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
	যদি (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		ঘূৰাই 0;
	}

	/* Mark off keys we've already seen for this host */
	বাবে (i = 0; i < ctx->nkeys; i++) {
		যদি (!sshkey_equal(l->চাবি, ctx->চাবিগুলি[i]))
			অনুৱর্ত;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->চাবিগুলি[i]), l->path, l->linenum);
		ctx->চাবিগুলি_match[i] |= l->match;
		ঘূৰাই 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->চাবি),
	    l->path, l->linenum);
	যদি ((tmp = recallocarray(ctx->old_চাবিগুলি, ctx->nold, ctx->nold + 1,
	    পরিমাণ(*ctx->old_চাবিগুলি))) == রিক্ত)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_চাবিগুলি = tmp;
	ctx->old_চাবিগুলি[ctx->nold++] = l->চাবি;
	l->চাবি = রিক্ত;

	ঘূৰাই 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
স্থির পূর্ণাঙ্ক
hostkeys_check_old(সংরচনা hostkey_foreach_সাৰি *l, শূন্য *_ctx)
{
	সংরচনা hostkeys_update_ctx *ctx = (সংরচনা hostkeys_update_ctx *)_ctx;
	size_t i;
	পূর্ণাঙ্ক hashed;

	/* only care about lines that *don't* match the active host spec */
	যদি (l->status == HKF_STATUS_MATCHED || l->চাবি == রিক্ত)
		ঘূৰাই 0;

	hashed = l->match & (HKF_MATCH_HOST_HASHED|HKF_MATCH_IP_HASHED);
	বাবে (i = 0; i < ctx->nold; i++) {
		যদি (!sshkey_equal(l->চাবি, ctx->old_চাবিগুলি[i]))
			অনুৱর্ত;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_চাবিগুলি[i]), l->path, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_চাবি_seen = 1;
		ভঙ্গ;
	}
	ঘূৰাই 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
স্থির পূর্ণাঙ্ক
check_old_চাবিগুলি_othernames(সংরচনা hostkeys_update_ctx *ctx)
{
	size_t i;
	পূর্ণাঙ্ক r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	বাবে (i = 0; i < options.অঙ্ক_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		যদি ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_চাবি, 0)) != 0) {
			যদি (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				অনুৱর্ত;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			ঘূৰাই -1;
		}
	}
	ঘূৰাই 0;
}

স্থির শূন্য
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

স্থির শূন্য
update_known_hosts(সংরচনা hostkeys_update_ctx *ctx)
{
	পূর্ণাঙ্ক r, was_raw = 0, first = 1;
	পূর্ণাঙ্ক asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	ৱর্ণ *fp, *response;
	size_t i;
	সংরচনা stat sb;

	বাবে (i = 0; i < ctx->nkeys; i++) {
		যদি (!ctx->চাবিগুলি_verified[i])
			অনুৱর্ত;
		যদি ((fp = sshkey_fingerprint(ctx->চাবিগুলি[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত)
			fatal_f("sshkey_fingerprint failed");
		যদি (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->চাবিগুলি[i]), fp);
		first = 0;
		মুক্ত(fp);
	}
	বাবে (i = 0; i < ctx->nold; i++) {
		যদি ((fp = sshkey_fingerprint(ctx->old_চাবিগুলি[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত)
			fatal_f("sshkey_fingerprint failed");
		যদি (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_চাবিগুলি[i]), fp);
		first = 0;
		মুক্ত(fp);
	}
	যদি (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		যদি (get_saved_tio() != রিক্ত) {
			leave_raw_mode(1);
			was_raw = 1;
		}
		response = রিক্ত;
		বাবে (i = 0; !quit_pending && i < 3; i++) {
			মুক্ত(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			যদি (response != রিক্ত && strcasecmp(response, "yes") == 0)
				ভঙ্গ;
			অন্যথা যদি (quit_pending || response == রিক্ত ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				ভঙ্গ;
			} অন্যথা {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		যদি (quit_pending || i >= 3 || response == রিক্ত)
			options.update_hostkeys = 0;
		মুক্ত(response);
		যদি (was_raw)
			enter_raw_mode(1);
	}
	যদি (options.update_hostkeys == 0)
		ঘূৰাই;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	বাবে (i = 0; i < options.অঙ্ক_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		যদি (stat(options.user_hostfiles[i], &sb) != 0) {
			যদি (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} অন্যথা {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			অনুৱর্ত;
		}
		যদি ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->চাবিগুলি : রিক্ত, i == 0 ? ctx->nkeys : 0,
		    options.hash_known_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

স্থির শূন্য
client_global_hostkeys_prove_confirm(সংরচনা ssh *ssh, পূর্ণাঙ্ক type,
    uint32_t seq, শূন্য *_ctx)
{
	সংরচনা hostkeys_update_ctx *ctx = (সংরচনা hostkeys_update_ctx *)_ctx;
	size_t i, ndone;
	সংরচনা sshbuf *signdata;
	পূর্ণাঙ্ক r, plaintype;
	ধ্রুৱ u_char *sig;
	ধ্রুৱ ৱর্ণ *rsa_kexalg = রিক্ত;
	ৱর্ণ *alg = রিক্ত;
	size_t siglen;

	যদি (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	যদি (type != SSH2_বাৰ্তা_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		ঘূৰাই;
	}
	যদি (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == চাবি_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	যদি ((signdata = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	বাবে (ndone = i = 0; i < ctx->nkeys; i++) {
		যদি (ctx->চাবিগুলি_match[i])
			অনুৱর্ত;
		plaintype = sshkey_type_plain(ctx->চাবিগুলি[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		যদি ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->চাবিগুলি[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		যদি ((r = sshpkt_get_string_direct(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			গচ্ছ out;
		}
		যদি ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->চাবিগুলি[i]), i);
			গচ্ছ out;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		যদি (plaintype == চাবি_RSA && rsa_kexalg == রিক্ত &&
		    match_pattern_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			মুক্ত(alg);
			/* zap the key from the list */
			sshkey_free(ctx->চাবিগুলি[i]);
			ctx->চাবিগুলি[i] = রিক্ত;
			ndone++;
			অনুৱর্ত;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->চাবিগুলি[i]), i, alg);
		মুক্ত(alg);
		যদি ((r = sshkey_verify(ctx->চাবিগুলি[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == চাবি_RSA ? rsa_kexalg : রিক্ত, 0, রিক্ত)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->চাবিগুলি[i]), i);
			গচ্ছ out;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->চাবিগুলি_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	যদি (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	যদি ((r = sshpkt_get_end(ssh)) != 0) {
		error_f("protocol error");
		গচ্ছ out;
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
স্থির পূর্ণাঙ্ক
client_প্ৰবেশ_hostkeys(সংরচনা ssh *ssh)
{
	ধ্রুৱ u_char *blob = রিক্ত;
	size_t i, len = 0;
	সংরচনা sshbuf *buf = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত, **tmp;
	পূর্ণাঙ্ক r, prove_sent = 0;
	ৱর্ণ *fp;
	স্থির পূর্ণাঙ্ক hostkeys_seen = 0; /* XXX use struct ssh */
	বাহ্য সংরচনা sockaddr_storage hostaddr; /* XXX from ssh.c */
	সংরচনা hostkeys_update_ctx *ctx = রিক্ত;
	u_int want;

	যদি (hostkeys_seen)
		fatal_f("server already sent hostkeys");
	যদি (!can_update_hostkeys())
		ঘূৰাই 1;
	hostkeys_seen = 1;

	ctx = xcalloc(1, পরিমাণ(*ctx));
	যেতিয়ালৈ (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(চাবি);
		চাবি = রিক্ত;
		যদি ((r = sshpkt_get_string_direct(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			গচ্ছ out;
		}
		যদি ((r = sshkey_from_blob(blob, len, &চাবি)) != 0) {
			do_log2_fr(r, r == SSH_ERR_চাবি_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			অনুৱর্ত;
		}
		fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(চাবি), fp);
		মুক্ত(fp);

		যদি (!hostkey_accepted_by_hostkeyalgs(চাবি)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(চাবি));
			অনুৱর্ত;
		}
		/* Skip certs */
		যদি (sshkey_is_cert(চাবি)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(চাবি));
			অনুৱর্ত;
		}
		/* Ensure keys are unique */
		বাবে (i = 0; i < ctx->nkeys; i++) {
			যদি (sshkey_equal(চাবি, ctx->চাবিগুলি[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(চাবি));
				গচ্ছ out;
			}
		}
		/* Key is good, record it */
		যদি ((tmp = recallocarray(ctx->চাবিগুলি, ctx->nkeys, ctx->nkeys + 1,
		    পরিমাণ(*ctx->চাবিগুলি))) == রিক্ত)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->চাবিগুলি = tmp;
		ctx->চাবিগুলি[ctx->nkeys++] = চাবি;
		চাবি = রিক্ত;
	}

	যদি (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		গচ্ছ out;
	}

	যদি ((ctx->চাবিগুলি_match = calloc(ctx->nkeys,
	    পরিমাণ(*ctx->চাবিগুলি_match))) == রিক্ত ||
	    (ctx->চাবিগুলি_verified = calloc(ctx->nkeys,
	    পরিমাণ(*ctx->চাবিগুলি_verified))) == রিক্ত)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (সংরচনা sockaddr *)&hostaddr : রিক্ত,
	    options.port, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : রিক্ত);

	/* Find which keys we already know about. */
	বাবে (i = 0; i < options.অঙ্ক_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		যদি ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_চাবি, 0)) != 0) {
			যদি (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				অনুৱর্ত;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			গচ্ছ out;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_MATCH_HOST | ( options.check_host_ip ? HKF_MATCH_IP : 0);
	বাবে (i = 0; i < ctx->nkeys; i++) {
		যদি (ctx->চাবিগুলি_match[i] == 0)
			ctx->nnew++;
		যদি ((ctx->চাবিগুলি_match[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	যদি (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		গচ্ছ out;
	}

	/* Various reasons why we cannot proceed with the update */
	যদি (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		গচ্ছ out;
	}
	যদি (ctx->other_name_seen) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		গচ্ছ out;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	যদি (ctx->nold != 0) {
		যদি (check_old_চাবিগুলি_othernames(ctx) != 0)
			গচ্ছ out; /* error already logged */
		যদি (ctx->old_চাবি_seen) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == রিক্ত ? "" : ",",
			    ctx->ip_str == রিক্ত ? "" : ctx->ip_str);
			গচ্ছ out;
		}
	}

	যদি (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_known_hosts(ctx);
		গচ্ছ out;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	যদি ((buf = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	বাবে (i = 0; i < ctx->nkeys; i++) {
		যদি (ctx->চাবিগুলি_match[i])
			অনুৱর্ত;
		sshbuf_reset(buf);
		যদি ((r = sshkey_putb(ctx->চাবিগুলি[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	যদি ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_register_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = রিক্ত;  /* will be freed in callback */
	prove_sent = 1;

	/* Success */
 out:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(চাবি);
	sshbuf_free(buf);
	যদি (!prove_sent) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	ঘূৰাই 1;
}

স্থির পূর্ণাঙ্ক
client_প্ৰবেশ_global_request(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	ৱর্ণ *rtype;
	u_char want_reply;
	পূর্ণাঙ্ক r, success = 0;

	যদি ((r = sshpkt_get_cstring(ssh, &rtype, রিক্ত)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		গচ্ছ out;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_reply);
	যদি (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_প্ৰবেশ_hostkeys(ssh);
	যদি (want_reply) {
		যদি ((r = sshpkt_start(ssh, success ? SSH2_বাৰ্তা_REQUEST_SUCCESS :
		    SSH2_বাৰ্তা_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			গচ্ছ out;
	}
	r = 0;
 out:
	মুক্ত(rtype);
	ঘূৰাই r;
}

স্থির শূন্য
client_send_env(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, ধ্রুৱ ৱর্ণ *name, ধ্রুৱ ৱর্ণ *val)
{
	পূর্ণাঙ্ক r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	যদি ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

শূন্য
client_session2_setup(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, পূর্ণাঙ্ক want_tty, পূর্ণাঙ্ক want_subsystem,
    ধ্রুৱ ৱর্ণ *term, সংরচনা termios *tiop, পূর্ণাঙ্ক in_fd, সংরচনা sshbuf *cmd,
    ৱর্ণ **env)
{
	size_t i, j, len;
	পূর্ণাঙ্ক matched, r;
	ৱর্ণ *type = রিক্ত, *cmdstring = রিক্ত, *name, *val;
	Channel *c = রিক্ত;

	debug2_f("id %d", id);

	যদি ((c = channel_lookup(ssh, id)) == রিক্ত)
		fatal_f("channel %d: unknown channel", id);

	যদি (want_tty) {
		সংরচনা winsize ws;

		/* Store window size in the packet. */
		যদি (ioctl(in_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, পরিমাণ(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		যদি ((r = sshpkt_put_cstring(ssh, term != রিক্ত ? term : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		যদি (tiop == রিক্ত)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		যদি ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	যদি (options.অঙ্ক_send_env != 0 && env != রিক্ত) {
		debug("Sending environment.");
		বাবে (i = 0; env[i] != রিক্ত; i++) {
			/* Split */
			name = xstrdup(env[i]);
			যদি ((val = strchr(name, '=')) == রিক্ত) {
				মুক্ত(name);
				অনুৱর্ত;
			}
			*val++ = '\0';

			matched = 0;
			বাবে (j = 0; j < options.অঙ্ক_send_env; j++) {
				যদি (match_pattern(name, options.send_env[j])) {
					matched = 1;
					ভঙ্গ;
				}
			}
			যদি (!matched) {
				debug3("Ignored env %s", name);
				মুক্ত(name);
				অনুৱর্ত;
			}
			client_send_env(ssh, id, name, val);
			মুক্ত(name);
		}
	}
	বাবে (i = 0; i < options.অঙ্ক_setenv; i++) {
		/* Split */
		name = xstrdup(options.setenv[i]);
		যদি ((val = strchr(name, '=')) == রিক্ত) {
			মুক্ত(name);
			অনুৱর্ত;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		মুক্ত(name);
	}

	len = sshbuf_len(cmd);
	যদি (len > 0) {
		যদি ((cmdstring = sshbuf_dup_string(cmd)) == রিক্ত)
			fatal_f("sshbuf_dup_string failed");
		যদি (len > 900)
			len = 900;
		যদি (want_subsystem) {
			debug("Sending subsystem: %.*s", (পূর্ণাঙ্ক)len, cmdstring);
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} অন্যথা {
			debug("Sending command: %.*s", (পূর্ণাঙ্ক)len, cmdstring);
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		যদি ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} অন্যথা {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		যদি ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_set_xtype(ssh, id, type);
	মুক্ত(cmdstring);
	মুক্ত(type);

	session_setup_complete = 1;
	client_repledge();
}

শূন্য
client_channel_request_agent_forwarding(সংরচনা ssh *ssh, পূর্ণাঙ্ক id)
{
	ধ্রুৱ ৱর্ণ *req = "auth-agent-req@openssh.com";
	পূর্ণাঙ্ক r;

	যদি (ssh->kex != রিক্ত && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_start(ssh, id, req, 0);
	যদি ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

স্থির শূন্য
client_init_dispatch(সংরচনা ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_CLOSE, &channel_প্ৰবেশ_oclose);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_DATA, &channel_প্ৰবেশ_data);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_EOF, &channel_প্ৰবেশ_ieof);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_EXTENDED_DATA, &channel_প্ৰবেশ_extended_data);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_OPEN, &client_প্ৰবেশ_channel_open);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_OPEN_CONFIRMATION, &channel_প্ৰবেশ_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_OPEN_FAILURE, &channel_প্ৰবেশ_open_failure);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_REQUEST, &client_প্ৰবেশ_channel_req);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_WINDOW_ADJUST, &channel_প্ৰবেশ_window_adjust);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_SUCCESS, &channel_প্ৰবেশ_status_confirm);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_CHANNEL_FAILURE, &channel_প্ৰবেশ_status_confirm);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_GLOBAL_REQUEST, &client_প্ৰবেশ_global_request);

	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_KEXINIT, &kex_প্ৰবেশ_kexinit);

	/* global request reply messages */
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_REQUEST_FAILURE, &client_global_request_reply);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_REQUEST_SUCCESS, &client_global_request_reply);
}

শূন্য
client_stop_mux(শূন্য)
{
	যদি (options.control_path != রিক্ত && muxserver_sock != -1)
		unlink(options.control_path);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	যদি (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
শূন্য
cleanup_exit(পূর্ণাঙ্ক i)
{
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	যদি (options.control_path != রিক্ত && muxserver_sock != -1)
		unlink(options.control_path);
	ssh_kill_proxy_command();
	_exit(i);
}
