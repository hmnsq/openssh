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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/ioctl.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "readconf.h"
#அந்தர்பாவ "clientloop.h"
#அந்தர்பாவ "sshconnect.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "sshpty.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#define HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#define SSH_KEYSTROKE_TIMING_FUZZ 10

வெளி எழுத்து *__progname;

/* import options */
வெளி Options options;

/* Control socket */
வெளி முழு muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
வெளி எழுத்து *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
வெளி எழுத்து *forward_agent_sock_path;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
நிலையான நிலையற்ற sig_atomic_t received_window_change_signal = 0;
நிலையான நிலையற்ற sig_atomic_t siginfo_received = 0;
நிலையான நிலையற்ற sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
நிலையான time_t control_persist_exit_time = 0;

/* Common data for the client loop code. */
நிலையற்ற sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
நிலையான முழு last_was_cr;		/* Last character was a newline. */
நிலையான முழு exit_status;		/* Used to store the command exit status. */
நிலையான முழு connection_in;	/* Connection to server (input). */
நிலையான முழு connection_out;	/* Connection to server (output). */
நிலையான முழு need_rekeying;	/* Set to non-zero if rekeying is requested. */
நிலையான முழு session_closed;	/* In SSH2: login session closed. */
நிலையான time_t x11_refuse_time;	/* If >0, refuse x11 opens after this time. */
நிலையான time_t server_alive_time;	/* Time to do server_alive_check */
நிலையான முழு hostkeys_update_complete;
நிலையான முழு session_setup_complete;

நிலையான வெறுமை client_init_dispatch(கட்டமைப்பு ssh *ssh);
முழு	session_ident = -1;

/* Track escape per proto2 channel */
கட்டமைப்பு escape_filter_ctx {
	முழு escape_pending;
	முழு escape_char;
};

/* Context for channel confirmation replies */
கட்டமைப்பு channel_reply_ctx {
	மாறிலி எழுத்து *request_type;
	முழு id;
	எண்ணிக்கை confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
கட்டமைப்பு global_confirm {
	TAILQ_ENTRY(global_confirm) entry;
	global_confirm_cb *cb;
	வெறுமை *ctx;
	முழு ref_மொத்தம்;
};
TAILQ_HEAD(global_confirms, global_confirm);
நிலையான கட்டமைப்பு global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

நிலையான வெறுமை quit_message(மாறிலி எழுத்து *fmt, ...)
    __attribute__((__format__ (printf, 1, 2)));

நிலையான வெறுமை
quit_message(மாறிலி எழுத்து *fmt, ...)
{
	எழுத்து *செய்தி, *fmt2;
	va_list args;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(args, fmt);
	xvasprintf(&செய்தி, fmt2, args);
	va_end(args);

	(வெறுமை)atomicio(vwrite, STDERR_FILENO, செய்தி, strlen(செய்தி));
	விடுவி(செய்தி);
	விடுவி(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
நிலையான வெறுமை
window_change_handler(முழு sig)
{
	received_window_change_signal = 1;
}

#ifdef SIGINFO
/* Signal handler for SIGINFO */
நிலையான வெறுமை
siginfo_handler(முழு sig)
{
	siginfo_received = 1;
}
#endif

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
நிலையான வெறுமை
signal_handler(முழு sig)
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
நிலையான வெறுமை
set_control_persist_exit_time(கட்டமைப்பு ssh *ssh)
{
	எனில் (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} இல்லையெனில் எனில் (channel_still_open(ssh)) {
		/* some client connections are still open */
		எனில் (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} இல்லையெனில் எனில் (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#define SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
நிலையான முழு
client_x11_display_valid(மாறிலி எழுத்து *display)
{
	size_t i, dlen;

	எனில் (display == வெற்று)
		திரும்பு 0;

	dlen = strlen(display);
	க்கு (i = 0; i < dlen; i++) {
		எனில் (!isalnum((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == வெற்று) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			திரும்பு 0;
		}
	}
	திரும்பு 1;
}

#define SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#define X11_TIMEOUT_SLACK	60
முழு
client_x11_get_proto(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *display,
    மாறிலி எழுத்து *xauth_path, u_int trusted, u_int timeout,
    எழுத்து **_proto, எழுத்து **_data)
{
	எழுத்து *cmd, வரி[512], xdisplay[512];
	எழுத்து xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	நிலையான எழுத்து proto[512], data[512];
	FILE *f;
	முழு got_data = 0, generated = 0, do_unlink = 0, r;
	கட்டமைப்பு stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*_data = data;
	proto[0] = data[0] = xauthfile[0] = xauthdir[0] = '\0';

	எனில் (!client_x11_display_valid(display)) {
		எனில் (display != வெற்று)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		திரும்பு -1;
	}
	எனில் (xauth_path != வெற்று && stat(xauth_path, &st) == -1) {
		debug("No xauth program.");
		xauth_path = வெற்று;
	}

	எனில் (xauth_path != வெற்று) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		எனில் (strncmp(display, "localhost:", 10) == 0) {
			எனில் ((r = snprintf(xdisplay, அளவு(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (size_t)r >= அளவு(xdisplay)) {
				error_f("display name too long");
				திரும்பு -1;
			}
			display = xdisplay;
		}
		எனில் (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, அளவு(xauthdir));
			எனில் (mkdtemp(xauthdir) == வெற்று) {
				error_f("mkdtemp: %s", strerror(errno));
				திரும்பு -1;
			}
			do_unlink = 1;
			எனில் ((r = snprintf(xauthfile, அளவு(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (size_t)r >= அளவு(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				திரும்பு -1;
			}

			எனில் (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} இல்லையெனில் {
				/* Add some slack to requested expiry */
				எனில் (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				இல்லையெனில் {
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

			எனில் (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				எனில் (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				இல்லையெனில்
					x11_refuse_time = now + timeout;
				channel_set_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			எனில் (system(cmd) == 0)
				generated = 1;
			விடுவி(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		எனில் (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_path,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			எனில் (f && fgets(வரி, அளவு(வரி), f) &&
			    sscanf(வரி, "%*s %511s %511s", proto, data) == 2)
				got_data = 1;
			எனில் (f)
				pclose(f);
			விடுவி(cmd);
		}
	}

	எனில் (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	எனில் (!trusted && !got_data) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		திரும்பு -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	எனில் (!got_data) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, அளவு proto);
		arc4random_buf(rnd, அளவு(rnd));
		க்கு (i = 0; i < அளவு(rnd); i++) {
			snprintf(data + 2 * i, அளவு data - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	திரும்பு 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

நிலையான வெறுமை
client_check_window_change(கட்டமைப்பு ssh *ssh)
{
	எனில் (!received_window_change_signal)
		திரும்பு;
	received_window_change_signal = 0;
	debug2_f("changed");
	channel_send_window_changes(ssh);
}

நிலையான முழு
client_global_request_reply(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு global_confirm *gc;

	எனில் ((gc = TAILQ_FIRST(&global_confirms)) == வெற்று)
		திரும்பு 0;
	எனில் (gc->cb != வெற்று)
		gc->cb(ssh, type, seq, gc->ctx);
	எனில் (--gc->ref_மொத்தம் <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, entry);
		freezero(gc, அளவு(*gc));
	}

	ssh_packet_set_alive_timeouts(ssh, 0);
	திரும்பு 0;
}

நிலையான வெறுமை
schedule_server_alive_check(வெறுமை)
{
	எனில் (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

நிலையான வெறுமை
server_alive_check(கட்டமைப்பு ssh *ssh)
{
	முழு r;

	எனில் (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_மொத்தம்_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_register_global_confirm(வெற்று, வெற்று);
	schedule_server_alive_check();
}

/* Try to send a dummy keystroke */
நிலையான முழு
send_chaff(கட்டமைப்பு ssh *ssh)
{
	முழு r;

	எனில் (ssh->kex == வெற்று || (ssh->kex->flags & KEX_HAS_PING) == 0)
		திரும்பு 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	திரும்பு 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
நிலையான வெறுமை
set_next_interval(மாறிலி கட்டமைப்பு timespec *now, கட்டமைப்பு timespec *next_interval,
    u_int interval_ms, முழு starting)
{
	கட்டமைப்பு timespec tmp;
	long long interval_ns, fuzz_ns;
	நிலையான long long rate_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	எனில் (fuzz_ns > INT_MAX)
		fuzz_ns = INT_MAX;
	எனில் (fuzz_ns > interval_ns) {
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
	எனில் (starting)
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
நிலையான முழு
obfuscate_keystroke_timing(கட்டமைப்பு ssh *ssh, கட்டமைப்பு timespec *timeout,
    முழு channel_did_enqueue)
{
	நிலையான முழு active;
	நிலையான கட்டமைப்பு timespec next_interval, chaff_until;
	கட்டமைப்பு timespec now, tmp;
	முழு just_started = 0, had_keystroke = 0;
	நிலையான unsigned long long nchaff;
	எழுத்து *stop_reason = வெற்று;
	long long n;

	monotime_ts(&now);

	எனில் (options.obscure_keystroke_timing_interval <= 0)
		திரும்பு 1;	/* disabled in config */

	எனில் (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} இல்லையெனில் எனில் (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} இல்லையெனில் எனில் (!ssh_packet_interactive_data_to_write(ssh) &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} இல்லையெனில் எனில் (active && channel_did_enqueue &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} இல்லையெனில் எனில் (active) {
		எனில் (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} இல்லையெனில் எனில் (timespeccmp(&now, &next_interval, >=) &&
		    !ssh_packet_have_data_to_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			எனில் (send_chaff(ssh))
				nchaff++;
		}
	}

	எனில் (stop_reason != வெற்று) {
		எனில் (active) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			active = 0;
		}
		திரும்பு 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	எனில் (!active && ssh_packet_interactive_data_to_write(ssh) &&
	    channel_did_enqueue && ssh_packet_have_data_to_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = active = 1;
		nchaff = 0;
		set_next_interval(&now, &next_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	எனில் (!active)
		திரும்பு 1;

	எனில் (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_to_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_uniform(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &next_interval);

	எனில் (just_started)
		திரும்பு 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	எனில் (timespeccmp(&now, &next_interval, <))
		/* ...unless there's x11 communication happening */
		திரும்பு x11_channel_used_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - next_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - next_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	set_next_interval(&now, &next_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	திரும்பு 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
நிலையான வெறுமை
client_wait_until_can_do_something(கட்டமைப்பு ssh *ssh, கட்டமைப்பு pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, முழு channel_did_enqueue,
    sigset_t *sigsetp, முழு *conn_in_readyp, முழு *conn_out_readyp)
{
	கட்டமைப்பு timespec timeout;
	முழு ret, oready;
	u_int p;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	எனில் (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	எனில் (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_data_to_write(ssh)) {
		/* clear events since we did not call poll() */
		க்கு (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		திரும்பு;
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
	எனில் (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	எனில் (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	எனில் (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	எனில் (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		க்கு (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		எனில் (errno == EINTR)
			திரும்பு;
		/* Note: we might still have data in the buffers. */
		quit_message("poll: %s", strerror(errno));
		திரும்பு;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	எனில் (options.server_alive_interval > 0 && !*conn_in_readyp &&
	    monotime() >= server_alive_time) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

நிலையான வெறுமை
client_suspend_self(கட்டமைப்பு sshbuf *bin, கட்டமைப்பு sshbuf *bout, கட்டமைப்பு sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	எனில் (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	எனில் (sshbuf_len(berr) > 0)
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

நிலையான வெறுமை
client_process_net_உள்ளீடு(கட்டமைப்பு ssh *ssh)
{
	முழு r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	schedule_server_alive_check();
	எனில் ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		திரும்பு; /* success */
	எனில் (r == SSH_ERR_SYSTEM_ERROR) {
		எனில் (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			திரும்பு;
		எனில் (errno == EPIPE) {
			quit_message("Connection to %s closed by remote host.",
			    host);
			திரும்பு;
		}
	}
	quit_message("Read from remote host %s: %s", host, ssh_err(r));
}

நிலையான வெறுமை
client_status_confirm(கட்டமைப்பு ssh *ssh, முழு type, Channel *c, வெறுமை *ctx)
{
	கட்டமைப்பு channel_reply_ctx *cr = (கட்டமைப்பு channel_reply_ctx *)ctx;
	எழுத்து errmsg[256];
	முழு r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	எனில் (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	எனில் (type == SSH2_செய்தி_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} இல்லையெனில் எனில் (type == SSH2_செய்தி_CHANNEL_FAILURE) {
		எனில் (tochan) {
			snprintf(errmsg, அளவு(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} இல்லையெனில் {
			snprintf(errmsg, அளவு(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		எனில் (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		எனில் (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			எனில் ((r = sshbuf_put(c->extended, errmsg,
			    strlen(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} இல்லையெனில்
			error("%s", errmsg);
		எனில் (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			எனில் (c->self == session_ident)
				leave_raw_mode(0);
			இல்லையெனில்
				mux_tty_alloc_failed(ssh, c);
		} இல்லையெனில் எனில் (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	விடுவி(cr);
}

நிலையான வெறுமை
client_abandon_status_confirm(கட்டமைப்பு ssh *ssh, Channel *c, வெறுமை *ctx)
{
	விடுவி(ctx);
}

வெறுமை
client_expect_confirm(கட்டமைப்பு ssh *ssh, முழு id, மாறிலி எழுத்து *request,
    எண்ணிக்கை confirm_action action)
{
	கட்டமைப்பு channel_reply_ctx *cr = xcalloc(1, அளவு(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_register_status_confirm(ssh, id, client_status_confirm,
	    client_abandon_status_confirm, cr);
}

வெறுமை
client_register_global_confirm(global_confirm_cb *cb, வெறுமை *ctx)
{
	கட்டமைப்பு global_confirm *gc, *last_gc;

	/* Coalesce identical callbacks */
	last_gc = TAILQ_LAST(&global_confirms, global_confirms);
	எனில் (last_gc && last_gc->cb == cb && last_gc->ctx == ctx) {
		எனில் (++last_gc->ref_மொத்தம் >= INT_MAX)
			fatal_f("last_gc->ref_count = %d",
			    last_gc->ref_மொத்தம்);
		திரும்பு;
	}

	gc = xcalloc(1, அளவு(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_மொத்தம் = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, entry);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
நிலையான முழு
can_update_hostkeys(வெறுமை)
{
	எனில் (hostkeys_update_complete)
		திரும்பு 0;
	எனில் (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_mode)
		திரும்பு 0; /* won't ask in batchmode, so don't even try */
	எனில் (!options.update_hostkeys || options.இலக்கம்_user_hostfiles <= 0)
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான வெறுமை
client_repledge(வெறுமை)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	எனில் (options.control_master || options.control_path != வெற்று ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != வெற்று || can_update_hostkeys() ||
	    (session_ident != -1 && !session_setup_complete)) {
		/* Can't tighten */
		திரும்பு;
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
	எனில் (options.இலக்கம்_local_forwards != 0 ||
	    options.இலக்கம்_remote_forwards != 0 ||
	    options.இலக்கம்_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		எனில் (pledge("stdio unix inet dns proc tty", வெற்று) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} இல்லையெனில் எனில் (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		எனில் (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", வெற்று) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} இல்லையெனில் {
		debug("pledge: fork");
		எனில் (pledge(PLEDGE_EXTRA_INET "stdio proc tty", வெற்று) == -1)
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

நிலையான வெறுமை
process_cmdline(கட்டமைப்பு ssh *ssh)
{
	வெறுமை (*handler)(முழு);
	எழுத்து *s, *cmd;
	முழு ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	கட்டமைப்பு Forward fwd;

	memset(&fwd, 0, அளவு(fwd));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	எனில் (s == வெற்று)
		செல் out;
	போது (isspace((u_char)*s))
		s++;
	எனில் (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	எனில் (*s == '\0')
		செல் out;

	எனில் (*s == 'h' || *s == 'H' || *s == '?') {
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
		எனில் (!options.permit_local_command)
			செல் out;
		logit("      !args                                  "
		    "Execute local command");
		செல் out;
	}

	எனில் (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		செல் out;
	}

	எனில் (*s == 'K') {
		delete = 1;
		s++;
	}
	எனில் (*s == 'L')
		local = 1;
	இல்லையெனில் எனில் (*s == 'R')
		remote = 1;
	இல்லையெனில் எனில் (*s == 'D')
		dynamic = 1;
	இல்லையெனில் {
		logit("Invalid command.");
		செல் out;
	}

	போது (isspace((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	எனில் (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		எனில் (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			செல் out;
		}
		எனில் (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		இல்லையெனில் எனில் (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		இல்லையெனில்
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_PORT_STATIC,
			    &options.fwd_opts) > 0;
		எனில் (!ok) {
			logit("Unknown port forwarding.");
			செல் out;
		}
		logit("Canceled forwarding.");
	} இல்லையெனில் {
		/* -R specs can be both dynamic or not, so check both. */
		எனில் (remote) {
			எனில் (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				செல் out;
			}
		} இல்லையெனில் எனில் (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			செல் out;
		}
		எனில் (local || dynamic) {
			எனில் (!channel_setup_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				செல் out;
			}
		} இல்லையெனில் {
			எனில் (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				செல் out;
			}
		}
		logit("Forwarding port.");
	}

out:
	ssh_signal(SIGINT, handler);
	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	விடுவி(cmd);
	விடுவி(fwd.listen_host);
	விடுவி(fwd.listen_path);
	விடுவி(fwd.connect_host);
	விடுவி(fwd.connect_path);
}

/* reasons to suppress output of an escape command in help output */
#define SUPPRESS_NEVER		0	/* never suppress, always show */
#define SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#define SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#define SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#define SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
கட்டமைப்பு escape_help_text {
	மாறிலி எழுத்து *cmd;
	மாறிலி எழுத்து *text;
	unsigned முழு flags;
};
நிலையான கட்டமைப்பு escape_help_text esc_txt[] = {
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

நிலையான வெறுமை
print_escape_help(கட்டமைப்பு sshbuf *b, முழு escape_char, முழு mux_client,
    முழு using_stderr)
{
	unsigned முழு i, suppress_flags;
	முழு r;

	எனில் ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	க்கு (i = 0; i < அளவு(esc_txt)/அளவு(esc_txt[0]); i++) {
		எனில் (esc_txt[i].flags & suppress_flags)
			தொடர்;
		எனில் ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	எனில் ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
நிலையான முழு
process_escapes(கட்டமைப்பு ssh *ssh, Channel *c,
    கட்டமைப்பு sshbuf *bin, கட்டமைப்பு sshbuf *bout, கட்டமைப்பு sshbuf *berr,
    எழுத்து *buf, முழு len)
{
	pid_t pid;
	முழு r, bytes = 0;
	u_int i;
	u_char ch;
	எழுத்து *s;
	கட்டமைப்பு escape_filter_ctx *efc;

	எனில் (c == வெற்று || c->filter_ctx == வெற்று || len <= 0)
		திரும்பு 0;

	efc = (கட்டமைப்பு escape_filter_ctx *)c->filter_ctx;

	க்கு (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		எனில் (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			தேர்வு (ch) {
			நிலை '.':
				/* Terminate the connection. */
				எனில் ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				எனில் (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					திரும்பு 0;
				} இல்லையெனில்
					quit_pending = 1;
				திரும்பு -1;

			நிலை 'Z' - 64:
				/* XXX support this for mux clients */
				எனில் (c && c->ctl_chan != -1) {
					எழுத்து b[16];
 noescape:
					எனில் (ch == 'Z' - 64)
						snprintf(b, அளவு b, "^Z");
					இல்லையெனில்
						snprintf(b, அளவு b, "%c", ch);
					எனில் ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					தொடர்;
				}
				/* Suspend the program. Inform the user */
				எனில் ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				தொடர்;

			நிலை 'B':
				எனில் ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				எனில் ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				தொடர்;

			நிலை 'I':
				எனில் ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_message(ssh);
				எனில் ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				விடுவி(s);
				தொடர்;

			நிலை 'R':
				எனில் (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				இல்லையெனில்
					need_rekeying = 1;
				தொடர்;

			நிலை 'V':
				/* FALLTHROUGH */
			நிலை 'v':
				எனில் (c && c->ctl_chan != -1)
					செல் noescape;
				எனில் (!log_is_on_stderr()) {
					எனில் ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					தொடர்;
				}
				எனில் (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				எனில் (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				எனில் ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				தொடர்;

			நிலை '&':
				எனில் (c->ctl_chan != -1)
					செல் noescape;
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

				எனில் ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				எனில் (pid == -1) {
					error("fork: %.100s", strerror(errno));
					தொடர்;
				}
				எனில் (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					exit(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				எனில் ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				திரும்பு -1;
			நிலை '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				தொடர்;

			நிலை '#':
				எனில் ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_message(ssh);
				எனில் ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				விடுவி(s);
				தொடர்;

			நிலை 'C':
				எனில் (c && c->ctl_chan != -1)
					செல் noescape;
				எனில் (options.enable_escape_commandline == 0) {
					எனில் ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					தொடர்;
				}
				process_cmdline(ssh);
				தொடர்;

			இயல்பு:
				எனில் (ch != efc->escape_char) {
					எனில் ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					bytes++;
				}
				/* Escaped characters fall through here */
				நிறுத்து;
			}
		} இல்லையெனில் {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			எனில் (last_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				தொடர்;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		last_was_cr = (ch == '\r' || ch == '\n');
		எனில் ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		bytes++;
	}
	திரும்பு bytes;
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

நிலையான வெறுமை
client_process_buffered_உள்ளீடு_packets(கட்டமைப்பு ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
வெறுமை *
client_new_escape_filter_ctx(முழு escape_char)
{
	கட்டமைப்பு escape_filter_ctx *ret;

	ret = xcalloc(1, அளவு(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	திரும்பு (வெறுமை *)ret;
}

/* Free the escape filter context on channel free */
வெறுமை
client_filter_cleanup(கட்டமைப்பு ssh *ssh, முழு cid, வெறுமை *ctx)
{
	விடுவி(ctx);
}

முழு
client_simple_escape_filter(கட்டமைப்பு ssh *ssh, Channel *c, எழுத்து *buf, முழு len)
{
	எனில் (c->extended_usage != CHAN_EXTENDED_WRITE)
		திரும்பு 0;

	திரும்பு process_escapes(ssh, c, c->உள்ளீடு, c->output, c->extended,
	    buf, len);
}

நிலையான வெறுமை
client_channel_closed(கட்டமைப்பு ssh *ssh, முழு id, முழு force, வெறுமை *arg)
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
முழு
client_loop(கட்டமைப்பு ssh *ssh, முழு have_pty, முழு escape_char_arg,
    முழு ssh2_chan_id)
{
	கட்டமைப்பு pollfd *pfd = வெற்று;
	u_int npfd_alloc = 0, npfd_active = 0;
	இரட்டை start_time, total_time;
	முழு interactive = -1, channel_did_enqueue = 0, r;
	uint64_t ibytes, obytes;
	முழு conn_in_ready, conn_out_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	எனில் (options.pkcs11_provider != வெற்று)
		debug("pledge: disabled (PKCS11Provider active)");
	இல்லையெனில் எனில் (options.control_master &&
	    !option_clear_or_none(options.control_path)) {
		debug("pledge: id");
		எனில் (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    வெற்று) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} இல்லையெனில் எனில் (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		எனில் (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    வெற்று) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} இல்லையெனில் எனில் (options.update_hostkeys) {
		debug("pledge: filesystem");
		எனில் (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    வெற்று) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} இல்லையெனில் எனில் (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		எனில் (pledge("stdio cpath unix inet dns proc tty", வெற்று) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} இல்லையெனில் {
		debug("pledge: network");
		எனில் (pledge("stdio unix inet dns proc tty", வெற்று) == -1)
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
	எனில் (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	எனில் (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	எனில் (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	எனில் (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, window_change_handler);
#ifdef SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#endif

	எனில் (have_pty)
		enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	எனில் (session_ident != -1) {
		எனில் (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, வெற்று,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_register_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	schedule_server_alive_check();

	எனில் (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ifdef SIGINFO
	எனில் (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#endif

	/* Main loop of the client for the interactive session mode. */
	போது (!quit_pending) {
		channel_did_enqueue = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_உள்ளீடு_packets(ssh);

		எனில் (session_closed && !channel_still_open(ssh))
			நிறுத்து;

		எனில் (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} இல்லையெனில் எனில் (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			எனில் ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} இல்லையெனில் {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			எனில் (ssh_packet_not_very_much_data_to_write(ssh))
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
		எனில் (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		எனில் (siginfo_received) {
			எழுத்து ident[256];

			sshpkt_fmt_connection_id(ssh, ident, அளவு(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - start_time);
			siginfo_received = 0;
		}
		எனில் (quit_pending)
			நிறுத்து;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_active, channel_did_enqueue, &osigset,
		    &conn_in_ready, &conn_out_ready);
		எனில் (sigprocmask(SIG_SETMASK, &osigset, வெற்று) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		எனில் (quit_pending)
			நிறுத்து;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_active);

		/* Buffer input from the connection.  */
		எனில் (conn_in_ready)
			client_process_net_உள்ளீடு(ssh);

		எனில் (quit_pending)
			நிறுத்து;

		/* A timeout may have triggered rekeying */
		எனில் ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		எனில் (conn_out_ready) {
			எனில் (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_set_interactive(ssh, interactive);
			}
			எனில் ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		எனில் (control_persist_exit_time > 0) {
			எனில் (monotime() >= control_persist_exit_time) {
				debug("ControlPersist timeout expired");
				நிறுத்து;
			}
		}
	}
	விடுவி(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	எனில் (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_message("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	எனில் (have_pty)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	எனில் (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_status = 0;
	}

	எனில் (received_signal) {
		verbose("Killed by signal %d.", (முழு) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	total_time = monotime_double() - start_time;
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (unsigned long long)obytes, (unsigned long long)ibytes, total_time);
	எனில் (total_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / total_time, ibytes / total_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	திரும்பு exit_status;
}

/*********/

நிலையான Channel *
client_request_forwarded_tcpip(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *request_type,
    முழு rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = வெற்று;
	கட்டமைப்பு sshbuf *b = வெற்று;
	எழுத்து *listen_address, *originator_address;
	u_int listen_port, originator_port;
	முழு r;

	/* Get rest of the packet */
	எனில் ((r = sshpkt_get_cstring(ssh, &listen_address, வெற்று)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_address, வெற்று)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_address, listen_port, originator_address, originator_port);

	எனில் (listen_port > 0xffff)
		error_f("invalid listen port");
	இல்லையெனில் எனில் (originator_port > 0xffff)
		error_f("invalid originator port");
	இல்லையெனில் {
		c = channel_connect_by_listen_address(ssh,
		    listen_address, listen_port, "forwarded-tcpip",
		    originator_address);
	}

	எனில் (c != வெற்று && c->type == SSH_CHANNEL_MUX_CLIENT) {
		எனில் ((b = sshbuf_new()) == வெற்று) {
			error_f("alloc reply");
			செல் out;
		}
		/* reconstruct and send to muxclient */
		எனில் ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_செய்தி_CHANNEL_OPEN)) != 0 ||
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
			செல் out;
		}
	}

 out:
	sshbuf_free(b);
	விடுவி(originator_address);
	விடுவி(listen_address);
	திரும்பு c;
}

நிலையான Channel *
client_request_forwarded_streamlocal(கட்டமைப்பு ssh *ssh,
    மாறிலி எழுத்து *request_type, முழு rchan)
{
	Channel *c = வெற்று;
	எழுத்து *listen_path;
	முழு r;

	/* Get the remote path. */
	எனில் ((r = sshpkt_get_cstring(ssh, &listen_path, வெற்று)) != 0 ||
	    (r = sshpkt_get_string(ssh, வெற்று, வெற்று)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_path);

	c = channel_connect_by_listen_path(ssh, listen_path,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	விடுவி(listen_path);
	திரும்பு c;
}

நிலையான Channel *
client_request_x11(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *request_type, முழு rchan)
{
	Channel *c = வெற்று;
	எழுத்து *originator;
	u_int originator_port;
	முழு r, sock;

	எனில் (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		திரும்பு வெற்று;
	}
	எனில் (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		திரும்பு வெற்று;
	}
	எனில் ((r = sshpkt_get_cstring(ssh, &originator, வெற்று)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_port);
	விடுவி(originator);
	sock = x11_connect_display(ssh);
	எனில் (sock < 0)
		திரும்பு வெற்று;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	திரும்பு c;
}

நிலையான Channel *
client_request_agent(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *request_type, முழு rchan)
{
	Channel *c = வெற்று;
	முழு r, sock;

	எனில் (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		திரும்பு வெற்று;
	}
	எனில் (forward_agent_sock_path == வெற்று) {
		r = ssh_get_authentication_socket(&sock);
	} இல்லையெனில் {
		r = ssh_get_authentication_socket_path(forward_agent_sock_path, &sock);
	}
	எனில் (r != 0) {
		எனில் (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		திரும்பு வெற்று;
	}
	எனில் ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	இல்லையெனில்
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	திரும்பு c;
}

எழுத்து *
client_request_tun_fwd(கட்டமைப்பு ssh *ssh, முழு tun_mode,
    முழு local_tun, முழு remote_tun, channel_open_fn *cb, வெறுமை *cbctx)
{
	Channel *c;
	முழு r, fd;
	எழுத்து *ifname = வெற்று;

	எனில் (tun_mode == SSH_TUNMODE_NO)
		திரும்பு வெற்று;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	எனில் ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		திரும்பு வெற்று;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#எனில் defined(SSH_TUN_FILTER)
	எனில் (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, வெற்று, வெற்று);
#endif

	எனில் (cb != வெற்று)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	திரும்பு ifname;
}

/* XXXX move to generic input handler */
நிலையான முழு
client_உள்ளீடு_channel_open(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Channel *c = வெற்று;
	எழுத்து *ctype = வெற்று;
	முழு r;
	u_int rchan;
	size_t len;
	u_int rmaxpack, rwindow;

	எனில் ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		செல் out;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	எனில் (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} இல்லையெனில் எனில் (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} இல்லையெனில் எனில் (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} இல்லையெனில் எனில் (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	எனில் (c != வெற்று && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} இல்லையெனில் எனில் (c != வெற்று) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		எனில் (c->type != SSH_CHANNEL_CONNECTING) {
			எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} இல்லையெனில் {
		debug("failure %s", ctype);
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	விடுவி(ctype);
	திரும்பு r;
}

நிலையான முழு
client_உள்ளீடு_channel_req(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Channel *c = வெற்று;
	எழுத்து *rtype = வெற்று;
	u_char reply;
	u_int id, exitval;
	முழு r, success = 0;

	எனில் ((r = sshpkt_get_u32(ssh, &id)) != 0)
		திரும்பு r;
	எனில் (id <= INT_MAX)
		c = channel_lookup(ssh, id);
	எனில் (channel_proxy_upstream(c, type, seq, ssh))
		திரும்பு 0;
	எனில் ((r = sshpkt_get_cstring(ssh, &rtype, வெற்று)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &reply)) != 0)
		செல் out;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, reply);

	எனில் (c == வெற்று) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} இல்லையெனில் எனில் (strcmp(rtype, "eow@openssh.com") == 0) {
		எனில் ((r = sshpkt_get_end(ssh)) != 0)
			செல் out;
		chan_rcvd_eow(ssh, c);
	} இல்லையெனில் எனில் (strcmp(rtype, "exit-status") == 0) {
		எனில் ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			செல் out;
		எனில் (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} இல்லையெனில் எனில் ((முழு)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} இல்லையெனில் {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		எனில் ((r = sshpkt_get_end(ssh)) != 0)
			செல் out;
	}
	எனில் (reply && c != வெற்று && !(c->flags & CHAN_CLOSE_SENT)) {
		எனில் (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		எனில் ((r = sshpkt_start(ssh, success ?
		    SSH2_செய்தி_CHANNEL_SUCCESS : SSH2_செய்தி_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	விடுவி(rtype);
	திரும்பு r;
}

கட்டமைப்பு hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	எழுத்து *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	கட்டமைப்பு sshkey **சாவிகள்;
	u_int *சாவிகள்_match;	/* mask of HKF_MATCH_* from hostfile.h */
	முழு *சாவிகள்_verified;	/* flag for new keys verified by server */
	size_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	கட்டமைப்பு sshkey **old_சாவிகள்;
	size_t nold;

	/* Various special cases. */
	முழு complex_hostspec;	/* wildcard or manual pattern-list host name */
	முழு ca_available;	/* saw CA key for this host */
	முழு old_சாவி_seen;	/* saw old key with other name/addr */
	முழு other_name_seen;	/* saw key with other name/addr */
};

நிலையான வெறுமை
hostkeys_update_ctx_free(கட்டமைப்பு hostkeys_update_ctx *ctx)
{
	size_t i;

	எனில் (ctx == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->சாவிகள்[i]);
	விடுவி(ctx->சாவிகள்);
	விடுவி(ctx->சாவிகள்_match);
	விடுவி(ctx->சாவிகள்_verified);
	க்கு (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_சாவிகள்[i]);
	விடுவி(ctx->old_சாவிகள்);
	விடுவி(ctx->host_str);
	விடுவி(ctx->ip_str);
	விடுவி(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
நிலையான முழு
hostspec_is_complex(மாறிலி எழுத்து *hosts)
{
	எழுத்து *cp;

	/* wildcard */
	எனில் (strchr(hosts, '*') != வெற்று || strchr(hosts, '?') != வெற்று)
		திரும்பு 1;
	/* single host/ip = ok */
	எனில் ((cp = strchr(hosts, ',')) == வெற்று)
		திரும்பு 0;
	/* more than two entries on the line */
	எனில் (strchr(cp + 1, ',') != வெற்று)
		திரும்பு 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	திரும்பு 0;
}

/* callback to search for ctx->keys in known_hosts */
நிலையான முழு
hostkeys_find(கட்டமைப்பு hostkey_foreach_வரி *l, வெறுமை *_ctx)
{
	கட்டமைப்பு hostkeys_update_ctx *ctx = (கட்டமைப்பு hostkeys_update_ctx *)_ctx;
	size_t i;
	கட்டமைப்பு sshkey **tmp;

	எனில் (l->சாவி == வெற்று)
		திரும்பு 0;
	எனில் (l->status != HKF_STATUS_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		க்கு (i = 0; i < ctx->nkeys; i++) {
			எனில் (sshkey_equal(l->சாவி, ctx->சாவிகள்[i])) {
				ctx->other_name_seen = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->சாவிகள்[i]),
				    l->path, l->linenum);
				திரும்பு 0;
			}
		}
		திரும்பு 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	எனில் (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		திரும்பு 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	எனில் (ctx->ip_str != வெற்று && strchr(l->hosts, ',') != வெற்று) {
		எனில் ((l->match & HKF_MATCH_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_seen = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->path, l->linenum);
			திரும்பு 0;
		} இல்லையெனில் எனில் ((l->match & HKF_MATCH_IP) == 0) {
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
	எனில் (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		திரும்பு 0;
	}

	/* Mark off keys we've already seen for this host */
	க்கு (i = 0; i < ctx->nkeys; i++) {
		எனில் (!sshkey_equal(l->சாவி, ctx->சாவிகள்[i]))
			தொடர்;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->சாவிகள்[i]), l->path, l->linenum);
		ctx->சாவிகள்_match[i] |= l->match;
		திரும்பு 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->சாவி),
	    l->path, l->linenum);
	எனில் ((tmp = recallocarray(ctx->old_சாவிகள், ctx->nold, ctx->nold + 1,
	    அளவு(*ctx->old_சாவிகள்))) == வெற்று)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_சாவிகள் = tmp;
	ctx->old_சாவிகள்[ctx->nold++] = l->சாவி;
	l->சாவி = வெற்று;

	திரும்பு 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
நிலையான முழு
hostkeys_check_old(கட்டமைப்பு hostkey_foreach_வரி *l, வெறுமை *_ctx)
{
	கட்டமைப்பு hostkeys_update_ctx *ctx = (கட்டமைப்பு hostkeys_update_ctx *)_ctx;
	size_t i;
	முழு hashed;

	/* only care about lines that *don't* match the active host spec */
	எனில் (l->status == HKF_STATUS_MATCHED || l->சாவி == வெற்று)
		திரும்பு 0;

	hashed = l->match & (HKF_MATCH_HOST_HASHED|HKF_MATCH_IP_HASHED);
	க்கு (i = 0; i < ctx->nold; i++) {
		எனில் (!sshkey_equal(l->சாவி, ctx->old_சாவிகள்[i]))
			தொடர்;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_சாவிகள்[i]), l->path, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_சாவி_seen = 1;
		நிறுத்து;
	}
	திரும்பு 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
நிலையான முழு
check_old_சாவிகள்_othernames(கட்டமைப்பு hostkeys_update_ctx *ctx)
{
	size_t i;
	முழு r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	க்கு (i = 0; i < options.இலக்கம்_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		எனில் ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_சாவி, 0)) != 0) {
			எனில் (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				தொடர்;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			திரும்பு -1;
		}
	}
	திரும்பு 0;
}

நிலையான வெறுமை
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

நிலையான வெறுமை
update_known_hosts(கட்டமைப்பு hostkeys_update_ctx *ctx)
{
	முழு r, was_raw = 0, first = 1;
	முழு asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	எழுத்து *fp, *response;
	size_t i;
	கட்டமைப்பு stat sb;

	க்கு (i = 0; i < ctx->nkeys; i++) {
		எனில் (!ctx->சாவிகள்_verified[i])
			தொடர்;
		எனில் ((fp = sshkey_fingerprint(ctx->சாவிகள்[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("sshkey_fingerprint failed");
		எனில் (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->சாவிகள்[i]), fp);
		first = 0;
		விடுவி(fp);
	}
	க்கு (i = 0; i < ctx->nold; i++) {
		எனில் ((fp = sshkey_fingerprint(ctx->old_சாவிகள்[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("sshkey_fingerprint failed");
		எனில் (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_சாவிகள்[i]), fp);
		first = 0;
		விடுவி(fp);
	}
	எனில் (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		எனில் (get_saved_tio() != வெற்று) {
			leave_raw_mode(1);
			was_raw = 1;
		}
		response = வெற்று;
		க்கு (i = 0; !quit_pending && i < 3; i++) {
			விடுவி(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			எனில் (response != வெற்று && strcasecmp(response, "yes") == 0)
				நிறுத்து;
			இல்லையெனில் எனில் (quit_pending || response == வெற்று ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				நிறுத்து;
			} இல்லையெனில் {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		எனில் (quit_pending || i >= 3 || response == வெற்று)
			options.update_hostkeys = 0;
		விடுவி(response);
		எனில் (was_raw)
			enter_raw_mode(1);
	}
	எனில் (options.update_hostkeys == 0)
		திரும்பு;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	க்கு (i = 0; i < options.இலக்கம்_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		எனில் (stat(options.user_hostfiles[i], &sb) != 0) {
			எனில் (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} இல்லையெனில் {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			தொடர்;
		}
		எனில் ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->சாவிகள் : வெற்று, i == 0 ? ctx->nkeys : 0,
		    options.hash_known_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

நிலையான வெறுமை
client_global_hostkeys_prove_confirm(கட்டமைப்பு ssh *ssh, முழு type,
    uint32_t seq, வெறுமை *_ctx)
{
	கட்டமைப்பு hostkeys_update_ctx *ctx = (கட்டமைப்பு hostkeys_update_ctx *)_ctx;
	size_t i, ndone;
	கட்டமைப்பு sshbuf *signdata;
	முழு r, plaintype;
	மாறிலி u_char *sig;
	மாறிலி எழுத்து *rsa_kexalg = வெற்று;
	எழுத்து *alg = வெற்று;
	size_t siglen;

	எனில் (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	எனில் (type != SSH2_செய்தி_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		திரும்பு;
	}
	எனில் (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == சாவி_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	எனில் ((signdata = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	க்கு (ndone = i = 0; i < ctx->nkeys; i++) {
		எனில் (ctx->சாவிகள்_match[i])
			தொடர்;
		plaintype = sshkey_type_plain(ctx->சாவிகள்[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		எனில் ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->சாவிகள்[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		எனில் ((r = sshpkt_get_string_direct(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			செல் out;
		}
		எனில் ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->சாவிகள்[i]), i);
			செல் out;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		எனில் (plaintype == சாவி_RSA && rsa_kexalg == வெற்று &&
		    match_pattern_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			விடுவி(alg);
			/* zap the key from the list */
			sshkey_free(ctx->சாவிகள்[i]);
			ctx->சாவிகள்[i] = வெற்று;
			ndone++;
			தொடர்;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->சாவிகள்[i]), i, alg);
		விடுவி(alg);
		எனில் ((r = sshkey_verify(ctx->சாவிகள்[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == சாவி_RSA ? rsa_kexalg : வெற்று, 0, வெற்று)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->சாவிகள்[i]), i);
			செல் out;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->சாவிகள்_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	எனில் (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	எனில் ((r = sshpkt_get_end(ssh)) != 0) {
		error_f("protocol error");
		செல் out;
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
நிலையான முழு
client_உள்ளீடு_hostkeys(கட்டமைப்பு ssh *ssh)
{
	மாறிலி u_char *blob = வெற்று;
	size_t i, len = 0;
	கட்டமைப்பு sshbuf *buf = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று, **tmp;
	முழு r, prove_sent = 0;
	எழுத்து *fp;
	நிலையான முழு hostkeys_seen = 0; /* XXX use struct ssh */
	வெளி கட்டமைப்பு sockaddr_storage hostaddr; /* XXX from ssh.c */
	கட்டமைப்பு hostkeys_update_ctx *ctx = வெற்று;
	u_int want;

	எனில் (hostkeys_seen)
		fatal_f("server already sent hostkeys");
	எனில் (!can_update_hostkeys())
		திரும்பு 1;
	hostkeys_seen = 1;

	ctx = xcalloc(1, அளவு(*ctx));
	போது (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(சாவி);
		சாவி = வெற்று;
		எனில் ((r = sshpkt_get_string_direct(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			செல் out;
		}
		எனில் ((r = sshkey_from_blob(blob, len, &சாவி)) != 0) {
			do_log2_fr(r, r == SSH_ERR_சாவி_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			தொடர்;
		}
		fp = sshkey_fingerprint(சாவி, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(சாவி), fp);
		விடுவி(fp);

		எனில் (!hostkey_accepted_by_hostkeyalgs(சாவி)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(சாவி));
			தொடர்;
		}
		/* Skip certs */
		எனில் (sshkey_is_cert(சாவி)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(சாவி));
			தொடர்;
		}
		/* Ensure keys are unique */
		க்கு (i = 0; i < ctx->nkeys; i++) {
			எனில் (sshkey_equal(சாவி, ctx->சாவிகள்[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(சாவி));
				செல் out;
			}
		}
		/* Key is good, record it */
		எனில் ((tmp = recallocarray(ctx->சாவிகள், ctx->nkeys, ctx->nkeys + 1,
		    அளவு(*ctx->சாவிகள்))) == வெற்று)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->சாவிகள் = tmp;
		ctx->சாவிகள்[ctx->nkeys++] = சாவி;
		சாவி = வெற்று;
	}

	எனில் (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		செல் out;
	}

	எனில் ((ctx->சாவிகள்_match = calloc(ctx->nkeys,
	    அளவு(*ctx->சாவிகள்_match))) == வெற்று ||
	    (ctx->சாவிகள்_verified = calloc(ctx->nkeys,
	    அளவு(*ctx->சாவிகள்_verified))) == வெற்று)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (கட்டமைப்பு sockaddr *)&hostaddr : வெற்று,
	    options.port, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : வெற்று);

	/* Find which keys we already know about. */
	க்கு (i = 0; i < options.இலக்கம்_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		எனில் ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_சாவி, 0)) != 0) {
			எனில் (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				தொடர்;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			செல் out;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_MATCH_HOST | ( options.check_host_ip ? HKF_MATCH_IP : 0);
	க்கு (i = 0; i < ctx->nkeys; i++) {
		எனில் (ctx->சாவிகள்_match[i] == 0)
			ctx->nnew++;
		எனில் ((ctx->சாவிகள்_match[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	எனில் (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		செல் out;
	}

	/* Various reasons why we cannot proceed with the update */
	எனில் (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		செல் out;
	}
	எனில் (ctx->other_name_seen) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		செல் out;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	எனில் (ctx->nold != 0) {
		எனில் (check_old_சாவிகள்_othernames(ctx) != 0)
			செல் out; /* error already logged */
		எனில் (ctx->old_சாவி_seen) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == வெற்று ? "" : ",",
			    ctx->ip_str == வெற்று ? "" : ctx->ip_str);
			செல் out;
		}
	}

	எனில் (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_known_hosts(ctx);
		செல் out;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	எனில் ((buf = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	க்கு (i = 0; i < ctx->nkeys; i++) {
		எனில் (ctx->சாவிகள்_match[i])
			தொடர்;
		sshbuf_reset(buf);
		எனில் ((r = sshkey_putb(ctx->சாவிகள்[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	எனில் ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_register_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = வெற்று;  /* will be freed in callback */
	prove_sent = 1;

	/* Success */
 out:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(சாவி);
	sshbuf_free(buf);
	எனில் (!prove_sent) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	திரும்பு 1;
}

நிலையான முழு
client_உள்ளீடு_global_request(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	எழுத்து *rtype;
	u_char want_reply;
	முழு r, success = 0;

	எனில் ((r = sshpkt_get_cstring(ssh, &rtype, வெற்று)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		செல் out;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_reply);
	எனில் (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_உள்ளீடு_hostkeys(ssh);
	எனில் (want_reply) {
		எனில் ((r = sshpkt_start(ssh, success ? SSH2_செய்தி_REQUEST_SUCCESS :
		    SSH2_செய்தி_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			செல் out;
	}
	r = 0;
 out:
	விடுவி(rtype);
	திரும்பு r;
}

நிலையான வெறுமை
client_send_env(கட்டமைப்பு ssh *ssh, முழு id, மாறிலி எழுத்து *name, மாறிலி எழுத்து *val)
{
	முழு r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	எனில் ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

வெறுமை
client_session2_setup(கட்டமைப்பு ssh *ssh, முழு id, முழு want_tty, முழு want_subsystem,
    மாறிலி எழுத்து *term, கட்டமைப்பு termios *tiop, முழு in_fd, கட்டமைப்பு sshbuf *cmd,
    எழுத்து **env)
{
	size_t i, j, len;
	முழு matched, r;
	எழுத்து *type = வெற்று, *cmdstring = வெற்று, *name, *val;
	Channel *c = வெற்று;

	debug2_f("id %d", id);

	எனில் ((c = channel_lookup(ssh, id)) == வெற்று)
		fatal_f("channel %d: unknown channel", id);

	எனில் (want_tty) {
		கட்டமைப்பு winsize ws;

		/* Store window size in the packet. */
		எனில் (ioctl(in_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, அளவு(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		எனில் ((r = sshpkt_put_cstring(ssh, term != வெற்று ? term : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		எனில் (tiop == வெற்று)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		எனில் ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	எனில் (options.இலக்கம்_send_env != 0 && env != வெற்று) {
		debug("Sending environment.");
		க்கு (i = 0; env[i] != வெற்று; i++) {
			/* Split */
			name = xstrdup(env[i]);
			எனில் ((val = strchr(name, '=')) == வெற்று) {
				விடுவி(name);
				தொடர்;
			}
			*val++ = '\0';

			matched = 0;
			க்கு (j = 0; j < options.இலக்கம்_send_env; j++) {
				எனில் (match_pattern(name, options.send_env[j])) {
					matched = 1;
					நிறுத்து;
				}
			}
			எனில் (!matched) {
				debug3("Ignored env %s", name);
				விடுவி(name);
				தொடர்;
			}
			client_send_env(ssh, id, name, val);
			விடுவி(name);
		}
	}
	க்கு (i = 0; i < options.இலக்கம்_setenv; i++) {
		/* Split */
		name = xstrdup(options.setenv[i]);
		எனில் ((val = strchr(name, '=')) == வெற்று) {
			விடுவி(name);
			தொடர்;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		விடுவி(name);
	}

	len = sshbuf_len(cmd);
	எனில் (len > 0) {
		எனில் ((cmdstring = sshbuf_dup_string(cmd)) == வெற்று)
			fatal_f("sshbuf_dup_string failed");
		எனில் (len > 900)
			len = 900;
		எனில் (want_subsystem) {
			debug("Sending subsystem: %.*s", (முழு)len, cmdstring);
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} இல்லையெனில் {
			debug("Sending command: %.*s", (முழு)len, cmdstring);
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		எனில் ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} இல்லையெனில் {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		எனில் ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_set_xtype(ssh, id, type);
	விடுவி(cmdstring);
	விடுவி(type);

	session_setup_complete = 1;
	client_repledge();
}

வெறுமை
client_channel_request_agent_forwarding(கட்டமைப்பு ssh *ssh, முழு id)
{
	மாறிலி எழுத்து *req = "auth-agent-req@openssh.com";
	முழு r;

	எனில் (ssh->kex != வெற்று && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_start(ssh, id, req, 0);
	எனில் ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

நிலையான வெறுமை
client_init_dispatch(கட்டமைப்பு ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_CLOSE, &channel_உள்ளீடு_oclose);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_DATA, &channel_உள்ளீடு_data);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_EOF, &channel_உள்ளீடு_ieof);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_EXTENDED_DATA, &channel_உள்ளீடு_extended_data);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_OPEN, &client_உள்ளீடு_channel_open);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION, &channel_உள்ளீடு_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_OPEN_FAILURE, &channel_உள்ளீடு_open_failure);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_REQUEST, &client_உள்ளீடு_channel_req);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_WINDOW_ADJUST, &channel_உள்ளீடு_window_adjust);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_SUCCESS, &channel_உள்ளீடு_status_confirm);
	ssh_dispatch_set(ssh, SSH2_செய்தி_CHANNEL_FAILURE, &channel_உள்ளீடு_status_confirm);
	ssh_dispatch_set(ssh, SSH2_செய்தி_GLOBAL_REQUEST, &client_உள்ளீடு_global_request);

	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEXINIT, &kex_உள்ளீடு_kexinit);

	/* global request reply messages */
	ssh_dispatch_set(ssh, SSH2_செய்தி_REQUEST_FAILURE, &client_global_request_reply);
	ssh_dispatch_set(ssh, SSH2_செய்தி_REQUEST_SUCCESS, &client_global_request_reply);
}

வெறுமை
client_stop_mux(வெறுமை)
{
	எனில் (options.control_path != வெற்று && muxserver_sock != -1)
		unlink(options.control_path);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	எனில் (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
வெறுமை
cleanup_exit(முழு i)
{
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	எனில் (options.control_path != வெற்று && muxserver_sock != -1)
		unlink(options.control_path);
	ssh_kill_proxy_command();
	_exit(i);
}
