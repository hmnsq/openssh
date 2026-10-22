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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/ioctl.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/queue.h>

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "readconf.h"
#અન્તર્ભાવ "clientloop.h"
#અન્તર્ભાવ "sshconnect.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "sshpty.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#define HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#define SSH_KEYSTROKE_TIMING_FUZZ 10

બાહ્ય અક્ષર *__progname;

/* import options */
બાહ્ય Options options;

/* Control socket */
બાહ્ય પૂર્ણાંક muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
બાહ્ય અક્ષર *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
બાહ્ય અક્ષર *forward_agent_sock_path;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
સ્થિર અસ્થિર sig_atomic_t received_window_change_signal = 0;
સ્થિર અસ્થિર sig_atomic_t siginfo_received = 0;
સ્થિર અસ્થિર sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
સ્થિર time_t control_persist_exit_time = 0;

/* Common data for the client loop code. */
અસ્થિર sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
સ્થિર પૂર્ણાંક last_was_cr;		/* Last character was a newline. */
સ્થિર પૂર્ણાંક exit_status;		/* Used to store the command exit status. */
સ્થિર પૂર્ણાંક connection_in;	/* Connection to server (input). */
સ્થિર પૂર્ણાંક connection_out;	/* Connection to server (output). */
સ્થિર પૂર્ણાંક need_rekeying;	/* Set to non-zero if rekeying is requested. */
સ્થિર પૂર્ણાંક session_closed;	/* In SSH2: login session closed. */
સ્થિર time_t x11_refuse_time;	/* If >0, refuse x11 opens after this time. */
સ્થિર time_t server_alive_time;	/* Time to do server_alive_check */
સ્થિર પૂર્ણાંક hostkeys_update_complete;
સ્થિર પૂર્ણાંક session_setup_complete;

સ્થિર શૂન્ય client_init_dispatch(સંરચના ssh *ssh);
પૂર્ણાંક	session_ident = -1;

/* Track escape per proto2 channel */
સંરચના escape_filter_ctx {
	પૂર્ણાંક escape_pending;
	પૂર્ણાંક escape_char;
};

/* Context for channel confirmation replies */
સંરચના channel_reply_ctx {
	અચલ અક્ષર *request_type;
	પૂર્ણાંક id;
	ગણના confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
સંરચના global_confirm {
	TAILQ_ENTRY(global_confirm) entry;
	global_confirm_cb *cb;
	શૂન્ય *ctx;
	પૂર્ણાંક ref_ગણતરી;
};
TAILQ_HEAD(global_confirms, global_confirm);
સ્થિર સંરચના global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

સ્થિર શૂન્ય quit_message(અચલ અક્ષર *fmt, ...)
    __attribute__((__format__ (printf, 1, 2)));

સ્થિર શૂન્ય
quit_message(અચલ અક્ષર *fmt, ...)
{
	અક્ષર *સંદેશ, *fmt2;
	va_list args;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(args, fmt);
	xvasprintf(&સંદેશ, fmt2, args);
	va_end(args);

	(શૂન્ય)atomicio(vwrite, STDERR_FILENO, સંદેશ, strlen(સંદેશ));
	મુક્ત(સંદેશ);
	મુક્ત(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
સ્થિર શૂન્ય
window_change_handler(પૂર્ણાંક sig)
{
	received_window_change_signal = 1;
}

#ifdef SIGINFO
/* Signal handler for SIGINFO */
સ્થિર શૂન્ય
siginfo_handler(પૂર્ણાંક sig)
{
	siginfo_received = 1;
}
#endif

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
સ્થિર શૂન્ય
signal_handler(પૂર્ણાંક sig)
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
સ્થિર શૂન્ય
set_control_persist_exit_time(સંરચના ssh *ssh)
{
	જો (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} નહીંતર જો (channel_still_open(ssh)) {
		/* some client connections are still open */
		જો (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} નહીંતર જો (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#define SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
સ્થિર પૂર્ણાંક
client_x11_display_valid(અચલ અક્ષર *display)
{
	size_t i, dlen;

	જો (display == ખાલી)
		પાછા 0;

	dlen = strlen(display);
	માટે (i = 0; i < dlen; i++) {
		જો (!isalnum((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == ખાલી) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			પાછા 0;
		}
	}
	પાછા 1;
}

#define SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#define X11_TIMEOUT_SLACK	60
પૂર્ણાંક
client_x11_get_proto(સંરચના ssh *ssh, અચલ અક્ષર *display,
    અચલ અક્ષર *xauth_path, u_int trusted, u_int timeout,
    અક્ષર **_proto, અક્ષર **_data)
{
	અક્ષર *cmd, લીટી[512], xdisplay[512];
	અક્ષર xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	સ્થિર અક્ષર proto[512], data[512];
	FILE *f;
	પૂર્ણાંક got_data = 0, generated = 0, do_unlink = 0, r;
	સંરચના stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*_data = data;
	proto[0] = data[0] = xauthfile[0] = xauthdir[0] = '\0';

	જો (!client_x11_display_valid(display)) {
		જો (display != ખાલી)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		પાછા -1;
	}
	જો (xauth_path != ખાલી && stat(xauth_path, &st) == -1) {
		debug("No xauth program.");
		xauth_path = ખાલી;
	}

	જો (xauth_path != ખાલી) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		જો (strncmp(display, "localhost:", 10) == 0) {
			જો ((r = snprintf(xdisplay, કદ(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (size_t)r >= કદ(xdisplay)) {
				error_f("display name too long");
				પાછા -1;
			}
			display = xdisplay;
		}
		જો (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, કદ(xauthdir));
			જો (mkdtemp(xauthdir) == ખાલી) {
				error_f("mkdtemp: %s", strerror(errno));
				પાછા -1;
			}
			do_unlink = 1;
			જો ((r = snprintf(xauthfile, કદ(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (size_t)r >= કદ(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				પાછા -1;
			}

			જો (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} નહીંતર {
				/* Add some slack to requested expiry */
				જો (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				નહીંતર {
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

			જો (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				જો (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				નહીંતર
					x11_refuse_time = now + timeout;
				channel_set_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			જો (system(cmd) == 0)
				generated = 1;
			મુક્ત(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		જો (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_path,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			જો (f && fgets(લીટી, કદ(લીટી), f) &&
			    sscanf(લીટી, "%*s %511s %511s", proto, data) == 2)
				got_data = 1;
			જો (f)
				pclose(f);
			મુક્ત(cmd);
		}
	}

	જો (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	જો (!trusted && !got_data) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		પાછા -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	જો (!got_data) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, કદ proto);
		arc4random_buf(rnd, કદ(rnd));
		માટે (i = 0; i < કદ(rnd); i++) {
			snprintf(data + 2 * i, કદ data - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	પાછા 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

સ્થિર શૂન્ય
client_check_window_change(સંરચના ssh *ssh)
{
	જો (!received_window_change_signal)
		પાછા;
	received_window_change_signal = 0;
	debug2_f("changed");
	channel_send_window_changes(ssh);
}

સ્થિર પૂર્ણાંક
client_global_request_reply(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના global_confirm *gc;

	જો ((gc = TAILQ_FIRST(&global_confirms)) == ખાલી)
		પાછા 0;
	જો (gc->cb != ખાલી)
		gc->cb(ssh, type, seq, gc->ctx);
	જો (--gc->ref_ગણતરી <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, entry);
		freezero(gc, કદ(*gc));
	}

	ssh_packet_set_alive_timeouts(ssh, 0);
	પાછા 0;
}

સ્થિર શૂન્ય
schedule_server_alive_check(શૂન્ય)
{
	જો (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

સ્થિર શૂન્ય
server_alive_check(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	જો (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_ગણતરી_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_register_global_confirm(ખાલી, ખાલી);
	schedule_server_alive_check();
}

/* Try to send a dummy keystroke */
સ્થિર પૂર્ણાંક
send_chaff(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	જો (ssh->kex == ખાલી || (ssh->kex->flags & KEX_HAS_PING) == 0)
		પાછા 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	પાછા 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
સ્થિર શૂન્ય
set_next_interval(અચલ સંરચના timespec *now, સંરચના timespec *next_interval,
    u_int interval_ms, પૂર્ણાંક starting)
{
	સંરચના timespec tmp;
	long long interval_ns, fuzz_ns;
	સ્થિર long long rate_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	જો (fuzz_ns > INT_MAX)
		fuzz_ns = INT_MAX;
	જો (fuzz_ns > interval_ns) {
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
	જો (starting)
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
સ્થિર પૂર્ણાંક
obfuscate_keystroke_timing(સંરચના ssh *ssh, સંરચના timespec *timeout,
    પૂર્ણાંક channel_did_enqueue)
{
	સ્થિર પૂર્ણાંક active;
	સ્થિર સંરચના timespec next_interval, chaff_until;
	સંરચના timespec now, tmp;
	પૂર્ણાંક just_started = 0, had_keystroke = 0;
	સ્થિર unsigned long long nchaff;
	અક્ષર *stop_reason = ખાલી;
	long long n;

	monotime_ts(&now);

	જો (options.obscure_keystroke_timing_interval <= 0)
		પાછા 1;	/* disabled in config */

	જો (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} નહીંતર જો (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} નહીંતર જો (!ssh_packet_interactive_data_to_write(ssh) &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} નહીંતર જો (active && channel_did_enqueue &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} નહીંતર જો (active) {
		જો (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} નહીંતર જો (timespeccmp(&now, &next_interval, >=) &&
		    !ssh_packet_have_data_to_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			જો (send_chaff(ssh))
				nchaff++;
		}
	}

	જો (stop_reason != ખાલી) {
		જો (active) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			active = 0;
		}
		પાછા 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	જો (!active && ssh_packet_interactive_data_to_write(ssh) &&
	    channel_did_enqueue && ssh_packet_have_data_to_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = active = 1;
		nchaff = 0;
		set_next_interval(&now, &next_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	જો (!active)
		પાછા 1;

	જો (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_to_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_uniform(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &next_interval);

	જો (just_started)
		પાછા 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	જો (timespeccmp(&now, &next_interval, <))
		/* ...unless there's x11 communication happening */
		પાછા x11_channel_used_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - next_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - next_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	set_next_interval(&now, &next_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	પાછા 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
સ્થિર શૂન્ય
client_wait_until_can_do_something(સંરચના ssh *ssh, સંરચના pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, પૂર્ણાંક channel_did_enqueue,
    sigset_t *sigsetp, પૂર્ણાંક *conn_in_readyp, પૂર્ણાંક *conn_out_readyp)
{
	સંરચના timespec timeout;
	પૂર્ણાંક ret, oready;
	u_int p;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	જો (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	જો (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_data_to_write(ssh)) {
		/* clear events since we did not call poll() */
		માટે (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		પાછા;
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
	જો (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	જો (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	જો (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	જો (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		માટે (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		જો (errno == EINTR)
			પાછા;
		/* Note: we might still have data in the buffers. */
		quit_message("poll: %s", strerror(errno));
		પાછા;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	જો (options.server_alive_interval > 0 && !*conn_in_readyp &&
	    monotime() >= server_alive_time) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

સ્થિર શૂન્ય
client_suspend_self(સંરચના sshbuf *bin, સંરચના sshbuf *bout, સંરચના sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	જો (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	જો (sshbuf_len(berr) > 0)
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

સ્થિર શૂન્ય
client_process_net_આગત(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	schedule_server_alive_check();
	જો ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		પાછા; /* success */
	જો (r == SSH_ERR_SYSTEM_ERROR) {
		જો (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			પાછા;
		જો (errno == EPIPE) {
			quit_message("Connection to %s closed by remote host.",
			    host);
			પાછા;
		}
	}
	quit_message("Read from remote host %s: %s", host, ssh_err(r));
}

સ્થિર શૂન્ય
client_status_confirm(સંરચના ssh *ssh, પૂર્ણાંક type, Channel *c, શૂન્ય *ctx)
{
	સંરચના channel_reply_ctx *cr = (સંરચના channel_reply_ctx *)ctx;
	અક્ષર errmsg[256];
	પૂર્ણાંક r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	જો (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	જો (type == SSH2_સંદેશ_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} નહીંતર જો (type == SSH2_સંદેશ_CHANNEL_FAILURE) {
		જો (tochan) {
			snprintf(errmsg, કદ(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} નહીંતર {
			snprintf(errmsg, કદ(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		જો (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		જો (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			જો ((r = sshbuf_put(c->extended, errmsg,
			    strlen(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} નહીંતર
			error("%s", errmsg);
		જો (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			જો (c->self == session_ident)
				leave_raw_mode(0);
			નહીંતર
				mux_tty_alloc_failed(ssh, c);
		} નહીંતર જો (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	મુક્ત(cr);
}

સ્થિર શૂન્ય
client_abandon_status_confirm(સંરચના ssh *ssh, Channel *c, શૂન્ય *ctx)
{
	મુક્ત(ctx);
}

શૂન્ય
client_expect_confirm(સંરચના ssh *ssh, પૂર્ણાંક id, અચલ અક્ષર *request,
    ગણના confirm_action action)
{
	સંરચના channel_reply_ctx *cr = xcalloc(1, કદ(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_register_status_confirm(ssh, id, client_status_confirm,
	    client_abandon_status_confirm, cr);
}

શૂન્ય
client_register_global_confirm(global_confirm_cb *cb, શૂન્ય *ctx)
{
	સંરચના global_confirm *gc, *last_gc;

	/* Coalesce identical callbacks */
	last_gc = TAILQ_LAST(&global_confirms, global_confirms);
	જો (last_gc && last_gc->cb == cb && last_gc->ctx == ctx) {
		જો (++last_gc->ref_ગણતરી >= INT_MAX)
			fatal_f("last_gc->ref_count = %d",
			    last_gc->ref_ગણતરી);
		પાછા;
	}

	gc = xcalloc(1, કદ(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_ગણતરી = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, entry);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
સ્થિર પૂર્ણાંક
can_update_hostkeys(શૂન્ય)
{
	જો (hostkeys_update_complete)
		પાછા 0;
	જો (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_mode)
		પાછા 0; /* won't ask in batchmode, so don't even try */
	જો (!options.update_hostkeys || options.અંક_user_hostfiles <= 0)
		પાછા 0;
	પાછા 1;
}

સ્થિર શૂન્ય
client_repledge(શૂન્ય)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	જો (options.control_master || options.control_path != ખાલી ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != ખાલી || can_update_hostkeys() ||
	    (session_ident != -1 && !session_setup_complete)) {
		/* Can't tighten */
		પાછા;
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
	જો (options.અંક_local_forwards != 0 ||
	    options.અંક_remote_forwards != 0 ||
	    options.અંક_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		જો (pledge("stdio unix inet dns proc tty", ખાલી) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} નહીંતર જો (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		જો (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", ખાલી) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} નહીંતર {
		debug("pledge: fork");
		જો (pledge(PLEDGE_EXTRA_INET "stdio proc tty", ખાલી) == -1)
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

સ્થિર શૂન્ય
process_cmdline(સંરચના ssh *ssh)
{
	શૂન્ય (*handler)(પૂર્ણાંક);
	અક્ષર *s, *cmd;
	પૂર્ણાંક ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	સંરચના Forward fwd;

	memset(&fwd, 0, કદ(fwd));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	જો (s == ખાલી)
		જાઓ out;
	જ્યારે (isspace((u_char)*s))
		s++;
	જો (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	જો (*s == '\0')
		જાઓ out;

	જો (*s == 'h' || *s == 'H' || *s == '?') {
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
		જો (!options.permit_local_command)
			જાઓ out;
		logit("      !args                                  "
		    "Execute local command");
		જાઓ out;
	}

	જો (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		જાઓ out;
	}

	જો (*s == 'K') {
		delete = 1;
		s++;
	}
	જો (*s == 'L')
		local = 1;
	નહીંતર જો (*s == 'R')
		remote = 1;
	નહીંતર જો (*s == 'D')
		dynamic = 1;
	નહીંતર {
		logit("Invalid command.");
		જાઓ out;
	}

	જ્યારે (isspace((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	જો (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		જો (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			જાઓ out;
		}
		જો (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		નહીંતર જો (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		નહીંતર
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_PORT_STATIC,
			    &options.fwd_opts) > 0;
		જો (!ok) {
			logit("Unknown port forwarding.");
			જાઓ out;
		}
		logit("Canceled forwarding.");
	} નહીંતર {
		/* -R specs can be both dynamic or not, so check both. */
		જો (remote) {
			જો (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				જાઓ out;
			}
		} નહીંતર જો (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			જાઓ out;
		}
		જો (local || dynamic) {
			જો (!channel_setup_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				જાઓ out;
			}
		} નહીંતર {
			જો (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				જાઓ out;
			}
		}
		logit("Forwarding port.");
	}

out:
	ssh_signal(SIGINT, handler);
	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	મુક્ત(cmd);
	મુક્ત(fwd.listen_host);
	મુક્ત(fwd.listen_path);
	મુક્ત(fwd.connect_host);
	મુક્ત(fwd.connect_path);
}

/* reasons to suppress output of an escape command in help output */
#define SUPPRESS_NEVER		0	/* never suppress, always show */
#define SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#define SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#define SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#define SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
સંરચના escape_help_text {
	અચલ અક્ષર *cmd;
	અચલ અક્ષર *text;
	unsigned પૂર્ણાંક flags;
};
સ્થિર સંરચના escape_help_text esc_txt[] = {
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

સ્થિર શૂન્ય
print_escape_help(સંરચના sshbuf *b, પૂર્ણાંક escape_char, પૂર્ણાંક mux_client,
    પૂર્ણાંક using_stderr)
{
	unsigned પૂર્ણાંક i, suppress_flags;
	પૂર્ણાંક r;

	જો ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	માટે (i = 0; i < કદ(esc_txt)/કદ(esc_txt[0]); i++) {
		જો (esc_txt[i].flags & suppress_flags)
			ચાલુ;
		જો ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	જો ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
સ્થિર પૂર્ણાંક
process_escapes(સંરચના ssh *ssh, Channel *c,
    સંરચના sshbuf *bin, સંરચના sshbuf *bout, સંરચના sshbuf *berr,
    અક્ષર *buf, પૂર્ણાંક len)
{
	pid_t pid;
	પૂર્ણાંક r, bytes = 0;
	u_int i;
	u_char ch;
	અક્ષર *s;
	સંરચના escape_filter_ctx *efc;

	જો (c == ખાલી || c->filter_ctx == ખાલી || len <= 0)
		પાછા 0;

	efc = (સંરચના escape_filter_ctx *)c->filter_ctx;

	માટે (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		જો (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			પસંદગી (ch) {
			સ્થિતિ '.':
				/* Terminate the connection. */
				જો ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				જો (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					પાછા 0;
				} નહીંતર
					quit_pending = 1;
				પાછા -1;

			સ્થિતિ 'Z' - 64:
				/* XXX support this for mux clients */
				જો (c && c->ctl_chan != -1) {
					અક્ષર b[16];
 noescape:
					જો (ch == 'Z' - 64)
						snprintf(b, કદ b, "^Z");
					નહીંતર
						snprintf(b, કદ b, "%c", ch);
					જો ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					ચાલુ;
				}
				/* Suspend the program. Inform the user */
				જો ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				ચાલુ;

			સ્થિતિ 'B':
				જો ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				જો ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				ચાલુ;

			સ્થિતિ 'I':
				જો ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_message(ssh);
				જો ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				મુક્ત(s);
				ચાલુ;

			સ્થિતિ 'R':
				જો (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				નહીંતર
					need_rekeying = 1;
				ચાલુ;

			સ્થિતિ 'V':
				/* FALLTHROUGH */
			સ્થિતિ 'v':
				જો (c && c->ctl_chan != -1)
					જાઓ noescape;
				જો (!log_is_on_stderr()) {
					જો ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					ચાલુ;
				}
				જો (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				જો (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				જો ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				ચાલુ;

			સ્થિતિ '&':
				જો (c->ctl_chan != -1)
					જાઓ noescape;
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

				જો ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				જો (pid == -1) {
					error("fork: %.100s", strerror(errno));
					ચાલુ;
				}
				જો (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					exit(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				જો ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				પાછા -1;
			સ્થિતિ '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				ચાલુ;

			સ્થિતિ '#':
				જો ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_message(ssh);
				જો ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				મુક્ત(s);
				ચાલુ;

			સ્થિતિ 'C':
				જો (c && c->ctl_chan != -1)
					જાઓ noescape;
				જો (options.enable_escape_commandline == 0) {
					જો ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					ચાલુ;
				}
				process_cmdline(ssh);
				ચાલુ;

			મૂળભૂત:
				જો (ch != efc->escape_char) {
					જો ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					bytes++;
				}
				/* Escaped characters fall through here */
				તોડો;
			}
		} નહીંતર {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			જો (last_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				ચાલુ;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		last_was_cr = (ch == '\r' || ch == '\n');
		જો ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		bytes++;
	}
	પાછા bytes;
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

સ્થિર શૂન્ય
client_process_buffered_આગત_packets(સંરચના ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
શૂન્ય *
client_new_escape_filter_ctx(પૂર્ણાંક escape_char)
{
	સંરચના escape_filter_ctx *ret;

	ret = xcalloc(1, કદ(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	પાછા (શૂન્ય *)ret;
}

/* Free the escape filter context on channel free */
શૂન્ય
client_filter_cleanup(સંરચના ssh *ssh, પૂર્ણાંક cid, શૂન્ય *ctx)
{
	મુક્ત(ctx);
}

પૂર્ણાંક
client_simple_escape_filter(સંરચના ssh *ssh, Channel *c, અક્ષર *buf, પૂર્ણાંક len)
{
	જો (c->extended_usage != CHAN_EXTENDED_WRITE)
		પાછા 0;

	પાછા process_escapes(ssh, c, c->આગત, c->output, c->extended,
	    buf, len);
}

સ્થિર શૂન્ય
client_channel_closed(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક force, શૂન્ય *arg)
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
પૂર્ણાંક
client_loop(સંરચના ssh *ssh, પૂર્ણાંક have_pty, પૂર્ણાંક escape_char_arg,
    પૂર્ણાંક ssh2_chan_id)
{
	સંરચના pollfd *pfd = ખાલી;
	u_int npfd_alloc = 0, npfd_active = 0;
	દ્વિગુણ start_time, total_time;
	પૂર્ણાંક interactive = -1, channel_did_enqueue = 0, r;
	uint64_t ibytes, obytes;
	પૂર્ણાંક conn_in_ready, conn_out_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	જો (options.pkcs11_provider != ખાલી)
		debug("pledge: disabled (PKCS11Provider active)");
	નહીંતર જો (options.control_master &&
	    !option_clear_or_none(options.control_path)) {
		debug("pledge: id");
		જો (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    ખાલી) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} નહીંતર જો (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		જો (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    ખાલી) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} નહીંતર જો (options.update_hostkeys) {
		debug("pledge: filesystem");
		જો (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    ખાલી) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} નહીંતર જો (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		જો (pledge("stdio cpath unix inet dns proc tty", ખાલી) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} નહીંતર {
		debug("pledge: network");
		જો (pledge("stdio unix inet dns proc tty", ખાલી) == -1)
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
	જો (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	જો (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	જો (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	જો (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, window_change_handler);
#ifdef SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#endif

	જો (have_pty)
		enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	જો (session_ident != -1) {
		જો (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, ખાલી,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_register_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	schedule_server_alive_check();

	જો (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ifdef SIGINFO
	જો (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#endif

	/* Main loop of the client for the interactive session mode. */
	જ્યારે (!quit_pending) {
		channel_did_enqueue = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_આગત_packets(ssh);

		જો (session_closed && !channel_still_open(ssh))
			તોડો;

		જો (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} નહીંતર જો (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			જો ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} નહીંતર {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			જો (ssh_packet_not_very_much_data_to_write(ssh))
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
		જો (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		જો (siginfo_received) {
			અક્ષર ident[256];

			sshpkt_fmt_connection_id(ssh, ident, કદ(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - start_time);
			siginfo_received = 0;
		}
		જો (quit_pending)
			તોડો;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_active, channel_did_enqueue, &osigset,
		    &conn_in_ready, &conn_out_ready);
		જો (sigprocmask(SIG_SETMASK, &osigset, ખાલી) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		જો (quit_pending)
			તોડો;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_active);

		/* Buffer input from the connection.  */
		જો (conn_in_ready)
			client_process_net_આગત(ssh);

		જો (quit_pending)
			તોડો;

		/* A timeout may have triggered rekeying */
		જો ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		જો (conn_out_ready) {
			જો (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_set_interactive(ssh, interactive);
			}
			જો ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		જો (control_persist_exit_time > 0) {
			જો (monotime() >= control_persist_exit_time) {
				debug("ControlPersist timeout expired");
				તોડો;
			}
		}
	}
	મુક્ત(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	જો (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_message("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	જો (have_pty)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	જો (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_status = 0;
	}

	જો (received_signal) {
		verbose("Killed by signal %d.", (પૂર્ણાંક) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	total_time = monotime_double() - start_time;
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (unsigned long long)obytes, (unsigned long long)ibytes, total_time);
	જો (total_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / total_time, ibytes / total_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	પાછા exit_status;
}

/*********/

સ્થિર Channel *
client_request_forwarded_tcpip(સંરચના ssh *ssh, અચલ અક્ષર *request_type,
    પૂર્ણાંક rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = ખાલી;
	સંરચના sshbuf *b = ખાલી;
	અક્ષર *listen_address, *originator_address;
	u_int listen_port, originator_port;
	પૂર્ણાંક r;

	/* Get rest of the packet */
	જો ((r = sshpkt_get_cstring(ssh, &listen_address, ખાલી)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_address, ખાલી)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_address, listen_port, originator_address, originator_port);

	જો (listen_port > 0xffff)
		error_f("invalid listen port");
	નહીંતર જો (originator_port > 0xffff)
		error_f("invalid originator port");
	નહીંતર {
		c = channel_connect_by_listen_address(ssh,
		    listen_address, listen_port, "forwarded-tcpip",
		    originator_address);
	}

	જો (c != ખાલી && c->type == SSH_CHANNEL_MUX_CLIENT) {
		જો ((b = sshbuf_new()) == ખાલી) {
			error_f("alloc reply");
			જાઓ out;
		}
		/* reconstruct and send to muxclient */
		જો ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_સંદેશ_CHANNEL_OPEN)) != 0 ||
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
			જાઓ out;
		}
	}

 out:
	sshbuf_free(b);
	મુક્ત(originator_address);
	મુક્ત(listen_address);
	પાછા c;
}

સ્થિર Channel *
client_request_forwarded_streamlocal(સંરચના ssh *ssh,
    અચલ અક્ષર *request_type, પૂર્ણાંક rchan)
{
	Channel *c = ખાલી;
	અક્ષર *listen_path;
	પૂર્ણાંક r;

	/* Get the remote path. */
	જો ((r = sshpkt_get_cstring(ssh, &listen_path, ખાલી)) != 0 ||
	    (r = sshpkt_get_string(ssh, ખાલી, ખાલી)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_path);

	c = channel_connect_by_listen_path(ssh, listen_path,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	મુક્ત(listen_path);
	પાછા c;
}

સ્થિર Channel *
client_request_x11(સંરચના ssh *ssh, અચલ અક્ષર *request_type, પૂર્ણાંક rchan)
{
	Channel *c = ખાલી;
	અક્ષર *originator;
	u_int originator_port;
	પૂર્ણાંક r, sock;

	જો (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		પાછા ખાલી;
	}
	જો (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		પાછા ખાલી;
	}
	જો ((r = sshpkt_get_cstring(ssh, &originator, ખાલી)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_port);
	મુક્ત(originator);
	sock = x11_connect_display(ssh);
	જો (sock < 0)
		પાછા ખાલી;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	પાછા c;
}

સ્થિર Channel *
client_request_agent(સંરચના ssh *ssh, અચલ અક્ષર *request_type, પૂર્ણાંક rchan)
{
	Channel *c = ખાલી;
	પૂર્ણાંક r, sock;

	જો (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		પાછા ખાલી;
	}
	જો (forward_agent_sock_path == ખાલી) {
		r = ssh_get_authentication_socket(&sock);
	} નહીંતર {
		r = ssh_get_authentication_socket_path(forward_agent_sock_path, &sock);
	}
	જો (r != 0) {
		જો (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		પાછા ખાલી;
	}
	જો ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	નહીંતર
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	પાછા c;
}

અક્ષર *
client_request_tun_fwd(સંરચના ssh *ssh, પૂર્ણાંક tun_mode,
    પૂર્ણાંક local_tun, પૂર્ણાંક remote_tun, channel_open_fn *cb, શૂન્ય *cbctx)
{
	Channel *c;
	પૂર્ણાંક r, fd;
	અક્ષર *ifname = ખાલી;

	જો (tun_mode == SSH_TUNMODE_NO)
		પાછા ખાલી;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	જો ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		પાછા ખાલી;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#જો defined(SSH_TUN_FILTER)
	જો (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ખાલી, ખાલી);
#endif

	જો (cb != ખાલી)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	પાછા ifname;
}

/* XXXX move to generic input handler */
સ્થિર પૂર્ણાંક
client_આગત_channel_open(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Channel *c = ખાલી;
	અક્ષર *ctype = ખાલી;
	પૂર્ણાંક r;
	u_int rchan;
	size_t len;
	u_int rmaxpack, rwindow;

	જો ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		જાઓ out;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	જો (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} નહીંતર જો (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} નહીંતર જો (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} નહીંતર જો (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	જો (c != ખાલી && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} નહીંતર જો (c != ખાલી) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		જો (c->type != SSH_CHANNEL_CONNECTING) {
			જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} નહીંતર {
		debug("failure %s", ctype);
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	મુક્ત(ctype);
	પાછા r;
}

સ્થિર પૂર્ણાંક
client_આગત_channel_req(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Channel *c = ખાલી;
	અક્ષર *rtype = ખાલી;
	u_char reply;
	u_int id, exitval;
	પૂર્ણાંક r, success = 0;

	જો ((r = sshpkt_get_u32(ssh, &id)) != 0)
		પાછા r;
	જો (id <= INT_MAX)
		c = channel_lookup(ssh, id);
	જો (channel_proxy_upstream(c, type, seq, ssh))
		પાછા 0;
	જો ((r = sshpkt_get_cstring(ssh, &rtype, ખાલી)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &reply)) != 0)
		જાઓ out;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, reply);

	જો (c == ખાલી) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} નહીંતર જો (strcmp(rtype, "eow@openssh.com") == 0) {
		જો ((r = sshpkt_get_end(ssh)) != 0)
			જાઓ out;
		chan_rcvd_eow(ssh, c);
	} નહીંતર જો (strcmp(rtype, "exit-status") == 0) {
		જો ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			જાઓ out;
		જો (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} નહીંતર જો ((પૂર્ણાંક)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} નહીંતર {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		જો ((r = sshpkt_get_end(ssh)) != 0)
			જાઓ out;
	}
	જો (reply && c != ખાલી && !(c->flags & CHAN_CLOSE_SENT)) {
		જો (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		જો ((r = sshpkt_start(ssh, success ?
		    SSH2_સંદેશ_CHANNEL_SUCCESS : SSH2_સંદેશ_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	મુક્ત(rtype);
	પાછા r;
}

સંરચના hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	અક્ષર *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	સંરચના sshkey **ચાવીઓ;
	u_int *ચાવીઓ_match;	/* mask of HKF_MATCH_* from hostfile.h */
	પૂર્ણાંક *ચાવીઓ_verified;	/* flag for new keys verified by server */
	size_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	સંરચના sshkey **old_ચાવીઓ;
	size_t nold;

	/* Various special cases. */
	પૂર્ણાંક complex_hostspec;	/* wildcard or manual pattern-list host name */
	પૂર્ણાંક ca_available;	/* saw CA key for this host */
	પૂર્ણાંક old_ચાવી_seen;	/* saw old key with other name/addr */
	પૂર્ણાંક other_name_seen;	/* saw key with other name/addr */
};

સ્થિર શૂન્ય
hostkeys_update_ctx_free(સંરચના hostkeys_update_ctx *ctx)
{
	size_t i;

	જો (ctx == ખાલી)
		પાછા;
	માટે (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->ચાવીઓ[i]);
	મુક્ત(ctx->ચાવીઓ);
	મુક્ત(ctx->ચાવીઓ_match);
	મુક્ત(ctx->ચાવીઓ_verified);
	માટે (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_ચાવીઓ[i]);
	મુક્ત(ctx->old_ચાવીઓ);
	મુક્ત(ctx->host_str);
	મુક્ત(ctx->ip_str);
	મુક્ત(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
સ્થિર પૂર્ણાંક
hostspec_is_complex(અચલ અક્ષર *hosts)
{
	અક્ષર *cp;

	/* wildcard */
	જો (strchr(hosts, '*') != ખાલી || strchr(hosts, '?') != ખાલી)
		પાછા 1;
	/* single host/ip = ok */
	જો ((cp = strchr(hosts, ',')) == ખાલી)
		પાછા 0;
	/* more than two entries on the line */
	જો (strchr(cp + 1, ',') != ખાલી)
		પાછા 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	પાછા 0;
}

/* callback to search for ctx->keys in known_hosts */
સ્થિર પૂર્ણાંક
hostkeys_find(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *_ctx)
{
	સંરચના hostkeys_update_ctx *ctx = (સંરચના hostkeys_update_ctx *)_ctx;
	size_t i;
	સંરચના sshkey **tmp;

	જો (l->ચાવી == ખાલી)
		પાછા 0;
	જો (l->status != HKF_STATUS_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		માટે (i = 0; i < ctx->nkeys; i++) {
			જો (sshkey_equal(l->ચાવી, ctx->ચાવીઓ[i])) {
				ctx->other_name_seen = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->ચાવીઓ[i]),
				    l->path, l->linenum);
				પાછા 0;
			}
		}
		પાછા 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	જો (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		પાછા 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	જો (ctx->ip_str != ખાલી && strchr(l->hosts, ',') != ખાલી) {
		જો ((l->match & HKF_MATCH_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_seen = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->path, l->linenum);
			પાછા 0;
		} નહીંતર જો ((l->match & HKF_MATCH_IP) == 0) {
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
	જો (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		પાછા 0;
	}

	/* Mark off keys we've already seen for this host */
	માટે (i = 0; i < ctx->nkeys; i++) {
		જો (!sshkey_equal(l->ચાવી, ctx->ચાવીઓ[i]))
			ચાલુ;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->ચાવીઓ[i]), l->path, l->linenum);
		ctx->ચાવીઓ_match[i] |= l->match;
		પાછા 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->ચાવી),
	    l->path, l->linenum);
	જો ((tmp = recallocarray(ctx->old_ચાવીઓ, ctx->nold, ctx->nold + 1,
	    કદ(*ctx->old_ચાવીઓ))) == ખાલી)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_ચાવીઓ = tmp;
	ctx->old_ચાવીઓ[ctx->nold++] = l->ચાવી;
	l->ચાવી = ખાલી;

	પાછા 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
સ્થિર પૂર્ણાંક
hostkeys_check_old(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *_ctx)
{
	સંરચના hostkeys_update_ctx *ctx = (સંરચના hostkeys_update_ctx *)_ctx;
	size_t i;
	પૂર્ણાંક hashed;

	/* only care about lines that *don't* match the active host spec */
	જો (l->status == HKF_STATUS_MATCHED || l->ચાવી == ખાલી)
		પાછા 0;

	hashed = l->match & (HKF_MATCH_HOST_HASHED|HKF_MATCH_IP_HASHED);
	માટે (i = 0; i < ctx->nold; i++) {
		જો (!sshkey_equal(l->ચાવી, ctx->old_ચાવીઓ[i]))
			ચાલુ;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_ચાવીઓ[i]), l->path, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_ચાવી_seen = 1;
		તોડો;
	}
	પાછા 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
સ્થિર પૂર્ણાંક
check_old_ચાવીઓ_othernames(સંરચના hostkeys_update_ctx *ctx)
{
	size_t i;
	પૂર્ણાંક r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	માટે (i = 0; i < options.અંક_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		જો ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_ચાવી, 0)) != 0) {
			જો (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				ચાલુ;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			પાછા -1;
		}
	}
	પાછા 0;
}

સ્થિર શૂન્ય
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

સ્થિર શૂન્ય
update_known_hosts(સંરચના hostkeys_update_ctx *ctx)
{
	પૂર્ણાંક r, was_raw = 0, first = 1;
	પૂર્ણાંક asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	અક્ષર *fp, *response;
	size_t i;
	સંરચના stat sb;

	માટે (i = 0; i < ctx->nkeys; i++) {
		જો (!ctx->ચાવીઓ_verified[i])
			ચાલુ;
		જો ((fp = sshkey_fingerprint(ctx->ચાવીઓ[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("sshkey_fingerprint failed");
		જો (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->ચાવીઓ[i]), fp);
		first = 0;
		મુક્ત(fp);
	}
	માટે (i = 0; i < ctx->nold; i++) {
		જો ((fp = sshkey_fingerprint(ctx->old_ચાવીઓ[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("sshkey_fingerprint failed");
		જો (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_ચાવીઓ[i]), fp);
		first = 0;
		મુક્ત(fp);
	}
	જો (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		જો (get_saved_tio() != ખાલી) {
			leave_raw_mode(1);
			was_raw = 1;
		}
		response = ખાલી;
		માટે (i = 0; !quit_pending && i < 3; i++) {
			મુક્ત(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			જો (response != ખાલી && strcasecmp(response, "yes") == 0)
				તોડો;
			નહીંતર જો (quit_pending || response == ખાલી ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				તોડો;
			} નહીંતર {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		જો (quit_pending || i >= 3 || response == ખાલી)
			options.update_hostkeys = 0;
		મુક્ત(response);
		જો (was_raw)
			enter_raw_mode(1);
	}
	જો (options.update_hostkeys == 0)
		પાછા;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	માટે (i = 0; i < options.અંક_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		જો (stat(options.user_hostfiles[i], &sb) != 0) {
			જો (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} નહીંતર {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			ચાલુ;
		}
		જો ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->ચાવીઓ : ખાલી, i == 0 ? ctx->nkeys : 0,
		    options.hash_known_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

સ્થિર શૂન્ય
client_global_hostkeys_prove_confirm(સંરચના ssh *ssh, પૂર્ણાંક type,
    uint32_t seq, શૂન્ય *_ctx)
{
	સંરચના hostkeys_update_ctx *ctx = (સંરચના hostkeys_update_ctx *)_ctx;
	size_t i, ndone;
	સંરચના sshbuf *signdata;
	પૂર્ણાંક r, plaintype;
	અચલ u_char *sig;
	અચલ અક્ષર *rsa_kexalg = ખાલી;
	અક્ષર *alg = ખાલી;
	size_t siglen;

	જો (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	જો (type != SSH2_સંદેશ_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		પાછા;
	}
	જો (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == ચાવી_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	જો ((signdata = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	માટે (ndone = i = 0; i < ctx->nkeys; i++) {
		જો (ctx->ચાવીઓ_match[i])
			ચાલુ;
		plaintype = sshkey_type_plain(ctx->ચાવીઓ[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		જો ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->ચાવીઓ[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		જો ((r = sshpkt_get_string_direct(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			જાઓ out;
		}
		જો ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->ચાવીઓ[i]), i);
			જાઓ out;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		જો (plaintype == ચાવી_RSA && rsa_kexalg == ખાલી &&
		    match_pattern_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			મુક્ત(alg);
			/* zap the key from the list */
			sshkey_free(ctx->ચાવીઓ[i]);
			ctx->ચાવીઓ[i] = ખાલી;
			ndone++;
			ચાલુ;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->ચાવીઓ[i]), i, alg);
		મુક્ત(alg);
		જો ((r = sshkey_verify(ctx->ચાવીઓ[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == ચાવી_RSA ? rsa_kexalg : ખાલી, 0, ખાલી)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->ચાવીઓ[i]), i);
			જાઓ out;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->ચાવીઓ_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	જો (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	જો ((r = sshpkt_get_end(ssh)) != 0) {
		error_f("protocol error");
		જાઓ out;
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
સ્થિર પૂર્ણાંક
client_આગત_hostkeys(સંરચના ssh *ssh)
{
	અચલ u_char *blob = ખાલી;
	size_t i, len = 0;
	સંરચના sshbuf *buf = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી, **tmp;
	પૂર્ણાંક r, prove_sent = 0;
	અક્ષર *fp;
	સ્થિર પૂર્ણાંક hostkeys_seen = 0; /* XXX use struct ssh */
	બાહ્ય સંરચના sockaddr_storage hostaddr; /* XXX from ssh.c */
	સંરચના hostkeys_update_ctx *ctx = ખાલી;
	u_int want;

	જો (hostkeys_seen)
		fatal_f("server already sent hostkeys");
	જો (!can_update_hostkeys())
		પાછા 1;
	hostkeys_seen = 1;

	ctx = xcalloc(1, કદ(*ctx));
	જ્યારે (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(ચાવી);
		ચાવી = ખાલી;
		જો ((r = sshpkt_get_string_direct(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			જાઓ out;
		}
		જો ((r = sshkey_from_blob(blob, len, &ચાવી)) != 0) {
			do_log2_fr(r, r == SSH_ERR_ચાવી_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			ચાલુ;
		}
		fp = sshkey_fingerprint(ચાવી, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(ચાવી), fp);
		મુક્ત(fp);

		જો (!hostkey_accepted_by_hostkeyalgs(ચાવી)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(ચાવી));
			ચાલુ;
		}
		/* Skip certs */
		જો (sshkey_is_cert(ચાવી)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(ચાવી));
			ચાલુ;
		}
		/* Ensure keys are unique */
		માટે (i = 0; i < ctx->nkeys; i++) {
			જો (sshkey_equal(ચાવી, ctx->ચાવીઓ[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(ચાવી));
				જાઓ out;
			}
		}
		/* Key is good, record it */
		જો ((tmp = recallocarray(ctx->ચાવીઓ, ctx->nkeys, ctx->nkeys + 1,
		    કદ(*ctx->ચાવીઓ))) == ખાલી)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->ચાવીઓ = tmp;
		ctx->ચાવીઓ[ctx->nkeys++] = ચાવી;
		ચાવી = ખાલી;
	}

	જો (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		જાઓ out;
	}

	જો ((ctx->ચાવીઓ_match = calloc(ctx->nkeys,
	    કદ(*ctx->ચાવીઓ_match))) == ખાલી ||
	    (ctx->ચાવીઓ_verified = calloc(ctx->nkeys,
	    કદ(*ctx->ચાવીઓ_verified))) == ખાલી)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (સંરચના sockaddr *)&hostaddr : ખાલી,
	    options.port, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : ખાલી);

	/* Find which keys we already know about. */
	માટે (i = 0; i < options.અંક_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		જો ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_ચાવી, 0)) != 0) {
			જો (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				ચાલુ;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			જાઓ out;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_MATCH_HOST | ( options.check_host_ip ? HKF_MATCH_IP : 0);
	માટે (i = 0; i < ctx->nkeys; i++) {
		જો (ctx->ચાવીઓ_match[i] == 0)
			ctx->nnew++;
		જો ((ctx->ચાવીઓ_match[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	જો (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		જાઓ out;
	}

	/* Various reasons why we cannot proceed with the update */
	જો (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		જાઓ out;
	}
	જો (ctx->other_name_seen) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		જાઓ out;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	જો (ctx->nold != 0) {
		જો (check_old_ચાવીઓ_othernames(ctx) != 0)
			જાઓ out; /* error already logged */
		જો (ctx->old_ચાવી_seen) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == ખાલી ? "" : ",",
			    ctx->ip_str == ખાલી ? "" : ctx->ip_str);
			જાઓ out;
		}
	}

	જો (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_known_hosts(ctx);
		જાઓ out;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	જો ((buf = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	માટે (i = 0; i < ctx->nkeys; i++) {
		જો (ctx->ચાવીઓ_match[i])
			ચાલુ;
		sshbuf_reset(buf);
		જો ((r = sshkey_putb(ctx->ચાવીઓ[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	જો ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_register_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = ખાલી;  /* will be freed in callback */
	prove_sent = 1;

	/* Success */
 out:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(ચાવી);
	sshbuf_free(buf);
	જો (!prove_sent) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	પાછા 1;
}

સ્થિર પૂર્ણાંક
client_આગત_global_request(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	અક્ષર *rtype;
	u_char want_reply;
	પૂર્ણાંક r, success = 0;

	જો ((r = sshpkt_get_cstring(ssh, &rtype, ખાલી)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		જાઓ out;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_reply);
	જો (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_આગત_hostkeys(ssh);
	જો (want_reply) {
		જો ((r = sshpkt_start(ssh, success ? SSH2_સંદેશ_REQUEST_SUCCESS :
		    SSH2_સંદેશ_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			જાઓ out;
	}
	r = 0;
 out:
	મુક્ત(rtype);
	પાછા r;
}

સ્થિર શૂન્ય
client_send_env(સંરચના ssh *ssh, પૂર્ણાંક id, અચલ અક્ષર *name, અચલ અક્ષર *val)
{
	પૂર્ણાંક r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	જો ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

શૂન્ય
client_session2_setup(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક want_tty, પૂર્ણાંક want_subsystem,
    અચલ અક્ષર *term, સંરચના termios *tiop, પૂર્ણાંક in_fd, સંરચના sshbuf *cmd,
    અક્ષર **env)
{
	size_t i, j, len;
	પૂર્ણાંક matched, r;
	અક્ષર *type = ખાલી, *cmdstring = ખાલી, *name, *val;
	Channel *c = ખાલી;

	debug2_f("id %d", id);

	જો ((c = channel_lookup(ssh, id)) == ખાલી)
		fatal_f("channel %d: unknown channel", id);

	જો (want_tty) {
		સંરચના winsize ws;

		/* Store window size in the packet. */
		જો (ioctl(in_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, કદ(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		જો ((r = sshpkt_put_cstring(ssh, term != ખાલી ? term : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		જો (tiop == ખાલી)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		જો ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	જો (options.અંક_send_env != 0 && env != ખાલી) {
		debug("Sending environment.");
		માટે (i = 0; env[i] != ખાલી; i++) {
			/* Split */
			name = xstrdup(env[i]);
			જો ((val = strchr(name, '=')) == ખાલી) {
				મુક્ત(name);
				ચાલુ;
			}
			*val++ = '\0';

			matched = 0;
			માટે (j = 0; j < options.અંક_send_env; j++) {
				જો (match_pattern(name, options.send_env[j])) {
					matched = 1;
					તોડો;
				}
			}
			જો (!matched) {
				debug3("Ignored env %s", name);
				મુક્ત(name);
				ચાલુ;
			}
			client_send_env(ssh, id, name, val);
			મુક્ત(name);
		}
	}
	માટે (i = 0; i < options.અંક_setenv; i++) {
		/* Split */
		name = xstrdup(options.setenv[i]);
		જો ((val = strchr(name, '=')) == ખાલી) {
			મુક્ત(name);
			ચાલુ;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		મુક્ત(name);
	}

	len = sshbuf_len(cmd);
	જો (len > 0) {
		જો ((cmdstring = sshbuf_dup_string(cmd)) == ખાલી)
			fatal_f("sshbuf_dup_string failed");
		જો (len > 900)
			len = 900;
		જો (want_subsystem) {
			debug("Sending subsystem: %.*s", (પૂર્ણાંક)len, cmdstring);
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} નહીંતર {
			debug("Sending command: %.*s", (પૂર્ણાંક)len, cmdstring);
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		જો ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} નહીંતર {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		જો ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_set_xtype(ssh, id, type);
	મુક્ત(cmdstring);
	મુક્ત(type);

	session_setup_complete = 1;
	client_repledge();
}

શૂન્ય
client_channel_request_agent_forwarding(સંરચના ssh *ssh, પૂર્ણાંક id)
{
	અચલ અક્ષર *req = "auth-agent-req@openssh.com";
	પૂર્ણાંક r;

	જો (ssh->kex != ખાલી && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_start(ssh, id, req, 0);
	જો ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

સ્થિર શૂન્ય
client_init_dispatch(સંરચના ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_CLOSE, &channel_આગત_oclose);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_DATA, &channel_આગત_data);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_EOF, &channel_આગત_ieof);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_EXTENDED_DATA, &channel_આગત_extended_data);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_OPEN, &client_આગત_channel_open);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION, &channel_આગત_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_OPEN_FAILURE, &channel_આગત_open_failure);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_REQUEST, &client_આગત_channel_req);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_WINDOW_ADJUST, &channel_આગત_window_adjust);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_SUCCESS, &channel_આગત_status_confirm);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_CHANNEL_FAILURE, &channel_આગત_status_confirm);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_GLOBAL_REQUEST, &client_આગત_global_request);

	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEXINIT, &kex_આગત_kexinit);

	/* global request reply messages */
	ssh_dispatch_set(ssh, SSH2_સંદેશ_REQUEST_FAILURE, &client_global_request_reply);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_REQUEST_SUCCESS, &client_global_request_reply);
}

શૂન્ય
client_stop_mux(શૂન્ય)
{
	જો (options.control_path != ખાલી && muxserver_sock != -1)
		unlink(options.control_path);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	જો (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
શૂન્ય
cleanup_exit(પૂર્ણાંક i)
{
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	જો (options.control_path != ખાલી && muxserver_sock != -1)
		unlink(options.control_path);
	ssh_kill_proxy_command();
	_exit(i);
}
