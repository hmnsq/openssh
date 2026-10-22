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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>
#شامل <sys/stat.h>
#شامل <sys/time.h>
#شامل <sys/queue.h>

#شامل <ctype.h>
#شامل <errno.h>
#شامل <paths.h>
#شامل <poll.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>
#شامل <limits.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "packet.h"
#شامل "sshbuf.h"
#شامل "compat.h"
#شامل "channels.h"
#شامل "dispatch.h"
#شامل "sshkey.h"
#شامل "kex.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "readconf.h"
#شامل "clientloop.h"
#شامل "sshconnect.h"
#شامل "authfd.h"
#شامل "atomicio.h"
#شامل "sshpty.h"
#شامل "match.h"
#شامل "ssherr.h"
#شامل "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#تعریف_کرو HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#تعریف_کرو SSH_KEYSTROKE_TIMING_FUZZ 10

خارجی حرف *__progname;

/* import options */
خارجی Options options;

/* Control socket */
خارجی صحیح muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
خارجی حرف *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
خارجی حرف *forward_agent_sock_راستہ;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
ساکن متلون sig_atomic_t received_کھڑکی_change_signal = 0;
ساکن متلون sig_atomic_t siginfo_received = 0;
ساکن متلون sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
ساکن time_t control_persist_exit_وقت = 0;

/* Common data for the client loop code. */
متلون sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
ساکن صحیح آخری_was_cr;		/* Last character was a newline. */
ساکن صحیح exit_حالت;		/* Used to store the command exit status. */
ساکن صحیح connection_اندر;	/* Connection to server (input). */
ساکن صحیح connection_برآمد;	/* Connection to server (output). */
ساکن صحیح need_rekeying;	/* Set to non-zero if rekeying is requested. */
ساکن صحیح session_closed;	/* In SSH2: login session closed. */
ساکن time_t x11_refuse_وقت;	/* If >0, refuse x11 opens after this time. */
ساکن time_t server_alive_وقت;	/* Time to do server_alive_check */
ساکن صحیح hostkeys_update_complete;
ساکن صحیح session_تیاری_complete;

ساکن خالی client_init_dispatch(ساخت ssh *ssh);
صحیح	session_ident = -1;

/* Track escape per proto2 channel */
ساخت escape_filter_ctx {
	صحیح escape_pending;
	صحیح escape_char;
};

/* Context for channel confirmation replies */
ساخت channel_جواب_ctx {
	ثابت حرف *request_type;
	صحیح id;
	شمار confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
ساخت global_confirm {
	TAILQ_ENTRY(global_confirm) اندراج_2;
	global_confirm_cb *cb;
	خالی *ctx;
	صحیح ref_گنتی;
};
TAILQ_HEAD(global_confirms, global_confirm);
ساکن ساخت global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

ساکن خالی quit_پیغام(ثابت حرف *fmt, ...)
    __attribute__((__format__ (لکھو, 1, 2)));

ساکن خالی
quit_پیغام(ثابت حرف *fmt, ...)
{
	حرف *پیغام, *fmt2;
	va_list دلائل;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(دلائل, fmt);
	xvasprintf(&پیغام, fmt2, دلائل);
	va_end(دلائل);

	(خالی)atomicio(vwrite, STDERR_FILENO, پیغام, لڑی_لمبائی(پیغام));
	آزاد(پیغام);
	آزاد(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
ساکن خالی
کھڑکی_change_handler(صحیح sig)
{
	received_کھڑکی_change_signal = 1;
}

#اگر_تعریف_شدہ SIGINFO
/* Signal handler for SIGINFO */
ساکن خالی
siginfo_handler(صحیح sig)
{
	siginfo_received = 1;
}
#اگر_ختم

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
ساکن خالی
signal_handler(صحیح sig)
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
ساکن خالی
سیٹ_control_persist_exit_وقت(ساخت ssh *ssh)
{
	اگر (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_وقت = 0;
	} ورنہ اگر (channel_still_open(ssh)) {
		/* some client connections are still open */
		اگر (control_persist_exit_وقت > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_وقت = 0;
	} ورنہ اگر (control_persist_exit_وقت <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_وقت = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#تعریف_کرو SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
ساکن صحیح
client_x11_display_valid(ثابت حرف *display)
{
	سائز_t i, dlen;

	اگر (display == تہی)
		واپس 0;

	dlen = لڑی_لمبائی(display);
	برائے (i = 0; i < dlen; i++) {
		اگر (!حرف_یا_ہندسہ((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == تہی) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			واپس 0;
		}
	}
	واپس 1;
}

#تعریف_کرو SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#تعریف_کرو X11_TIMEOUT_SLACK	60
صحیح
client_x11_get_proto(ساخت ssh *ssh, ثابت حرف *display,
    ثابت حرف *xauth_راستہ, u_int trusted, u_int timeout,
    حرف **_proto, حرف **ڈیٹا_2)
{
	حرف *cmd, سطر[512], xdisplay[512];
	حرف xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	ساکن حرف proto[512], ڈیٹا[512];
	FILE *f;
	صحیح got_ڈیٹا = 0, generated = 0, do_unlink = 0, r;
	ساخت stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*ڈیٹا_2 = ڈیٹا;
	proto[0] = ڈیٹا[0] = xauthfile[0] = xauthdir[0] = '\0';

	اگر (!client_x11_display_valid(display)) {
		اگر (display != تہی)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		واپس -1;
	}
	اگر (xauth_راستہ != تہی && stat(xauth_راستہ, &st) == -1) {
		debug("No xauth program.");
		xauth_راستہ = تہی;
	}

	اگر (xauth_راستہ != تہی) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		اگر (لڑی_موازنہ(display, "localhost:", 10) == 0) {
			اگر ((r = snprintf(xdisplay, حجم(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (سائز_t)r >= حجم(xdisplay)) {
				error_f("display name too long");
				واپس -1;
			}
			display = xdisplay;
		}
		اگر (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, حجم(xauthdir));
			اگر (mkdtemp(xauthdir) == تہی) {
				error_f("mkdtemp: %s", strerror(errno));
				واپس -1;
			}
			do_unlink = 1;
			اگر ((r = snprintf(xauthfile, حجم(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (سائز_t)r >= حجم(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				واپس -1;
			}

			اگر (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_راستہ, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} ورنہ {
				/* Add some slack to requested expiry */
				اگر (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				ورنہ {
					/* Don't overflow on long timeouts */
					x11_timeout_real = UINT_MAX;
				}
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted timeout %u 2>%s",
				    xauth_راستہ, xauthfile, display,
				    SSH_X11_PROTO, x11_timeout_real,
				    _PATH_DEVNULL);
			}
			debug2_f("xauth command: %s", cmd);

			اگر (timeout != 0 && x11_refuse_وقت == 0) {
				now = monotime() + 1;
				اگر (SSH_وقت_T_MAX - timeout < now)
					x11_refuse_وقت = SSH_وقت_T_MAX;
				ورنہ
					x11_refuse_وقت = now + timeout;
				channel_سیٹ_x11_refuse_وقت(ssh,
				    x11_refuse_وقت);
			}
			اگر (system(cmd) == 0)
				generated = 1;
			آزاد(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		اگر (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_راستہ,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			اگر (f && fgets(سطر, حجم(سطر), f) &&
			    لڑی_سے_پڑھو(سطر, "%*s %511s %511s", proto, ڈیٹا) == 2)
				got_ڈیٹا = 1;
			اگر (f)
				pclose(f);
			آزاد(cmd);
		}
	}

	اگر (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	اگر (!trusted && !got_ڈیٹا) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		واپس -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	اگر (!got_ڈیٹا) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, حجم proto);
		arc4random_buf(rnd, حجم(rnd));
		برائے (i = 0; i < حجم(rnd); i++) {
			snprintf(ڈیٹا + 2 * i, حجم ڈیٹا - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	واپس 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

ساکن خالی
client_check_کھڑکی_change(ساخت ssh *ssh)
{
	اگر (!received_کھڑکی_change_signal)
		واپس;
	received_کھڑکی_change_signal = 0;
	debug2_f("changed");
	channel_send_کھڑکی_changes(ssh);
}

ساکن صحیح
client_global_request_جواب(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	ساخت global_confirm *gc;

	اگر ((gc = TAILQ_FIRST(&global_confirms)) == تہی)
		واپس 0;
	اگر (gc->cb != تہی)
		gc->cb(ssh, type, seq, gc->ctx);
	اگر (--gc->ref_گنتی <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, اندراج_2);
		freezero(gc, حجم(*gc));
	}

	ssh_packet_سیٹ_alive_timeouts(ssh, 0);
	واپس 0;
}

ساکن خالی
جدول_وقت_server_alive_check(خالی)
{
	اگر (options.server_alive_interval > 0)
		server_alive_وقت = monotime() + options.server_alive_interval;
}

ساکن خالی
server_alive_check(ساخت ssh *ssh)
{
	صحیح r;

	اگر (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_گنتی_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_رجسٹر_global_confirm(تہی, تہی);
	جدول_وقت_server_alive_check();
}

/* Try to send a dummy keystroke */
ساکن صحیح
send_chaff(ساخت ssh *ssh)
{
	صحیح r;

	اگر (ssh->kex == تہی || (ssh->kex->flags & KEX_HAS_PING) == 0)
		واپس 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	واپس 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
ساکن خالی
سیٹ_اگلا_interval(ثابت ساخت timespec *now, ساخت timespec *اگلا_interval,
    u_int interval_ms, صحیح starting)
{
	ساخت timespec tmp;
	طویل طویل interval_ns, fuzz_ns;
	ساکن طویل طویل شرح_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	اگر (fuzz_ns > زیادہ_سے_زیادہ_عدد)
		fuzz_ns = زیادہ_سے_زیادہ_عدد;
	اگر (fuzz_ns > interval_ns) {
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
	اگر (starting)
		شرح_fuzz = arc4random_یکساں(fuzz_ns);
	interval_ns -= fuzz_ns;
	interval_ns += arc4random_یکساں(fuzz_ns) + شرح_fuzz;

	tmp.tv_sec = interval_ns / (1000 * 1000 * 1000);
	tmp.tv_nsec = interval_ns % (1000 * 1000 * 1000);

	timespecadd(now, &tmp, اگلا_interval);
}

/*
 * Performs keystroke timing obfuscation. Returns non-zero if the
 * output fd should be polled.
 */
ساکن صحیح
obfuscate_keystroke_timing(ساخت ssh *ssh, ساخت timespec *timeout,
    صحیح channel_did_قطار_میں_ڈالو)
{
	ساکن صحیح فعال;
	ساکن ساخت timespec اگلا_interval, chaff_until;
	ساخت timespec now, tmp;
	صحیح just_started = 0, had_keystroke = 0;
	ساکن غیرعلامتی طویل طویل nchaff;
	حرف *stop_reason = تہی;
	طویل طویل n;

	monotime_ts(&now);

	اگر (options.obscure_keystroke_timing_interval <= 0)
		واپس 1;	/* disabled in config */

	اگر (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} ورنہ اگر (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} ورنہ اگر (!ssh_packet_interactive_ڈیٹا_مقصد_write(ssh) &&
	    ssh_packet_have_ڈیٹا_مقصد_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} ورنہ اگر (فعال && channel_did_قطار_میں_ڈالو &&
	    ssh_packet_have_ڈیٹا_مقصد_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} ورنہ اگر (فعال) {
		اگر (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} ورنہ اگر (timespeccmp(&now, &اگلا_interval, >=) &&
		    !ssh_packet_have_ڈیٹا_مقصد_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			اگر (send_chaff(ssh))
				nchaff++;
		}
	}

	اگر (stop_reason != تہی) {
		اگر (فعال) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			فعال = 0;
		}
		واپس 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	اگر (!فعال && ssh_packet_interactive_ڈیٹا_مقصد_write(ssh) &&
	    channel_did_قطار_میں_ڈالو && ssh_packet_have_ڈیٹا_مقصد_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = فعال = 1;
		nchaff = 0;
		سیٹ_اگلا_interval(&now, &اگلا_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	اگر (!فعال)
		واپس 1;

	اگر (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_مقصد_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_یکساں(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &اگلا_interval);

	اگر (just_started)
		واپس 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	اگر (timespeccmp(&now, &اگلا_interval, <))
		/* ...unless there's x11 communication happening */
		واپس x11_channel_مستعمل_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - اگلا_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - اگلا_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	سیٹ_اگلا_interval(&now, &اگلا_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	واپس 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
ساکن خالی
client_wait_until_can_do_something(ساخت ssh *ssh, ساخت pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, صحیح channel_did_قطار_میں_ڈالو,
    sigset_t *sigsetp, صحیح *conn_اندر_readyp, صحیح *conn_برآمد_readyp)
{
	ساخت timespec timeout;
	صحیح ret, oready;
	u_int p;

	*conn_اندر_readyp = *conn_برآمد_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	اگر (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	اگر (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_ڈیٹا_مقصد_write(ssh)) {
		/* clear events since we did not call poll() */
		برائے (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		واپس;
	}

	oready = obfuscate_keystroke_timing(ssh, &timeout, channel_did_قطار_میں_ڈالو);

	/* Monitor server connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_اندر;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_برآمد;
	(*pfdp)[1].events = (oready && ssh_packet_have_ڈیٹا_مقصد_write(ssh)) ?
	    POLLOUT : 0;

	/*
	 * Wait for something to happen.  This will suspend the process until
	 * some polled descriptor can be read, written, or has some other
	 * event pending, or a timeout expires.
	 */
	سیٹ_control_persist_exit_وقت(ssh);
	اگر (control_persist_exit_وقت > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_وقت);
	اگر (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_وقت);
	اگر (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	اگر (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		برائے (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		اگر (errno == EINTR)
			واپس;
		/* Note: we might still have data in the buffers. */
		quit_پیغام("poll: %s", strerror(errno));
		واپس;
	}

	*conn_اندر_readyp = (*pfdp)[0].revents != 0;
	*conn_برآمد_readyp = (*pfdp)[1].revents != 0;

	اگر (options.server_alive_interval > 0 && !*conn_اندر_readyp &&
	    monotime() >= server_alive_وقت) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

ساکن خالی
client_suspend_self(ساخت sshbuf *bin, ساخت sshbuf *bout, ساخت sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	اگر (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	اگر (sshbuf_len(berr) > 0)
		atomicio(vwrite, fileno(stderr), sshbuf_mutable_ptr(berr),
		    sshbuf_len(berr));

	leave_raw_منوال(options.request_tty == REQUEST_TTY_FORCE);

	sshbuf_reset(bin);
	sshbuf_reset(bout);
	sshbuf_reset(berr);

	/* Send the suspend signal to the program itself. */
	kill(getpid(), SIGTSTP);

	/* Reset window sizes in case they have changed */
	received_کھڑکی_change_signal = 1;

	enter_raw_منوال(options.request_tty == REQUEST_TTY_FORCE);
}

ساکن خالی
client_process_net_داخلہ(ساخت ssh *ssh)
{
	صحیح r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	جدول_وقت_server_alive_check();
	اگر ((r = ssh_packet_process_read(ssh, connection_اندر)) == 0)
		واپس; /* success */
	اگر (r == SSH_ERR_SYSTEM_ERROR) {
		اگر (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			واپس;
		اگر (errno == EPIPE) {
			quit_پیغام("Connection to %s closed by remote host.",
			    host);
			واپس;
		}
	}
	quit_پیغام("Read from remote host %s: %s", host, ssh_err(r));
}

ساکن خالی
client_حالت_confirm(ساخت ssh *ssh, صحیح type, Channel *c, خالی *ctx)
{
	ساخت channel_جواب_ctx *cr = (ساخت channel_جواب_ctx *)ctx;
	حرف errmsg[256];
	صحیح r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	اگر (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	اگر (type == SSH2_پیغام_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} ورنہ اگر (type == SSH2_پیغام_CHANNEL_FAILURE) {
		اگر (tochan) {
			snprintf(errmsg, حجم(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} ورنہ {
			snprintf(errmsg, حجم(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		اگر (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		اگر (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			اگر ((r = sshbuf_put(c->extended, errmsg,
			    لڑی_لمبائی(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} ورنہ
			error("%s", errmsg);
		اگر (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			اگر (c->self == session_ident)
				leave_raw_منوال(0);
			ورنہ
				mux_tty_alloc_failed(ssh, c);
		} ورنہ اگر (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	آزاد(cr);
}

ساکن خالی
client_abandon_حالت_confirm(ساخت ssh *ssh, Channel *c, خالی *ctx)
{
	آزاد(ctx);
}

خالی
client_expect_confirm(ساخت ssh *ssh, صحیح id, ثابت حرف *request,
    شمار confirm_action action)
{
	ساخت channel_جواب_ctx *cr = xcalloc(1, حجم(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_رجسٹر_حالت_confirm(ssh, id, client_حالت_confirm,
	    client_abandon_حالت_confirm, cr);
}

خالی
client_رجسٹر_global_confirm(global_confirm_cb *cb, خالی *ctx)
{
	ساخت global_confirm *gc, *آخری_gc;

	/* Coalesce identical callbacks */
	آخری_gc = TAILQ_LAST(&global_confirms, global_confirms);
	اگر (آخری_gc && آخری_gc->cb == cb && آخری_gc->ctx == ctx) {
		اگر (++آخری_gc->ref_گنتی >= زیادہ_سے_زیادہ_عدد)
			fatal_f("last_gc->ref_count = %d",
			    آخری_gc->ref_گنتی);
		واپس;
	}

	gc = xcalloc(1, حجم(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_گنتی = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, اندراج_2);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
ساکن صحیح
can_update_hostkeys(خالی)
{
	اگر (hostkeys_update_complete)
		واپس 0;
	اگر (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_منوال)
		واپس 0; /* won't ask in batchmode, so don't even try */
	اگر (!options.update_hostkeys || options.عدد_user_hostfiles <= 0)
		واپس 0;
	واپس 1;
}

ساکن خالی
client_repledge(خالی)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	اگر (options.control_master || options.control_راستہ != تہی ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != تہی || can_update_hostkeys() ||
	    (session_ident != -1 && !session_تیاری_complete)) {
		/* Can't tighten */
		واپس;
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
	اگر (options.عدد_local_forwards != 0 ||
	    options.عدد_remote_forwards != 0 ||
	    options.عدد_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		اگر (pledge("stdio unix inet dns proc tty", تہی) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} ورنہ اگر (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		اگر (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", تہی) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} ورنہ {
		debug("pledge: fork");
		اگر (pledge(PLEDGE_EXTRA_INET "stdio proc tty", تہی) == -1)
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

ساکن خالی
process_cmdline(ساخت ssh *ssh)
{
	خالی (*handler)(صحیح);
	حرف *s, *cmd;
	صحیح ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	ساخت Forward fwd;

	memset(&fwd, 0, حجم(fwd));

	leave_raw_منوال(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	اگر (s == تہی)
		جاؤ برآمد;
	جب (خلا_ہے((u_char)*s))
		s++;
	اگر (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	اگر (*s == '\0')
		جاؤ برآمد;

	اگر (*s == 'h' || *s == 'H' || *s == '?') {
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
		اگر (!options.permit_local_command)
			جاؤ برآمد;
		logit("      !args                                  "
		    "Execute local command");
		جاؤ برآمد;
	}

	اگر (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		جاؤ برآمد;
	}

	اگر (*s == 'K') {
		delete = 1;
		s++;
	}
	اگر (*s == 'L')
		local = 1;
	ورنہ اگر (*s == 'R')
		remote = 1;
	ورنہ اگر (*s == 'D')
		dynamic = 1;
	ورنہ {
		logit("Invalid command.");
		جاؤ برآمد;
	}

	جب (خلا_ہے((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	اگر (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		اگر (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			جاؤ برآمد;
		}
		اگر (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		ورنہ اگر (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		ورنہ
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_پورٹ_STATIC,
			    &options.fwd_opts) > 0;
		اگر (!ok) {
			logit("Unknown port forwarding.");
			جاؤ برآمد;
		}
		logit("Canceled forwarding.");
	} ورنہ {
		/* -R specs can be both dynamic or not, so check both. */
		اگر (remote) {
			اگر (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				جاؤ برآمد;
			}
		} ورنہ اگر (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			جاؤ برآمد;
		}
		اگر (local || dynamic) {
			اگر (!channel_تیاری_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				جاؤ برآمد;
			}
		} ورنہ {
			اگر (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				جاؤ برآمد;
			}
		}
		logit("Forwarding port.");
	}

برآمد:
	ssh_signal(SIGINT, handler);
	enter_raw_منوال(options.request_tty == REQUEST_TTY_FORCE);
	آزاد(cmd);
	آزاد(fwd.listen_host);
	آزاد(fwd.listen_راستہ);
	آزاد(fwd.connect_host);
	آزاد(fwd.connect_راستہ);
}

/* reasons to suppress output of an escape command in help output */
#تعریف_کرو SUPPRESS_NEVER		0	/* never suppress, always show */
#تعریف_کرو SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#تعریف_کرو SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#تعریف_کرو SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#تعریف_کرو SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
ساخت escape_help_متن {
	ثابت حرف *cmd;
	ثابت حرف *متن;
	غیرعلامتی صحیح flags;
};
ساکن ساخت escape_help_متن esc_txt[] = {
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

ساکن خالی
print_escape_help(ساخت sshbuf *b, صحیح escape_char, صحیح mux_client,
    صحیح using_stderr)
{
	غیرعلامتی صحیح i, suppress_flags;
	صحیح r;

	اگر ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	برائے (i = 0; i < حجم(esc_txt)/حجم(esc_txt[0]); i++) {
		اگر (esc_txt[i].flags & suppress_flags)
			جاری;
		اگر ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].متن)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	اگر ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
ساکن صحیح
process_escapes(ساخت ssh *ssh, Channel *c,
    ساخت sshbuf *bin, ساخت sshbuf *bout, ساخت sshbuf *berr,
    حرف *buf, صحیح len)
{
	pid_t pid;
	صحیح r, بائٹیں = 0;
	u_int i;
	u_char ch;
	حرف *s;
	ساخت escape_filter_ctx *efc;

	اگر (c == تہی || c->filter_ctx == تہی || len <= 0)
		واپس 0;

	efc = (ساخت escape_filter_ctx *)c->filter_ctx;

	برائے (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		اگر (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			انتخاب (ch) {
			حالت '.':
				/* Terminate the connection. */
				اگر ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				اگر (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					واپس 0;
				} ورنہ
					quit_pending = 1;
				واپس -1;

			حالت 'Z' - 64:
				/* XXX support this for mux clients */
				اگر (c && c->ctl_chan != -1) {
					حرف b[16];
 noescape:
					اگر (ch == 'Z' - 64)
						snprintf(b, حجم b, "^Z");
					ورنہ
						snprintf(b, حجم b, "%c", ch);
					اگر ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					جاری;
				}
				/* Suspend the program. Inform the user */
				اگر ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				جاری;

			حالت 'B':
				اگر ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_آغاز(ssh, c->self, "break", 0);
				اگر ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				جاری;

			حالت 'I':
				اگر ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_پیغام(ssh);
				اگر ((r = sshbuf_put(berr, s, لڑی_لمبائی(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				آزاد(s);
				جاری;

			حالت 'R':
				اگر (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				ورنہ
					need_rekeying = 1;
				جاری;

			حالت 'V':
				/* FALLTHROUGH */
			حالت 'v':
				اگر (c && c->ctl_chan != -1)
					جاؤ noescape;
				اگر (!log_is_on_stderr()) {
					اگر ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					جاری;
				}
				اگر (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				اگر (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				اگر ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				جاری;

			حالت '&':
				اگر (c->ctl_chan != -1)
					جاؤ noescape;
				/*
				 * Detach the program (continue to serve
				 * connections, but put in background and no
				 * more new connections).
				 */
				/* Restore tty modes. */
				leave_raw_منوال(
				    options.request_tty == REQUEST_TTY_FORCE);

				/* Stop listening for new connections. */
				channel_stop_listening(ssh);

				اگر ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				اگر (pid == -1) {
					error("fork: %.100s", strerror(errno));
					جاری;
				}
				اگر (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					باہر_نکلو(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				اگر ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				واپس -1;
			حالت '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				جاری;

			حالت '#':
				اگر ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_پیغام(ssh);
				اگر ((r = sshbuf_put(berr, s, لڑی_لمبائی(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				آزاد(s);
				جاری;

			حالت 'C':
				اگر (c && c->ctl_chan != -1)
					جاؤ noescape;
				اگر (options.enable_escape_commandline == 0) {
					اگر ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					جاری;
				}
				process_cmdline(ssh);
				جاری;

			طےشدہ:
				اگر (ch != efc->escape_char) {
					اگر ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					بائٹیں++;
				}
				/* Escaped characters fall through here */
				توڑو;
			}
		} ورنہ {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			اگر (آخری_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				جاری;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		آخری_was_cr = (ch == '\r' || ch == '\n');
		اگر ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		بائٹیں++;
	}
	واپس بائٹیں;
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

ساکن خالی
client_process_buffered_داخلہ_packets(ساخت ssh *ssh)
{
	ssh_dispatch_تسلسل_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
خالی *
client_new_escape_filter_ctx(صحیح escape_char)
{
	ساخت escape_filter_ctx *ret;

	ret = xcalloc(1, حجم(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	واپس (خالی *)ret;
}

/* Free the escape filter context on channel free */
خالی
client_filter_cleanup(ساخت ssh *ssh, صحیح cid, خالی *ctx)
{
	آزاد(ctx);
}

صحیح
client_simple_escape_filter(ساخت ssh *ssh, Channel *c, حرف *buf, صحیح len)
{
	اگر (c->extended_usage != CHAN_EXTENDED_WRITE)
		واپس 0;

	واپس process_escapes(ssh, c, c->داخلہ, c->output, c->extended,
	    buf, len);
}

ساکن خالی
client_channel_closed(ساخت ssh *ssh, صحیح id, صحیح force, خالی *arg)
{
	channel_cancel_cleanup(ssh, id);
	session_closed = 1;
	leave_raw_منوال(options.request_tty == REQUEST_TTY_FORCE);
}

/*
 * Implements the interactive session with the server.  This is called after
 * the user has been authenticated, and a command has been started on the
 * remote host.  If escape_char != SSH_ESCAPECHAR_NONE, it is the character
 * used as an escape character for terminating or suspending the session.
 */
صحیح
client_loop(ساخت ssh *ssh, صحیح have_pty, صحیح escape_char_arg,
    صحیح ssh2_chan_id)
{
	ساخت pollfd *pfd = تہی;
	u_int npfd_alloc = 0, npfd_فعال = 0;
	دوہرا آغاز_وقت, کل_وقت;
	صحیح interactive = -1, channel_did_قطار_میں_ڈالو = 0, r;
	uint64_t ibytes, obytes;
	صحیح conn_اندر_ready, conn_برآمد_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	اگر (options.pkcs11_provider != تہی)
		debug("pledge: disabled (PKCS11Provider active)");
	ورنہ اگر (options.control_master &&
	    !option_clear_or_none(options.control_راستہ)) {
		debug("pledge: id");
		اگر (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    تہی) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ورنہ اگر (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		اگر (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    تہی) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ورنہ اگر (options.update_hostkeys) {
		debug("pledge: filesystem");
		اگر (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    تہی) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ورنہ اگر (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		اگر (pledge("stdio cpath unix inet dns proc tty", تہی) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} ورنہ {
		debug("pledge: network");
		اگر (pledge("stdio unix inet dns proc tty", تہی) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	}

	/* might be able to tighten now */
	client_repledge();

	آغاز_وقت = monotime_double();

	/* Initialize variables. */
	آخری_was_cr = 1;
	exit_حالت = -1;
	connection_اندر = ssh_packet_get_connection_اندر(ssh);
	connection_برآمد = ssh_packet_get_connection_برآمد(ssh);

	quit_pending = 0;

	client_init_dispatch(ssh);

	/*
	 * Set signal handlers, (e.g. to restore non-blocking mode)
	 * but don't overwrite SIG_IGN, matches behaviour from rsh(1)
	 */
	اگر (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	اگر (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	اگر (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	اگر (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, کھڑکی_change_handler);
#اگر_تعریف_شدہ SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#اگر_ختم

	اگر (have_pty)
		enter_raw_منوال(options.request_tty == REQUEST_TTY_FORCE);

	اگر (session_ident != -1) {
		اگر (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_رجسٹر_filter(ssh, session_ident,
			    client_simple_escape_filter, تہی,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_رجسٹر_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	جدول_وقت_server_alive_check();

	اگر (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#اگر_تعریف_شدہ SIGINFO
	اگر (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#اگر_ختم

	/* Main loop of the client for the interactive session mode. */
	جب (!quit_pending) {
		channel_did_قطار_میں_ڈالو = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_داخلہ_packets(ssh);

		اگر (session_closed && !channel_still_open(ssh))
			توڑو;

		اگر (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} ورنہ اگر (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			اگر ((r = kex_آغاز_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} ورنہ {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			اگر (ssh_packet_not_very_much_ڈیٹا_مقصد_write(ssh))
				channel_did_قطار_میں_ڈالو = channel_output_poll(ssh);

			/*
			 * Check if the window size has changed, and buffer a
			 * message about it to the server if so.
			 */
			client_check_کھڑکی_change(ssh);
		}
		/*
		 * Wait until we have something to do (something becomes
		 * available on one of the descriptors).
		 */
		اگر (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		اگر (siginfo_received) {
			حرف ident[256];

			sshpkt_fmt_connection_id(ssh, ident, حجم(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - آغاز_وقت);
			siginfo_received = 0;
		}
		اگر (quit_pending)
			توڑو;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_فعال, channel_did_قطار_میں_ڈالو, &osigset,
		    &conn_اندر_ready, &conn_برآمد_ready);
		اگر (sigprocmask(SIG_SETMASK, &osigset, تہی) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		اگر (quit_pending)
			توڑو;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_فعال);

		/* Buffer input from the connection.  */
		اگر (conn_اندر_ready)
			client_process_net_داخلہ(ssh);

		اگر (quit_pending)
			توڑو;

		/* A timeout may have triggered rekeying */
		اگر ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		اگر (conn_برآمد_ready) {
			اگر (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_سیٹ_interactive(ssh, interactive);
			}
			اگر ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		اگر (control_persist_exit_وقت > 0) {
			اگر (monotime() >= control_persist_exit_وقت) {
				debug("ControlPersist timeout expired");
				توڑو;
			}
		}
	}
	آزاد(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	اگر (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_پیغام("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	اگر (have_pty)
		leave_raw_منوال(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	اگر (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_حالت = 0;
	}

	اگر (received_signal) {
		verbose("Killed by signal %d.", (صحیح) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	کل_وقت = monotime_double() - آغاز_وقت;
	ssh_packet_get_بائٹیں(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (غیرعلامتی طویل طویل)obytes, (غیرعلامتی طویل طویل)ibytes, کل_وقت);
	اگر (کل_وقت > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / کل_وقت, ibytes / کل_وقت);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_حالت);
	واپس exit_حالت;
}

/*********/

ساکن Channel *
client_request_forwarded_tcpip(ساخت ssh *ssh, ثابت حرف *request_type,
    صحیح rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = تہی;
	ساخت sshbuf *b = تہی;
	حرف *listen_پتہ, *originator_پتہ;
	u_int listen_پورٹ, originator_پورٹ;
	صحیح r;

	/* Get rest of the packet */
	اگر ((r = sshpkt_get_cstring(ssh, &listen_پتہ, تہی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_پورٹ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_پتہ, تہی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_پورٹ)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_پتہ, listen_پورٹ, originator_پتہ, originator_پورٹ);

	اگر (listen_پورٹ > 0xffff)
		error_f("invalid listen port");
	ورنہ اگر (originator_پورٹ > 0xffff)
		error_f("invalid originator port");
	ورنہ {
		c = channel_connect_by_listen_پتہ(ssh,
		    listen_پتہ, listen_پورٹ, "forwarded-tcpip",
		    originator_پتہ);
	}

	اگر (c != تہی && c->type == SSH_CHANNEL_MUX_CLIENT) {
		اگر ((b = sshbuf_new()) == تہی) {
			error_f("alloc reply");
			جاؤ برآمد;
		}
		/* reconstruct and send to muxclient */
		اگر ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_پیغام_CHANNEL_OPEN)) != 0 ||
		    (r = sshbuf_put_cstring(b, request_type)) != 0 ||
		    (r = sshbuf_put_u32(b, rchan)) != 0 ||
		    (r = sshbuf_put_u32(b, rwindow)) != 0 ||
		    (r = sshbuf_put_u32(b, rmaxpack)) != 0 ||
		    (r = sshbuf_put_cstring(b, listen_پتہ)) != 0 ||
		    (r = sshbuf_put_u32(b, listen_پورٹ)) != 0 ||
		    (r = sshbuf_put_cstring(b, originator_پتہ)) != 0 ||
		    (r = sshbuf_put_u32(b, originator_پورٹ)) != 0 ||
		    (r = sshbuf_put_stringb(c->output, b)) != 0) {
			error_fr(r, "compose for muxclient");
			جاؤ برآمد;
		}
	}

 برآمد:
	sshbuf_free(b);
	آزاد(originator_پتہ);
	آزاد(listen_پتہ);
	واپس c;
}

ساکن Channel *
client_request_forwarded_streamlocal(ساخت ssh *ssh,
    ثابت حرف *request_type, صحیح rchan)
{
	Channel *c = تہی;
	حرف *listen_راستہ;
	صحیح r;

	/* Get the remote path. */
	اگر ((r = sshpkt_get_cstring(ssh, &listen_راستہ, تہی)) != 0 ||
	    (r = sshpkt_get_string(ssh, تہی, تہی)) != 0 ||	/* reserved */
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_راستہ);

	c = channel_connect_by_listen_راستہ(ssh, listen_راستہ,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	آزاد(listen_راستہ);
	واپس c;
}

ساکن Channel *
client_request_x11(ساخت ssh *ssh, ثابت حرف *request_type, صحیح rchan)
{
	Channel *c = تہی;
	حرف *originator;
	u_int originator_پورٹ;
	صحیح r, sock;

	اگر (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		واپس تہی;
	}
	اگر (x11_refuse_وقت != 0 && monotime() >= x11_refuse_وقت) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		واپس تہی;
	}
	اگر ((r = sshpkt_get_cstring(ssh, &originator, تہی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_پورٹ)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_پورٹ);
	آزاد(originator);
	sock = x11_connect_display(ssh);
	اگر (sock < 0)
		واپس تہی;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_کھڑکی_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	واپس c;
}

ساکن Channel *
client_request_agent(ساخت ssh *ssh, ثابت حرف *request_type, صحیح rchan)
{
	Channel *c = تہی;
	صحیح r, sock;

	اگر (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		واپس تہی;
	}
	اگر (forward_agent_sock_راستہ == تہی) {
		r = ssh_get_authentication_socket(&sock);
	} ورنہ {
		r = ssh_get_authentication_socket_راستہ(forward_agent_sock_راستہ, &sock);
	}
	اگر (r != 0) {
		اگر (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		واپس تہی;
	}
	اگر ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	ورنہ
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	واپس c;
}

حرف *
client_request_tun_fwd(ساخت ssh *ssh, صحیح tun_منوال,
    صحیح local_tun, صحیح remote_tun, channel_open_fn *cb, خالی *cbctx)
{
	Channel *c;
	صحیح r, fd;
	حرف *ifname = تہی;

	اگر (tun_منوال == SSH_TUNMODE_NO)
		واپس تہی;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_منوال);

	/* Open local tunnel device */
	اگر ((fd = tun_open(local_tun, tun_منوال, &ifname)) == -1) {
		error("Tunnel device open failed.");
		واپس تہی;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#اگر defined(SSH_TUN_FILTER)
	اگر (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_رجسٹر_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, تہی, تہی);
#اگر_ختم

	اگر (cb != تہی)
		channel_رجسٹر_open_confirm(ssh, c->self, cb, cbctx);

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_کھڑکی_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_منوال)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	واپس ifname;
}

/* XXXX move to generic input handler */
ساکن صحیح
client_داخلہ_channel_open(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Channel *c = تہی;
	حرف *ctype = تہی;
	صحیح r;
	u_int rchan;
	سائز_t len;
	u_int rmaxpack, rwindow;

	اگر ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		جاؤ برآمد;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	اگر (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} ورنہ اگر (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} ورنہ اگر (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} ورنہ اگر (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	اگر (c != تہی && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} ورنہ اگر (c != تہی) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_کھڑکی = rwindow;
		c->remote_maxpacket = rmaxpack;
		اگر (c->type != SSH_CHANNEL_CONNECTING) {
			اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_کھڑکی)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} ورنہ {
		debug("failure %s", ctype);
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 برآمد:
	آزاد(ctype);
	واپس r;
}

ساکن صحیح
client_داخلہ_channel_req(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Channel *c = تہی;
	حرف *rtype = تہی;
	u_char جواب;
	u_int id, exitval;
	صحیح r, success = 0;

	اگر ((r = sshpkt_get_u32(ssh, &id)) != 0)
		واپس r;
	اگر (id <= زیادہ_سے_زیادہ_عدد)
		c = channel_lookup(ssh, id);
	اگر (channel_proxy_upstream(c, type, seq, ssh))
		واپس 0;
	اگر ((r = sshpkt_get_cstring(ssh, &rtype, تہی)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &جواب)) != 0)
		جاؤ برآمد;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, جواب);

	اگر (c == تہی) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} ورنہ اگر (strcmp(rtype, "eow@openssh.com") == 0) {
		اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
			جاؤ برآمد;
		chan_rcvd_eow(ssh, c);
	} ورنہ اگر (strcmp(rtype, "exit-status") == 0) {
		اگر ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			جاؤ برآمد;
		اگر (c->ctl_chan != -1) {
			mux_exit_پیغام(ssh, c, exitval);
			success = 1;
		} ورنہ اگر ((صحیح)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_حالت = exitval;
		} ورنہ {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
			جاؤ برآمد;
	}
	اگر (جواب && c != تہی && !(c->flags & CHAN_CLOSE_بھیجا)) {
		اگر (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		اگر ((r = sshpkt_آغاز(ssh, success ?
		    SSH2_پیغام_CHANNEL_SUCCESS : SSH2_پیغام_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 برآمد:
	آزاد(rtype);
	واپس r;
}

ساخت hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	حرف *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	ساخت sshkey **کلیدیں;
	u_int *کلیدیں_مطابقت;	/* mask of HKF_MATCH_* from hostfile.h */
	صحیح *کلیدیں_verified;	/* flag for new keys verified by server */
	سائز_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	ساخت sshkey **old_کلیدیں;
	سائز_t nold;

	/* Various special cases. */
	صحیح complex_hostspec;	/* wildcard or manual pattern-list host name */
	صحیح ca_دستیاب;	/* saw CA key for this host */
	صحیح old_کلید_نظر_آیا;	/* saw old key with other name/addr */
	صحیح other_name_نظر_آیا;	/* saw key with other name/addr */
};

ساکن خالی
hostkeys_update_ctx_free(ساخت hostkeys_update_ctx *ctx)
{
	سائز_t i;

	اگر (ctx == تہی)
		واپس;
	برائے (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->کلیدیں[i]);
	آزاد(ctx->کلیدیں);
	آزاد(ctx->کلیدیں_مطابقت);
	آزاد(ctx->کلیدیں_verified);
	برائے (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_کلیدیں[i]);
	آزاد(ctx->old_کلیدیں);
	آزاد(ctx->host_str);
	آزاد(ctx->ip_str);
	آزاد(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
ساکن صحیح
hostspec_is_complex(ثابت حرف *hosts)
{
	حرف *cp;

	/* wildcard */
	اگر (strchr(hosts, '*') != تہی || strchr(hosts, '?') != تہی)
		واپس 1;
	/* single host/ip = ok */
	اگر ((cp = strchr(hosts, ',')) == تہی)
		واپس 0;
	/* more than two entries on the line */
	اگر (strchr(cp + 1, ',') != تہی)
		واپس 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	واپس 0;
}

/* callback to search for ctx->keys in known_hosts */
ساکن صحیح
hostkeys_ڈھونڈو(ساخت hostkey_foreach_سطر *l, خالی *_ctx)
{
	ساخت hostkeys_update_ctx *ctx = (ساخت hostkeys_update_ctx *)_ctx;
	سائز_t i;
	ساخت sshkey **tmp;

	اگر (l->کلید == تہی)
		واپس 0;
	اگر (l->حالت_2 != HKF_حالت_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		برائے (i = 0; i < ctx->nkeys; i++) {
			اگر (sshkey_equal(l->کلید, ctx->کلیدیں[i])) {
				ctx->other_name_نظر_آیا = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->کلیدیں[i]),
				    l->راستہ, l->linenum);
				واپس 0;
			}
		}
		واپس 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	اگر (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->راستہ, l->linenum);
		ctx->complex_hostspec = 1;
		واپس 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	اگر (ctx->ip_str != تہی && strchr(l->hosts, ',') != تہی) {
		اگر ((l->مطابقت & HKF_مطابقت_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_نظر_آیا = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->راستہ, l->linenum);
			واپس 0;
		} ورنہ اگر ((l->مطابقت & HKF_مطابقت_IP) == 0) {
			/* Record if hostname matched a different address. */
			ctx->other_name_نظر_آیا = 1;
			debug3_f("found hostname %s against different address "
			    "at %s:%ld", ctx->host_str, l->راستہ, l->linenum);
		}
	}

	/*
	 * UpdateHostkeys is skipped for wildcard host names and hostnames
	 * that contain more than two entries (ssh never writes these).
	 */
	اگر (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->راستہ, l->linenum);
		ctx->complex_hostspec = 1;
		واپس 0;
	}

	/* Mark off keys we've already seen for this host */
	برائے (i = 0; i < ctx->nkeys; i++) {
		اگر (!sshkey_equal(l->کلید, ctx->کلیدیں[i]))
			جاری;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->کلیدیں[i]), l->راستہ, l->linenum);
		ctx->کلیدیں_مطابقت[i] |= l->مطابقت;
		واپس 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->کلید),
	    l->راستہ, l->linenum);
	اگر ((tmp = recallocarray(ctx->old_کلیدیں, ctx->nold, ctx->nold + 1,
	    حجم(*ctx->old_کلیدیں))) == تہی)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_کلیدیں = tmp;
	ctx->old_کلیدیں[ctx->nold++] = l->کلید;
	l->کلید = تہی;

	واپس 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
ساکن صحیح
hostkeys_check_old(ساخت hostkey_foreach_سطر *l, خالی *_ctx)
{
	ساخت hostkeys_update_ctx *ctx = (ساخت hostkeys_update_ctx *)_ctx;
	سائز_t i;
	صحیح hashed;

	/* only care about lines that *don't* match the active host spec */
	اگر (l->حالت_2 == HKF_حالت_MATCHED || l->کلید == تہی)
		واپس 0;

	hashed = l->مطابقت & (HKF_مطابقت_HOST_HASHED|HKF_مطابقت_IP_HASHED);
	برائے (i = 0; i < ctx->nold; i++) {
		اگر (!sshkey_equal(l->کلید, ctx->old_کلیدیں[i]))
			جاری;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_کلیدیں[i]), l->راستہ, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_کلید_نظر_آیا = 1;
		توڑو;
	}
	واپس 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
ساکن صحیح
check_old_کلیدیں_othernames(ساخت hostkeys_update_ctx *ctx)
{
	سائز_t i;
	صحیح r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	برائے (i = 0; i < options.عدد_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		اگر ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_کلید, 0)) != 0) {
			اگر (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				جاری;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			واپس -1;
		}
	}
	واپس 0;
}

ساکن خالی
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

ساکن خالی
update_معلوم_hosts(ساخت hostkeys_update_ctx *ctx)
{
	صحیح r, was_raw = 0, پہلا = 1;
	صحیح asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	حرف *fp, *response;
	سائز_t i;
	ساخت stat sb;

	برائے (i = 0; i < ctx->nkeys; i++) {
		اگر (!ctx->کلیدیں_verified[i])
			جاری;
		اگر ((fp = sshkey_fingerprint(ctx->کلیدیں[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی)
			fatal_f("sshkey_fingerprint failed");
		اگر (پہلا && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->کلیدیں[i]), fp);
		پہلا = 0;
		آزاد(fp);
	}
	برائے (i = 0; i < ctx->nold; i++) {
		اگر ((fp = sshkey_fingerprint(ctx->old_کلیدیں[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی)
			fatal_f("sshkey_fingerprint failed");
		اگر (پہلا && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_کلیدیں[i]), fp);
		پہلا = 0;
		آزاد(fp);
	}
	اگر (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		اگر (get_saved_tio() != تہی) {
			leave_raw_منوال(1);
			was_raw = 1;
		}
		response = تہی;
		برائے (i = 0; !quit_pending && i < 3; i++) {
			آزاد(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			اگر (response != تہی && strcasecmp(response, "yes") == 0)
				توڑو;
			ورنہ اگر (quit_pending || response == تہی ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				توڑو;
			} ورنہ {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		اگر (quit_pending || i >= 3 || response == تہی)
			options.update_hostkeys = 0;
		آزاد(response);
		اگر (was_raw)
			enter_raw_منوال(1);
	}
	اگر (options.update_hostkeys == 0)
		واپس;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	برائے (i = 0; i < options.عدد_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		اگر (stat(options.user_hostfiles[i], &sb) != 0) {
			اگر (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} ورنہ {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			جاری;
		}
		اگر ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->کلیدیں : تہی, i == 0 ? ctx->nkeys : 0,
		    options.hash_معلوم_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

ساکن خالی
client_global_hostkeys_prove_confirm(ساخت ssh *ssh, صحیح type,
    uint32_t seq, خالی *_ctx)
{
	ساخت hostkeys_update_ctx *ctx = (ساخت hostkeys_update_ctx *)_ctx;
	سائز_t i, ndone;
	ساخت sshbuf *signdata;
	صحیح r, plaintype;
	ثابت u_char *sig;
	ثابت حرف *rsa_kexalg = تہی;
	حرف *alg = تہی;
	سائز_t siglen;

	اگر (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	اگر (type != SSH2_پیغام_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		واپس;
	}
	اگر (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == کلید_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	اگر ((signdata = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	برائے (ndone = i = 0; i < ctx->nkeys; i++) {
		اگر (ctx->کلیدیں_مطابقت[i])
			جاری;
		plaintype = sshkey_type_plain(ctx->کلیدیں[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		اگر ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->کلیدیں[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		اگر ((r = sshpkt_get_string_براہ_راست(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			جاؤ برآمد;
		}
		اگر ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->کلیدیں[i]), i);
			جاؤ برآمد;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		اگر (plaintype == کلید_RSA && rsa_kexalg == تہی &&
		    مطابقت_نمونہ_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			آزاد(alg);
			/* zap the key from the list */
			sshkey_free(ctx->کلیدیں[i]);
			ctx->کلیدیں[i] = تہی;
			ndone++;
			جاری;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->کلیدیں[i]), i, alg);
		آزاد(alg);
		اگر ((r = sshkey_verify(ctx->کلیدیں[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == کلید_RSA ? rsa_kexalg : تہی, 0, تہی)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->کلیدیں[i]), i);
			جاؤ برآمد;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->کلیدیں_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	اگر (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	اگر ((r = sshpkt_get_انتہا(ssh)) != 0) {
		error_f("protocol error");
		جاؤ برآمد;
	}

	/* Make the edits to known_hosts */
	update_معلوم_hosts(ctx);
 برآمد:
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
ساکن صحیح
client_داخلہ_hostkeys(ساخت ssh *ssh)
{
	ثابت u_char *blob = تہی;
	سائز_t i, len = 0;
	ساخت sshbuf *buf = تہی;
	ساخت sshkey *کلید = تہی, **tmp;
	صحیح r, prove_بھیجا = 0;
	حرف *fp;
	ساکن صحیح hostkeys_نظر_آیا = 0; /* XXX use struct ssh */
	خارجی ساخت sockaddr_storage hostaddr; /* XXX from ssh.c */
	ساخت hostkeys_update_ctx *ctx = تہی;
	u_int want;

	اگر (hostkeys_نظر_آیا)
		fatal_f("server already sent hostkeys");
	اگر (!can_update_hostkeys())
		واپس 1;
	hostkeys_نظر_آیا = 1;

	ctx = xcalloc(1, حجم(*ctx));
	جب (ssh_packet_بقایا(ssh) > 0) {
		sshkey_free(کلید);
		کلید = تہی;
		اگر ((r = sshpkt_get_string_براہ_راست(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			جاؤ برآمد;
		}
		اگر ((r = sshkey_from_blob(blob, len, &کلید)) != 0) {
			do_log2_fr(r, r == SSH_ERR_کلید_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			جاری;
		}
		fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(کلید), fp);
		آزاد(fp);

		اگر (!hostkey_accepted_by_hostkeyalgs(کلید)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(کلید));
			جاری;
		}
		/* Skip certs */
		اگر (sshkey_is_cert(کلید)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(کلید));
			جاری;
		}
		/* Ensure keys are unique */
		برائے (i = 0; i < ctx->nkeys; i++) {
			اگر (sshkey_equal(کلید, ctx->کلیدیں[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(کلید));
				جاؤ برآمد;
			}
		}
		/* Key is good, record it */
		اگر ((tmp = recallocarray(ctx->کلیدیں, ctx->nkeys, ctx->nkeys + 1,
		    حجم(*ctx->کلیدیں))) == تہی)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->کلیدیں = tmp;
		ctx->کلیدیں[ctx->nkeys++] = کلید;
		کلید = تہی;
	}

	اگر (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		جاؤ برآمد;
	}

	اگر ((ctx->کلیدیں_مطابقت = صفر_حافظہ_دو(ctx->nkeys,
	    حجم(*ctx->کلیدیں_مطابقت))) == تہی ||
	    (ctx->کلیدیں_verified = صفر_حافظہ_دو(ctx->nkeys,
	    حجم(*ctx->کلیدیں_verified))) == تہی)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (ساخت sockaddr *)&hostaddr : تہی,
	    options.پورٹ, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : تہی);

	/* Find which keys we already know about. */
	برائے (i = 0; i < options.عدد_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		اگر ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_ڈھونڈو, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_کلید, 0)) != 0) {
			اگر (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				جاری;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			جاؤ برآمد;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_مطابقت_HOST | ( options.check_host_ip ? HKF_مطابقت_IP : 0);
	برائے (i = 0; i < ctx->nkeys; i++) {
		اگر (ctx->کلیدیں_مطابقت[i] == 0)
			ctx->nnew++;
		اگر ((ctx->کلیدیں_مطابقت[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	اگر (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		جاؤ برآمد;
	}

	/* Various reasons why we cannot proceed with the update */
	اگر (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		جاؤ برآمد;
	}
	اگر (ctx->other_name_نظر_آیا) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		جاؤ برآمد;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	اگر (ctx->nold != 0) {
		اگر (check_old_کلیدیں_othernames(ctx) != 0)
			جاؤ برآمد; /* error already logged */
		اگر (ctx->old_کلید_نظر_آیا) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == تہی ? "" : ",",
			    ctx->ip_str == تہی ? "" : ctx->ip_str);
			جاؤ برآمد;
		}
	}

	اگر (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_معلوم_hosts(ctx);
		جاؤ برآمد;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	اگر ((buf = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	برائے (i = 0; i < ctx->nkeys; i++) {
		اگر (ctx->کلیدیں_مطابقت[i])
			جاری;
		sshbuf_reset(buf);
		اگر ((r = sshkey_putb(ctx->کلیدیں[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_رجسٹر_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = تہی;  /* will be freed in callback */
	prove_بھیجا = 1;

	/* Success */
 برآمد:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(کلید);
	sshbuf_free(buf);
	اگر (!prove_بھیجا) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	واپس 1;
}

ساکن صحیح
client_داخلہ_global_request(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	حرف *rtype;
	u_char want_جواب;
	صحیح r, success = 0;

	اگر ((r = sshpkt_get_cstring(ssh, &rtype, تہی)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_جواب)) != 0)
		جاؤ برآمد;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_جواب);
	اگر (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_داخلہ_hostkeys(ssh);
	اگر (want_جواب) {
		اگر ((r = sshpkt_آغاز(ssh, success ? SSH2_پیغام_REQUEST_SUCCESS :
		    SSH2_پیغام_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			جاؤ برآمد;
	}
	r = 0;
 برآمد:
	آزاد(rtype);
	واپس r;
}

ساکن خالی
client_send_env(ساخت ssh *ssh, صحیح id, ثابت حرف *name, ثابت حرف *val)
{
	صحیح r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_آغاز(ssh, id, "env", 0);
	اگر ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

خالی
client_session2_تیاری(ساخت ssh *ssh, صحیح id, صحیح want_tty, صحیح want_subsystem,
    ثابت حرف *رکن, ساخت termios *tiop, صحیح اندر_fd, ساخت sshbuf *cmd,
    حرف **env)
{
	سائز_t i, j, len;
	صحیح matched, r;
	حرف *type = تہی, *cmdstring = تہی, *name, *val;
	Channel *c = تہی;

	debug2_f("id %d", id);

	اگر ((c = channel_lookup(ssh, id)) == تہی)
		fatal_f("channel %d: unknown channel", id);

	اگر (want_tty) {
		ساخت winsize ws;

		/* Store window size in the packet. */
		اگر (ioctl(اندر_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, حجم(ws));

		channel_request_آغاز(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		اگر ((r = sshpkt_put_cstring(ssh, رکن != تہی ? رکن : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ستون)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_صف)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		اگر (tiop == تہی)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		اگر ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	اگر (options.عدد_send_env != 0 && env != تہی) {
		debug("Sending environment.");
		برائے (i = 0; env[i] != تہی; i++) {
			/*بانٹو*/
			name = xstrdup(env[i]);
			اگر ((val = strchr(name, '=')) == تہی) {
				آزاد(name);
				جاری;
			}
			*val++ = '\0';

			matched = 0;
			برائے (j = 0; j < options.عدد_send_env; j++) {
				اگر (مطابقت_نمونہ(name, options.send_env[j])) {
					matched = 1;
					توڑو;
				}
			}
			اگر (!matched) {
				debug3("Ignored env %s", name);
				آزاد(name);
				جاری;
			}
			client_send_env(ssh, id, name, val);
			آزاد(name);
		}
	}
	برائے (i = 0; i < options.عدد_setenv; i++) {
		/*بانٹو*/
		name = xstrdup(options.setenv[i]);
		اگر ((val = strchr(name, '=')) == تہی) {
			آزاد(name);
			جاری;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		آزاد(name);
	}

	len = sshbuf_len(cmd);
	اگر (len > 0) {
		اگر ((cmdstring = sshbuf_dup_string(cmd)) == تہی)
			fatal_f("sshbuf_dup_string failed");
		اگر (len > 900)
			len = 900;
		اگر (want_subsystem) {
			debug("Sending subsystem: %.*s", (صحیح)len, cmdstring);
			channel_request_آغاز(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} ورنہ {
			debug("Sending command: %.*s", (صحیح)len, cmdstring);
			channel_request_آغاز(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		اگر ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} ورنہ {
		channel_request_آغاز(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		اگر ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_سیٹ_xtype(ssh, id, type);
	آزاد(cmdstring);
	آزاد(type);

	session_تیاری_complete = 1;
	client_repledge();
}

خالی
client_channel_request_agent_forwarding(ساخت ssh *ssh, صحیح id)
{
	ثابت حرف *req = "auth-agent-req@openssh.com";
	صحیح r;

	اگر (ssh->kex != تہی && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_آغاز(ssh, id, req, 0);
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

ساکن خالی
client_init_dispatch(ساخت ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_CLOSE, &channel_داخلہ_oclose);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_ڈیٹا, &channel_داخلہ_ڈیٹا);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_EOF, &channel_داخلہ_ieof);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_EXTENDED_ڈیٹا, &channel_داخلہ_extended_ڈیٹا);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_OPEN, &client_داخلہ_channel_open);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION, &channel_داخلہ_open_confirmation);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_OPEN_FAILURE, &channel_داخلہ_open_failure);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_REQUEST, &client_داخلہ_channel_req);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_کھڑکی_ADJUST, &channel_داخلہ_کھڑکی_adjust);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_SUCCESS, &channel_داخلہ_حالت_confirm);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_CHANNEL_FAILURE, &channel_داخلہ_حالت_confirm);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_GLOBAL_REQUEST, &client_داخلہ_global_request);

	/* rekeying */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEXINIT, &kex_داخلہ_kexinit);

	/* global request reply messages */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_REQUEST_FAILURE, &client_global_request_جواب);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_REQUEST_SUCCESS, &client_global_request_جواب);
}

خالی
client_stop_mux(خالی)
{
	اگر (options.control_راستہ != تہی && muxserver_sock != -1)
		unlink(options.control_راستہ);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	اگر (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
خالی
cleanup_exit(صحیح i)
{
	leave_raw_منوال(options.request_tty == REQUEST_TTY_FORCE);
	اگر (options.control_راستہ != تہی && muxserver_sock != -1)
		unlink(options.control_راستہ);
	ssh_kill_proxy_command();
	_exit(i);
}
