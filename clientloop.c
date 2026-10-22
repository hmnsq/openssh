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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/ioctl.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "readconf.h"
#అన్తర్భావ "clientloop.h"
#అన్తర్భావ "sshconnect.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "sshpty.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#నిర్వచించు HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#నిర్వచించు SSH_KEYSTROKE_TIMING_FUZZ 10

బాహ్య అక్షరం *__progname;

/* import options */
బాహ్య Options options;

/* Control socket */
బాహ్య పూర్ణాంకం muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
బాహ్య అక్షరం *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
బాహ్య అక్షరం *forward_agent_sock_మార్గం;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
స్థిర అస్థిర sig_atomic_t received_కిటికీ_change_signal = 0;
స్థిర అస్థిర sig_atomic_t siginfo_received = 0;
స్థిర అస్థిర sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
స్థిర time_t control_persist_exit_సమయం = 0;

/* Common data for the client loop code. */
అస్థిర sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
స్థిర పూర్ణాంకం చివరి_was_cr;		/* Last character was a newline. */
స్థిర పూర్ణాంకం exit_స్థితి;		/* Used to store the command exit status. */
స్థిర పూర్ణాంకం connection_లోపల;	/* Connection to server (input). */
స్థిర పూర్ణాంకం connection_బహిర్గతం;	/* Connection to server (output). */
స్థిర పూర్ణాంకం need_rekeying;	/* Set to non-zero if rekeying is requested. */
స్థిర పూర్ణాంకం session_closed;	/* In SSH2: login session closed. */
స్థిర time_t x11_refuse_సమయం;	/* If >0, refuse x11 opens after this time. */
స్థిర time_t server_alive_సమయం;	/* Time to do server_alive_check */
స్థిర పూర్ణాంకం hostkeys_update_complete;
స్థిర పూర్ణాంకం session_అమరిక_complete;

స్థిర శూన్య client_init_dispatch(నిర్మాణం ssh *ssh);
పూర్ణాంకం	session_ident = -1;

/* Track escape per proto2 channel */
నిర్మాణం escape_filter_ctx {
	పూర్ణాంకం escape_pending;
	పూర్ణాంకం escape_char;
};

/* Context for channel confirmation replies */
నిర్మాణం channel_జవాబు_ctx {
	స్థిరరాశి అక్షరం *request_type;
	పూర్ణాంకం id;
	గణన confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
నిర్మాణం global_confirm {
	TAILQ_ENTRY(global_confirm) నమోదు_2;
	global_confirm_cb *cb;
	శూన్య *ctx;
	పూర్ణాంకం ref_లెక్క;
};
TAILQ_HEAD(global_confirms, global_confirm);
స్థిర నిర్మాణం global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

స్థిర శూన్య quit_సందేశం(స్థిరరాశి అక్షరం *fmt, ...)
    __attribute__((__format__ (రాయి, 1, 2)));

స్థిర శూన్య
quit_సందేశం(స్థిరరాశి అక్షరం *fmt, ...)
{
	అక్షరం *సందేశం, *fmt2;
	va_list వాదనలు;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(వాదనలు, fmt);
	xvasprintf(&సందేశం, fmt2, వాదనలు);
	va_end(వాదనలు);

	(శూన్య)atomicio(vwrite, STDERR_FILENO, సందేశం, అక్షరశ్రేణి_పొడవు(సందేశం));
	విడుదల(సందేశం);
	విడుదల(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
స్థిర శూన్య
కిటికీ_change_handler(పూర్ణాంకం sig)
{
	received_కిటికీ_change_signal = 1;
}

#నిర్వచితమైతే SIGINFO
/* Signal handler for SIGINFO */
స్థిర శూన్య
siginfo_handler(పూర్ణాంకం sig)
{
	siginfo_received = 1;
}
#అయితే_ముగింపు

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
స్థిర శూన్య
signal_handler(పూర్ణాంకం sig)
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
స్థిర శూన్య
సమితి_control_persist_exit_సమయం(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_సమయం = 0;
	} లేకపోతే ఒకవేళ (channel_still_open(ssh)) {
		/* some client connections are still open */
		ఒకవేళ (control_persist_exit_సమయం > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_సమయం = 0;
	} లేకపోతే ఒకవేళ (control_persist_exit_సమయం <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_సమయం = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#నిర్వచించు SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
స్థిర పూర్ణాంకం
client_x11_display_valid(స్థిరరాశి అక్షరం *display)
{
	కొలత_t i, dlen;

	ఒకవేళ (display == ఖాళీ)
		తిరిగి 0;

	dlen = అక్షరశ్రేణి_పొడవు(display);
	కొరకు (i = 0; i < dlen; i++) {
		ఒకవేళ (!అక్షరమా_అంకెనా((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == ఖాళీ) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			తిరిగి 0;
		}
	}
	తిరిగి 1;
}

#నిర్వచించు SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#నిర్వచించు X11_TIMEOUT_SLACK	60
పూర్ణాంకం
client_x11_get_proto(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *display,
    స్థిరరాశి అక్షరం *xauth_మార్గం, u_int trusted, u_int timeout,
    అక్షరం **_proto, అక్షరం **దత్తాంశం_2)
{
	అక్షరం *cmd, పంక్తి[512], xdisplay[512];
	అక్షరం xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	స్థిర అక్షరం proto[512], దత్తాంశం[512];
	FILE *f;
	పూర్ణాంకం got_దత్తాంశం = 0, generated = 0, do_unlink = 0, r;
	నిర్మాణం stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*దత్తాంశం_2 = దత్తాంశం;
	proto[0] = దత్తాంశం[0] = xauthfile[0] = xauthdir[0] = '\0';

	ఒకవేళ (!client_x11_display_valid(display)) {
		ఒకవేళ (display != ఖాళీ)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		తిరిగి -1;
	}
	ఒకవేళ (xauth_మార్గం != ఖాళీ && stat(xauth_మార్గం, &st) == -1) {
		debug("No xauth program.");
		xauth_మార్గం = ఖాళీ;
	}

	ఒకవేళ (xauth_మార్గం != ఖాళీ) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(display, "localhost:", 10) == 0) {
			ఒకవేళ ((r = snprintf(xdisplay, పరిమాణం(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (కొలత_t)r >= పరిమాణం(xdisplay)) {
				error_f("display name too long");
				తిరిగి -1;
			}
			display = xdisplay;
		}
		ఒకవేళ (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, పరిమాణం(xauthdir));
			ఒకవేళ (mkdtemp(xauthdir) == ఖాళీ) {
				error_f("mkdtemp: %s", strerror(errno));
				తిరిగి -1;
			}
			do_unlink = 1;
			ఒకవేళ ((r = snprintf(xauthfile, పరిమాణం(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (కొలత_t)r >= పరిమాణం(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				తిరిగి -1;
			}

			ఒకవేళ (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_మార్గం, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} లేకపోతే {
				/* Add some slack to requested expiry */
				ఒకవేళ (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				లేకపోతే {
					/* Don't overflow on long timeouts */
					x11_timeout_real = UINT_MAX;
				}
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted timeout %u 2>%s",
				    xauth_మార్గం, xauthfile, display,
				    SSH_X11_PROTO, x11_timeout_real,
				    _PATH_DEVNULL);
			}
			debug2_f("xauth command: %s", cmd);

			ఒకవేళ (timeout != 0 && x11_refuse_సమయం == 0) {
				now = monotime() + 1;
				ఒకవేళ (SSH_సమయం_T_MAX - timeout < now)
					x11_refuse_సమయం = SSH_సమయం_T_MAX;
				లేకపోతే
					x11_refuse_సమయం = now + timeout;
				channel_సమితి_x11_refuse_సమయం(ssh,
				    x11_refuse_సమయం);
			}
			ఒకవేళ (system(cmd) == 0)
				generated = 1;
			విడుదల(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		ఒకవేళ (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_మార్గం,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			ఒకవేళ (f && fgets(పంక్తి, పరిమాణం(పంక్తి), f) &&
			    అక్షరశ్రేణి_చదువు(పంక్తి, "%*s %511s %511s", proto, దత్తాంశం) == 2)
				got_దత్తాంశం = 1;
			ఒకవేళ (f)
				pclose(f);
			విడుదల(cmd);
		}
	}

	ఒకవేళ (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	ఒకవేళ (!trusted && !got_దత్తాంశం) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		తిరిగి -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	ఒకవేళ (!got_దత్తాంశం) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, పరిమాణం proto);
		arc4random_buf(rnd, పరిమాణం(rnd));
		కొరకు (i = 0; i < పరిమాణం(rnd); i++) {
			snprintf(దత్తాంశం + 2 * i, పరిమాణం దత్తాంశం - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	తిరిగి 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

స్థిర శూన్య
client_check_కిటికీ_change(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (!received_కిటికీ_change_signal)
		తిరిగి;
	received_కిటికీ_change_signal = 0;
	debug2_f("changed");
	channel_send_కిటికీ_changes(ssh);
}

స్థిర పూర్ణాంకం
client_global_request_జవాబు(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం global_confirm *gc;

	ఒకవేళ ((gc = TAILQ_FIRST(&global_confirms)) == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (gc->cb != ఖాళీ)
		gc->cb(ssh, type, seq, gc->ctx);
	ఒకవేళ (--gc->ref_లెక్క <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, నమోదు_2);
		freezero(gc, పరిమాణం(*gc));
	}

	ssh_packet_సమితి_alive_timeouts(ssh, 0);
	తిరిగి 0;
}

స్థిర శూన్య
కాలపట్టిక_server_alive_check(శూన్య)
{
	ఒకవేళ (options.server_alive_interval > 0)
		server_alive_సమయం = monotime() + options.server_alive_interval;
}

స్థిర శూన్య
server_alive_check(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	ఒకవేళ (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_లెక్క_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_రిజిస్టరు_global_confirm(ఖాళీ, ఖాళీ);
	కాలపట్టిక_server_alive_check();
}

/* Try to send a dummy keystroke */
స్థిర పూర్ణాంకం
send_chaff(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	ఒకవేళ (ssh->kex == ఖాళీ || (ssh->kex->flags & KEX_HAS_PING) == 0)
		తిరిగి 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	తిరిగి 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
స్థిర శూన్య
సమితి_తదుపరి_interval(స్థిరరాశి నిర్మాణం timespec *now, నిర్మాణం timespec *తదుపరి_interval,
    u_int interval_ms, పూర్ణాంకం starting)
{
	నిర్మాణం timespec tmp;
	దీర్ఘ దీర్ఘ interval_ns, fuzz_ns;
	స్థిర దీర్ఘ దీర్ఘ రేటు_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	ఒకవేళ (fuzz_ns > గరిష్ఠ_పూర్ణాంకం)
		fuzz_ns = గరిష్ఠ_పూర్ణాంకం;
	ఒకవేళ (fuzz_ns > interval_ns) {
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
	ఒకవేళ (starting)
		రేటు_fuzz = arc4random_ఏకరీతి(fuzz_ns);
	interval_ns -= fuzz_ns;
	interval_ns += arc4random_ఏకరీతి(fuzz_ns) + రేటు_fuzz;

	tmp.tv_sec = interval_ns / (1000 * 1000 * 1000);
	tmp.tv_nsec = interval_ns % (1000 * 1000 * 1000);

	timespecadd(now, &tmp, తదుపరి_interval);
}

/*
 * Performs keystroke timing obfuscation. Returns non-zero if the
 * output fd should be polled.
 */
స్థిర పూర్ణాంకం
obfuscate_keystroke_timing(నిర్మాణం ssh *ssh, నిర్మాణం timespec *timeout,
    పూర్ణాంకం channel_did_వరుసలో_చేర్చు)
{
	స్థిర పూర్ణాంకం చురుకైన;
	స్థిర నిర్మాణం timespec తదుపరి_interval, chaff_until;
	నిర్మాణం timespec now, tmp;
	పూర్ణాంకం just_started = 0, had_keystroke = 0;
	స్థిర గుర్తులేని దీర్ఘ దీర్ఘ nchaff;
	అక్షరం *stop_reason = ఖాళీ;
	దీర్ఘ దీర్ఘ n;

	monotime_ts(&now);

	ఒకవేళ (options.obscure_keystroke_timing_interval <= 0)
		తిరిగి 1;	/* disabled in config */

	ఒకవేళ (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} లేకపోతే ఒకవేళ (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} లేకపోతే ఒకవేళ (!ssh_packet_interactive_దత్తాంశం_గమ్యం_write(ssh) &&
	    ssh_packet_have_దత్తాంశం_గమ్యం_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} లేకపోతే ఒకవేళ (చురుకైన && channel_did_వరుసలో_చేర్చు &&
	    ssh_packet_have_దత్తాంశం_గమ్యం_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} లేకపోతే ఒకవేళ (చురుకైన) {
		ఒకవేళ (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} లేకపోతే ఒకవేళ (timespeccmp(&now, &తదుపరి_interval, >=) &&
		    !ssh_packet_have_దత్తాంశం_గమ్యం_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			ఒకవేళ (send_chaff(ssh))
				nchaff++;
		}
	}

	ఒకవేళ (stop_reason != ఖాళీ) {
		ఒకవేళ (చురుకైన) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			చురుకైన = 0;
		}
		తిరిగి 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	ఒకవేళ (!చురుకైన && ssh_packet_interactive_దత్తాంశం_గమ్యం_write(ssh) &&
	    channel_did_వరుసలో_చేర్చు && ssh_packet_have_దత్తాంశం_గమ్యం_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = చురుకైన = 1;
		nchaff = 0;
		సమితి_తదుపరి_interval(&now, &తదుపరి_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	ఒకవేళ (!చురుకైన)
		తిరిగి 1;

	ఒకవేళ (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_గమ్యం_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_ఏకరీతి(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &తదుపరి_interval);

	ఒకవేళ (just_started)
		తిరిగి 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	ఒకవేళ (timespeccmp(&now, &తదుపరి_interval, <))
		/* ...unless there's x11 communication happening */
		తిరిగి x11_channel_వాడిన_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - తదుపరి_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - తదుపరి_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	సమితి_తదుపరి_interval(&now, &తదుపరి_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	తిరిగి 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
స్థిర శూన్య
client_wait_until_can_do_something(నిర్మాణం ssh *ssh, నిర్మాణం pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, పూర్ణాంకం channel_did_వరుసలో_చేర్చు,
    sigset_t *sigsetp, పూర్ణాంకం *conn_లోపల_readyp, పూర్ణాంకం *conn_బహిర్గతం_readyp)
{
	నిర్మాణం timespec timeout;
	పూర్ణాంకం ret, oready;
	u_int p;

	*conn_లోపల_readyp = *conn_బహిర్గతం_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	ఒకవేళ (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	ఒకవేళ (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_దత్తాంశం_గమ్యం_write(ssh)) {
		/* clear events since we did not call poll() */
		కొరకు (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		తిరిగి;
	}

	oready = obfuscate_keystroke_timing(ssh, &timeout, channel_did_వరుసలో_చేర్చు);

	/* Monitor server connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_లోపల;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_బహిర్గతం;
	(*pfdp)[1].events = (oready && ssh_packet_have_దత్తాంశం_గమ్యం_write(ssh)) ?
	    POLLOUT : 0;

	/*
	 * Wait for something to happen.  This will suspend the process until
	 * some polled descriptor can be read, written, or has some other
	 * event pending, or a timeout expires.
	 */
	సమితి_control_persist_exit_సమయం(ssh);
	ఒకవేళ (control_persist_exit_సమయం > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_సమయం);
	ఒకవేళ (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_సమయం);
	ఒకవేళ (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	ఒకవేళ (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		కొరకు (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		ఒకవేళ (errno == EINTR)
			తిరిగి;
		/* Note: we might still have data in the buffers. */
		quit_సందేశం("poll: %s", strerror(errno));
		తిరిగి;
	}

	*conn_లోపల_readyp = (*pfdp)[0].revents != 0;
	*conn_బహిర్గతం_readyp = (*pfdp)[1].revents != 0;

	ఒకవేళ (options.server_alive_interval > 0 && !*conn_లోపల_readyp &&
	    monotime() >= server_alive_సమయం) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

స్థిర శూన్య
client_suspend_self(నిర్మాణం sshbuf *bin, నిర్మాణం sshbuf *bout, నిర్మాణం sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	ఒకవేళ (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	ఒకవేళ (sshbuf_len(berr) > 0)
		atomicio(vwrite, fileno(stderr), sshbuf_mutable_ptr(berr),
		    sshbuf_len(berr));

	leave_raw_బహుళకం(options.request_tty == REQUEST_TTY_FORCE);

	sshbuf_reset(bin);
	sshbuf_reset(bout);
	sshbuf_reset(berr);

	/* Send the suspend signal to the program itself. */
	kill(getpid(), SIGTSTP);

	/* Reset window sizes in case they have changed */
	received_కిటికీ_change_signal = 1;

	enter_raw_బహుళకం(options.request_tty == REQUEST_TTY_FORCE);
}

స్థిర శూన్య
client_process_net_ఆదానం(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	కాలపట్టిక_server_alive_check();
	ఒకవేళ ((r = ssh_packet_process_read(ssh, connection_లోపల)) == 0)
		తిరిగి; /* success */
	ఒకవేళ (r == SSH_ERR_SYSTEM_ERROR) {
		ఒకవేళ (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			తిరిగి;
		ఒకవేళ (errno == EPIPE) {
			quit_సందేశం("Connection to %s closed by remote host.",
			    host);
			తిరిగి;
		}
	}
	quit_సందేశం("Read from remote host %s: %s", host, ssh_err(r));
}

స్థిర శూన్య
client_స్థితి_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం type, Channel *c, శూన్య *ctx)
{
	నిర్మాణం channel_జవాబు_ctx *cr = (నిర్మాణం channel_జవాబు_ctx *)ctx;
	అక్షరం errmsg[256];
	పూర్ణాంకం r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	ఒకవేళ (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	ఒకవేళ (type == SSH2_సందేశం_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} లేకపోతే ఒకవేళ (type == SSH2_సందేశం_CHANNEL_FAILURE) {
		ఒకవేళ (tochan) {
			snprintf(errmsg, పరిమాణం(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} లేకపోతే {
			snprintf(errmsg, పరిమాణం(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		ఒకవేళ (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		ఒకవేళ (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			ఒకవేళ ((r = sshbuf_put(c->extended, errmsg,
			    అక్షరశ్రేణి_పొడవు(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} లేకపోతే
			error("%s", errmsg);
		ఒకవేళ (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			ఒకవేళ (c->self == session_ident)
				leave_raw_బహుళకం(0);
			లేకపోతే
				mux_tty_alloc_failed(ssh, c);
		} లేకపోతే ఒకవేళ (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	విడుదల(cr);
}

స్థిర శూన్య
client_abandon_స్థితి_confirm(నిర్మాణం ssh *ssh, Channel *c, శూన్య *ctx)
{
	విడుదల(ctx);
}

శూన్య
client_expect_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం id, స్థిరరాశి అక్షరం *request,
    గణన confirm_action action)
{
	నిర్మాణం channel_జవాబు_ctx *cr = xcalloc(1, పరిమాణం(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_రిజిస్టరు_స్థితి_confirm(ssh, id, client_స్థితి_confirm,
	    client_abandon_స్థితి_confirm, cr);
}

శూన్య
client_రిజిస్టరు_global_confirm(global_confirm_cb *cb, శూన్య *ctx)
{
	నిర్మాణం global_confirm *gc, *చివరి_gc;

	/* Coalesce identical callbacks */
	చివరి_gc = TAILQ_LAST(&global_confirms, global_confirms);
	ఒకవేళ (చివరి_gc && చివరి_gc->cb == cb && చివరి_gc->ctx == ctx) {
		ఒకవేళ (++చివరి_gc->ref_లెక్క >= గరిష్ఠ_పూర్ణాంకం)
			fatal_f("last_gc->ref_count = %d",
			    చివరి_gc->ref_లెక్క);
		తిరిగి;
	}

	gc = xcalloc(1, పరిమాణం(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_లెక్క = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, నమోదు_2);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
స్థిర పూర్ణాంకం
can_update_hostkeys(శూన్య)
{
	ఒకవేళ (hostkeys_update_complete)
		తిరిగి 0;
	ఒకవేళ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_బహుళకం)
		తిరిగి 0; /* won't ask in batchmode, so don't even try */
	ఒకవేళ (!options.update_hostkeys || options.అంకె_user_hostfiles <= 0)
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర శూన్య
client_repledge(శూన్య)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	ఒకవేళ (options.control_master || options.control_మార్గం != ఖాళీ ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != ఖాళీ || can_update_hostkeys() ||
	    (session_ident != -1 && !session_అమరిక_complete)) {
		/* Can't tighten */
		తిరిగి;
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
	ఒకవేళ (options.అంకె_local_forwards != 0 ||
	    options.అంకె_remote_forwards != 0 ||
	    options.అంకె_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		ఒకవేళ (pledge("stdio unix inet dns proc tty", ఖాళీ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} లేకపోతే ఒకవేళ (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		ఒకవేళ (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", ఖాళీ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} లేకపోతే {
		debug("pledge: fork");
		ఒకవేళ (pledge(PLEDGE_EXTRA_INET "stdio proc tty", ఖాళీ) == -1)
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

స్థిర శూన్య
process_cmdline(నిర్మాణం ssh *ssh)
{
	శూన్య (*handler)(పూర్ణాంకం);
	అక్షరం *s, *cmd;
	పూర్ణాంకం ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	నిర్మాణం Forward fwd;

	memset(&fwd, 0, పరిమాణం(fwd));

	leave_raw_బహుళకం(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	ఒకవేళ (s == ఖాళీ)
		వెళ్ళు బహిర్గతం;
	అయితే (ఖాళీనా((u_char)*s))
		s++;
	ఒకవేళ (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	ఒకవేళ (*s == '\0')
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (*s == 'h' || *s == 'H' || *s == '?') {
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
		ఒకవేళ (!options.permit_local_command)
			వెళ్ళు బహిర్గతం;
		logit("      !args                                  "
		    "Execute local command");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (*s == 'K') {
		delete = 1;
		s++;
	}
	ఒకవేళ (*s == 'L')
		local = 1;
	లేకపోతే ఒకవేళ (*s == 'R')
		remote = 1;
	లేకపోతే ఒకవేళ (*s == 'D')
		dynamic = 1;
	లేకపోతే {
		logit("Invalid command.");
		వెళ్ళు బహిర్గతం;
	}

	అయితే (ఖాళీనా((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	ఒకవేళ (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		ఒకవేళ (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		లేకపోతే ఒకవేళ (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		లేకపోతే
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_పోర్టు_STATIC,
			    &options.fwd_opts) > 0;
		ఒకవేళ (!ok) {
			logit("Unknown port forwarding.");
			వెళ్ళు బహిర్గతం;
		}
		logit("Canceled forwarding.");
	} లేకపోతే {
		/* -R specs can be both dynamic or not, so check both. */
		ఒకవేళ (remote) {
			ఒకవేళ (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				వెళ్ళు బహిర్గతం;
			}
		} లేకపోతే ఒకవేళ (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (local || dynamic) {
			ఒకవేళ (!channel_అమరిక_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				వెళ్ళు బహిర్గతం;
			}
		} లేకపోతే {
			ఒకవేళ (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				వెళ్ళు బహిర్గతం;
			}
		}
		logit("Forwarding port.");
	}

బహిర్గతం:
	ssh_signal(SIGINT, handler);
	enter_raw_బహుళకం(options.request_tty == REQUEST_TTY_FORCE);
	విడుదల(cmd);
	విడుదల(fwd.listen_host);
	విడుదల(fwd.listen_మార్గం);
	విడుదల(fwd.connect_host);
	విడుదల(fwd.connect_మార్గం);
}

/* reasons to suppress output of an escape command in help output */
#నిర్వచించు SUPPRESS_NEVER		0	/* never suppress, always show */
#నిర్వచించు SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#నిర్వచించు SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#నిర్వచించు SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#నిర్వచించు SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
నిర్మాణం escape_help_పాఠ్యం {
	స్థిరరాశి అక్షరం *cmd;
	స్థిరరాశి అక్షరం *పాఠ్యం;
	గుర్తులేని పూర్ణాంకం flags;
};
స్థిర నిర్మాణం escape_help_పాఠ్యం esc_txt[] = {
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

స్థిర శూన్య
print_escape_help(నిర్మాణం sshbuf *b, పూర్ణాంకం escape_char, పూర్ణాంకం mux_client,
    పూర్ణాంకం using_stderr)
{
	గుర్తులేని పూర్ణాంకం i, suppress_flags;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	కొరకు (i = 0; i < పరిమాణం(esc_txt)/పరిమాణం(esc_txt[0]); i++) {
		ఒకవేళ (esc_txt[i].flags & suppress_flags)
			కొనసాగు;
		ఒకవేళ ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].పాఠ్యం)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	ఒకవేళ ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
స్థిర పూర్ణాంకం
process_escapes(నిర్మాణం ssh *ssh, Channel *c,
    నిర్మాణం sshbuf *bin, నిర్మాణం sshbuf *bout, నిర్మాణం sshbuf *berr,
    అక్షరం *buf, పూర్ణాంకం len)
{
	pid_t pid;
	పూర్ణాంకం r, బైట్లు = 0;
	u_int i;
	u_char ch;
	అక్షరం *s;
	నిర్మాణం escape_filter_ctx *efc;

	ఒకవేళ (c == ఖాళీ || c->filter_ctx == ఖాళీ || len <= 0)
		తిరిగి 0;

	efc = (నిర్మాణం escape_filter_ctx *)c->filter_ctx;

	కొరకు (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		ఒకవేళ (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			ఎంపిక (ch) {
			స్థితి '.':
				/* Terminate the connection. */
				ఒకవేళ ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				ఒకవేళ (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					తిరిగి 0;
				} లేకపోతే
					quit_pending = 1;
				తిరిగి -1;

			స్థితి 'Z' - 64:
				/* XXX support this for mux clients */
				ఒకవేళ (c && c->ctl_chan != -1) {
					అక్షరం b[16];
 noescape:
					ఒకవేళ (ch == 'Z' - 64)
						snprintf(b, పరిమాణం b, "^Z");
					లేకపోతే
						snprintf(b, పరిమాణం b, "%c", ch);
					ఒకవేళ ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					కొనసాగు;
				}
				/* Suspend the program. Inform the user */
				ఒకవేళ ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				కొనసాగు;

			స్థితి 'B':
				ఒకవేళ ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_ప్రారంభం(ssh, c->self, "break", 0);
				ఒకవేళ ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				కొనసాగు;

			స్థితి 'I':
				ఒకవేళ ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_సందేశం(ssh);
				ఒకవేళ ((r = sshbuf_put(berr, s, అక్షరశ్రేణి_పొడవు(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				విడుదల(s);
				కొనసాగు;

			స్థితి 'R':
				ఒకవేళ (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				లేకపోతే
					need_rekeying = 1;
				కొనసాగు;

			స్థితి 'V':
				/* FALLTHROUGH */
			స్థితి 'v':
				ఒకవేళ (c && c->ctl_chan != -1)
					వెళ్ళు noescape;
				ఒకవేళ (!log_is_on_stderr()) {
					ఒకవేళ ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					కొనసాగు;
				}
				ఒకవేళ (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				ఒకవేళ (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				ఒకవేళ ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				కొనసాగు;

			స్థితి '&':
				ఒకవేళ (c->ctl_chan != -1)
					వెళ్ళు noescape;
				/*
				 * Detach the program (continue to serve
				 * connections, but put in background and no
				 * more new connections).
				 */
				/* Restore tty modes. */
				leave_raw_బహుళకం(
				    options.request_tty == REQUEST_TTY_FORCE);

				/* Stop listening for new connections. */
				channel_stop_listening(ssh);

				ఒకవేళ ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				ఒకవేళ (pid == -1) {
					error("fork: %.100s", strerror(errno));
					కొనసాగు;
				}
				ఒకవేళ (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					నిష్క్రమించు(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				ఒకవేళ ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				తిరిగి -1;
			స్థితి '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				కొనసాగు;

			స్థితి '#':
				ఒకవేళ ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_సందేశం(ssh);
				ఒకవేళ ((r = sshbuf_put(berr, s, అక్షరశ్రేణి_పొడవు(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				విడుదల(s);
				కొనసాగు;

			స్థితి 'C':
				ఒకవేళ (c && c->ctl_chan != -1)
					వెళ్ళు noescape;
				ఒకవేళ (options.enable_escape_commandline == 0) {
					ఒకవేళ ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					కొనసాగు;
				}
				process_cmdline(ssh);
				కొనసాగు;

			అప్రమేయ:
				ఒకవేళ (ch != efc->escape_char) {
					ఒకవేళ ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					బైట్లు++;
				}
				/* Escaped characters fall through here */
				ఆపు;
			}
		} లేకపోతే {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			ఒకవేళ (చివరి_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				కొనసాగు;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		చివరి_was_cr = (ch == '\r' || ch == '\n');
		ఒకవేళ ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		బైట్లు++;
	}
	తిరిగి బైట్లు;
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

స్థిర శూన్య
client_process_buffered_ఆదానం_packets(నిర్మాణం ssh *ssh)
{
	ssh_dispatch_నిరంతరం_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
శూన్య *
client_new_escape_filter_ctx(పూర్ణాంకం escape_char)
{
	నిర్మాణం escape_filter_ctx *ret;

	ret = xcalloc(1, పరిమాణం(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	తిరిగి (శూన్య *)ret;
}

/* Free the escape filter context on channel free */
శూన్య
client_filter_cleanup(నిర్మాణం ssh *ssh, పూర్ణాంకం cid, శూన్య *ctx)
{
	విడుదల(ctx);
}

పూర్ణాంకం
client_simple_escape_filter(నిర్మాణం ssh *ssh, Channel *c, అక్షరం *buf, పూర్ణాంకం len)
{
	ఒకవేళ (c->extended_usage != CHAN_EXTENDED_WRITE)
		తిరిగి 0;

	తిరిగి process_escapes(ssh, c, c->ఆదానం, c->output, c->extended,
	    buf, len);
}

స్థిర శూన్య
client_channel_closed(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం force, శూన్య *arg)
{
	channel_cancel_cleanup(ssh, id);
	session_closed = 1;
	leave_raw_బహుళకం(options.request_tty == REQUEST_TTY_FORCE);
}

/*
 * Implements the interactive session with the server.  This is called after
 * the user has been authenticated, and a command has been started on the
 * remote host.  If escape_char != SSH_ESCAPECHAR_NONE, it is the character
 * used as an escape character for terminating or suspending the session.
 */
పూర్ణాంకం
client_loop(నిర్మాణం ssh *ssh, పూర్ణాంకం have_pty, పూర్ణాంకం escape_char_arg,
    పూర్ణాంకం ssh2_chan_id)
{
	నిర్మాణం pollfd *pfd = ఖాళీ;
	u_int npfd_alloc = 0, npfd_చురుకైన = 0;
	ద్విగుణ ప్రారంభం_సమయం, మొత్తం_సమయం;
	పూర్ణాంకం interactive = -1, channel_did_వరుసలో_చేర్చు = 0, r;
	uint64_t ibytes, obytes;
	పూర్ణాంకం conn_లోపల_ready, conn_బహిర్గతం_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	ఒకవేళ (options.pkcs11_provider != ఖాళీ)
		debug("pledge: disabled (PKCS11Provider active)");
	లేకపోతే ఒకవేళ (options.control_master &&
	    !option_clear_or_none(options.control_మార్గం)) {
		debug("pledge: id");
		ఒకవేళ (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    ఖాళీ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} లేకపోతే ఒకవేళ (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		ఒకవేళ (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    ఖాళీ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} లేకపోతే ఒకవేళ (options.update_hostkeys) {
		debug("pledge: filesystem");
		ఒకవేళ (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    ఖాళీ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} లేకపోతే ఒకవేళ (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		ఒకవేళ (pledge("stdio cpath unix inet dns proc tty", ఖాళీ) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} లేకపోతే {
		debug("pledge: network");
		ఒకవేళ (pledge("stdio unix inet dns proc tty", ఖాళీ) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	}

	/* might be able to tighten now */
	client_repledge();

	ప్రారంభం_సమయం = monotime_double();

	/* Initialize variables. */
	చివరి_was_cr = 1;
	exit_స్థితి = -1;
	connection_లోపల = ssh_packet_get_connection_లోపల(ssh);
	connection_బహిర్గతం = ssh_packet_get_connection_బహిర్గతం(ssh);

	quit_pending = 0;

	client_init_dispatch(ssh);

	/*
	 * Set signal handlers, (e.g. to restore non-blocking mode)
	 * but don't overwrite SIG_IGN, matches behaviour from rsh(1)
	 */
	ఒకవేళ (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	ఒకవేళ (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	ఒకవేళ (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	ఒకవేళ (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, కిటికీ_change_handler);
#నిర్వచితమైతే SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#అయితే_ముగింపు

	ఒకవేళ (have_pty)
		enter_raw_బహుళకం(options.request_tty == REQUEST_TTY_FORCE);

	ఒకవేళ (session_ident != -1) {
		ఒకవేళ (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_రిజిస్టరు_filter(ssh, session_ident,
			    client_simple_escape_filter, ఖాళీ,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_రిజిస్టరు_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	కాలపట్టిక_server_alive_check();

	ఒకవేళ (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#నిర్వచితమైతే SIGINFO
	ఒకవేళ (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#అయితే_ముగింపు

	/* Main loop of the client for the interactive session mode. */
	అయితే (!quit_pending) {
		channel_did_వరుసలో_చేర్చు = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_ఆదానం_packets(ssh);

		ఒకవేళ (session_closed && !channel_still_open(ssh))
			ఆపు;

		ఒకవేళ (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} లేకపోతే ఒకవేళ (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			ఒకవేళ ((r = kex_ప్రారంభం_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} లేకపోతే {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			ఒకవేళ (ssh_packet_not_very_much_దత్తాంశం_గమ్యం_write(ssh))
				channel_did_వరుసలో_చేర్చు = channel_output_poll(ssh);

			/*
			 * Check if the window size has changed, and buffer a
			 * message about it to the server if so.
			 */
			client_check_కిటికీ_change(ssh);
		}
		/*
		 * Wait until we have something to do (something becomes
		 * available on one of the descriptors).
		 */
		ఒకవేళ (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		ఒకవేళ (siginfo_received) {
			అక్షరం ident[256];

			sshpkt_fmt_connection_id(ssh, ident, పరిమాణం(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - ప్రారంభం_సమయం);
			siginfo_received = 0;
		}
		ఒకవేళ (quit_pending)
			ఆపు;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_చురుకైన, channel_did_వరుసలో_చేర్చు, &osigset,
		    &conn_లోపల_ready, &conn_బహిర్గతం_ready);
		ఒకవేళ (sigprocmask(SIG_SETMASK, &osigset, ఖాళీ) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		ఒకవేళ (quit_pending)
			ఆపు;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_చురుకైన);

		/* Buffer input from the connection.  */
		ఒకవేళ (conn_లోపల_ready)
			client_process_net_ఆదానం(ssh);

		ఒకవేళ (quit_pending)
			ఆపు;

		/* A timeout may have triggered rekeying */
		ఒకవేళ ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		ఒకవేళ (conn_బహిర్గతం_ready) {
			ఒకవేళ (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_సమితి_interactive(ssh, interactive);
			}
			ఒకవేళ ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		ఒకవేళ (control_persist_exit_సమయం > 0) {
			ఒకవేళ (monotime() >= control_persist_exit_సమయం) {
				debug("ControlPersist timeout expired");
				ఆపు;
			}
		}
	}
	విడుదల(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	ఒకవేళ (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_సందేశం("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	ఒకవేళ (have_pty)
		leave_raw_బహుళకం(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	ఒకవేళ (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_స్థితి = 0;
	}

	ఒకవేళ (received_signal) {
		verbose("Killed by signal %d.", (పూర్ణాంకం) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	మొత్తం_సమయం = monotime_double() - ప్రారంభం_సమయం;
	ssh_packet_get_బైట్లు(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)obytes, (గుర్తులేని దీర్ఘ దీర్ఘ)ibytes, మొత్తం_సమయం);
	ఒకవేళ (మొత్తం_సమయం > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / మొత్తం_సమయం, ibytes / మొత్తం_సమయం);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_స్థితి);
	తిరిగి exit_స్థితి;
}

/*********/

స్థిర Channel *
client_request_forwarded_tcpip(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *request_type,
    పూర్ణాంకం rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = ఖాళీ;
	నిర్మాణం sshbuf *b = ఖాళీ;
	అక్షరం *listen_చిరునామా, *originator_చిరునామా;
	u_int listen_పోర్టు, originator_పోర్టు;
	పూర్ణాంకం r;

	/* Get rest of the packet */
	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &listen_చిరునామా, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_పోర్టు)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_చిరునామా, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_పోర్టు)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_చిరునామా, listen_పోర్టు, originator_చిరునామా, originator_పోర్టు);

	ఒకవేళ (listen_పోర్టు > 0xffff)
		error_f("invalid listen port");
	లేకపోతే ఒకవేళ (originator_పోర్టు > 0xffff)
		error_f("invalid originator port");
	లేకపోతే {
		c = channel_connect_by_listen_చిరునామా(ssh,
		    listen_చిరునామా, listen_పోర్టు, "forwarded-tcpip",
		    originator_చిరునామా);
	}

	ఒకవేళ (c != ఖాళీ && c->type == SSH_CHANNEL_MUX_CLIENT) {
		ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
			error_f("alloc reply");
			వెళ్ళు బహిర్గతం;
		}
		/* reconstruct and send to muxclient */
		ఒకవేళ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_సందేశం_CHANNEL_OPEN)) != 0 ||
		    (r = sshbuf_put_cstring(b, request_type)) != 0 ||
		    (r = sshbuf_put_u32(b, rchan)) != 0 ||
		    (r = sshbuf_put_u32(b, rwindow)) != 0 ||
		    (r = sshbuf_put_u32(b, rmaxpack)) != 0 ||
		    (r = sshbuf_put_cstring(b, listen_చిరునామా)) != 0 ||
		    (r = sshbuf_put_u32(b, listen_పోర్టు)) != 0 ||
		    (r = sshbuf_put_cstring(b, originator_చిరునామా)) != 0 ||
		    (r = sshbuf_put_u32(b, originator_పోర్టు)) != 0 ||
		    (r = sshbuf_put_stringb(c->output, b)) != 0) {
			error_fr(r, "compose for muxclient");
			వెళ్ళు బహిర్గతం;
		}
	}

 బహిర్గతం:
	sshbuf_free(b);
	విడుదల(originator_చిరునామా);
	విడుదల(listen_చిరునామా);
	తిరిగి c;
}

స్థిర Channel *
client_request_forwarded_streamlocal(నిర్మాణం ssh *ssh,
    స్థిరరాశి అక్షరం *request_type, పూర్ణాంకం rchan)
{
	Channel *c = ఖాళీ;
	అక్షరం *listen_మార్గం;
	పూర్ణాంకం r;

	/* Get the remote path. */
	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &listen_మార్గం, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_string(ssh, ఖాళీ, ఖాళీ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_చివర(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_మార్గం);

	c = channel_connect_by_listen_మార్గం(ssh, listen_మార్గం,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	విడుదల(listen_మార్గం);
	తిరిగి c;
}

స్థిర Channel *
client_request_x11(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *request_type, పూర్ణాంకం rchan)
{
	Channel *c = ఖాళీ;
	అక్షరం *originator;
	u_int originator_పోర్టు;
	పూర్ణాంకం r, sock;

	ఒకవేళ (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (x11_refuse_సమయం != 0 && monotime() >= x11_refuse_సమయం) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &originator, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_పోర్టు)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_పోర్టు);
	విడుదల(originator);
	sock = x11_connect_display(ssh);
	ఒకవేళ (sock < 0)
		తిరిగి ఖాళీ;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_కిటికీ_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	తిరిగి c;
}

స్థిర Channel *
client_request_agent(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *request_type, పూర్ణాంకం rchan)
{
	Channel *c = ఖాళీ;
	పూర్ణాంకం r, sock;

	ఒకవేళ (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (forward_agent_sock_మార్గం == ఖాళీ) {
		r = ssh_get_authentication_socket(&sock);
	} లేకపోతే {
		r = ssh_get_authentication_socket_మార్గం(forward_agent_sock_మార్గం, &sock);
	}
	ఒకవేళ (r != 0) {
		ఒకవేళ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	లేకపోతే
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	తిరిగి c;
}

అక్షరం *
client_request_tun_fwd(నిర్మాణం ssh *ssh, పూర్ణాంకం tun_బహుళకం,
    పూర్ణాంకం local_tun, పూర్ణాంకం remote_tun, channel_open_fn *cb, శూన్య *cbctx)
{
	Channel *c;
	పూర్ణాంకం r, fd;
	అక్షరం *ifname = ఖాళీ;

	ఒకవేళ (tun_బహుళకం == SSH_TUNMODE_NO)
		తిరిగి ఖాళీ;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_బహుళకం);

	/* Open local tunnel device */
	ఒకవేళ ((fd = tun_open(local_tun, tun_బహుళకం, &ifname)) == -1) {
		error("Tunnel device open failed.");
		తిరిగి ఖాళీ;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#ఒకవేళ defined(SSH_TUN_FILTER)
	ఒకవేళ (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_రిజిస్టరు_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, ఖాళీ, ఖాళీ);
#అయితే_ముగింపు

	ఒకవేళ (cb != ఖాళీ)
		channel_రిజిస్టరు_open_confirm(ssh, c->self, cb, cbctx);

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_కిటికీ_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_బహుళకం)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	తిరిగి ifname;
}

/* XXXX move to generic input handler */
స్థిర పూర్ణాంకం
client_ఆదానం_channel_open(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Channel *c = ఖాళీ;
	అక్షరం *ctype = ఖాళీ;
	పూర్ణాంకం r;
	u_int rchan;
	కొలత_t len;
	u_int rmaxpack, rwindow;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		వెళ్ళు బహిర్గతం;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	ఒకవేళ (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} లేకపోతే ఒకవేళ (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} లేకపోతే ఒకవేళ (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} లేకపోతే ఒకవేళ (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	ఒకవేళ (c != ఖాళీ && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} లేకపోతే ఒకవేళ (c != ఖాళీ) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_కిటికీ = rwindow;
		c->remote_maxpacket = rmaxpack;
		ఒకవేళ (c->type != SSH_CHANNEL_CONNECTING) {
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_కిటికీ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} లేకపోతే {
		debug("failure %s", ctype);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 బహిర్గతం:
	విడుదల(ctype);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
client_ఆదానం_channel_req(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Channel *c = ఖాళీ;
	అక్షరం *rtype = ఖాళీ;
	u_char జవాబు;
	u_int id, exitval;
	పూర్ణాంకం r, success = 0;

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &id)) != 0)
		తిరిగి r;
	ఒకవేళ (id <= గరిష్ఠ_పూర్ణాంకం)
		c = channel_lookup(ssh, id);
	ఒకవేళ (channel_proxy_upstream(c, type, seq, ssh))
		తిరిగి 0;
	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &rtype, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &జవాబు)) != 0)
		వెళ్ళు బహిర్గతం;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, జవాబు);

	ఒకవేళ (c == ఖాళీ) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} లేకపోతే ఒకవేళ (strcmp(rtype, "eow@openssh.com") == 0) {
		ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
			వెళ్ళు బహిర్గతం;
		chan_rcvd_eow(ssh, c);
	} లేకపోతే ఒకవేళ (strcmp(rtype, "exit-status") == 0) {
		ఒకవేళ ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (c->ctl_chan != -1) {
			mux_exit_సందేశం(ssh, c, exitval);
			success = 1;
		} లేకపోతే ఒకవేళ ((పూర్ణాంకం)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_స్థితి = exitval;
		} లేకపోతే {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (జవాబు && c != ఖాళీ && !(c->flags & CHAN_CLOSE_పంపిన)) {
		ఒకవేళ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, success ?
		    SSH2_సందేశం_CHANNEL_SUCCESS : SSH2_సందేశం_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 బహిర్గతం:
	విడుదల(rtype);
	తిరిగి r;
}

నిర్మాణం hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	అక్షరం *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	నిర్మాణం sshkey **కీలకాలు;
	u_int *కీలకాలు_సరిపోలిక;	/* mask of HKF_MATCH_* from hostfile.h */
	పూర్ణాంకం *కీలకాలు_verified;	/* flag for new keys verified by server */
	కొలత_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	నిర్మాణం sshkey **old_కీలకాలు;
	కొలత_t nold;

	/* Various special cases. */
	పూర్ణాంకం complex_hostspec;	/* wildcard or manual pattern-list host name */
	పూర్ణాంకం ca_అందుబాటు;	/* saw CA key for this host */
	పూర్ణాంకం old_కీలకం_చూసిన;	/* saw old key with other name/addr */
	పూర్ణాంకం other_name_చూసిన;	/* saw key with other name/addr */
};

స్థిర శూన్య
hostkeys_update_ctx_free(నిర్మాణం hostkeys_update_ctx *ctx)
{
	కొలత_t i;

	ఒకవేళ (ctx == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->కీలకాలు[i]);
	విడుదల(ctx->కీలకాలు);
	విడుదల(ctx->కీలకాలు_సరిపోలిక);
	విడుదల(ctx->కీలకాలు_verified);
	కొరకు (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_కీలకాలు[i]);
	విడుదల(ctx->old_కీలకాలు);
	విడుదల(ctx->host_str);
	విడుదల(ctx->ip_str);
	విడుదల(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
స్థిర పూర్ణాంకం
hostspec_is_complex(స్థిరరాశి అక్షరం *hosts)
{
	అక్షరం *cp;

	/* wildcard */
	ఒకవేళ (strchr(hosts, '*') != ఖాళీ || strchr(hosts, '?') != ఖాళీ)
		తిరిగి 1;
	/* single host/ip = ok */
	ఒకవేళ ((cp = strchr(hosts, ',')) == ఖాళీ)
		తిరిగి 0;
	/* more than two entries on the line */
	ఒకవేళ (strchr(cp + 1, ',') != ఖాళీ)
		తిరిగి 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	తిరిగి 0;
}

/* callback to search for ctx->keys in known_hosts */
స్థిర పూర్ణాంకం
hostkeys_కనుగొను(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *_ctx)
{
	నిర్మాణం hostkeys_update_ctx *ctx = (నిర్మాణం hostkeys_update_ctx *)_ctx;
	కొలత_t i;
	నిర్మాణం sshkey **tmp;

	ఒకవేళ (l->కీలకం == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (l->స్థితి_2 != HKF_స్థితి_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		కొరకు (i = 0; i < ctx->nkeys; i++) {
			ఒకవేళ (sshkey_equal(l->కీలకం, ctx->కీలకాలు[i])) {
				ctx->other_name_చూసిన = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->కీలకాలు[i]),
				    l->మార్గం, l->linenum);
				తిరిగి 0;
			}
		}
		తిరిగి 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	ఒకవేళ (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->మార్గం, l->linenum);
		ctx->complex_hostspec = 1;
		తిరిగి 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	ఒకవేళ (ctx->ip_str != ఖాళీ && strchr(l->hosts, ',') != ఖాళీ) {
		ఒకవేళ ((l->సరిపోలిక & HKF_సరిపోలిక_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_చూసిన = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->మార్గం, l->linenum);
			తిరిగి 0;
		} లేకపోతే ఒకవేళ ((l->సరిపోలిక & HKF_సరిపోలిక_IP) == 0) {
			/* Record if hostname matched a different address. */
			ctx->other_name_చూసిన = 1;
			debug3_f("found hostname %s against different address "
			    "at %s:%ld", ctx->host_str, l->మార్గం, l->linenum);
		}
	}

	/*
	 * UpdateHostkeys is skipped for wildcard host names and hostnames
	 * that contain more than two entries (ssh never writes these).
	 */
	ఒకవేళ (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->మార్గం, l->linenum);
		ctx->complex_hostspec = 1;
		తిరిగి 0;
	}

	/* Mark off keys we've already seen for this host */
	కొరకు (i = 0; i < ctx->nkeys; i++) {
		ఒకవేళ (!sshkey_equal(l->కీలకం, ctx->కీలకాలు[i]))
			కొనసాగు;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->కీలకాలు[i]), l->మార్గం, l->linenum);
		ctx->కీలకాలు_సరిపోలిక[i] |= l->సరిపోలిక;
		తిరిగి 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->కీలకం),
	    l->మార్గం, l->linenum);
	ఒకవేళ ((tmp = recallocarray(ctx->old_కీలకాలు, ctx->nold, ctx->nold + 1,
	    పరిమాణం(*ctx->old_కీలకాలు))) == ఖాళీ)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_కీలకాలు = tmp;
	ctx->old_కీలకాలు[ctx->nold++] = l->కీలకం;
	l->కీలకం = ఖాళీ;

	తిరిగి 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
స్థిర పూర్ణాంకం
hostkeys_check_old(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *_ctx)
{
	నిర్మాణం hostkeys_update_ctx *ctx = (నిర్మాణం hostkeys_update_ctx *)_ctx;
	కొలత_t i;
	పూర్ణాంకం hashed;

	/* only care about lines that *don't* match the active host spec */
	ఒకవేళ (l->స్థితి_2 == HKF_స్థితి_MATCHED || l->కీలకం == ఖాళీ)
		తిరిగి 0;

	hashed = l->సరిపోలిక & (HKF_సరిపోలిక_HOST_HASHED|HKF_సరిపోలిక_IP_HASHED);
	కొరకు (i = 0; i < ctx->nold; i++) {
		ఒకవేళ (!sshkey_equal(l->కీలకం, ctx->old_కీలకాలు[i]))
			కొనసాగు;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_కీలకాలు[i]), l->మార్గం, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_కీలకం_చూసిన = 1;
		ఆపు;
	}
	తిరిగి 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
స్థిర పూర్ణాంకం
check_old_కీలకాలు_othernames(నిర్మాణం hostkeys_update_ctx *ctx)
{
	కొలత_t i;
	పూర్ణాంకం r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	కొరకు (i = 0; i < options.అంకె_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		ఒకవేళ ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_కీలకం, 0)) != 0) {
			ఒకవేళ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				కొనసాగు;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			తిరిగి -1;
		}
	}
	తిరిగి 0;
}

స్థిర శూన్య
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

స్థిర శూన్య
update_తెలిసిన_hosts(నిర్మాణం hostkeys_update_ctx *ctx)
{
	పూర్ణాంకం r, was_raw = 0, మొదటి = 1;
	పూర్ణాంకం asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	అక్షరం *fp, *response;
	కొలత_t i;
	నిర్మాణం stat sb;

	కొరకు (i = 0; i < ctx->nkeys; i++) {
		ఒకవేళ (!ctx->కీలకాలు_verified[i])
			కొనసాగు;
		ఒకవేళ ((fp = sshkey_fingerprint(ctx->కీలకాలు[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("sshkey_fingerprint failed");
		ఒకవేళ (మొదటి && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->కీలకాలు[i]), fp);
		మొదటి = 0;
		విడుదల(fp);
	}
	కొరకు (i = 0; i < ctx->nold; i++) {
		ఒకవేళ ((fp = sshkey_fingerprint(ctx->old_కీలకాలు[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("sshkey_fingerprint failed");
		ఒకవేళ (మొదటి && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_కీలకాలు[i]), fp);
		మొదటి = 0;
		విడుదల(fp);
	}
	ఒకవేళ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		ఒకవేళ (get_saved_tio() != ఖాళీ) {
			leave_raw_బహుళకం(1);
			was_raw = 1;
		}
		response = ఖాళీ;
		కొరకు (i = 0; !quit_pending && i < 3; i++) {
			విడుదల(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			ఒకవేళ (response != ఖాళీ && strcasecmp(response, "yes") == 0)
				ఆపు;
			లేకపోతే ఒకవేళ (quit_pending || response == ఖాళీ ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				ఆపు;
			} లేకపోతే {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		ఒకవేళ (quit_pending || i >= 3 || response == ఖాళీ)
			options.update_hostkeys = 0;
		విడుదల(response);
		ఒకవేళ (was_raw)
			enter_raw_బహుళకం(1);
	}
	ఒకవేళ (options.update_hostkeys == 0)
		తిరిగి;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	కొరకు (i = 0; i < options.అంకె_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		ఒకవేళ (stat(options.user_hostfiles[i], &sb) != 0) {
			ఒకవేళ (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} లేకపోతే {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			కొనసాగు;
		}
		ఒకవేళ ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->కీలకాలు : ఖాళీ, i == 0 ? ctx->nkeys : 0,
		    options.hash_తెలిసిన_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

స్థిర శూన్య
client_global_hostkeys_prove_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం type,
    uint32_t seq, శూన్య *_ctx)
{
	నిర్మాణం hostkeys_update_ctx *ctx = (నిర్మాణం hostkeys_update_ctx *)_ctx;
	కొలత_t i, ndone;
	నిర్మాణం sshbuf *signdata;
	పూర్ణాంకం r, plaintype;
	స్థిరరాశి u_char *sig;
	స్థిరరాశి అక్షరం *rsa_kexalg = ఖాళీ;
	అక్షరం *alg = ఖాళీ;
	కొలత_t siglen;

	ఒకవేళ (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	ఒకవేళ (type != SSH2_సందేశం_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		తిరిగి;
	}
	ఒకవేళ (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == కీలకం_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	ఒకవేళ ((signdata = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	కొరకు (ndone = i = 0; i < ctx->nkeys; i++) {
		ఒకవేళ (ctx->కీలకాలు_సరిపోలిక[i])
			కొనసాగు;
		plaintype = sshkey_type_plain(ctx->కీలకాలు[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		ఒకవేళ ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->కీలకాలు[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		ఒకవేళ ((r = sshpkt_get_string_ప్రత్యక్ష(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->కీలకాలు[i]), i);
			వెళ్ళు బహిర్గతం;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		ఒకవేళ (plaintype == కీలకం_RSA && rsa_kexalg == ఖాళీ &&
		    సరిపోలిక_నమూనా_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			విడుదల(alg);
			/* zap the key from the list */
			sshkey_free(ctx->కీలకాలు[i]);
			ctx->కీలకాలు[i] = ఖాళీ;
			ndone++;
			కొనసాగు;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->కీలకాలు[i]), i, alg);
		విడుదల(alg);
		ఒకవేళ ((r = sshkey_verify(ctx->కీలకాలు[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == కీలకం_RSA ? rsa_kexalg : ఖాళీ, 0, ఖాళీ)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->కీలకాలు[i]), i);
			వెళ్ళు బహిర్గతం;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->కీలకాలు_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	ఒకవేళ (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0) {
		error_f("protocol error");
		వెళ్ళు బహిర్గతం;
	}

	/* Make the edits to known_hosts */
	update_తెలిసిన_hosts(ctx);
 బహిర్గతం:
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
స్థిర పూర్ణాంకం
client_ఆదానం_hostkeys(నిర్మాణం ssh *ssh)
{
	స్థిరరాశి u_char *blob = ఖాళీ;
	కొలత_t i, len = 0;
	నిర్మాణం sshbuf *buf = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ, **tmp;
	పూర్ణాంకం r, prove_పంపిన = 0;
	అక్షరం *fp;
	స్థిర పూర్ణాంకం hostkeys_చూసిన = 0; /* XXX use struct ssh */
	బాహ్య నిర్మాణం sockaddr_storage hostaddr; /* XXX from ssh.c */
	నిర్మాణం hostkeys_update_ctx *ctx = ఖాళీ;
	u_int want;

	ఒకవేళ (hostkeys_చూసిన)
		fatal_f("server already sent hostkeys");
	ఒకవేళ (!can_update_hostkeys())
		తిరిగి 1;
	hostkeys_చూసిన = 1;

	ctx = xcalloc(1, పరిమాణం(*ctx));
	అయితే (ssh_packet_మిగిలిన(ssh) > 0) {
		sshkey_free(కీలకం);
		కీలకం = ఖాళీ;
		ఒకవేళ ((r = sshpkt_get_string_ప్రత్యక్ష(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshkey_from_blob(blob, len, &కీలకం)) != 0) {
			do_log2_fr(r, r == SSH_ERR_కీలకం_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			కొనసాగు;
		}
		fp = sshkey_fingerprint(కీలకం, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(కీలకం), fp);
		విడుదల(fp);

		ఒకవేళ (!hostkey_accepted_by_hostkeyalgs(కీలకం)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(కీలకం));
			కొనసాగు;
		}
		/* Skip certs */
		ఒకవేళ (sshkey_is_cert(కీలకం)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(కీలకం));
			కొనసాగు;
		}
		/* Ensure keys are unique */
		కొరకు (i = 0; i < ctx->nkeys; i++) {
			ఒకవేళ (sshkey_equal(కీలకం, ctx->కీలకాలు[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(కీలకం));
				వెళ్ళు బహిర్గతం;
			}
		}
		/* Key is good, record it */
		ఒకవేళ ((tmp = recallocarray(ctx->కీలకాలు, ctx->nkeys, ctx->nkeys + 1,
		    పరిమాణం(*ctx->కీలకాలు))) == ఖాళీ)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->కీలకాలు = tmp;
		ctx->కీలకాలు[ctx->nkeys++] = కీలకం;
		కీలకం = ఖాళీ;
	}

	ఒకవేళ (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((ctx->కీలకాలు_సరిపోలిక = సున్నా_జ్ఞాపకం_ఇవ్వు(ctx->nkeys,
	    పరిమాణం(*ctx->కీలకాలు_సరిపోలిక))) == ఖాళీ ||
	    (ctx->కీలకాలు_verified = సున్నా_జ్ఞాపకం_ఇవ్వు(ctx->nkeys,
	    పరిమాణం(*ctx->కీలకాలు_verified))) == ఖాళీ)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (నిర్మాణం sockaddr *)&hostaddr : ఖాళీ,
	    options.పోర్టు, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : ఖాళీ);

	/* Find which keys we already know about. */
	కొరకు (i = 0; i < options.అంకె_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		ఒకవేళ ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_కనుగొను, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_కీలకం, 0)) != 0) {
			ఒకవేళ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				కొనసాగు;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			వెళ్ళు బహిర్గతం;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_సరిపోలిక_HOST | ( options.check_host_ip ? HKF_సరిపోలిక_IP : 0);
	కొరకు (i = 0; i < ctx->nkeys; i++) {
		ఒకవేళ (ctx->కీలకాలు_సరిపోలిక[i] == 0)
			ctx->nnew++;
		ఒకవేళ ((ctx->కీలకాలు_సరిపోలిక[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	ఒకవేళ (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		వెళ్ళు బహిర్గతం;
	}

	/* Various reasons why we cannot proceed with the update */
	ఒకవేళ (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (ctx->other_name_చూసిన) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		వెళ్ళు బహిర్గతం;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	ఒకవేళ (ctx->nold != 0) {
		ఒకవేళ (check_old_కీలకాలు_othernames(ctx) != 0)
			వెళ్ళు బహిర్గతం; /* error already logged */
		ఒకవేళ (ctx->old_కీలకం_చూసిన) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == ఖాళీ ? "" : ",",
			    ctx->ip_str == ఖాళీ ? "" : ctx->ip_str);
			వెళ్ళు బహిర్గతం;
		}
	}

	ఒకవేళ (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_తెలిసిన_hosts(ctx);
		వెళ్ళు బహిర్గతం;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	కొరకు (i = 0; i < ctx->nkeys; i++) {
		ఒకవేళ (ctx->కీలకాలు_సరిపోలిక[i])
			కొనసాగు;
		sshbuf_reset(buf);
		ఒకవేళ ((r = sshkey_putb(ctx->కీలకాలు[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_రిజిస్టరు_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = ఖాళీ;  /* will be freed in callback */
	prove_పంపిన = 1;

	/* Success */
 బహిర్గతం:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(కీలకం);
	sshbuf_free(buf);
	ఒకవేళ (!prove_పంపిన) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
client_ఆదానం_global_request(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	అక్షరం *rtype;
	u_char want_జవాబు;
	పూర్ణాంకం r, success = 0;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &rtype, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_జవాబు)) != 0)
		వెళ్ళు బహిర్గతం;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_జవాబు);
	ఒకవేళ (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_ఆదానం_hostkeys(ssh);
	ఒకవేళ (want_జవాబు) {
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, success ? SSH2_సందేశం_REQUEST_SUCCESS :
		    SSH2_సందేశం_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	r = 0;
 బహిర్గతం:
	విడుదల(rtype);
	తిరిగి r;
}

స్థిర శూన్య
client_send_env(నిర్మాణం ssh *ssh, పూర్ణాంకం id, స్థిరరాశి అక్షరం *name, స్థిరరాశి అక్షరం *val)
{
	పూర్ణాంకం r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_ప్రారంభం(ssh, id, "env", 0);
	ఒకవేళ ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

శూన్య
client_session2_అమరిక(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం want_tty, పూర్ణాంకం want_subsystem,
    స్థిరరాశి అక్షరం *పదం, నిర్మాణం termios *tiop, పూర్ణాంకం లోపల_fd, నిర్మాణం sshbuf *cmd,
    అక్షరం **env)
{
	కొలత_t i, j, len;
	పూర్ణాంకం matched, r;
	అక్షరం *type = ఖాళీ, *cmdstring = ఖాళీ, *name, *val;
	Channel *c = ఖాళీ;

	debug2_f("id %d", id);

	ఒకవేళ ((c = channel_lookup(ssh, id)) == ఖాళీ)
		fatal_f("channel %d: unknown channel", id);

	ఒకవేళ (want_tty) {
		నిర్మాణం winsize ws;

		/* Store window size in the packet. */
		ఒకవేళ (ioctl(లోపల_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, పరిమాణం(ws));

		channel_request_ప్రారంభం(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, పదం != ఖాళీ ? పదం : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_నిలువు)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_అడ్డువరుస)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		ఒకవేళ (tiop == ఖాళీ)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	ఒకవేళ (options.అంకె_send_env != 0 && env != ఖాళీ) {
		debug("Sending environment.");
		కొరకు (i = 0; env[i] != ఖాళీ; i++) {
			/*విభజించు*/
			name = xstrdup(env[i]);
			ఒకవేళ ((val = strchr(name, '=')) == ఖాళీ) {
				విడుదల(name);
				కొనసాగు;
			}
			*val++ = '\0';

			matched = 0;
			కొరకు (j = 0; j < options.అంకె_send_env; j++) {
				ఒకవేళ (సరిపోలిక_నమూనా(name, options.send_env[j])) {
					matched = 1;
					ఆపు;
				}
			}
			ఒకవేళ (!matched) {
				debug3("Ignored env %s", name);
				విడుదల(name);
				కొనసాగు;
			}
			client_send_env(ssh, id, name, val);
			విడుదల(name);
		}
	}
	కొరకు (i = 0; i < options.అంకె_setenv; i++) {
		/*విభజించు*/
		name = xstrdup(options.setenv[i]);
		ఒకవేళ ((val = strchr(name, '=')) == ఖాళీ) {
			విడుదల(name);
			కొనసాగు;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		విడుదల(name);
	}

	len = sshbuf_len(cmd);
	ఒకవేళ (len > 0) {
		ఒకవేళ ((cmdstring = sshbuf_dup_string(cmd)) == ఖాళీ)
			fatal_f("sshbuf_dup_string failed");
		ఒకవేళ (len > 900)
			len = 900;
		ఒకవేళ (want_subsystem) {
			debug("Sending subsystem: %.*s", (పూర్ణాంకం)len, cmdstring);
			channel_request_ప్రారంభం(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} లేకపోతే {
			debug("Sending command: %.*s", (పూర్ణాంకం)len, cmdstring);
			channel_request_ప్రారంభం(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		ఒకవేళ ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} లేకపోతే {
		channel_request_ప్రారంభం(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_సమితి_xtype(ssh, id, type);
	విడుదల(cmdstring);
	విడుదల(type);

	session_అమరిక_complete = 1;
	client_repledge();
}

శూన్య
client_channel_request_agent_forwarding(నిర్మాణం ssh *ssh, పూర్ణాంకం id)
{
	స్థిరరాశి అక్షరం *req = "auth-agent-req@openssh.com";
	పూర్ణాంకం r;

	ఒకవేళ (ssh->kex != ఖాళీ && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_ప్రారంభం(ssh, id, req, 0);
	ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

స్థిర శూన్య
client_init_dispatch(నిర్మాణం ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_CLOSE, &channel_ఆదానం_oclose);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_దత్తాంశం, &channel_ఆదానం_దత్తాంశం);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_EOF, &channel_ఆదానం_ieof);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_EXTENDED_దత్తాంశం, &channel_ఆదానం_extended_దత్తాంశం);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_OPEN, &client_ఆదానం_channel_open);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION, &channel_ఆదానం_open_confirmation);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_OPEN_FAILURE, &channel_ఆదానం_open_failure);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_REQUEST, &client_ఆదానం_channel_req);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_కిటికీ_ADJUST, &channel_ఆదానం_కిటికీ_adjust);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_SUCCESS, &channel_ఆదానం_స్థితి_confirm);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_CHANNEL_FAILURE, &channel_ఆదానం_స్థితి_confirm);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_GLOBAL_REQUEST, &client_ఆదానం_global_request);

	/* rekeying */
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEXINIT, &kex_ఆదానం_kexinit);

	/* global request reply messages */
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_REQUEST_FAILURE, &client_global_request_జవాబు);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_REQUEST_SUCCESS, &client_global_request_జవాబు);
}

శూన్య
client_stop_mux(శూన్య)
{
	ఒకవేళ (options.control_మార్గం != ఖాళీ && muxserver_sock != -1)
		unlink(options.control_మార్గం);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	ఒకవేళ (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
శూన్య
cleanup_exit(పూర్ణాంకం i)
{
	leave_raw_బహుళకం(options.request_tty == REQUEST_TTY_FORCE);
	ఒకవేళ (options.control_మార్గం != ఖాళీ && muxserver_sock != -1)
		unlink(options.control_మార్గం);
	ssh_kill_proxy_command();
	_exit(i);
}
