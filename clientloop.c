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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "readconf.h"
#अन्तर्भाव "clientloop.h"
#अन्तर्भाव "sshconnect.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "sshpty.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#define HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#define SSH_KEYSTROKE_TIMING_FUZZ 10

बाह्य वर्ण *__progname;

/* import options */
बाह्य Options options;

/* Control socket */
बाह्य पूर्णाङ्क muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
बाह्य वर्ण *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
बाह्य वर्ण *forward_agent_sock_path;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
स्थिर चञ्चल sig_atomic_t received_window_change_signal = 0;
स्थिर चञ्चल sig_atomic_t siginfo_received = 0;
स्थिर चञ्चल sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
स्थिर time_t control_persist_exit_time = 0;

/* Common data for the client loop code. */
चञ्चल sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
स्थिर पूर्णाङ्क last_was_cr;		/* Last character was a newline. */
स्थिर पूर्णाङ्क exit_status;		/* Used to store the command exit status. */
स्थिर पूर्णाङ्क connection_in;	/* Connection to server (input). */
स्थिर पूर्णाङ्क connection_out;	/* Connection to server (output). */
स्थिर पूर्णाङ्क need_rekeying;	/* Set to non-zero if rekeying is requested. */
स्थिर पूर्णाङ्क session_closed;	/* In SSH2: login session closed. */
स्थिर time_t x11_refuse_time;	/* If >0, refuse x11 opens after this time. */
स्थिर time_t server_alive_time;	/* Time to do server_alive_check */
स्थिर पूर्णाङ्क hostkeys_update_complete;
स्थिर पूर्णाङ्क session_setup_complete;

स्थिर शून्य client_init_dispatch(संरचना ssh *ssh);
पूर्णाङ्क	session_ident = -1;

/* Track escape per proto2 channel */
संरचना escape_filter_ctx {
	पूर्णाङ्क escape_pending;
	पूर्णाङ्क escape_char;
};

/* Context for channel confirmation replies */
संरचना channel_reply_ctx {
	ध्रुव वर्ण *request_type;
	पूर्णाङ्क id;
	गणना confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
संरचना global_confirm {
	TAILQ_ENTRY(global_confirm) entry;
	global_confirm_cb *cb;
	शून्य *ctx;
	पूर्णाङ्क ref_गणनम्;
};
TAILQ_HEAD(global_confirms, global_confirm);
स्थिर संरचना global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

स्थिर शून्य quit_message(ध्रुव वर्ण *fmt, ...)
    __attribute__((__format__ (printf, 1, 2)));

स्थिर शून्य
quit_message(ध्रुव वर्ण *fmt, ...)
{
	वर्ण *सन्देशः, *fmt2;
	va_list args;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(args, fmt);
	xvasprintf(&सन्देशः, fmt2, args);
	va_end(args);

	(शून्य)atomicio(vwrite, STDERR_FILENO, सन्देशः, strlen(सन्देशः));
	मुक्त(सन्देशः);
	मुक्त(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
स्थिर शून्य
window_change_handler(पूर्णाङ्क sig)
{
	received_window_change_signal = 1;
}

#ifdef SIGINFO
/* Signal handler for SIGINFO */
स्थिर शून्य
siginfo_handler(पूर्णाङ्क sig)
{
	siginfo_received = 1;
}
#endif

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
स्थिर शून्य
signal_handler(पूर्णाङ्क sig)
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
स्थिर शून्य
set_control_persist_exit_time(संरचना ssh *ssh)
{
	सचे (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} अञ्ञथा सचे (channel_still_open(ssh)) {
		/* some client connections are still open */
		सचे (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} अञ्ञथा सचे (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#define SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
स्थिर पूर्णाङ्क
client_x11_display_valid(ध्रुव वर्ण *display)
{
	size_t i, dlen;

	सचे (display == रिक्त)
		पटिनिवत्त 0;

	dlen = strlen(display);
	अत्थाय (i = 0; i < dlen; i++) {
		सचे (!isalnum((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == रिक्त) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			पटिनिवत्त 0;
		}
	}
	पटिनिवत्त 1;
}

#define SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#define X11_TIMEOUT_SLACK	60
पूर्णाङ्क
client_x11_get_proto(संरचना ssh *ssh, ध्रुव वर्ण *display,
    ध्रुव वर्ण *xauth_path, u_int trusted, u_int timeout,
    वर्ण **_proto, वर्ण **_data)
{
	वर्ण *cmd, पङ्क्तिः[512], xdisplay[512];
	वर्ण xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	स्थिर वर्ण proto[512], data[512];
	FILE *f;
	पूर्णाङ्क got_data = 0, generated = 0, do_unlink = 0, r;
	संरचना stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*_data = data;
	proto[0] = data[0] = xauthfile[0] = xauthdir[0] = '\0';

	सचे (!client_x11_display_valid(display)) {
		सचे (display != रिक्त)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		पटिनिवत्त -1;
	}
	सचे (xauth_path != रिक्त && stat(xauth_path, &st) == -1) {
		debug("No xauth program.");
		xauth_path = रिक्त;
	}

	सचे (xauth_path != रिक्त) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		सचे (strncmp(display, "localhost:", 10) == 0) {
			सचे ((r = snprintf(xdisplay, परिमाण(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (size_t)r >= परिमाण(xdisplay)) {
				error_f("display name too long");
				पटिनिवत्त -1;
			}
			display = xdisplay;
		}
		सचे (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, परिमाण(xauthdir));
			सचे (mkdtemp(xauthdir) == रिक्त) {
				error_f("mkdtemp: %s", strerror(errno));
				पटिनिवत्त -1;
			}
			do_unlink = 1;
			सचे ((r = snprintf(xauthfile, परिमाण(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (size_t)r >= परिमाण(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				पटिनिवत्त -1;
			}

			सचे (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} अञ्ञथा {
				/* Add some slack to requested expiry */
				सचे (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				अञ्ञथा {
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

			सचे (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				सचे (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				अञ्ञथा
					x11_refuse_time = now + timeout;
				channel_set_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			सचे (system(cmd) == 0)
				generated = 1;
			मुक्त(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		सचे (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_path,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			सचे (f && fgets(पङ्क्तिः, परिमाण(पङ्क्तिः), f) &&
			    sscanf(पङ्क्तिः, "%*s %511s %511s", proto, data) == 2)
				got_data = 1;
			सचे (f)
				pclose(f);
			मुक्त(cmd);
		}
	}

	सचे (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	सचे (!trusted && !got_data) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		पटिनिवत्त -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	सचे (!got_data) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, परिमाण proto);
		arc4random_buf(rnd, परिमाण(rnd));
		अत्थाय (i = 0; i < परिमाण(rnd); i++) {
			snprintf(data + 2 * i, परिमाण data - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	पटिनिवत्त 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

स्थिर शून्य
client_check_window_change(संरचना ssh *ssh)
{
	सचे (!received_window_change_signal)
		पटिनिवत्त;
	received_window_change_signal = 0;
	debug2_f("changed");
	channel_send_window_changes(ssh);
}

स्थिर पूर्णाङ्क
client_global_request_reply(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना global_confirm *gc;

	सचे ((gc = TAILQ_FIRST(&global_confirms)) == रिक्त)
		पटिनिवत्त 0;
	सचे (gc->cb != रिक्त)
		gc->cb(ssh, type, seq, gc->ctx);
	सचे (--gc->ref_गणनम् <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, entry);
		freezero(gc, परिमाण(*gc));
	}

	ssh_packet_set_alive_timeouts(ssh, 0);
	पटिनिवत्त 0;
}

स्थिर शून्य
schedule_server_alive_check(शून्य)
{
	सचे (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

स्थिर शून्य
server_alive_check(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	सचे (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_गणनम्_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_register_global_confirm(रिक्त, रिक्त);
	schedule_server_alive_check();
}

/* Try to send a dummy keystroke */
स्थिर पूर्णाङ्क
send_chaff(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	सचे (ssh->kex == रिक्त || (ssh->kex->flags & KEX_HAS_PING) == 0)
		पटिनिवत्त 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	पटिनिवत्त 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
स्थिर शून्य
set_next_interval(ध्रुव संरचना timespec *now, संरचना timespec *next_interval,
    u_int interval_ms, पूर्णाङ्क starting)
{
	संरचना timespec tmp;
	long long interval_ns, fuzz_ns;
	स्थिर long long rate_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	सचे (fuzz_ns > INT_MAX)
		fuzz_ns = INT_MAX;
	सचे (fuzz_ns > interval_ns) {
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
	सचे (starting)
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
स्थिर पूर्णाङ्क
obfuscate_keystroke_timing(संरचना ssh *ssh, संरचना timespec *timeout,
    पूर्णाङ्क channel_did_enqueue)
{
	स्थिर पूर्णाङ्क active;
	स्थिर संरचना timespec next_interval, chaff_until;
	संरचना timespec now, tmp;
	पूर्णाङ्क just_started = 0, had_keystroke = 0;
	स्थिर unsigned long long nchaff;
	वर्ण *stop_reason = रिक्त;
	long long n;

	monotime_ts(&now);

	सचे (options.obscure_keystroke_timing_interval <= 0)
		पटिनिवत्त 1;	/* disabled in config */

	सचे (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} अञ्ञथा सचे (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} अञ्ञथा सचे (!ssh_packet_interactive_data_to_write(ssh) &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} अञ्ञथा सचे (active && channel_did_enqueue &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} अञ्ञथा सचे (active) {
		सचे (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} अञ्ञथा सचे (timespeccmp(&now, &next_interval, >=) &&
		    !ssh_packet_have_data_to_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			सचे (send_chaff(ssh))
				nchaff++;
		}
	}

	सचे (stop_reason != रिक्त) {
		सचे (active) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			active = 0;
		}
		पटिनिवत्त 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	सचे (!active && ssh_packet_interactive_data_to_write(ssh) &&
	    channel_did_enqueue && ssh_packet_have_data_to_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = active = 1;
		nchaff = 0;
		set_next_interval(&now, &next_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	सचे (!active)
		पटिनिवत्त 1;

	सचे (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_to_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_uniform(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &next_interval);

	सचे (just_started)
		पटिनिवत्त 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	सचे (timespeccmp(&now, &next_interval, <))
		/* ...unless there's x11 communication happening */
		पटिनिवत्त x11_channel_used_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - next_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - next_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	set_next_interval(&now, &next_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	पटिनिवत्त 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
स्थिर शून्य
client_wait_until_can_do_something(संरचना ssh *ssh, संरचना pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, पूर्णाङ्क channel_did_enqueue,
    sigset_t *sigsetp, पूर्णाङ्क *conn_in_readyp, पूर्णाङ्क *conn_out_readyp)
{
	संरचना timespec timeout;
	पूर्णाङ्क ret, oready;
	u_int p;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	सचे (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	सचे (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_data_to_write(ssh)) {
		/* clear events since we did not call poll() */
		अत्थाय (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		पटिनिवत्त;
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
	सचे (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	सचे (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	सचे (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	सचे (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		अत्थाय (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		सचे (errno == EINTR)
			पटिनिवत्त;
		/* Note: we might still have data in the buffers. */
		quit_message("poll: %s", strerror(errno));
		पटिनिवत्त;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	सचे (options.server_alive_interval > 0 && !*conn_in_readyp &&
	    monotime() >= server_alive_time) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

स्थिर शून्य
client_suspend_self(संरचना sshbuf *bin, संरचना sshbuf *bout, संरचना sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	सचे (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	सचे (sshbuf_len(berr) > 0)
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

स्थिर शून्य
client_process_net_निवेशः(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	schedule_server_alive_check();
	सचे ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		पटिनिवत्त; /* success */
	सचे (r == SSH_ERR_SYSTEM_ERROR) {
		सचे (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			पटिनिवत्त;
		सचे (errno == EPIPE) {
			quit_message("Connection to %s closed by remote host.",
			    host);
			पटिनिवत्त;
		}
	}
	quit_message("Read from remote host %s: %s", host, ssh_err(r));
}

स्थिर शून्य
client_status_confirm(संरचना ssh *ssh, पूर्णाङ्क type, Channel *c, शून्य *ctx)
{
	संरचना channel_reply_ctx *cr = (संरचना channel_reply_ctx *)ctx;
	वर्ण errmsg[256];
	पूर्णाङ्क r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	सचे (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	सचे (type == SSH2_सन्देशः_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} अञ्ञथा सचे (type == SSH2_सन्देशः_CHANNEL_FAILURE) {
		सचे (tochan) {
			snprintf(errmsg, परिमाण(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} अञ्ञथा {
			snprintf(errmsg, परिमाण(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		सचे (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		सचे (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			सचे ((r = sshbuf_put(c->extended, errmsg,
			    strlen(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} अञ्ञथा
			error("%s", errmsg);
		सचे (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			सचे (c->self == session_ident)
				leave_raw_mode(0);
			अञ्ञथा
				mux_tty_alloc_failed(ssh, c);
		} अञ्ञथा सचे (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	मुक्त(cr);
}

स्थिर शून्य
client_abandon_status_confirm(संरचना ssh *ssh, Channel *c, शून्य *ctx)
{
	मुक्त(ctx);
}

शून्य
client_expect_confirm(संरचना ssh *ssh, पूर्णाङ्क id, ध्रुव वर्ण *request,
    गणना confirm_action action)
{
	संरचना channel_reply_ctx *cr = xcalloc(1, परिमाण(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_register_status_confirm(ssh, id, client_status_confirm,
	    client_abandon_status_confirm, cr);
}

शून्य
client_register_global_confirm(global_confirm_cb *cb, शून्य *ctx)
{
	संरचना global_confirm *gc, *last_gc;

	/* Coalesce identical callbacks */
	last_gc = TAILQ_LAST(&global_confirms, global_confirms);
	सचे (last_gc && last_gc->cb == cb && last_gc->ctx == ctx) {
		सचे (++last_gc->ref_गणनम् >= INT_MAX)
			fatal_f("last_gc->ref_count = %d",
			    last_gc->ref_गणनम्);
		पटिनिवत्त;
	}

	gc = xcalloc(1, परिमाण(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_गणनम् = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, entry);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
स्थिर पूर्णाङ्क
can_update_hostkeys(शून्य)
{
	सचे (hostkeys_update_complete)
		पटिनिवत्त 0;
	सचे (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_mode)
		पटिनिवत्त 0; /* won't ask in batchmode, so don't even try */
	सचे (!options.update_hostkeys || options.अङ्कः_user_hostfiles <= 0)
		पटिनिवत्त 0;
	पटिनिवत्त 1;
}

स्थिर शून्य
client_repledge(शून्य)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	सचे (options.control_master || options.control_path != रिक्त ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != रिक्त || can_update_hostkeys() ||
	    (session_ident != -1 && !session_setup_complete)) {
		/* Can't tighten */
		पटिनिवत्त;
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
	सचे (options.अङ्कः_local_forwards != 0 ||
	    options.अङ्कः_remote_forwards != 0 ||
	    options.अङ्कः_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		सचे (pledge("stdio unix inet dns proc tty", रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} अञ्ञथा सचे (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		सचे (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} अञ्ञथा {
		debug("pledge: fork");
		सचे (pledge(PLEDGE_EXTRA_INET "stdio proc tty", रिक्त) == -1)
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

स्थिर शून्य
process_cmdline(संरचना ssh *ssh)
{
	शून्य (*handler)(पूर्णाङ्क);
	वर्ण *s, *cmd;
	पूर्णाङ्क ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	संरचना Forward fwd;

	memset(&fwd, 0, परिमाण(fwd));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	सचे (s == रिक्त)
		गच्छ out;
	याव (isspace((u_char)*s))
		s++;
	सचे (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	सचे (*s == '\0')
		गच्छ out;

	सचे (*s == 'h' || *s == 'H' || *s == '?') {
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
		सचे (!options.permit_local_command)
			गच्छ out;
		logit("      !args                                  "
		    "Execute local command");
		गच्छ out;
	}

	सचे (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		गच्छ out;
	}

	सचे (*s == 'K') {
		delete = 1;
		s++;
	}
	सचे (*s == 'L')
		local = 1;
	अञ्ञथा सचे (*s == 'R')
		remote = 1;
	अञ्ञथा सचे (*s == 'D')
		dynamic = 1;
	अञ्ञथा {
		logit("Invalid command.");
		गच्छ out;
	}

	याव (isspace((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	सचे (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		सचे (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			गच्छ out;
		}
		सचे (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		अञ्ञथा सचे (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		अञ्ञथा
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_PORT_STATIC,
			    &options.fwd_opts) > 0;
		सचे (!ok) {
			logit("Unknown port forwarding.");
			गच्छ out;
		}
		logit("Canceled forwarding.");
	} अञ्ञथा {
		/* -R specs can be both dynamic or not, so check both. */
		सचे (remote) {
			सचे (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				गच्छ out;
			}
		} अञ्ञथा सचे (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			गच्छ out;
		}
		सचे (local || dynamic) {
			सचे (!channel_setup_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				गच्छ out;
			}
		} अञ्ञथा {
			सचे (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				गच्छ out;
			}
		}
		logit("Forwarding port.");
	}

out:
	ssh_signal(SIGINT, handler);
	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	मुक्त(cmd);
	मुक्त(fwd.listen_host);
	मुक्त(fwd.listen_path);
	मुक्त(fwd.connect_host);
	मुक्त(fwd.connect_path);
}

/* reasons to suppress output of an escape command in help output */
#define SUPPRESS_NEVER		0	/* never suppress, always show */
#define SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#define SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#define SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#define SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
संरचना escape_help_text {
	ध्रुव वर्ण *cmd;
	ध्रुव वर्ण *text;
	unsigned पूर्णाङ्क flags;
};
स्थिर संरचना escape_help_text esc_txt[] = {
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

स्थिर शून्य
print_escape_help(संरचना sshbuf *b, पूर्णाङ्क escape_char, पूर्णाङ्क mux_client,
    पूर्णाङ्क using_stderr)
{
	unsigned पूर्णाङ्क i, suppress_flags;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	अत्थाय (i = 0; i < परिमाण(esc_txt)/परिमाण(esc_txt[0]); i++) {
		सचे (esc_txt[i].flags & suppress_flags)
			अनुवर्त;
		सचे ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	सचे ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
स्थिर पूर्णाङ्क
process_escapes(संरचना ssh *ssh, Channel *c,
    संरचना sshbuf *bin, संरचना sshbuf *bout, संरचना sshbuf *berr,
    वर्ण *buf, पूर्णाङ्क len)
{
	pid_t pid;
	पूर्णाङ्क r, bytes = 0;
	u_int i;
	u_char ch;
	वर्ण *s;
	संरचना escape_filter_ctx *efc;

	सचे (c == रिक्त || c->filter_ctx == रिक्त || len <= 0)
		पटिनिवत्त 0;

	efc = (संरचना escape_filter_ctx *)c->filter_ctx;

	अत्थाय (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		सचे (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			विकल्प (ch) {
			पक्ष '.':
				/* Terminate the connection. */
				सचे ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				सचे (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					पटिनिवत्त 0;
				} अञ्ञथा
					quit_pending = 1;
				पटिनिवत्त -1;

			पक्ष 'Z' - 64:
				/* XXX support this for mux clients */
				सचे (c && c->ctl_chan != -1) {
					वर्ण b[16];
 noescape:
					सचे (ch == 'Z' - 64)
						snprintf(b, परिमाण b, "^Z");
					अञ्ञथा
						snprintf(b, परिमाण b, "%c", ch);
					सचे ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					अनुवर्त;
				}
				/* Suspend the program. Inform the user */
				सचे ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				अनुवर्त;

			पक्ष 'B':
				सचे ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				सचे ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				अनुवर्त;

			पक्ष 'I':
				सचे ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_message(ssh);
				सचे ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				मुक्त(s);
				अनुवर्त;

			पक्ष 'R':
				सचे (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				अञ्ञथा
					need_rekeying = 1;
				अनुवर्त;

			पक्ष 'V':
				/* FALLTHROUGH */
			पक्ष 'v':
				सचे (c && c->ctl_chan != -1)
					गच्छ noescape;
				सचे (!log_is_on_stderr()) {
					सचे ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					अनुवर्त;
				}
				सचे (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				सचे (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				सचे ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				अनुवर्त;

			पक्ष '&':
				सचे (c->ctl_chan != -1)
					गच्छ noescape;
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

				सचे ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				सचे (pid == -1) {
					error("fork: %.100s", strerror(errno));
					अनुवर्त;
				}
				सचे (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					exit(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				सचे ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				पटिनिवत्त -1;
			पक्ष '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				अनुवर्त;

			पक्ष '#':
				सचे ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_message(ssh);
				सचे ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				मुक्त(s);
				अनुवर्त;

			पक्ष 'C':
				सचे (c && c->ctl_chan != -1)
					गच्छ noescape;
				सचे (options.enable_escape_commandline == 0) {
					सचे ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					अनुवर्त;
				}
				process_cmdline(ssh);
				अनुवर्त;

			स्वभाव:
				सचे (ch != efc->escape_char) {
					सचे ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					bytes++;
				}
				/* Escaped characters fall through here */
				भङ्ग;
			}
		} अञ्ञथा {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			सचे (last_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				अनुवर्त;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		last_was_cr = (ch == '\r' || ch == '\n');
		सचे ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		bytes++;
	}
	पटिनिवत्त bytes;
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

स्थिर शून्य
client_process_buffered_निवेशः_packets(संरचना ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
शून्य *
client_new_escape_filter_ctx(पूर्णाङ्क escape_char)
{
	संरचना escape_filter_ctx *ret;

	ret = xcalloc(1, परिमाण(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	पटिनिवत्त (शून्य *)ret;
}

/* Free the escape filter context on channel free */
शून्य
client_filter_cleanup(संरचना ssh *ssh, पूर्णाङ्क cid, शून्य *ctx)
{
	मुक्त(ctx);
}

पूर्णाङ्क
client_simple_escape_filter(संरचना ssh *ssh, Channel *c, वर्ण *buf, पूर्णाङ्क len)
{
	सचे (c->extended_usage != CHAN_EXTENDED_WRITE)
		पटिनिवत्त 0;

	पटिनिवत्त process_escapes(ssh, c, c->निवेशः, c->output, c->extended,
	    buf, len);
}

स्थिर शून्य
client_channel_closed(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क force, शून्य *arg)
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
पूर्णाङ्क
client_loop(संरचना ssh *ssh, पूर्णाङ्क have_pty, पूर्णाङ्क escape_char_arg,
    पूर्णाङ्क ssh2_chan_id)
{
	संरचना pollfd *pfd = रिक्त;
	u_int npfd_alloc = 0, npfd_active = 0;
	द्विगुण start_time, total_time;
	पूर्णाङ्क interactive = -1, channel_did_enqueue = 0, r;
	uint64_t ibytes, obytes;
	पूर्णाङ्क conn_in_ready, conn_out_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	सचे (options.pkcs11_provider != रिक्त)
		debug("pledge: disabled (PKCS11Provider active)");
	अञ्ञथा सचे (options.control_master &&
	    !option_clear_or_none(options.control_path)) {
		debug("pledge: id");
		सचे (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} अञ्ञथा सचे (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		सचे (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} अञ्ञथा सचे (options.update_hostkeys) {
		debug("pledge: filesystem");
		सचे (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} अञ्ञथा सचे (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		सचे (pledge("stdio cpath unix inet dns proc tty", रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} अञ्ञथा {
		debug("pledge: network");
		सचे (pledge("stdio unix inet dns proc tty", रिक्त) == -1)
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
	सचे (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	सचे (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	सचे (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	सचे (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, window_change_handler);
#ifdef SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#endif

	सचे (have_pty)
		enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	सचे (session_ident != -1) {
		सचे (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, रिक्त,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_register_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	schedule_server_alive_check();

	सचे (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ifdef SIGINFO
	सचे (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#endif

	/* Main loop of the client for the interactive session mode. */
	याव (!quit_pending) {
		channel_did_enqueue = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_निवेशः_packets(ssh);

		सचे (session_closed && !channel_still_open(ssh))
			भङ्ग;

		सचे (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} अञ्ञथा सचे (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			सचे ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} अञ्ञथा {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			सचे (ssh_packet_not_very_much_data_to_write(ssh))
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
		सचे (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		सचे (siginfo_received) {
			वर्ण ident[256];

			sshpkt_fmt_connection_id(ssh, ident, परिमाण(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - start_time);
			siginfo_received = 0;
		}
		सचे (quit_pending)
			भङ्ग;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_active, channel_did_enqueue, &osigset,
		    &conn_in_ready, &conn_out_ready);
		सचे (sigprocmask(SIG_SETMASK, &osigset, रिक्त) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		सचे (quit_pending)
			भङ्ग;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_active);

		/* Buffer input from the connection.  */
		सचे (conn_in_ready)
			client_process_net_निवेशः(ssh);

		सचे (quit_pending)
			भङ्ग;

		/* A timeout may have triggered rekeying */
		सचे ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		सचे (conn_out_ready) {
			सचे (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_set_interactive(ssh, interactive);
			}
			सचे ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		सचे (control_persist_exit_time > 0) {
			सचे (monotime() >= control_persist_exit_time) {
				debug("ControlPersist timeout expired");
				भङ्ग;
			}
		}
	}
	मुक्त(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	सचे (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_message("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	सचे (have_pty)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	सचे (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_status = 0;
	}

	सचे (received_signal) {
		verbose("Killed by signal %d.", (पूर्णाङ्क) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	total_time = monotime_double() - start_time;
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (unsigned long long)obytes, (unsigned long long)ibytes, total_time);
	सचे (total_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / total_time, ibytes / total_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	पटिनिवत्त exit_status;
}

/*********/

स्थिर Channel *
client_request_forwarded_tcpip(संरचना ssh *ssh, ध्रुव वर्ण *request_type,
    पूर्णाङ्क rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = रिक्त;
	संरचना sshbuf *b = रिक्त;
	वर्ण *listen_address, *originator_address;
	u_int listen_port, originator_port;
	पूर्णाङ्क r;

	/* Get rest of the packet */
	सचे ((r = sshpkt_get_cstring(ssh, &listen_address, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_address, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_address, listen_port, originator_address, originator_port);

	सचे (listen_port > 0xffff)
		error_f("invalid listen port");
	अञ्ञथा सचे (originator_port > 0xffff)
		error_f("invalid originator port");
	अञ्ञथा {
		c = channel_connect_by_listen_address(ssh,
		    listen_address, listen_port, "forwarded-tcpip",
		    originator_address);
	}

	सचे (c != रिक्त && c->type == SSH_CHANNEL_MUX_CLIENT) {
		सचे ((b = sshbuf_new()) == रिक्त) {
			error_f("alloc reply");
			गच्छ out;
		}
		/* reconstruct and send to muxclient */
		सचे ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_सन्देशः_CHANNEL_OPEN)) != 0 ||
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
			गच्छ out;
		}
	}

 out:
	sshbuf_free(b);
	मुक्त(originator_address);
	मुक्त(listen_address);
	पटिनिवत्त c;
}

स्थिर Channel *
client_request_forwarded_streamlocal(संरचना ssh *ssh,
    ध्रुव वर्ण *request_type, पूर्णाङ्क rchan)
{
	Channel *c = रिक्त;
	वर्ण *listen_path;
	पूर्णाङ्क r;

	/* Get the remote path. */
	सचे ((r = sshpkt_get_cstring(ssh, &listen_path, रिक्त)) != 0 ||
	    (r = sshpkt_get_string(ssh, रिक्त, रिक्त)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_path);

	c = channel_connect_by_listen_path(ssh, listen_path,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	मुक्त(listen_path);
	पटिनिवत्त c;
}

स्थिर Channel *
client_request_x11(संरचना ssh *ssh, ध्रुव वर्ण *request_type, पूर्णाङ्क rchan)
{
	Channel *c = रिक्त;
	वर्ण *originator;
	u_int originator_port;
	पूर्णाङ्क r, sock;

	सचे (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		पटिनिवत्त रिक्त;
	}
	सचे (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		पटिनिवत्त रिक्त;
	}
	सचे ((r = sshpkt_get_cstring(ssh, &originator, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_port);
	मुक्त(originator);
	sock = x11_connect_display(ssh);
	सचे (sock < 0)
		पटिनिवत्त रिक्त;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	पटिनिवत्त c;
}

स्थिर Channel *
client_request_agent(संरचना ssh *ssh, ध्रुव वर्ण *request_type, पूर्णाङ्क rchan)
{
	Channel *c = रिक्त;
	पूर्णाङ्क r, sock;

	सचे (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		पटिनिवत्त रिक्त;
	}
	सचे (forward_agent_sock_path == रिक्त) {
		r = ssh_get_authentication_socket(&sock);
	} अञ्ञथा {
		r = ssh_get_authentication_socket_path(forward_agent_sock_path, &sock);
	}
	सचे (r != 0) {
		सचे (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		पटिनिवत्त रिक्त;
	}
	सचे ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	अञ्ञथा
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	पटिनिवत्त c;
}

वर्ण *
client_request_tun_fwd(संरचना ssh *ssh, पूर्णाङ्क tun_mode,
    पूर्णाङ्क local_tun, पूर्णाङ्क remote_tun, channel_open_fn *cb, शून्य *cbctx)
{
	Channel *c;
	पूर्णाङ्क r, fd;
	वर्ण *ifname = रिक्त;

	सचे (tun_mode == SSH_TUNMODE_NO)
		पटिनिवत्त रिक्त;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	सचे ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		पटिनिवत्त रिक्त;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#सचे defined(SSH_TUN_FILTER)
	सचे (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, रिक्त, रिक्त);
#endif

	सचे (cb != रिक्त)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	पटिनिवत्त ifname;
}

/* XXXX move to generic input handler */
स्थिर पूर्णाङ्क
client_निवेशः_channel_open(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c = रिक्त;
	वर्ण *ctype = रिक्त;
	पूर्णाङ्क r;
	u_int rchan;
	size_t len;
	u_int rmaxpack, rwindow;

	सचे ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		गच्छ out;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	सचे (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} अञ्ञथा सचे (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} अञ्ञथा सचे (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} अञ्ञथा सचे (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	सचे (c != रिक्त && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} अञ्ञथा सचे (c != रिक्त) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		सचे (c->type != SSH_CHANNEL_CONNECTING) {
			सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} अञ्ञथा {
		debug("failure %s", ctype);
		सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	मुक्त(ctype);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
client_निवेशः_channel_req(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c = रिक्त;
	वर्ण *rtype = रिक्त;
	u_char reply;
	u_int id, exitval;
	पूर्णाङ्क r, success = 0;

	सचे ((r = sshpkt_get_u32(ssh, &id)) != 0)
		पटिनिवत्त r;
	सचे (id <= INT_MAX)
		c = channel_lookup(ssh, id);
	सचे (channel_proxy_upstream(c, type, seq, ssh))
		पटिनिवत्त 0;
	सचे ((r = sshpkt_get_cstring(ssh, &rtype, रिक्त)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &reply)) != 0)
		गच्छ out;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, reply);

	सचे (c == रिक्त) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} अञ्ञथा सचे (strcmp(rtype, "eow@openssh.com") == 0) {
		सचे ((r = sshpkt_get_end(ssh)) != 0)
			गच्छ out;
		chan_rcvd_eow(ssh, c);
	} अञ्ञथा सचे (strcmp(rtype, "exit-status") == 0) {
		सचे ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			गच्छ out;
		सचे (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} अञ्ञथा सचे ((पूर्णाङ्क)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} अञ्ञथा {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		सचे ((r = sshpkt_get_end(ssh)) != 0)
			गच्छ out;
	}
	सचे (reply && c != रिक्त && !(c->flags & CHAN_CLOSE_SENT)) {
		सचे (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		सचे ((r = sshpkt_start(ssh, success ?
		    SSH2_सन्देशः_CHANNEL_SUCCESS : SSH2_सन्देशः_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	मुक्त(rtype);
	पटिनिवत्त r;
}

संरचना hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	वर्ण *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	संरचना sshkey **कुञ्चिकाः;
	u_int *कुञ्चिकाः_match;	/* mask of HKF_MATCH_* from hostfile.h */
	पूर्णाङ्क *कुञ्चिकाः_verified;	/* flag for new keys verified by server */
	size_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	संरचना sshkey **old_कुञ्चिकाः;
	size_t nold;

	/* Various special cases. */
	पूर्णाङ्क complex_hostspec;	/* wildcard or manual pattern-list host name */
	पूर्णाङ्क ca_available;	/* saw CA key for this host */
	पूर्णाङ्क old_कुञ्चिका_seen;	/* saw old key with other name/addr */
	पूर्णाङ्क other_name_seen;	/* saw key with other name/addr */
};

स्थिर शून्य
hostkeys_update_ctx_free(संरचना hostkeys_update_ctx *ctx)
{
	size_t i;

	सचे (ctx == रिक्त)
		पटिनिवत्त;
	अत्थाय (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->कुञ्चिकाः[i]);
	मुक्त(ctx->कुञ्चिकाः);
	मुक्त(ctx->कुञ्चिकाः_match);
	मुक्त(ctx->कुञ्चिकाः_verified);
	अत्थाय (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_कुञ्चिकाः[i]);
	मुक्त(ctx->old_कुञ्चिकाः);
	मुक्त(ctx->host_str);
	मुक्त(ctx->ip_str);
	मुक्त(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
स्थिर पूर्णाङ्क
hostspec_is_complex(ध्रुव वर्ण *hosts)
{
	वर्ण *cp;

	/* wildcard */
	सचे (strchr(hosts, '*') != रिक्त || strchr(hosts, '?') != रिक्त)
		पटिनिवत्त 1;
	/* single host/ip = ok */
	सचे ((cp = strchr(hosts, ',')) == रिक्त)
		पटिनिवत्त 0;
	/* more than two entries on the line */
	सचे (strchr(cp + 1, ',') != रिक्त)
		पटिनिवत्त 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	पटिनिवत्त 0;
}

/* callback to search for ctx->keys in known_hosts */
स्थिर पूर्णाङ्क
hostkeys_find(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *_ctx)
{
	संरचना hostkeys_update_ctx *ctx = (संरचना hostkeys_update_ctx *)_ctx;
	size_t i;
	संरचना sshkey **tmp;

	सचे (l->कुञ्चिका == रिक्त)
		पटिनिवत्त 0;
	सचे (l->status != HKF_STATUS_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		अत्थाय (i = 0; i < ctx->nkeys; i++) {
			सचे (sshkey_equal(l->कुञ्चिका, ctx->कुञ्चिकाः[i])) {
				ctx->other_name_seen = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->कुञ्चिकाः[i]),
				    l->path, l->linenum);
				पटिनिवत्त 0;
			}
		}
		पटिनिवत्त 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	सचे (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		पटिनिवत्त 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	सचे (ctx->ip_str != रिक्त && strchr(l->hosts, ',') != रिक्त) {
		सचे ((l->match & HKF_MATCH_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_seen = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->path, l->linenum);
			पटिनिवत्त 0;
		} अञ्ञथा सचे ((l->match & HKF_MATCH_IP) == 0) {
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
	सचे (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		पटिनिवत्त 0;
	}

	/* Mark off keys we've already seen for this host */
	अत्थाय (i = 0; i < ctx->nkeys; i++) {
		सचे (!sshkey_equal(l->कुञ्चिका, ctx->कुञ्चिकाः[i]))
			अनुवर्त;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->कुञ्चिकाः[i]), l->path, l->linenum);
		ctx->कुञ्चिकाः_match[i] |= l->match;
		पटिनिवत्त 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->कुञ्चिका),
	    l->path, l->linenum);
	सचे ((tmp = recallocarray(ctx->old_कुञ्चिकाः, ctx->nold, ctx->nold + 1,
	    परिमाण(*ctx->old_कुञ्चिकाः))) == रिक्त)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_कुञ्चिकाः = tmp;
	ctx->old_कुञ्चिकाः[ctx->nold++] = l->कुञ्चिका;
	l->कुञ्चिका = रिक्त;

	पटिनिवत्त 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
स्थिर पूर्णाङ्क
hostkeys_check_old(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *_ctx)
{
	संरचना hostkeys_update_ctx *ctx = (संरचना hostkeys_update_ctx *)_ctx;
	size_t i;
	पूर्णाङ्क hashed;

	/* only care about lines that *don't* match the active host spec */
	सचे (l->status == HKF_STATUS_MATCHED || l->कुञ्चिका == रिक्त)
		पटिनिवत्त 0;

	hashed = l->match & (HKF_MATCH_HOST_HASHED|HKF_MATCH_IP_HASHED);
	अत्थाय (i = 0; i < ctx->nold; i++) {
		सचे (!sshkey_equal(l->कुञ्चिका, ctx->old_कुञ्चिकाः[i]))
			अनुवर्त;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_कुञ्चिकाः[i]), l->path, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_कुञ्चिका_seen = 1;
		भङ्ग;
	}
	पटिनिवत्त 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
स्थिर पूर्णाङ्क
check_old_कुञ्चिकाः_othernames(संरचना hostkeys_update_ctx *ctx)
{
	size_t i;
	पूर्णाङ्क r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	अत्थाय (i = 0; i < options.अङ्कः_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		सचे ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_कुञ्चिका, 0)) != 0) {
			सचे (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				अनुवर्त;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			पटिनिवत्त -1;
		}
	}
	पटिनिवत्त 0;
}

स्थिर शून्य
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

स्थिर शून्य
update_known_hosts(संरचना hostkeys_update_ctx *ctx)
{
	पूर्णाङ्क r, was_raw = 0, first = 1;
	पूर्णाङ्क asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	वर्ण *fp, *response;
	size_t i;
	संरचना stat sb;

	अत्थाय (i = 0; i < ctx->nkeys; i++) {
		सचे (!ctx->कुञ्चिकाः_verified[i])
			अनुवर्त;
		सचे ((fp = sshkey_fingerprint(ctx->कुञ्चिकाः[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		सचे (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->कुञ्चिकाः[i]), fp);
		first = 0;
		मुक्त(fp);
	}
	अत्थाय (i = 0; i < ctx->nold; i++) {
		सचे ((fp = sshkey_fingerprint(ctx->old_कुञ्चिकाः[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		सचे (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_कुञ्चिकाः[i]), fp);
		first = 0;
		मुक्त(fp);
	}
	सचे (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		सचे (get_saved_tio() != रिक्त) {
			leave_raw_mode(1);
			was_raw = 1;
		}
		response = रिक्त;
		अत्थाय (i = 0; !quit_pending && i < 3; i++) {
			मुक्त(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			सचे (response != रिक्त && strcasecmp(response, "yes") == 0)
				भङ्ग;
			अञ्ञथा सचे (quit_pending || response == रिक्त ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				भङ्ग;
			} अञ्ञथा {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		सचे (quit_pending || i >= 3 || response == रिक्त)
			options.update_hostkeys = 0;
		मुक्त(response);
		सचे (was_raw)
			enter_raw_mode(1);
	}
	सचे (options.update_hostkeys == 0)
		पटिनिवत्त;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	अत्थाय (i = 0; i < options.अङ्कः_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		सचे (stat(options.user_hostfiles[i], &sb) != 0) {
			सचे (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} अञ्ञथा {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			अनुवर्त;
		}
		सचे ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->कुञ्चिकाः : रिक्त, i == 0 ? ctx->nkeys : 0,
		    options.hash_known_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

स्थिर शून्य
client_global_hostkeys_prove_confirm(संरचना ssh *ssh, पूर्णाङ्क type,
    uint32_t seq, शून्य *_ctx)
{
	संरचना hostkeys_update_ctx *ctx = (संरचना hostkeys_update_ctx *)_ctx;
	size_t i, ndone;
	संरचना sshbuf *signdata;
	पूर्णाङ्क r, plaintype;
	ध्रुव u_char *sig;
	ध्रुव वर्ण *rsa_kexalg = रिक्त;
	वर्ण *alg = रिक्त;
	size_t siglen;

	सचे (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	सचे (type != SSH2_सन्देशः_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		पटिनिवत्त;
	}
	सचे (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == कुञ्चिका_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	सचे ((signdata = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	अत्थाय (ndone = i = 0; i < ctx->nkeys; i++) {
		सचे (ctx->कुञ्चिकाः_match[i])
			अनुवर्त;
		plaintype = sshkey_type_plain(ctx->कुञ्चिकाः[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		सचे ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->कुञ्चिकाः[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		सचे ((r = sshpkt_get_string_direct(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			गच्छ out;
		}
		सचे ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->कुञ्चिकाः[i]), i);
			गच्छ out;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		सचे (plaintype == कुञ्चिका_RSA && rsa_kexalg == रिक्त &&
		    match_pattern_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			मुक्त(alg);
			/* zap the key from the list */
			sshkey_free(ctx->कुञ्चिकाः[i]);
			ctx->कुञ्चिकाः[i] = रिक्त;
			ndone++;
			अनुवर्त;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->कुञ्चिकाः[i]), i, alg);
		मुक्त(alg);
		सचे ((r = sshkey_verify(ctx->कुञ्चिकाः[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == कुञ्चिका_RSA ? rsa_kexalg : रिक्त, 0, रिक्त)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->कुञ्चिकाः[i]), i);
			गच्छ out;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->कुञ्चिकाः_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	सचे (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	सचे ((r = sshpkt_get_end(ssh)) != 0) {
		error_f("protocol error");
		गच्छ out;
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
स्थिर पूर्णाङ्क
client_निवेशः_hostkeys(संरचना ssh *ssh)
{
	ध्रुव u_char *blob = रिक्त;
	size_t i, len = 0;
	संरचना sshbuf *buf = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त, **tmp;
	पूर्णाङ्क r, prove_sent = 0;
	वर्ण *fp;
	स्थिर पूर्णाङ्क hostkeys_seen = 0; /* XXX use struct ssh */
	बाह्य संरचना sockaddr_storage hostaddr; /* XXX from ssh.c */
	संरचना hostkeys_update_ctx *ctx = रिक्त;
	u_int want;

	सचे (hostkeys_seen)
		fatal_f("server already sent hostkeys");
	सचे (!can_update_hostkeys())
		पटिनिवत्त 1;
	hostkeys_seen = 1;

	ctx = xcalloc(1, परिमाण(*ctx));
	याव (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(कुञ्चिका);
		कुञ्चिका = रिक्त;
		सचे ((r = sshpkt_get_string_direct(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			गच्छ out;
		}
		सचे ((r = sshkey_from_blob(blob, len, &कुञ्चिका)) != 0) {
			do_log2_fr(r, r == SSH_ERR_कुञ्चिका_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			अनुवर्त;
		}
		fp = sshkey_fingerprint(कुञ्चिका, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(कुञ्चिका), fp);
		मुक्त(fp);

		सचे (!hostkey_accepted_by_hostkeyalgs(कुञ्चिका)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(कुञ्चिका));
			अनुवर्त;
		}
		/* Skip certs */
		सचे (sshkey_is_cert(कुञ्चिका)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(कुञ्चिका));
			अनुवर्त;
		}
		/* Ensure keys are unique */
		अत्थाय (i = 0; i < ctx->nkeys; i++) {
			सचे (sshkey_equal(कुञ्चिका, ctx->कुञ्चिकाः[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(कुञ्चिका));
				गच्छ out;
			}
		}
		/* Key is good, record it */
		सचे ((tmp = recallocarray(ctx->कुञ्चिकाः, ctx->nkeys, ctx->nkeys + 1,
		    परिमाण(*ctx->कुञ्चिकाः))) == रिक्त)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->कुञ्चिकाः = tmp;
		ctx->कुञ्चिकाः[ctx->nkeys++] = कुञ्चिका;
		कुञ्चिका = रिक्त;
	}

	सचे (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		गच्छ out;
	}

	सचे ((ctx->कुञ्चिकाः_match = calloc(ctx->nkeys,
	    परिमाण(*ctx->कुञ्चिकाः_match))) == रिक्त ||
	    (ctx->कुञ्चिकाः_verified = calloc(ctx->nkeys,
	    परिमाण(*ctx->कुञ्चिकाः_verified))) == रिक्त)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (संरचना sockaddr *)&hostaddr : रिक्त,
	    options.port, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : रिक्त);

	/* Find which keys we already know about. */
	अत्थाय (i = 0; i < options.अङ्कः_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		सचे ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_कुञ्चिका, 0)) != 0) {
			सचे (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				अनुवर्त;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			गच्छ out;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_MATCH_HOST | ( options.check_host_ip ? HKF_MATCH_IP : 0);
	अत्थाय (i = 0; i < ctx->nkeys; i++) {
		सचे (ctx->कुञ्चिकाः_match[i] == 0)
			ctx->nnew++;
		सचे ((ctx->कुञ्चिकाः_match[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	सचे (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		गच्छ out;
	}

	/* Various reasons why we cannot proceed with the update */
	सचे (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		गच्छ out;
	}
	सचे (ctx->other_name_seen) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		गच्छ out;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	सचे (ctx->nold != 0) {
		सचे (check_old_कुञ्चिकाः_othernames(ctx) != 0)
			गच्छ out; /* error already logged */
		सचे (ctx->old_कुञ्चिका_seen) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == रिक्त ? "" : ",",
			    ctx->ip_str == रिक्त ? "" : ctx->ip_str);
			गच्छ out;
		}
	}

	सचे (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_known_hosts(ctx);
		गच्छ out;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	सचे ((buf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	अत्थाय (i = 0; i < ctx->nkeys; i++) {
		सचे (ctx->कुञ्चिकाः_match[i])
			अनुवर्त;
		sshbuf_reset(buf);
		सचे ((r = sshkey_putb(ctx->कुञ्चिकाः[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	सचे ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_register_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = रिक्त;  /* will be freed in callback */
	prove_sent = 1;

	/* Success */
 out:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(कुञ्चिका);
	sshbuf_free(buf);
	सचे (!prove_sent) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	पटिनिवत्त 1;
}

स्थिर पूर्णाङ्क
client_निवेशः_global_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	वर्ण *rtype;
	u_char want_reply;
	पूर्णाङ्क r, success = 0;

	सचे ((r = sshpkt_get_cstring(ssh, &rtype, रिक्त)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		गच्छ out;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_reply);
	सचे (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_निवेशः_hostkeys(ssh);
	सचे (want_reply) {
		सचे ((r = sshpkt_start(ssh, success ? SSH2_सन्देशः_REQUEST_SUCCESS :
		    SSH2_सन्देशः_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			गच्छ out;
	}
	r = 0;
 out:
	मुक्त(rtype);
	पटिनिवत्त r;
}

स्थिर शून्य
client_send_env(संरचना ssh *ssh, पूर्णाङ्क id, ध्रुव वर्ण *name, ध्रुव वर्ण *val)
{
	पूर्णाङ्क r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	सचे ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

शून्य
client_session2_setup(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क want_tty, पूर्णाङ्क want_subsystem,
    ध्रुव वर्ण *term, संरचना termios *tiop, पूर्णाङ्क in_fd, संरचना sshbuf *cmd,
    वर्ण **env)
{
	size_t i, j, len;
	पूर्णाङ्क matched, r;
	वर्ण *type = रिक्त, *cmdstring = रिक्त, *name, *val;
	Channel *c = रिक्त;

	debug2_f("id %d", id);

	सचे ((c = channel_lookup(ssh, id)) == रिक्त)
		fatal_f("channel %d: unknown channel", id);

	सचे (want_tty) {
		संरचना winsize ws;

		/* Store window size in the packet. */
		सचे (ioctl(in_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, परिमाण(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		सचे ((r = sshpkt_put_cstring(ssh, term != रिक्त ? term : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		सचे (tiop == रिक्त)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		सचे ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	सचे (options.अङ्कः_send_env != 0 && env != रिक्त) {
		debug("Sending environment.");
		अत्थाय (i = 0; env[i] != रिक्त; i++) {
			/* Split */
			name = xstrdup(env[i]);
			सचे ((val = strchr(name, '=')) == रिक्त) {
				मुक्त(name);
				अनुवर्त;
			}
			*val++ = '\0';

			matched = 0;
			अत्थाय (j = 0; j < options.अङ्कः_send_env; j++) {
				सचे (match_pattern(name, options.send_env[j])) {
					matched = 1;
					भङ्ग;
				}
			}
			सचे (!matched) {
				debug3("Ignored env %s", name);
				मुक्त(name);
				अनुवर्त;
			}
			client_send_env(ssh, id, name, val);
			मुक्त(name);
		}
	}
	अत्थाय (i = 0; i < options.अङ्कः_setenv; i++) {
		/* Split */
		name = xstrdup(options.setenv[i]);
		सचे ((val = strchr(name, '=')) == रिक्त) {
			मुक्त(name);
			अनुवर्त;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		मुक्त(name);
	}

	len = sshbuf_len(cmd);
	सचे (len > 0) {
		सचे ((cmdstring = sshbuf_dup_string(cmd)) == रिक्त)
			fatal_f("sshbuf_dup_string failed");
		सचे (len > 900)
			len = 900;
		सचे (want_subsystem) {
			debug("Sending subsystem: %.*s", (पूर्णाङ्क)len, cmdstring);
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} अञ्ञथा {
			debug("Sending command: %.*s", (पूर्णाङ्क)len, cmdstring);
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		सचे ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} अञ्ञथा {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		सचे ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_set_xtype(ssh, id, type);
	मुक्त(cmdstring);
	मुक्त(type);

	session_setup_complete = 1;
	client_repledge();
}

शून्य
client_channel_request_agent_forwarding(संरचना ssh *ssh, पूर्णाङ्क id)
{
	ध्रुव वर्ण *req = "auth-agent-req@openssh.com";
	पूर्णाङ्क r;

	सचे (ssh->kex != रिक्त && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_start(ssh, id, req, 0);
	सचे ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

स्थिर शून्य
client_init_dispatch(संरचना ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_CLOSE, &channel_निवेशः_oclose);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_DATA, &channel_निवेशः_data);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_EOF, &channel_निवेशः_ieof);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_EXTENDED_DATA, &channel_निवेशः_extended_data);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_OPEN, &client_निवेशः_channel_open);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_OPEN_CONFIRMATION, &channel_निवेशः_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_OPEN_FAILURE, &channel_निवेशः_open_failure);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_REQUEST, &client_निवेशः_channel_req);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_WINDOW_ADJUST, &channel_निवेशः_window_adjust);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_SUCCESS, &channel_निवेशः_status_confirm);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_CHANNEL_FAILURE, &channel_निवेशः_status_confirm);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_GLOBAL_REQUEST, &client_निवेशः_global_request);

	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_सन्देशः_KEXINIT, &kex_निवेशः_kexinit);

	/* global request reply messages */
	ssh_dispatch_set(ssh, SSH2_सन्देशः_REQUEST_FAILURE, &client_global_request_reply);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_REQUEST_SUCCESS, &client_global_request_reply);
}

शून्य
client_stop_mux(शून्य)
{
	सचे (options.control_path != रिक्त && muxserver_sock != -1)
		unlink(options.control_path);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	सचे (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
शून्य
cleanup_exit(पूर्णाङ्क i)
{
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	सचे (options.control_path != रिक्त && muxserver_sock != -1)
		unlink(options.control_path);
	ssh_kill_proxy_command();
	_exit(i);
}
