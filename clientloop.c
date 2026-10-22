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
#परिभाषय HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#परिभाषय SSH_KEYSTROKE_TIMING_FUZZ 10

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
बाह्य वर्ण *forward_agent_sock_मार्गः;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
स्थिर चञ्चल sig_atomic_t received_गवाक्षः_change_signal = 0;
स्थिर चञ्चल sig_atomic_t siginfo_received = 0;
स्थिर चञ्चल sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
स्थिर time_t control_persist_exit_time = 0;

/* Common data for the client loop code. */
चञ्चल sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
स्थिर पूर्णाङ्क चरमः_was_cr;		/* Last character was a newline. */
स्थिर पूर्णाङ्क exit_स्थितिः;		/* Used to store the command exit status. */
स्थिर पूर्णाङ्क connection_अन्तर्;	/* Connection to server (input). */
स्थिर पूर्णाङ्क connection_बहिर्गमनम्;	/* Connection to server (output). */
स्थिर पूर्णाङ्क need_rekeying;	/* Set to non-zero if rekeying is requested. */
स्थिर पूर्णाङ्क session_closed;	/* In SSH2: login session closed. */
स्थिर time_t x11_refuse_time;	/* If >0, refuse x11 opens after this time. */
स्थिर time_t server_alive_time;	/* Time to do server_alive_check */
स्थिर पूर्णाङ्क hostkeys_update_complete;
स्थिर पूर्णाङ्क session_सज्जता_complete;

स्थिर शून्य client_init_dispatch(संरचना ssh *ssh);
पूर्णाङ्क	session_ident = -1;

/* Track escape per proto2 channel */
संरचना escape_filter_ctx {
	पूर्णाङ्क escape_pending;
	पूर्णाङ्क escape_char;
};

/* Context for channel confirmation replies */
संरचना channel_प्रत्युत्तरम्_ctx {
	ध्रुव वर्ण *request_type;
	पूर्णाङ्क id;
	गणना confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
संरचना global_confirm {
	TAILQ_ENTRY(global_confirm) प्रविष्टिः;
	global_confirm_cb *cb;
	शून्य *ctx;
	पूर्णाङ्क ref_गणनम्;
};
TAILQ_HEAD(global_confirms, global_confirm);
स्थिर संरचना global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

स्थिर शून्य quit_सन्देशः(ध्रुव वर्ण *fmt, ...)
    __attribute__((__format__ (प्रारूप_लिख, 1, 2)));

स्थिर शून्य
quit_सन्देशः(ध्रुव वर्ण *fmt, ...)
{
	वर्ण *सन्देशः, *fmt2;
	va_list तर्काः;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(तर्काः, fmt);
	xvasprintf(&सन्देशः, fmt2, तर्काः);
	va_end(तर्काः);

	(शून्य)atomicio(vwrite, STDERR_FILENO, सन्देशः, वाक्यदैर्घ्यम्(सन्देशः));
	मुक्त(सन्देशः);
	मुक्त(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
स्थिर शून्य
गवाक्षः_change_handler(पूर्णाङ्क sig)
{
	received_गवाक्षः_change_signal = 1;
}

#यदि_परिभाषितम् SIGINFO
/* Signal handler for SIGINFO */
स्थिर शून्य
siginfo_handler(पूर्णाङ्क sig)
{
	siginfo_received = 1;
}
#यदि_अन्तः

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
समुच्चयः_control_persist_exit_time(संरचना ssh *ssh)
{
	यदि (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} अन्यथा यदि (channel_still_open(ssh)) {
		/* some client connections are still open */
		यदि (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} अन्यथा यदि (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#परिभाषय SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
स्थिर पूर्णाङ्क
client_x11_display_valid(ध्रुव वर्ण *display)
{
	आकार_t i, dlen;

	यदि (display == रिक्त)
		प्रत्यागम 0;

	dlen = वाक्यदैर्घ्यम्(display);
	प्रति (i = 0; i < dlen; i++) {
		यदि (!अक्षरम्_अङ्कः_वा((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == रिक्त) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			प्रत्यागम 0;
		}
	}
	प्रत्यागम 1;
}

#परिभाषय SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#परिभाषय X11_TIMEOUT_SLACK	60
पूर्णाङ्क
client_x11_get_proto(संरचना ssh *ssh, ध्रुव वर्ण *display,
    ध्रुव वर्ण *xauth_मार्गः, u_int trusted, u_int timeout,
    वर्ण **_proto, वर्ण **दत्त_2)
{
	वर्ण *cmd, पङ्क्तिः[512], xdisplay[512];
	वर्ण xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	स्थिर वर्ण proto[512], दत्त[512];
	FILE *f;
	पूर्णाङ्क got_दत्त = 0, generated = 0, do_unlink = 0, r;
	संरचना stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*दत्त_2 = दत्त;
	proto[0] = दत्त[0] = xauthfile[0] = xauthdir[0] = '\0';

	यदि (!client_x11_display_valid(display)) {
		यदि (display != रिक्त)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		प्रत्यागम -1;
	}
	यदि (xauth_मार्गः != रिक्त && stat(xauth_मार्गः, &st) == -1) {
		debug("No xauth program.");
		xauth_मार्गः = रिक्त;
	}

	यदि (xauth_मार्गः != रिक्त) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		यदि (वाक्ये_तुलय(display, "localhost:", 10) == 0) {
			यदि ((r = snprintf(xdisplay, परिमाण(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (आकार_t)r >= परिमाण(xdisplay)) {
				error_f("display name too long");
				प्रत्यागम -1;
			}
			display = xdisplay;
		}
		यदि (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, परिमाण(xauthdir));
			यदि (mkdtemp(xauthdir) == रिक्त) {
				error_f("mkdtemp: %s", strerror(errno));
				प्रत्यागम -1;
			}
			do_unlink = 1;
			यदि ((r = snprintf(xauthfile, परिमाण(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (आकार_t)r >= परिमाण(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				प्रत्यागम -1;
			}

			यदि (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_मार्गः, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} अन्यथा {
				/* Add some slack to requested expiry */
				यदि (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				अन्यथा {
					/* Don't overflow on long timeouts */
					x11_timeout_real = UINT_MAX;
				}
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted timeout %u 2>%s",
				    xauth_मार्गः, xauthfile, display,
				    SSH_X11_PROTO, x11_timeout_real,
				    _PATH_DEVNULL);
			}
			debug2_f("xauth command: %s", cmd);

			यदि (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				यदि (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				अन्यथा
					x11_refuse_time = now + timeout;
				channel_समुच्चयः_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			यदि (system(cmd) == 0)
				generated = 1;
			मुक्त(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		यदि (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_मार्गः,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			यदि (f && fgets(पङ्क्तिः, परिमाण(पङ्क्तिः), f) &&
			    वाक्यात्_पठ(पङ्क्तिः, "%*s %511s %511s", proto, दत्त) == 2)
				got_दत्त = 1;
			यदि (f)
				pclose(f);
			मुक्त(cmd);
		}
	}

	यदि (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	यदि (!trusted && !got_दत्त) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		प्रत्यागम -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	यदि (!got_दत्त) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, परिमाण proto);
		arc4random_buf(rnd, परिमाण(rnd));
		प्रति (i = 0; i < परिमाण(rnd); i++) {
			snprintf(दत्त + 2 * i, परिमाण दत्त - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	प्रत्यागम 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

स्थिर शून्य
client_check_गवाक्षः_change(संरचना ssh *ssh)
{
	यदि (!received_गवाक्षः_change_signal)
		प्रत्यागम;
	received_गवाक्षः_change_signal = 0;
	debug2_f("changed");
	channel_send_गवाक्षः_changes(ssh);
}

स्थिर पूर्णाङ्क
client_global_request_प्रत्युत्तरम्(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना global_confirm *gc;

	यदि ((gc = TAILQ_FIRST(&global_confirms)) == रिक्त)
		प्रत्यागम 0;
	यदि (gc->cb != रिक्त)
		gc->cb(ssh, type, seq, gc->ctx);
	यदि (--gc->ref_गणनम् <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, प्रविष्टिः);
		freezero(gc, परिमाण(*gc));
	}

	ssh_packet_समुच्चयः_alive_timeouts(ssh, 0);
	प्रत्यागम 0;
}

स्थिर शून्य
कालसारणी_server_alive_check(शून्य)
{
	यदि (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

स्थिर शून्य
server_alive_check(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	यदि (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_गणनम्_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_पञ्जिकाकोशः_global_confirm(रिक्त, रिक्त);
	कालसारणी_server_alive_check();
}

/* Try to send a dummy keystroke */
स्थिर पूर्णाङ्क
send_chaff(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	यदि (ssh->kex == रिक्त || (ssh->kex->flags & KEX_HAS_PING) == 0)
		प्रत्यागम 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	प्रत्यागम 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
स्थिर शून्य
समुच्चयः_अग्र_interval(ध्रुव संरचना timespec *now, संरचना timespec *अग्र_interval,
    u_int interval_ms, पूर्णाङ्क starting)
{
	संरचना timespec tmp;
	दीर्घ दीर्घ interval_ns, fuzz_ns;
	स्थिर दीर्घ दीर्घ दरः_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	यदि (fuzz_ns > अधिकतम_पूर्णाङ्कः)
		fuzz_ns = अधिकतम_पूर्णाङ्कः;
	यदि (fuzz_ns > interval_ns) {
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
	यदि (starting)
		दरः_fuzz = arc4random_एकरूपम्(fuzz_ns);
	interval_ns -= fuzz_ns;
	interval_ns += arc4random_एकरूपम्(fuzz_ns) + दरः_fuzz;

	tmp.tv_sec = interval_ns / (1000 * 1000 * 1000);
	tmp.tv_nsec = interval_ns % (1000 * 1000 * 1000);

	timespecadd(now, &tmp, अग्र_interval);
}

/*
 * Performs keystroke timing obfuscation. Returns non-zero if the
 * output fd should be polled.
 */
स्थिर पूर्णाङ्क
obfuscate_keystroke_timing(संरचना ssh *ssh, संरचना timespec *timeout,
    पूर्णाङ्क channel_did_पङ्क्तौ_निक्षिप)
{
	स्थिर पूर्णाङ्क सक्रिय;
	स्थिर संरचना timespec अग्र_interval, chaff_until;
	संरचना timespec now, tmp;
	पूर्णाङ्क just_started = 0, had_keystroke = 0;
	स्थिर अचिह्नित दीर्घ दीर्घ nchaff;
	वर्ण *stop_reason = रिक्त;
	दीर्घ दीर्घ n;

	monotime_ts(&now);

	यदि (options.obscure_keystroke_timing_interval <= 0)
		प्रत्यागम 1;	/* disabled in config */

	यदि (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} अन्यथा यदि (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} अन्यथा यदि (!ssh_packet_interactive_दत्त_गन्तव्यम्_write(ssh) &&
	    ssh_packet_have_दत्त_गन्तव्यम्_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} अन्यथा यदि (सक्रिय && channel_did_पङ्क्तौ_निक्षिप &&
	    ssh_packet_have_दत्त_गन्तव्यम्_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} अन्यथा यदि (सक्रिय) {
		यदि (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} अन्यथा यदि (timespeccmp(&now, &अग्र_interval, >=) &&
		    !ssh_packet_have_दत्त_गन्तव्यम्_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			यदि (send_chaff(ssh))
				nchaff++;
		}
	}

	यदि (stop_reason != रिक्त) {
		यदि (सक्रिय) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			सक्रिय = 0;
		}
		प्रत्यागम 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	यदि (!सक्रिय && ssh_packet_interactive_दत्त_गन्तव्यम्_write(ssh) &&
	    channel_did_पङ्क्तौ_निक्षिप && ssh_packet_have_दत्त_गन्तव्यम्_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = सक्रिय = 1;
		nchaff = 0;
		समुच्चयः_अग्र_interval(&now, &अग्र_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	यदि (!सक्रिय)
		प्रत्यागम 1;

	यदि (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_गन्तव्यम्_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_एकरूपम्(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &अग्र_interval);

	यदि (just_started)
		प्रत्यागम 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	यदि (timespeccmp(&now, &अग्र_interval, <))
		/* ...unless there's x11 communication happening */
		प्रत्यागम x11_channel_प्रयुक्तम्_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - अग्र_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - अग्र_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	समुच्चयः_अग्र_interval(&now, &अग्र_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	प्रत्यागम 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
स्थिर शून्य
client_wait_until_can_do_something(संरचना ssh *ssh, संरचना pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, पूर्णाङ्क channel_did_पङ्क्तौ_निक्षिप,
    sigset_t *sigsetp, पूर्णाङ्क *conn_अन्तर्_readyp, पूर्णाङ्क *conn_बहिर्गमनम्_readyp)
{
	संरचना timespec timeout;
	पूर्णाङ्क ret, oready;
	u_int p;

	*conn_अन्तर्_readyp = *conn_बहिर्गमनम्_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	यदि (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	यदि (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_दत्त_गन्तव्यम्_write(ssh)) {
		/* clear events since we did not call poll() */
		प्रति (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		प्रत्यागम;
	}

	oready = obfuscate_keystroke_timing(ssh, &timeout, channel_did_पङ्क्तौ_निक्षिप);

	/* Monitor server connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_अन्तर्;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_बहिर्गमनम्;
	(*pfdp)[1].events = (oready && ssh_packet_have_दत्त_गन्तव्यम्_write(ssh)) ?
	    POLLOUT : 0;

	/*
	 * Wait for something to happen.  This will suspend the process until
	 * some polled descriptor can be read, written, or has some other
	 * event pending, or a timeout expires.
	 */
	समुच्चयः_control_persist_exit_time(ssh);
	यदि (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	यदि (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	यदि (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	यदि (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		प्रति (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		यदि (errno == EINTR)
			प्रत्यागम;
		/* Note: we might still have data in the buffers. */
		quit_सन्देशः("poll: %s", strerror(errno));
		प्रत्यागम;
	}

	*conn_अन्तर्_readyp = (*pfdp)[0].revents != 0;
	*conn_बहिर्गमनम्_readyp = (*pfdp)[1].revents != 0;

	यदि (options.server_alive_interval > 0 && !*conn_अन्तर्_readyp &&
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
	यदि (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	यदि (sshbuf_len(berr) > 0)
		atomicio(vwrite, fileno(stderr), sshbuf_mutable_ptr(berr),
		    sshbuf_len(berr));

	leave_raw_बहुलकम्(options.request_tty == REQUEST_TTY_FORCE);

	sshbuf_reset(bin);
	sshbuf_reset(bout);
	sshbuf_reset(berr);

	/* Send the suspend signal to the program itself. */
	kill(getpid(), SIGTSTP);

	/* Reset window sizes in case they have changed */
	received_गवाक्षः_change_signal = 1;

	enter_raw_बहुलकम्(options.request_tty == REQUEST_TTY_FORCE);
}

स्थिर शून्य
client_process_net_निवेशः(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	कालसारणी_server_alive_check();
	यदि ((r = ssh_packet_process_read(ssh, connection_अन्तर्)) == 0)
		प्रत्यागम; /* success */
	यदि (r == SSH_ERR_SYSTEM_ERROR) {
		यदि (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			प्रत्यागम;
		यदि (errno == EPIPE) {
			quit_सन्देशः("Connection to %s closed by remote host.",
			    host);
			प्रत्यागम;
		}
	}
	quit_सन्देशः("Read from remote host %s: %s", host, ssh_err(r));
}

स्थिर शून्य
client_स्थितिः_confirm(संरचना ssh *ssh, पूर्णाङ्क type, Channel *c, शून्य *ctx)
{
	संरचना channel_प्रत्युत्तरम्_ctx *cr = (संरचना channel_प्रत्युत्तरम्_ctx *)ctx;
	वर्ण errmsg[256];
	पूर्णाङ्क r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	यदि (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	यदि (type == SSH2_सन्देशः_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} अन्यथा यदि (type == SSH2_सन्देशः_CHANNEL_FAILURE) {
		यदि (tochan) {
			snprintf(errmsg, परिमाण(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} अन्यथा {
			snprintf(errmsg, परिमाण(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		यदि (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		यदि (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			यदि ((r = sshbuf_put(c->extended, errmsg,
			    वाक्यदैर्घ्यम्(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} अन्यथा
			error("%s", errmsg);
		यदि (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			यदि (c->self == session_ident)
				leave_raw_बहुलकम्(0);
			अन्यथा
				mux_tty_alloc_failed(ssh, c);
		} अन्यथा यदि (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	मुक्त(cr);
}

स्थिर शून्य
client_abandon_स्थितिः_confirm(संरचना ssh *ssh, Channel *c, शून्य *ctx)
{
	मुक्त(ctx);
}

शून्य
client_expect_confirm(संरचना ssh *ssh, पूर्णाङ्क id, ध्रुव वर्ण *request,
    गणना confirm_action action)
{
	संरचना channel_प्रत्युत्तरम्_ctx *cr = xcalloc(1, परिमाण(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_पञ्जिकाकोशः_स्थितिः_confirm(ssh, id, client_स्थितिः_confirm,
	    client_abandon_स्थितिः_confirm, cr);
}

शून्य
client_पञ्जिकाकोशः_global_confirm(global_confirm_cb *cb, शून्य *ctx)
{
	संरचना global_confirm *gc, *चरमः_gc;

	/* Coalesce identical callbacks */
	चरमः_gc = TAILQ_LAST(&global_confirms, global_confirms);
	यदि (चरमः_gc && चरमः_gc->cb == cb && चरमः_gc->ctx == ctx) {
		यदि (++चरमः_gc->ref_गणनम् >= अधिकतम_पूर्णाङ्कः)
			fatal_f("last_gc->ref_count = %d",
			    चरमः_gc->ref_गणनम्);
		प्रत्यागम;
	}

	gc = xcalloc(1, परिमाण(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_गणनम् = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, प्रविष्टिः);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
स्थिर पूर्णाङ्क
can_update_hostkeys(शून्य)
{
	यदि (hostkeys_update_complete)
		प्रत्यागम 0;
	यदि (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_बहुलकम्)
		प्रत्यागम 0; /* won't ask in batchmode, so don't even try */
	यदि (!options.update_hostkeys || options.अङ्कः_user_hostfiles <= 0)
		प्रत्यागम 0;
	प्रत्यागम 1;
}

स्थिर शून्य
client_repledge(शून्य)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	यदि (options.control_master || options.control_मार्गः != रिक्त ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != रिक्त || can_update_hostkeys() ||
	    (session_ident != -1 && !session_सज्जता_complete)) {
		/* Can't tighten */
		प्रत्यागम;
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
	यदि (options.अङ्कः_local_forwards != 0 ||
	    options.अङ्कः_remote_forwards != 0 ||
	    options.अङ्कः_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		यदि (pledge("stdio unix inet dns proc tty", रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} अन्यथा यदि (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		यदि (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} अन्यथा {
		debug("pledge: fork");
		यदि (pledge(PLEDGE_EXTRA_INET "stdio proc tty", रिक्त) == -1)
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

	स्मृतिं_पूरय(&fwd, 0, परिमाण(fwd));

	leave_raw_बहुलकम्(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	यदि (s == रिक्त)
		गच्छ बहिर्गमनम्;
	यावत् (रिक्तम्_वा((u_char)*s))
		s++;
	यदि (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	यदि (*s == '\0')
		गच्छ बहिर्गमनम्;

	यदि (*s == 'h' || *s == 'H' || *s == '?') {
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
		यदि (!options.permit_local_command)
			गच्छ बहिर्गमनम्;
		logit("      !args                                  "
		    "Execute local command");
		गच्छ बहिर्गमनम्;
	}

	यदि (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		गच्छ बहिर्गमनम्;
	}

	यदि (*s == 'K') {
		delete = 1;
		s++;
	}
	यदि (*s == 'L')
		local = 1;
	अन्यथा यदि (*s == 'R')
		remote = 1;
	अन्यथा यदि (*s == 'D')
		dynamic = 1;
	अन्यथा {
		logit("Invalid command.");
		गच्छ बहिर्गमनम्;
	}

	यावत् (रिक्तम्_वा((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	यदि (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		यदि (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			गच्छ बहिर्गमनम्;
		}
		यदि (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		अन्यथा यदि (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		अन्यथा
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_पत्तनम्_STATIC,
			    &options.fwd_opts) > 0;
		यदि (!ok) {
			logit("Unknown port forwarding.");
			गच्छ बहिर्गमनम्;
		}
		logit("Canceled forwarding.");
	} अन्यथा {
		/* -R specs can be both dynamic or not, so check both. */
		यदि (remote) {
			यदि (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				गच्छ बहिर्गमनम्;
			}
		} अन्यथा यदि (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			गच्छ बहिर्गमनम्;
		}
		यदि (local || dynamic) {
			यदि (!channel_सज्जता_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				गच्छ बहिर्गमनम्;
			}
		} अन्यथा {
			यदि (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				गच्छ बहिर्गमनम्;
			}
		}
		logit("Forwarding port.");
	}

बहिर्गमनम्:
	ssh_signal(SIGINT, handler);
	enter_raw_बहुलकम्(options.request_tty == REQUEST_TTY_FORCE);
	मुक्त(cmd);
	मुक्त(fwd.listen_host);
	मुक्त(fwd.listen_मार्गः);
	मुक्त(fwd.connect_host);
	मुक्त(fwd.connect_मार्गः);
}

/* reasons to suppress output of an escape command in help output */
#परिभाषय SUPPRESS_NEVER		0	/* never suppress, always show */
#परिभाषय SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#परिभाषय SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#परिभाषय SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#परिभाषय SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
संरचना escape_help_text {
	ध्रुव वर्ण *cmd;
	ध्रुव वर्ण *text;
	अचिह्नित पूर्णाङ्क flags;
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
	अचिह्नित पूर्णाङ्क i, suppress_flags;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	प्रति (i = 0; i < परिमाण(esc_txt)/परिमाण(esc_txt[0]); i++) {
		यदि (esc_txt[i].flags & suppress_flags)
			अनुवर्त;
		यदि ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	यदि ((r = sshbuf_putf(b,
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
	पूर्णाङ्क r, अष्टकानि = 0;
	u_int i;
	u_char ch;
	वर्ण *s;
	संरचना escape_filter_ctx *efc;

	यदि (c == रिक्त || c->filter_ctx == रिक्त || len <= 0)
		प्रत्यागम 0;

	efc = (संरचना escape_filter_ctx *)c->filter_ctx;

	प्रति (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		यदि (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			विकल्प (ch) {
			पक्ष '.':
				/* Terminate the connection. */
				यदि ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				यदि (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					प्रत्यागम 0;
				} अन्यथा
					quit_pending = 1;
				प्रत्यागम -1;

			पक्ष 'Z' - 64:
				/* XXX support this for mux clients */
				यदि (c && c->ctl_chan != -1) {
					वर्ण b[16];
 noescape:
					यदि (ch == 'Z' - 64)
						snprintf(b, परिमाण b, "^Z");
					अन्यथा
						snprintf(b, परिमाण b, "%c", ch);
					यदि ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					अनुवर्त;
				}
				/* Suspend the program. Inform the user */
				यदि ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				अनुवर्त;

			पक्ष 'B':
				यदि ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				यदि ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				अनुवर्त;

			पक्ष 'I':
				यदि ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_सन्देशः(ssh);
				यदि ((r = sshbuf_put(berr, s, वाक्यदैर्घ्यम्(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				मुक्त(s);
				अनुवर्त;

			पक्ष 'R':
				यदि (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				अन्यथा
					need_rekeying = 1;
				अनुवर्त;

			पक्ष 'V':
				/* FALLTHROUGH */
			पक्ष 'v':
				यदि (c && c->ctl_chan != -1)
					गच्छ noescape;
				यदि (!log_is_on_stderr()) {
					यदि ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					अनुवर्त;
				}
				यदि (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				यदि (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				यदि ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				अनुवर्त;

			पक्ष '&':
				यदि (c->ctl_chan != -1)
					गच्छ noescape;
				/*
				 * Detach the program (continue to serve
				 * connections, but put in background and no
				 * more new connections).
				 */
				/* Restore tty modes. */
				leave_raw_बहुलकम्(
				    options.request_tty == REQUEST_TTY_FORCE);

				/* Stop listening for new connections. */
				channel_stop_listening(ssh);

				यदि ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				यदि (pid == -1) {
					error("fork: %.100s", strerror(errno));
					अनुवर्त;
				}
				यदि (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					निर्गच्छ(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				यदि ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				प्रत्यागम -1;
			पक्ष '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				अनुवर्त;

			पक्ष '#':
				यदि ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_सन्देशः(ssh);
				यदि ((r = sshbuf_put(berr, s, वाक्यदैर्घ्यम्(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				मुक्त(s);
				अनुवर्त;

			पक्ष 'C':
				यदि (c && c->ctl_chan != -1)
					गच्छ noescape;
				यदि (options.enable_escape_commandline == 0) {
					यदि ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					अनुवर्त;
				}
				process_cmdline(ssh);
				अनुवर्त;

			स्वभाव:
				यदि (ch != efc->escape_char) {
					यदि ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					अष्टकानि++;
				}
				/* Escaped characters fall through here */
				भङ्ग;
			}
		} अन्यथा {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			यदि (चरमः_was_cr && ch == efc->escape_char) {
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
		चरमः_was_cr = (ch == '\r' || ch == '\n');
		यदि ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		अष्टकानि++;
	}
	प्रत्यागम अष्टकानि;
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
	ssh_dispatch_सततम्_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
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
	प्रत्यागम (शून्य *)ret;
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
	यदि (c->extended_usage != CHAN_EXTENDED_WRITE)
		प्रत्यागम 0;

	प्रत्यागम process_escapes(ssh, c, c->निवेशः, c->output, c->extended,
	    buf, len);
}

स्थिर शून्य
client_channel_closed(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क force, शून्य *arg)
{
	channel_cancel_cleanup(ssh, id);
	session_closed = 1;
	leave_raw_बहुलकम्(options.request_tty == REQUEST_TTY_FORCE);
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
	u_int npfd_alloc = 0, npfd_सक्रिय = 0;
	द्विगुण start_time, योग_time;
	पूर्णाङ्क interactive = -1, channel_did_पङ्क्तौ_निक्षिप = 0, r;
	uint64_t ibytes, obytes;
	पूर्णाङ्क conn_अन्तर्_ready, conn_बहिर्गमनम्_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	यदि (options.pkcs11_provider != रिक्त)
		debug("pledge: disabled (PKCS11Provider active)");
	अन्यथा यदि (options.control_master &&
	    !option_clear_or_none(options.control_मार्गः)) {
		debug("pledge: id");
		यदि (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} अन्यथा यदि (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		यदि (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} अन्यथा यदि (options.update_hostkeys) {
		debug("pledge: filesystem");
		यदि (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} अन्यथा यदि (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		यदि (pledge("stdio cpath unix inet dns proc tty", रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} अन्यथा {
		debug("pledge: network");
		यदि (pledge("stdio unix inet dns proc tty", रिक्त) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	}

	/* might be able to tighten now */
	client_repledge();

	start_time = monotime_double();

	/* Initialize variables. */
	चरमः_was_cr = 1;
	exit_स्थितिः = -1;
	connection_अन्तर् = ssh_packet_get_connection_अन्तर्(ssh);
	connection_बहिर्गमनम् = ssh_packet_get_connection_बहिर्गमनम्(ssh);

	quit_pending = 0;

	client_init_dispatch(ssh);

	/*
	 * Set signal handlers, (e.g. to restore non-blocking mode)
	 * but don't overwrite SIG_IGN, matches behaviour from rsh(1)
	 */
	यदि (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	यदि (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	यदि (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	यदि (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, गवाक्षः_change_handler);
#यदि_परिभाषितम् SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#यदि_अन्तः

	यदि (have_pty)
		enter_raw_बहुलकम्(options.request_tty == REQUEST_TTY_FORCE);

	यदि (session_ident != -1) {
		यदि (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_पञ्जिकाकोशः_filter(ssh, session_ident,
			    client_simple_escape_filter, रिक्त,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_पञ्जिकाकोशः_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	कालसारणी_server_alive_check();

	यदि (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#यदि_परिभाषितम् SIGINFO
	यदि (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#यदि_अन्तः

	/* Main loop of the client for the interactive session mode. */
	यावत् (!quit_pending) {
		channel_did_पङ्क्तौ_निक्षिप = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_निवेशः_packets(ssh);

		यदि (session_closed && !channel_still_open(ssh))
			भङ्ग;

		यदि (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} अन्यथा यदि (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			यदि ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} अन्यथा {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			यदि (ssh_packet_not_very_much_दत्त_गन्तव्यम्_write(ssh))
				channel_did_पङ्क्तौ_निक्षिप = channel_output_poll(ssh);

			/*
			 * Check if the window size has changed, and buffer a
			 * message about it to the server if so.
			 */
			client_check_गवाक्षः_change(ssh);
		}
		/*
		 * Wait until we have something to do (something becomes
		 * available on one of the descriptors).
		 */
		यदि (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		यदि (siginfo_received) {
			वर्ण ident[256];

			sshpkt_fmt_connection_id(ssh, ident, परिमाण(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - start_time);
			siginfo_received = 0;
		}
		यदि (quit_pending)
			भङ्ग;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_सक्रिय, channel_did_पङ्क्तौ_निक्षिप, &osigset,
		    &conn_अन्तर्_ready, &conn_बहिर्गमनम्_ready);
		यदि (sigprocmask(SIG_SETMASK, &osigset, रिक्त) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		यदि (quit_pending)
			भङ्ग;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_सक्रिय);

		/* Buffer input from the connection.  */
		यदि (conn_अन्तर्_ready)
			client_process_net_निवेशः(ssh);

		यदि (quit_pending)
			भङ्ग;

		/* A timeout may have triggered rekeying */
		यदि ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		यदि (conn_बहिर्गमनम्_ready) {
			यदि (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_समुच्चयः_interactive(ssh, interactive);
			}
			यदि ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		यदि (control_persist_exit_time > 0) {
			यदि (monotime() >= control_persist_exit_time) {
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
	यदि (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_सन्देशः("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	यदि (have_pty)
		leave_raw_बहुलकम्(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	यदि (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_स्थितिः = 0;
	}

	यदि (received_signal) {
		verbose("Killed by signal %d.", (पूर्णाङ्क) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	योग_time = monotime_double() - start_time;
	ssh_packet_get_अष्टकानि(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (अचिह्नित दीर्घ दीर्घ)obytes, (अचिह्नित दीर्घ दीर्घ)ibytes, योग_time);
	यदि (योग_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / योग_time, ibytes / योग_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_स्थितिः);
	प्रत्यागम exit_स्थितिः;
}

/*********/

स्थिर Channel *
client_request_forwarded_tcpip(संरचना ssh *ssh, ध्रुव वर्ण *request_type,
    पूर्णाङ्क rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = रिक्त;
	संरचना sshbuf *b = रिक्त;
	वर्ण *listen_स्थानाङ्कः, *originator_स्थानाङ्कः;
	u_int listen_पत्तनम्, originator_पत्तनम्;
	पूर्णाङ्क r;

	/* Get rest of the packet */
	यदि ((r = sshpkt_get_cstring(ssh, &listen_स्थानाङ्कः, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_पत्तनम्)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_स्थानाङ्कः, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_पत्तनम्)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_स्थानाङ्कः, listen_पत्तनम्, originator_स्थानाङ्कः, originator_पत्तनम्);

	यदि (listen_पत्तनम् > 0xffff)
		error_f("invalid listen port");
	अन्यथा यदि (originator_पत्तनम् > 0xffff)
		error_f("invalid originator port");
	अन्यथा {
		c = channel_connect_by_listen_स्थानाङ्कः(ssh,
		    listen_स्थानाङ्कः, listen_पत्तनम्, "forwarded-tcpip",
		    originator_स्थानाङ्कः);
	}

	यदि (c != रिक्त && c->type == SSH_CHANNEL_MUX_CLIENT) {
		यदि ((b = sshbuf_new()) == रिक्त) {
			error_f("alloc reply");
			गच्छ बहिर्गमनम्;
		}
		/* reconstruct and send to muxclient */
		यदि ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_सन्देशः_CHANNEL_OPEN)) != 0 ||
		    (r = sshbuf_put_cstring(b, request_type)) != 0 ||
		    (r = sshbuf_put_u32(b, rchan)) != 0 ||
		    (r = sshbuf_put_u32(b, rwindow)) != 0 ||
		    (r = sshbuf_put_u32(b, rmaxpack)) != 0 ||
		    (r = sshbuf_put_cstring(b, listen_स्थानाङ्कः)) != 0 ||
		    (r = sshbuf_put_u32(b, listen_पत्तनम्)) != 0 ||
		    (r = sshbuf_put_cstring(b, originator_स्थानाङ्कः)) != 0 ||
		    (r = sshbuf_put_u32(b, originator_पत्तनम्)) != 0 ||
		    (r = sshbuf_put_stringb(c->output, b)) != 0) {
			error_fr(r, "compose for muxclient");
			गच्छ बहिर्गमनम्;
		}
	}

 बहिर्गमनम्:
	sshbuf_free(b);
	मुक्त(originator_स्थानाङ्कः);
	मुक्त(listen_स्थानाङ्कः);
	प्रत्यागम c;
}

स्थिर Channel *
client_request_forwarded_streamlocal(संरचना ssh *ssh,
    ध्रुव वर्ण *request_type, पूर्णाङ्क rchan)
{
	Channel *c = रिक्त;
	वर्ण *listen_मार्गः;
	पूर्णाङ्क r;

	/* Get the remote path. */
	यदि ((r = sshpkt_get_cstring(ssh, &listen_मार्गः, रिक्त)) != 0 ||
	    (r = sshpkt_get_string(ssh, रिक्त, रिक्त)) != 0 ||	/* reserved */
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_मार्गः);

	c = channel_connect_by_listen_मार्गः(ssh, listen_मार्गः,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	मुक्त(listen_मार्गः);
	प्रत्यागम c;
}

स्थिर Channel *
client_request_x11(संरचना ssh *ssh, ध्रुव वर्ण *request_type, पूर्णाङ्क rchan)
{
	Channel *c = रिक्त;
	वर्ण *originator;
	u_int originator_पत्तनम्;
	पूर्णाङ्क r, sock;

	यदि (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		प्रत्यागम रिक्त;
	}
	यदि (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		प्रत्यागम रिक्त;
	}
	यदि ((r = sshpkt_get_cstring(ssh, &originator, रिक्त)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_पत्तनम्)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_पत्तनम्);
	मुक्त(originator);
	sock = x11_connect_display(ssh);
	यदि (sock < 0)
		प्रत्यागम रिक्त;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_गवाक्षः_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	प्रत्यागम c;
}

स्थिर Channel *
client_request_agent(संरचना ssh *ssh, ध्रुव वर्ण *request_type, पूर्णाङ्क rchan)
{
	Channel *c = रिक्त;
	पूर्णाङ्क r, sock;

	यदि (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		प्रत्यागम रिक्त;
	}
	यदि (forward_agent_sock_मार्गः == रिक्त) {
		r = ssh_get_authentication_socket(&sock);
	} अन्यथा {
		r = ssh_get_authentication_socket_मार्गः(forward_agent_sock_मार्गः, &sock);
	}
	यदि (r != 0) {
		यदि (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		प्रत्यागम रिक्त;
	}
	यदि ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	अन्यथा
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_गवाक्षः_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	प्रत्यागम c;
}

वर्ण *
client_request_tun_fwd(संरचना ssh *ssh, पूर्णाङ्क tun_बहुलकम्,
    पूर्णाङ्क local_tun, पूर्णाङ्क remote_tun, channel_open_fn *cb, शून्य *cbctx)
{
	Channel *c;
	पूर्णाङ्क r, fd;
	वर्ण *ifname = रिक्त;

	यदि (tun_बहुलकम् == SSH_TUNMODE_NO)
		प्रत्यागम रिक्त;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_बहुलकम्);

	/* Open local tunnel device */
	यदि ((fd = tun_open(local_tun, tun_बहुलकम्, &ifname)) == -1) {
		error("Tunnel device open failed.");
		प्रत्यागम रिक्त;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_गवाक्षः_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#यदि defined(SSH_TUN_FILTER)
	यदि (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_पञ्जिकाकोशः_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, रिक्त, रिक्त);
#यदि_अन्तः

	यदि (cb != रिक्त)
		channel_पञ्जिकाकोशः_open_confirm(ssh, c->self, cb, cbctx);

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_गवाक्षः_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_बहुलकम्)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	प्रत्यागम ifname;
}

/* XXXX move to generic input handler */
स्थिर पूर्णाङ्क
client_निवेशः_channel_open(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c = रिक्त;
	वर्ण *ctype = रिक्त;
	पूर्णाङ्क r;
	u_int rchan;
	आकार_t len;
	u_int rmaxpack, rwindow;

	यदि ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		गच्छ बहिर्गमनम्;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	यदि (वाक्यं_तुलय(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} अन्यथा यदि (वाक्यं_तुलय(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} अन्यथा यदि (वाक्यं_तुलय(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} अन्यथा यदि (वाक्यं_तुलय(ctype, "auth-agent@openssh.com") == 0 ||
	    वाक्यं_तुलय(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	यदि (c != रिक्त && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} अन्यथा यदि (c != रिक्त) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_गवाक्षः = rwindow;
		c->remote_maxpacket = rmaxpack;
		यदि (c->type != SSH_CHANNEL_CONNECTING) {
			यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_गवाक्षः)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} अन्यथा {
		debug("failure %s", ctype);
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 बहिर्गमनम्:
	मुक्त(ctype);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
client_निवेशः_channel_req(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c = रिक्त;
	वर्ण *rtype = रिक्त;
	u_char प्रत्युत्तरम्;
	u_int id, exitval;
	पूर्णाङ्क r, success = 0;

	यदि ((r = sshpkt_get_u32(ssh, &id)) != 0)
		प्रत्यागम r;
	यदि (id <= अधिकतम_पूर्णाङ्कः)
		c = channel_lookup(ssh, id);
	यदि (channel_proxy_upstream(c, type, seq, ssh))
		प्रत्यागम 0;
	यदि ((r = sshpkt_get_cstring(ssh, &rtype, रिक्त)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &प्रत्युत्तरम्)) != 0)
		गच्छ बहिर्गमनम्;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, प्रत्युत्तरम्);

	यदि (c == रिक्त) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} अन्यथा यदि (वाक्यं_तुलय(rtype, "eow@openssh.com") == 0) {
		यदि ((r = sshpkt_get_अन्तः(ssh)) != 0)
			गच्छ बहिर्गमनम्;
		chan_rcvd_eow(ssh, c);
	} अन्यथा यदि (वाक्यं_तुलय(rtype, "exit-status") == 0) {
		यदि ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			गच्छ बहिर्गमनम्;
		यदि (c->ctl_chan != -1) {
			mux_exit_सन्देशः(ssh, c, exitval);
			success = 1;
		} अन्यथा यदि ((पूर्णाङ्क)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_स्थितिः = exitval;
		} अन्यथा {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		यदि ((r = sshpkt_get_अन्तः(ssh)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि (प्रत्युत्तरम् && c != रिक्त && !(c->flags & CHAN_CLOSE_प्रेषितम्)) {
		यदि (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		यदि ((r = sshpkt_start(ssh, success ?
		    SSH2_सन्देशः_CHANNEL_SUCCESS : SSH2_सन्देशः_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 बहिर्गमनम्:
	मुक्त(rtype);
	प्रत्यागम r;
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
	u_int *कुञ्चिकाः_मेलनम्;	/* mask of HKF_MATCH_* from hostfile.h */
	पूर्णाङ्क *कुञ्चिकाः_verified;	/* flag for new keys verified by server */
	आकार_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	संरचना sshkey **old_कुञ्चिकाः;
	आकार_t nold;

	/* Various special cases. */
	पूर्णाङ्क complex_hostspec;	/* wildcard or manual pattern-list host name */
	पूर्णाङ्क ca_उपलब्धम्;	/* saw CA key for this host */
	पूर्णाङ्क old_कुञ्चिका_आलोकितम्;	/* saw old key with other name/addr */
	पूर्णाङ्क other_name_आलोकितम्;	/* saw key with other name/addr */
};

स्थिर शून्य
hostkeys_update_ctx_free(संरचना hostkeys_update_ctx *ctx)
{
	आकार_t i;

	यदि (ctx == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->कुञ्चिकाः[i]);
	मुक्त(ctx->कुञ्चिकाः);
	मुक्त(ctx->कुञ्चिकाः_मेलनम्);
	मुक्त(ctx->कुञ्चिकाः_verified);
	प्रति (i = 0; i < ctx->nold; i++)
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
	यदि (strchr(hosts, '*') != रिक्त || strchr(hosts, '?') != रिक्त)
		प्रत्यागम 1;
	/* single host/ip = ok */
	यदि ((cp = strchr(hosts, ',')) == रिक्त)
		प्रत्यागम 0;
	/* more than two entries on the line */
	यदि (strchr(cp + 1, ',') != रिक्त)
		प्रत्यागम 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	प्रत्यागम 0;
}

/* callback to search for ctx->keys in known_hosts */
स्थिर पूर्णाङ्क
hostkeys_find(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *_ctx)
{
	संरचना hostkeys_update_ctx *ctx = (संरचना hostkeys_update_ctx *)_ctx;
	आकार_t i;
	संरचना sshkey **tmp;

	यदि (l->कुञ्चिका == रिक्त)
		प्रत्यागम 0;
	यदि (l->स्थितिः != HKF_स्थितिः_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		प्रति (i = 0; i < ctx->nkeys; i++) {
			यदि (sshkey_equal(l->कुञ्चिका, ctx->कुञ्चिकाः[i])) {
				ctx->other_name_आलोकितम् = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->कुञ्चिकाः[i]),
				    l->मार्गः, l->linenum);
				प्रत्यागम 0;
			}
		}
		प्रत्यागम 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	यदि (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->मार्गः, l->linenum);
		ctx->complex_hostspec = 1;
		प्रत्यागम 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	यदि (ctx->ip_str != रिक्त && strchr(l->hosts, ',') != रिक्त) {
		यदि ((l->मेलनम् & HKF_मेलनम्_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_आलोकितम् = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->मार्गः, l->linenum);
			प्रत्यागम 0;
		} अन्यथा यदि ((l->मेलनम् & HKF_मेलनम्_IP) == 0) {
			/* Record if hostname matched a different address. */
			ctx->other_name_आलोकितम् = 1;
			debug3_f("found hostname %s against different address "
			    "at %s:%ld", ctx->host_str, l->मार्गः, l->linenum);
		}
	}

	/*
	 * UpdateHostkeys is skipped for wildcard host names and hostnames
	 * that contain more than two entries (ssh never writes these).
	 */
	यदि (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->मार्गः, l->linenum);
		ctx->complex_hostspec = 1;
		प्रत्यागम 0;
	}

	/* Mark off keys we've already seen for this host */
	प्रति (i = 0; i < ctx->nkeys; i++) {
		यदि (!sshkey_equal(l->कुञ्चिका, ctx->कुञ्चिकाः[i]))
			अनुवर्त;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->कुञ्चिकाः[i]), l->मार्गः, l->linenum);
		ctx->कुञ्चिकाः_मेलनम्[i] |= l->मेलनम्;
		प्रत्यागम 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->कुञ्चिका),
	    l->मार्गः, l->linenum);
	यदि ((tmp = recallocarray(ctx->old_कुञ्चिकाः, ctx->nold, ctx->nold + 1,
	    परिमाण(*ctx->old_कुञ्चिकाः))) == रिक्त)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_कुञ्चिकाः = tmp;
	ctx->old_कुञ्चिकाः[ctx->nold++] = l->कुञ्चिका;
	l->कुञ्चिका = रिक्त;

	प्रत्यागम 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
स्थिर पूर्णाङ्क
hostkeys_check_old(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *_ctx)
{
	संरचना hostkeys_update_ctx *ctx = (संरचना hostkeys_update_ctx *)_ctx;
	आकार_t i;
	पूर्णाङ्क hashed;

	/* only care about lines that *don't* match the active host spec */
	यदि (l->स्थितिः == HKF_स्थितिः_MATCHED || l->कुञ्चिका == रिक्त)
		प्रत्यागम 0;

	hashed = l->मेलनम् & (HKF_मेलनम्_HOST_HASHED|HKF_मेलनम्_IP_HASHED);
	प्रति (i = 0; i < ctx->nold; i++) {
		यदि (!sshkey_equal(l->कुञ्चिका, ctx->old_कुञ्चिकाः[i]))
			अनुवर्त;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_कुञ्चिकाः[i]), l->मार्गः, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_कुञ्चिका_आलोकितम् = 1;
		भङ्ग;
	}
	प्रत्यागम 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
स्थिर पूर्णाङ्क
check_old_कुञ्चिकाः_othernames(संरचना hostkeys_update_ctx *ctx)
{
	आकार_t i;
	पूर्णाङ्क r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	प्रति (i = 0; i < options.अङ्कः_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		यदि ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_कुञ्चिका, 0)) != 0) {
			यदि (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				अनुवर्त;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			प्रत्यागम -1;
		}
	}
	प्रत्यागम 0;
}

स्थिर शून्य
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

स्थिर शून्य
update_ज्ञातम्_hosts(संरचना hostkeys_update_ctx *ctx)
{
	पूर्णाङ्क r, was_raw = 0, first = 1;
	पूर्णाङ्क asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	वर्ण *fp, *response;
	आकार_t i;
	संरचना stat sb;

	प्रति (i = 0; i < ctx->nkeys; i++) {
		यदि (!ctx->कुञ्चिकाः_verified[i])
			अनुवर्त;
		यदि ((fp = sshkey_fingerprint(ctx->कुञ्चिकाः[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		यदि (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->कुञ्चिकाः[i]), fp);
		first = 0;
		मुक्त(fp);
	}
	प्रति (i = 0; i < ctx->nold; i++) {
		यदि ((fp = sshkey_fingerprint(ctx->old_कुञ्चिकाः[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		यदि (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_कुञ्चिकाः[i]), fp);
		first = 0;
		मुक्त(fp);
	}
	यदि (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		यदि (get_saved_tio() != रिक्त) {
			leave_raw_बहुलकम्(1);
			was_raw = 1;
		}
		response = रिक्त;
		प्रति (i = 0; !quit_pending && i < 3; i++) {
			मुक्त(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			यदि (response != रिक्त && strcasecmp(response, "yes") == 0)
				भङ्ग;
			अन्यथा यदि (quit_pending || response == रिक्त ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				भङ्ग;
			} अन्यथा {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		यदि (quit_pending || i >= 3 || response == रिक्त)
			options.update_hostkeys = 0;
		मुक्त(response);
		यदि (was_raw)
			enter_raw_बहुलकम्(1);
	}
	यदि (options.update_hostkeys == 0)
		प्रत्यागम;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	प्रति (i = 0; i < options.अङ्कः_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		यदि (stat(options.user_hostfiles[i], &sb) != 0) {
			यदि (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} अन्यथा {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			अनुवर्त;
		}
		यदि ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->कुञ्चिकाः : रिक्त, i == 0 ? ctx->nkeys : 0,
		    options.hash_ज्ञातम्_hosts, 0,
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
	आकार_t i, ndone;
	संरचना sshbuf *signdata;
	पूर्णाङ्क r, plaintype;
	ध्रुव u_char *sig;
	ध्रुव वर्ण *rsa_kexalg = रिक्त;
	वर्ण *alg = रिक्त;
	आकार_t siglen;

	यदि (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	यदि (type != SSH2_सन्देशः_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		प्रत्यागम;
	}
	यदि (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == कुञ्चिका_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	यदि ((signdata = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	प्रति (ndone = i = 0; i < ctx->nkeys; i++) {
		यदि (ctx->कुञ्चिकाः_मेलनम्[i])
			अनुवर्त;
		plaintype = sshkey_type_plain(ctx->कुञ्चिकाः[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		यदि ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->कुञ्चिकाः[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		यदि ((r = sshpkt_get_string_प्रत्यक्षम्(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			गच्छ बहिर्गमनम्;
		}
		यदि ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->कुञ्चिकाः[i]), i);
			गच्छ बहिर्गमनम्;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		यदि (plaintype == कुञ्चिका_RSA && rsa_kexalg == रिक्त &&
		    मेलनम्_आदर्शः_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
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
		यदि ((r = sshkey_verify(ctx->कुञ्चिकाः[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == कुञ्चिका_RSA ? rsa_kexalg : रिक्त, 0, रिक्त)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->कुञ्चिकाः[i]), i);
			गच्छ बहिर्गमनम्;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->कुञ्चिकाः_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	यदि (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	यदि ((r = sshpkt_get_अन्तः(ssh)) != 0) {
		error_f("protocol error");
		गच्छ बहिर्गमनम्;
	}

	/* Make the edits to known_hosts */
	update_ज्ञातम्_hosts(ctx);
 बहिर्गमनम्:
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
	आकार_t i, len = 0;
	संरचना sshbuf *buf = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त, **tmp;
	पूर्णाङ्क r, prove_प्रेषितम् = 0;
	वर्ण *fp;
	स्थिर पूर्णाङ्क hostkeys_आलोकितम् = 0; /* XXX use struct ssh */
	बाह्य संरचना sockaddr_storage hostaddr; /* XXX from ssh.c */
	संरचना hostkeys_update_ctx *ctx = रिक्त;
	u_int want;

	यदि (hostkeys_आलोकितम्)
		fatal_f("server already sent hostkeys");
	यदि (!can_update_hostkeys())
		प्रत्यागम 1;
	hostkeys_आलोकितम् = 1;

	ctx = xcalloc(1, परिमाण(*ctx));
	यावत् (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(कुञ्चिका);
		कुञ्चिका = रिक्त;
		यदि ((r = sshpkt_get_string_प्रत्यक्षम्(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			गच्छ बहिर्गमनम्;
		}
		यदि ((r = sshkey_from_blob(blob, len, &कुञ्चिका)) != 0) {
			do_log2_fr(r, r == SSH_ERR_कुञ्चिका_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			अनुवर्त;
		}
		fp = sshkey_fingerprint(कुञ्चिका, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(कुञ्चिका), fp);
		मुक्त(fp);

		यदि (!hostkey_accepted_by_hostkeyalgs(कुञ्चिका)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(कुञ्चिका));
			अनुवर्त;
		}
		/* Skip certs */
		यदि (sshkey_is_cert(कुञ्चिका)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(कुञ्चिका));
			अनुवर्त;
		}
		/* Ensure keys are unique */
		प्रति (i = 0; i < ctx->nkeys; i++) {
			यदि (sshkey_equal(कुञ्चिका, ctx->कुञ्चिकाः[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(कुञ्चिका));
				गच्छ बहिर्गमनम्;
			}
		}
		/* Key is good, record it */
		यदि ((tmp = recallocarray(ctx->कुञ्चिकाः, ctx->nkeys, ctx->nkeys + 1,
		    परिमाण(*ctx->कुञ्चिकाः))) == रिक्त)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->कुञ्चिकाः = tmp;
		ctx->कुञ्चिकाः[ctx->nkeys++] = कुञ्चिका;
		कुञ्चिका = रिक्त;
	}

	यदि (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		गच्छ बहिर्गमनम्;
	}

	यदि ((ctx->कुञ्चिकाः_मेलनम् = शून्यस्मृतिं_देहि(ctx->nkeys,
	    परिमाण(*ctx->कुञ्चिकाः_मेलनम्))) == रिक्त ||
	    (ctx->कुञ्चिकाः_verified = शून्यस्मृतिं_देहि(ctx->nkeys,
	    परिमाण(*ctx->कुञ्चिकाः_verified))) == रिक्त)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (संरचना sockaddr *)&hostaddr : रिक्त,
	    options.पत्तनम्, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : रिक्त);

	/* Find which keys we already know about. */
	प्रति (i = 0; i < options.अङ्कः_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		यदि ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_कुञ्चिका, 0)) != 0) {
			यदि (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				अनुवर्त;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			गच्छ बहिर्गमनम्;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_मेलनम्_HOST | ( options.check_host_ip ? HKF_मेलनम्_IP : 0);
	प्रति (i = 0; i < ctx->nkeys; i++) {
		यदि (ctx->कुञ्चिकाः_मेलनम्[i] == 0)
			ctx->nnew++;
		यदि ((ctx->कुञ्चिकाः_मेलनम्[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	यदि (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		गच्छ बहिर्गमनम्;
	}

	/* Various reasons why we cannot proceed with the update */
	यदि (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		गच्छ बहिर्गमनम्;
	}
	यदि (ctx->other_name_आलोकितम्) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		गच्छ बहिर्गमनम्;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	यदि (ctx->nold != 0) {
		यदि (check_old_कुञ्चिकाः_othernames(ctx) != 0)
			गच्छ बहिर्गमनम्; /* error already logged */
		यदि (ctx->old_कुञ्चिका_आलोकितम्) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == रिक्त ? "" : ",",
			    ctx->ip_str == रिक्त ? "" : ctx->ip_str);
			गच्छ बहिर्गमनम्;
		}
	}

	यदि (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_ज्ञातम्_hosts(ctx);
		गच्छ बहिर्गमनम्;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	यदि ((buf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	प्रति (i = 0; i < ctx->nkeys; i++) {
		यदि (ctx->कुञ्चिकाः_मेलनम्[i])
			अनुवर्त;
		sshbuf_reset(buf);
		यदि ((r = sshkey_putb(ctx->कुञ्चिकाः[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	यदि ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_पञ्जिकाकोशः_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = रिक्त;  /* will be freed in callback */
	prove_प्रेषितम् = 1;

	/* Success */
 बहिर्गमनम्:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(कुञ्चिका);
	sshbuf_free(buf);
	यदि (!prove_प्रेषितम्) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	प्रत्यागम 1;
}

स्थिर पूर्णाङ्क
client_निवेशः_global_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	वर्ण *rtype;
	u_char want_प्रत्युत्तरम्;
	पूर्णाङ्क r, success = 0;

	यदि ((r = sshpkt_get_cstring(ssh, &rtype, रिक्त)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_प्रत्युत्तरम्)) != 0)
		गच्छ बहिर्गमनम्;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_प्रत्युत्तरम्);
	यदि (वाक्यं_तुलय(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_निवेशः_hostkeys(ssh);
	यदि (want_प्रत्युत्तरम्) {
		यदि ((r = sshpkt_start(ssh, success ? SSH2_सन्देशः_REQUEST_SUCCESS :
		    SSH2_सन्देशः_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			गच्छ बहिर्गमनम्;
	}
	r = 0;
 बहिर्गमनम्:
	मुक्त(rtype);
	प्रत्यागम r;
}

स्थिर शून्य
client_send_env(संरचना ssh *ssh, पूर्णाङ्क id, ध्रुव वर्ण *name, ध्रुव वर्ण *val)
{
	पूर्णाङ्क r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	यदि ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

शून्य
client_session2_सज्जता(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क want_tty, पूर्णाङ्क want_subsystem,
    ध्रुव वर्ण *पदांशः, संरचना termios *tiop, पूर्णाङ्क अन्तर्_fd, संरचना sshbuf *cmd,
    वर्ण **env)
{
	आकार_t i, j, len;
	पूर्णाङ्क matched, r;
	वर्ण *type = रिक्त, *cmdstring = रिक्त, *name, *val;
	Channel *c = रिक्त;

	debug2_f("id %d", id);

	यदि ((c = channel_lookup(ssh, id)) == रिक्त)
		fatal_f("channel %d: unknown channel", id);

	यदि (want_tty) {
		संरचना winsize ws;

		/* Store window size in the packet. */
		यदि (ioctl(अन्तर्_fd, TIOCGWINSZ, &ws) == -1)
			स्मृतिं_पूरय(&ws, 0, परिमाण(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		यदि ((r = sshpkt_put_cstring(ssh, पदांशः != रिक्त ? पदांशः : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		यदि (tiop == रिक्त)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		यदि ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	यदि (options.अङ्कः_send_env != 0 && env != रिक्त) {
		debug("Sending environment.");
		प्रति (i = 0; env[i] != रिक्त; i++) {
			/*विभज*/
			name = xstrdup(env[i]);
			यदि ((val = strchr(name, '=')) == रिक्त) {
				मुक्त(name);
				अनुवर्त;
			}
			*val++ = '\0';

			matched = 0;
			प्रति (j = 0; j < options.अङ्कः_send_env; j++) {
				यदि (मेलनम्_आदर्शः(name, options.send_env[j])) {
					matched = 1;
					भङ्ग;
				}
			}
			यदि (!matched) {
				debug3("Ignored env %s", name);
				मुक्त(name);
				अनुवर्त;
			}
			client_send_env(ssh, id, name, val);
			मुक्त(name);
		}
	}
	प्रति (i = 0; i < options.अङ्कः_setenv; i++) {
		/*विभज*/
		name = xstrdup(options.setenv[i]);
		यदि ((val = strchr(name, '=')) == रिक्त) {
			मुक्त(name);
			अनुवर्त;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		मुक्त(name);
	}

	len = sshbuf_len(cmd);
	यदि (len > 0) {
		यदि ((cmdstring = sshbuf_dup_string(cmd)) == रिक्त)
			fatal_f("sshbuf_dup_string failed");
		यदि (len > 900)
			len = 900;
		यदि (want_subsystem) {
			debug("Sending subsystem: %.*s", (पूर्णाङ्क)len, cmdstring);
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} अन्यथा {
			debug("Sending command: %.*s", (पूर्णाङ्क)len, cmdstring);
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		यदि ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} अन्यथा {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		यदि ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_समुच्चयः_xtype(ssh, id, type);
	मुक्त(cmdstring);
	मुक्त(type);

	session_सज्जता_complete = 1;
	client_repledge();
}

शून्य
client_channel_request_agent_forwarding(संरचना ssh *ssh, पूर्णाङ्क id)
{
	ध्रुव वर्ण *req = "auth-agent-req@openssh.com";
	पूर्णाङ्क r;

	यदि (ssh->kex != रिक्त && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_start(ssh, id, req, 0);
	यदि ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

स्थिर शून्य
client_init_dispatch(संरचना ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_CLOSE, &channel_निवेशः_oclose);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_दत्त, &channel_निवेशः_दत्त);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_EOF, &channel_निवेशः_ieof);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_EXTENDED_दत्त, &channel_निवेशः_extended_दत्त);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_OPEN, &client_निवेशः_channel_open);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_OPEN_CONFIRMATION, &channel_निवेशः_open_confirmation);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_OPEN_FAILURE, &channel_निवेशः_open_failure);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_REQUEST, &client_निवेशः_channel_req);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_गवाक्षः_ADJUST, &channel_निवेशः_गवाक्षः_adjust);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_SUCCESS, &channel_निवेशः_स्थितिः_confirm);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_CHANNEL_FAILURE, &channel_निवेशः_स्थितिः_confirm);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_GLOBAL_REQUEST, &client_निवेशः_global_request);

	/* rekeying */
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_KEXINIT, &kex_निवेशः_kexinit);

	/* global request reply messages */
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_REQUEST_FAILURE, &client_global_request_प्रत्युत्तरम्);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_REQUEST_SUCCESS, &client_global_request_प्रत्युत्तरम्);
}

शून्य
client_stop_mux(शून्य)
{
	यदि (options.control_मार्गः != रिक्त && muxserver_sock != -1)
		unlink(options.control_मार्गः);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	यदि (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
शून्य
cleanup_exit(पूर्णाङ्क i)
{
	leave_raw_बहुलकम्(options.request_tty == REQUEST_TTY_FORCE);
	यदि (options.control_मार्गः != रिक्त && muxserver_sock != -1)
		unlink(options.control_मार्गः);
	ssh_kill_proxy_command();
	_exit(i);
}
