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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/ioctl.h>
#समावेश <sys/stat.h>
#समावेश <sys/time.h>
#समावेश <sys/queue.h>

#समावेश <ctype.h>
#समावेश <errno.h>
#समावेश <paths.h>
#समावेश <poll.h>
#समावेश <signal.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <unistd.h>
#समावेश <limits.h>

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "packet.h"
#समावेश "sshbuf.h"
#समावेश "compat.h"
#समावेश "channels.h"
#समावेश "dispatch.h"
#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "readconf.h"
#समावेश "clientloop.h"
#समावेश "sshconnect.h"
#समावेश "authfd.h"
#समावेश "atomicio.h"
#समावेश "sshpty.h"
#समावेश "match.h"
#समावेश "ssherr.h"
#समावेश "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#घोषणा HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#घोषणा SSH_KEYSTROKE_TIMING_FUZZ 10

बाह्य अक्षर *__progname;

/* import options */
बाह्य Options options;

/* Control socket */
बाह्य पूर्णांक muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
बाह्य अक्षर *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
बाह्य अक्षर *forward_agent_sock_path;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
अटल अस्थिर संक_पूर्ण_प्रकार received_window_change_signal = 0;
अटल अस्थिर संक_पूर्ण_प्रकार siginfo_received = 0;
अटल अस्थिर संक_पूर्ण_प्रकार received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
अटल समय_प्रकार control_persist_exit_time = 0;

/* Common data for the client loop code. */
अस्थिर संक_पूर्ण_प्रकार quit_pending; /* Set non-zero to quit the loop. */
अटल पूर्णांक last_was_cr;		/* Last character was a newline. */
अटल पूर्णांक exit_status;		/* Used to store the command exit status. */
अटल पूर्णांक connection_in;	/* Connection to server (input). */
अटल पूर्णांक connection_out;	/* Connection to server (output). */
अटल पूर्णांक need_rekeying;	/* Set to non-zero if rekeying is requested. */
अटल पूर्णांक session_closed;	/* In SSH2: login session closed. */
अटल समय_प्रकार x11_refuse_time;	/* If >0, refuse x11 opens after this time. */
अटल समय_प्रकार server_alive_time;	/* Time to do server_alive_check */
अटल पूर्णांक hostkeys_update_complete;
अटल पूर्णांक session_setup_complete;

अटल व्योम client_init_dispatch(काष्ठा ssh *ssh);
पूर्णांक	session_ident = -1;

/* Track escape per proto2 channel */
काष्ठा escape_filter_ctx {
	पूर्णांक escape_pending;
	पूर्णांक escape_char;
};

/* Context for channel confirmation replies */
काष्ठा channel_reply_ctx {
	स्थिर अक्षर *request_type;
	पूर्णांक id;
	क्रमागत confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
काष्ठा global_confirm {
	TAILQ_ENTRY(global_confirm) entry;
	global_confirm_cb *cb;
	व्योम *ctx;
	पूर्णांक ref_गिनती;
};
TAILQ_HEAD(global_confirms, global_confirm);
अटल काष्ठा global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

अटल व्योम quit_message(स्थिर अक्षर *fmt, ...)
    __attribute__((__format__ (म_लिखो, 1, 2)));

अटल व्योम
quit_message(स्थिर अक्षर *fmt, ...)
{
	अक्षर *संदेश, *fmt2;
	बहु_सूची args;
	xasprintf(&fmt2, "%s\r\n", fmt);

	बहु_शुरू(args, fmt);
	xvasprintf(&संदेश, fmt2, args);
	बहु_पूर्ण(args);

	(व्योम)atomicio(vwrite, STDERR_FILENO, संदेश, म_माप(संदेश));
	मुक्त(संदेश);
	मुक्त(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
अटल व्योम
window_change_handler(पूर्णांक sig)
{
	received_window_change_signal = 1;
}

#अगर_घोषित SIGINFO
/* Signal handler for SIGINFO */
अटल व्योम
siginfo_handler(पूर्णांक sig)
{
	siginfo_received = 1;
}
#पूर्ण_अगर

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
अटल व्योम
signal_handler(पूर्णांक sig)
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
अटल व्योम
set_control_persist_exit_time(काष्ठा ssh *ssh)
{
	अगर (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} अन्यथा अगर (channel_still_open(ssh)) {
		/* some client connections are still open */
		अगर (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} अन्यथा अगर (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(समय_प्रकार)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#घोषणा SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
अटल पूर्णांक
client_x11_display_valid(स्थिर अक्षर *display)
{
	माप_प्रकार i, dlen;

	अगर (display == शून्य)
		वापस 0;

	dlen = म_माप(display);
	क्रम (i = 0; i < dlen; i++) {
		अगर (!है_अक्षर_अंक((u_char)display[i]) &&
		    म_अक्षर(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == शून्य) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			वापस 0;
		}
	}
	वापस 1;
}

#घोषणा SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#घोषणा X11_TIMEOUT_SLACK	60
पूर्णांक
client_x11_get_proto(काष्ठा ssh *ssh, स्थिर अक्षर *display,
    स्थिर अक्षर *xauth_path, u_int trusted, u_int timeout,
    अक्षर **_proto, अक्षर **तथ्य_2)
{
	अक्षर *cmd, पंक्ति[512], xdisplay[512];
	अक्षर xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	अटल अक्षर proto[512], तथ्य[512];
	खाता *f;
	पूर्णांक got_तथ्य = 0, generated = 0, do_unlink = 0, r;
	काष्ठा stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*तथ्य_2 = तथ्य;
	proto[0] = तथ्य[0] = xauthfile[0] = xauthdir[0] = '\0';

	अगर (!client_x11_display_valid(display)) {
		अगर (display != शून्य)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		वापस -1;
	}
	अगर (xauth_path != शून्य && stat(xauth_path, &st) == -1) {
		debug("No xauth program.");
		xauth_path = शून्य;
	}

	अगर (xauth_path != शून्य) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		अगर (म_भेदन(display, "localhost:", 10) == 0) {
			अगर ((r = snprintf(xdisplay, माप(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (माप_प्रकार)r >= माप(xdisplay)) {
				error_f("display name too long");
				वापस -1;
			}
			display = xdisplay;
		}
		अगर (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, माप(xauthdir));
			अगर (mkdtemp(xauthdir) == शून्य) {
				error_f("mkdtemp: %s", म_त्रुटि(त्रुटि_सं));
				वापस -1;
			}
			do_unlink = 1;
			अगर ((r = snprintf(xauthfile, माप(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (माप_प्रकार)r >= माप(xauthfile)) {
				error_f("xauthfile path too long");
				सूची_हटाओ(xauthdir);
				वापस -1;
			}

			अगर (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} अन्यथा {
				/* Add some slack to requested expiry */
				अगर (timeout < अच_पूर्णांक_उच्च - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				अन्यथा {
					/* Don't overflow on long timeouts */
					x11_timeout_real = अच_पूर्णांक_उच्च;
				}
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted timeout %u 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, x11_timeout_real,
				    _PATH_DEVNULL);
			}
			debug2_f("xauth command: %s", cmd);

			अगर (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				अगर (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				अन्यथा
					x11_refuse_time = now + timeout;
				channel_set_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			अगर (प्रणाली(cmd) == 0)
				generated = 1;
			मुक्त(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		अगर (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_path,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			अगर (f && ख_माला_लो(पंक्ति, माप(पंक्ति), f) &&
			    माला_पूछो(पंक्ति, "%*s %511s %511s", proto, तथ्य) == 2)
				got_तथ्य = 1;
			अगर (f)
				pclose(f);
			मुक्त(cmd);
		}
	}

	अगर (do_unlink) {
		unlink(xauthfile);
		सूची_हटाओ(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	अगर (!trusted && !got_तथ्य) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		वापस -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	अगर (!got_तथ्य) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, माप proto);
		arc4random_buf(rnd, माप(rnd));
		क्रम (i = 0; i < माप(rnd); i++) {
			snprintf(तथ्य + 2 * i, माप तथ्य - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	वापस 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

अटल व्योम
client_check_window_change(काष्ठा ssh *ssh)
{
	अगर (!received_window_change_signal)
		वापस;
	received_window_change_signal = 0;
	debug2_f("changed");
	channel_send_window_changes(ssh);
}

अटल पूर्णांक
client_global_request_reply(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा global_confirm *gc;

	अगर ((gc = TAILQ_FIRST(&global_confirms)) == शून्य)
		वापस 0;
	अगर (gc->cb != शून्य)
		gc->cb(ssh, type, seq, gc->ctx);
	अगर (--gc->ref_गिनती <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, entry);
		freezero(gc, माप(*gc));
	}

	ssh_packet_set_alive_timeouts(ssh, 0);
	वापस 0;
}

अटल व्योम
schedule_server_alive_check(व्योम)
{
	अगर (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

अटल व्योम
server_alive_check(काष्ठा ssh *ssh)
{
	पूर्णांक r;

	अगर (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_गिनती_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_register_global_confirm(शून्य, शून्य);
	schedule_server_alive_check();
}

/* Try to send a dummy keystroke */
अटल पूर्णांक
send_chaff(काष्ठा ssh *ssh)
{
	पूर्णांक r;

	अगर (ssh->kex == शून्य || (ssh->kex->flags & KEX_HAS_PING) == 0)
		वापस 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	वापस 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
अटल व्योम
set_अग्र_interval(स्थिर काष्ठा timespec *now, काष्ठा timespec *अग्र_interval,
    u_int interval_ms, पूर्णांक starting)
{
	काष्ठा timespec tmp;
	दीर्घ दीर्घ interval_ns, fuzz_ns;
	अटल दीर्घ दीर्घ rate_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	अगर (fuzz_ns > पूर्णांक_उच्च)
		fuzz_ns = पूर्णांक_उच्च;
	अगर (fuzz_ns > interval_ns) {
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
	अगर (starting)
		rate_fuzz = arc4random_uniform(fuzz_ns);
	interval_ns -= fuzz_ns;
	interval_ns += arc4random_uniform(fuzz_ns) + rate_fuzz;

	tmp.tv_sec = interval_ns / (1000 * 1000 * 1000);
	tmp.tv_nsec = interval_ns % (1000 * 1000 * 1000);

	timespecadd(now, &tmp, अग्र_interval);
}

/*
 * Performs keystroke timing obfuscation. Returns non-zero if the
 * output fd should be polled.
 */
अटल पूर्णांक
obfuscate_keystroke_timing(काष्ठा ssh *ssh, काष्ठा timespec *timeout,
    पूर्णांक channel_did_enqueue)
{
	अटल पूर्णांक active;
	अटल काष्ठा timespec अग्र_interval, chaff_until;
	काष्ठा timespec now, tmp;
	पूर्णांक just_started = 0, had_keystroke = 0;
	अटल अचिन्हित दीर्घ दीर्घ nchaff;
	अक्षर *stop_reason = शून्य;
	दीर्घ दीर्घ n;

	monotime_ts(&now);

	अगर (options.obscure_keystroke_timing_interval <= 0)
		वापस 1;	/* disabled in config */

	अगर (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} अन्यथा अगर (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} अन्यथा अगर (!ssh_packet_interactive_तथ्य_to_write(ssh) &&
	    ssh_packet_have_तथ्य_to_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} अन्यथा अगर (active && channel_did_enqueue &&
	    ssh_packet_have_तथ्य_to_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} अन्यथा अगर (active) {
		अगर (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} अन्यथा अगर (timespeccmp(&now, &अग्र_interval, >=) &&
		    !ssh_packet_have_तथ्य_to_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			अगर (send_chaff(ssh))
				nchaff++;
		}
	}

	अगर (stop_reason != शून्य) {
		अगर (active) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			active = 0;
		}
		वापस 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	अगर (!active && ssh_packet_interactive_तथ्य_to_write(ssh) &&
	    channel_did_enqueue && ssh_packet_have_तथ्य_to_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = active = 1;
		nchaff = 0;
		set_अग्र_interval(&now, &अग्र_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	अगर (!active)
		वापस 1;

	अगर (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_to_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_uniform(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &अग्र_interval);

	अगर (just_started)
		वापस 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	अगर (timespeccmp(&now, &अग्र_interval, <))
		/* ...unless there's x11 communication happening */
		वापस x11_channel_used_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - अग्र_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - अग्र_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	set_अग्र_interval(&now, &अग्र_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	वापस 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
अटल व्योम
client_wait_until_can_do_something(काष्ठा ssh *ssh, काष्ठा pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, पूर्णांक channel_did_enqueue,
    sigset_t *sigsetp, पूर्णांक *conn_in_readyp, पूर्णांक *conn_out_readyp)
{
	काष्ठा timespec timeout;
	पूर्णांक ret, oready;
	u_int p;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	अगर (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	अगर (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_तथ्य_to_write(ssh)) {
		/* clear events since we did not call poll() */
		क्रम (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		वापस;
	}

	oready = obfuscate_keystroke_timing(ssh, &timeout, channel_did_enqueue);

	/* Monitor server connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_in;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_out;
	(*pfdp)[1].events = (oready && ssh_packet_have_तथ्य_to_write(ssh)) ?
	    POLLOUT : 0;

	/*
	 * Wait for something to happen.  This will suspend the process until
	 * some polled descriptor can be read, written, or has some other
	 * event pending, or a timeout expires.
	 */
	set_control_persist_exit_time(ssh);
	अगर (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	अगर (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	अगर (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	अगर (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		क्रम (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		अगर (त्रुटि_सं == EINTR)
			वापस;
		/* Note: we might still have data in the buffers. */
		quit_message("poll: %s", म_त्रुटि(त्रुटि_सं));
		वापस;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	अगर (options.server_alive_interval > 0 && !*conn_in_readyp &&
	    monotime() >= server_alive_time) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

अटल व्योम
client_suspend_self(काष्ठा sshbuf *bin, काष्ठा sshbuf *bout, काष्ठा sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	अगर (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(मानक_निकास), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	अगर (sshbuf_len(berr) > 0)
		atomicio(vwrite, fileno(मानक_त्रुटि), sshbuf_mutable_ptr(berr),
		    sshbuf_len(berr));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	sshbuf_reset(bin);
	sshbuf_reset(bout);
	sshbuf_reset(berr);

	/* Send the suspend signal to the program itself. */
	समाप्त(getpid(), SIGTSTP);

	/* Reset window sizes in case they have changed */
	received_window_change_signal = 1;

	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
}

अटल व्योम
client_process_net_निवेश(काष्ठा ssh *ssh)
{
	पूर्णांक r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	schedule_server_alive_check();
	अगर ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		वापस; /* success */
	अगर (r == SSH_ERR_SYSTEM_ERROR) {
		अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR || त्रुटि_सं == EWOULDBLOCK)
			वापस;
		अगर (त्रुटि_सं == EPIPE) {
			quit_message("Connection to %s closed by remote host.",
			    host);
			वापस;
		}
	}
	quit_message("Read from remote host %s: %s", host, ssh_err(r));
}

अटल व्योम
client_status_confirm(काष्ठा ssh *ssh, पूर्णांक type, Channel *c, व्योम *ctx)
{
	काष्ठा channel_reply_ctx *cr = (काष्ठा channel_reply_ctx *)ctx;
	अक्षर errmsg[256];
	पूर्णांक r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	अगर (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	अगर (type == SSH2_संदेश_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} अन्यथा अगर (type == SSH2_संदेश_CHANNEL_FAILURE) {
		अगर (tochan) {
			snprintf(errmsg, माप(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} अन्यथा {
			snprintf(errmsg, माप(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		अगर (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		अगर (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			अगर ((r = sshbuf_put(c->extended, errmsg,
			    म_माप(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} अन्यथा
			error("%s", errmsg);
		अगर (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			अगर (c->self == session_ident)
				leave_raw_mode(0);
			अन्यथा
				mux_tty_alloc_failed(ssh, c);
		} अन्यथा अगर (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	मुक्त(cr);
}

अटल व्योम
client_abandon_status_confirm(काष्ठा ssh *ssh, Channel *c, व्योम *ctx)
{
	मुक्त(ctx);
}

व्योम
client_expect_confirm(काष्ठा ssh *ssh, पूर्णांक id, स्थिर अक्षर *request,
    क्रमागत confirm_action action)
{
	काष्ठा channel_reply_ctx *cr = xcalloc(1, माप(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_register_status_confirm(ssh, id, client_status_confirm,
	    client_abandon_status_confirm, cr);
}

व्योम
client_register_global_confirm(global_confirm_cb *cb, व्योम *ctx)
{
	काष्ठा global_confirm *gc, *last_gc;

	/* Coalesce identical callbacks */
	last_gc = TAILQ_LAST(&global_confirms, global_confirms);
	अगर (last_gc && last_gc->cb == cb && last_gc->ctx == ctx) {
		अगर (++last_gc->ref_गिनती >= पूर्णांक_उच्च)
			fatal_f("last_gc->ref_count = %d",
			    last_gc->ref_गिनती);
		वापस;
	}

	gc = xcalloc(1, माप(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_गिनती = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, entry);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
अटल पूर्णांक
can_update_hostkeys(व्योम)
{
	अगर (hostkeys_update_complete)
		वापस 0;
	अगर (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_mode)
		वापस 0; /* won't ask in batchmode, so don't even try */
	अगर (!options.update_hostkeys || options.अंक_user_hostfiles <= 0)
		वापस 0;
	वापस 1;
}

अटल व्योम
client_repledge(व्योम)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	अगर (options.control_master || options.control_path != शून्य ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != शून्य || can_update_hostkeys() ||
	    (session_ident != -1 && !session_setup_complete)) {
		/* Can't tighten */
		वापस;
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
	अगर (options.अंक_local_forwards != 0 ||
	    options.अंक_remote_forwards != 0 ||
	    options.अंक_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		अगर (pledge("stdio unix inet dns proc tty", शून्य) == -1)
			fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));
	} अन्यथा अगर (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		अगर (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", शून्य) == -1)
			fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));
	} अन्यथा {
		debug("pledge: fork");
		अगर (pledge(PLEDGE_EXTRA_INET "stdio proc tty", शून्य) == -1)
			fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));
	}
	/* XXX further things to do:
	 *
	 * - might be able to get rid of proc if we kill ~^Z
	 * - ssh -N (no session)
	 * - stdio forwarding
	 * - sessions without tty
	 */
}

अटल व्योम
process_cmdline(काष्ठा ssh *ssh)
{
	व्योम (*handler)(पूर्णांक);
	अक्षर *s, *cmd;
	पूर्णांक ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	काष्ठा Forward fwd;

	स_रखो(&fwd, 0, माप(fwd));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(संक_विघ्न, संक_छोड़ो);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	अगर (s == शून्य)
		जाओ out;
	जबतक (है_खाली((u_char)*s))
		s++;
	अगर (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	अगर (*s == '\0')
		जाओ out;

	अगर (*s == 'h' || *s == 'H' || *s == '?') {
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
		अगर (!options.permit_local_command)
			जाओ out;
		logit("      !args                                  "
		    "Execute local command");
		जाओ out;
	}

	अगर (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		जाओ out;
	}

	अगर (*s == 'K') {
		delete = 1;
		s++;
	}
	अगर (*s == 'L')
		local = 1;
	अन्यथा अगर (*s == 'R')
		remote = 1;
	अन्यथा अगर (*s == 'D')
		dynamic = 1;
	अन्यथा {
		logit("Invalid command.");
		जाओ out;
	}

	जबतक (है_खाली((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	अगर (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		अगर (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			जाओ out;
		}
		अगर (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		अन्यथा अगर (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		अन्यथा
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_PORT_STATIC,
			    &options.fwd_opts) > 0;
		अगर (!ok) {
			logit("Unknown port forwarding.");
			जाओ out;
		}
		logit("Canceled forwarding.");
	} अन्यथा {
		/* -R specs can be both dynamic or not, so check both. */
		अगर (remote) {
			अगर (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				जाओ out;
			}
		} अन्यथा अगर (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			जाओ out;
		}
		अगर (local || dynamic) {
			अगर (!channel_setup_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				जाओ out;
			}
		} अन्यथा {
			अगर (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				जाओ out;
			}
		}
		logit("Forwarding port.");
	}

out:
	ssh_signal(संक_विघ्न, handler);
	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	मुक्त(cmd);
	मुक्त(fwd.listen_host);
	मुक्त(fwd.listen_path);
	मुक्त(fwd.connect_host);
	मुक्त(fwd.connect_path);
}

/* reasons to suppress output of an escape command in help output */
#घोषणा SUPPRESS_NEVER		0	/* never suppress, always show */
#घोषणा SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#घोषणा SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#घोषणा SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#घोषणा SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
काष्ठा escape_help_text {
	स्थिर अक्षर *cmd;
	स्थिर अक्षर *text;
	अचिन्हित पूर्णांक flags;
};
अटल काष्ठा escape_help_text esc_txt[] = {
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

अटल व्योम
print_escape_help(काष्ठा sshbuf *b, पूर्णांक escape_char, पूर्णांक mux_client,
    पूर्णांक using_stderr)
{
	अचिन्हित पूर्णांक i, suppress_flags;
	पूर्णांक r;

	अगर ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	क्रम (i = 0; i < माप(esc_txt)/माप(esc_txt[0]); i++) {
		अगर (esc_txt[i].flags & suppress_flags)
			जारी;
		अगर ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	अगर ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
अटल पूर्णांक
process_escapes(काष्ठा ssh *ssh, Channel *c,
    काष्ठा sshbuf *bin, काष्ठा sshbuf *bout, काष्ठा sshbuf *berr,
    अक्षर *buf, पूर्णांक len)
{
	pid_t pid;
	पूर्णांक r, bytes = 0;
	u_int i;
	u_char ch;
	अक्षर *s;
	काष्ठा escape_filter_ctx *efc;

	अगर (c == शून्य || c->filter_ctx == शून्य || len <= 0)
		वापस 0;

	efc = (काष्ठा escape_filter_ctx *)c->filter_ctx;

	क्रम (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		अगर (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			चयन (ch) {
			हाल '.':
				/* Terminate the connection. */
				अगर ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				अगर (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					वापस 0;
				} अन्यथा
					quit_pending = 1;
				वापस -1;

			हाल 'Z' - 64:
				/* XXX support this for mux clients */
				अगर (c && c->ctl_chan != -1) {
					अक्षर b[16];
 noescape:
					अगर (ch == 'Z' - 64)
						snprintf(b, माप b, "^Z");
					अन्यथा
						snprintf(b, माप b, "%c", ch);
					अगर ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					जारी;
				}
				/* Suspend the program. Inform the user */
				अगर ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				जारी;

			हाल 'B':
				अगर ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				अगर ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				जारी;

			हाल 'I':
				अगर ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_message(ssh);
				अगर ((r = sshbuf_put(berr, s, म_माप(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				मुक्त(s);
				जारी;

			हाल 'R':
				अगर (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				अन्यथा
					need_rekeying = 1;
				जारी;

			हाल 'V':
				/* FALLTHROUGH */
			हाल 'v':
				अगर (c && c->ctl_chan != -1)
					जाओ noescape;
				अगर (!log_is_on_stderr()) {
					अगर ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					जारी;
				}
				अगर (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				अगर (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				अगर ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				जारी;

			हाल '&':
				अगर (c->ctl_chan != -1)
					जाओ noescape;
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

				अगर ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = विभाजन();
				अगर (pid == -1) {
					error("fork: %.100s", म_त्रुटि(त्रुटि_सं));
					जारी;
				}
				अगर (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					निकास(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				अगर ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				वापस -1;
			हाल '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				जारी;

			हाल '#':
				अगर ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_message(ssh);
				अगर ((r = sshbuf_put(berr, s, म_माप(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				मुक्त(s);
				जारी;

			हाल 'C':
				अगर (c && c->ctl_chan != -1)
					जाओ noescape;
				अगर (options.enable_escape_commandline == 0) {
					अगर ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					जारी;
				}
				process_cmdline(ssh);
				जारी;

			शेष:
				अगर (ch != efc->escape_char) {
					अगर ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					bytes++;
				}
				/* Escaped characters fall through here */
				अवरोध;
			}
		} अन्यथा {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			अगर (last_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				जारी;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		last_was_cr = (ch == '\r' || ch == '\n');
		अगर ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		bytes++;
	}
	वापस bytes;
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

अटल व्योम
client_process_buffered_निवेश_packets(काष्ठा ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
व्योम *
client_new_escape_filter_ctx(पूर्णांक escape_char)
{
	काष्ठा escape_filter_ctx *ret;

	ret = xcalloc(1, माप(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	वापस (व्योम *)ret;
}

/* Free the escape filter context on channel free */
व्योम
client_filter_cleanup(काष्ठा ssh *ssh, पूर्णांक cid, व्योम *ctx)
{
	मुक्त(ctx);
}

पूर्णांक
client_simple_escape_filter(काष्ठा ssh *ssh, Channel *c, अक्षर *buf, पूर्णांक len)
{
	अगर (c->extended_usage != CHAN_EXTENDED_WRITE)
		वापस 0;

	वापस process_escapes(ssh, c, c->निवेश, c->output, c->extended,
	    buf, len);
}

अटल व्योम
client_channel_closed(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक force, व्योम *arg)
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
पूर्णांक
client_loop(काष्ठा ssh *ssh, पूर्णांक have_pty, पूर्णांक escape_char_arg,
    पूर्णांक ssh2_chan_id)
{
	काष्ठा pollfd *pfd = शून्य;
	u_int npfd_alloc = 0, npfd_active = 0;
	द्विगुन start_time, योग_time;
	पूर्णांक interactive = -1, channel_did_enqueue = 0, r;
	uint64_t ibytes, obytes;
	पूर्णांक conn_in_ready, conn_out_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	अगर (options.pkcs11_provider != शून्य)
		debug("pledge: disabled (PKCS11Provider active)");
	अन्यथा अगर (options.control_master &&
	    !option_clear_or_none(options.control_path)) {
		debug("pledge: id");
		अगर (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    शून्य) == -1)
			fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));

	} अन्यथा अगर (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		अगर (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    शून्य) == -1)
			fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));

	} अन्यथा अगर (options.update_hostkeys) {
		debug("pledge: filesystem");
		अगर (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    शून्य) == -1)
			fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));

	} अन्यथा अगर (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		अगर (pledge("stdio cpath unix inet dns proc tty", शून्य) == -1)
			fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));

	} अन्यथा {
		debug("pledge: network");
		अगर (pledge("stdio unix inet dns proc tty", शून्य) == -1)
			fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));
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
	अगर (ssh_signal(SIGHUP, संक_छोड़ो) != संक_छोड़ो)
		ssh_signal(SIGHUP, signal_handler);
	अगर (ssh_signal(संक_विघ्न, संक_छोड़ो) != संक_छोड़ो)
		ssh_signal(संक_विघ्न, signal_handler);
	अगर (ssh_signal(SIGQUIT, संक_छोड़ो) != संक_छोड़ो)
		ssh_signal(SIGQUIT, signal_handler);
	अगर (ssh_signal(संक_इति, संक_छोड़ो) != संक_छोड़ो)
		ssh_signal(संक_इति, signal_handler);
	ssh_signal(SIGWINCH, window_change_handler);
#अगर_घोषित SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#पूर्ण_अगर

	अगर (have_pty)
		enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	अगर (session_ident != -1) {
		अगर (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, शून्य,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_register_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	schedule_server_alive_check();

	अगर (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, संक_विघ्न) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, संक_इति) == -1)
		error_f("bsigset setup: %s", म_त्रुटि(त्रुटि_सं));
#अगर_घोषित SIGINFO
	अगर (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर

	/* Main loop of the client for the interactive session mode. */
	जबतक (!quit_pending) {
		channel_did_enqueue = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_निवेश_packets(ssh);

		अगर (session_closed && !channel_still_open(ssh))
			अवरोध;

		अगर (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} अन्यथा अगर (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			अगर ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} अन्यथा {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			अगर (ssh_packet_not_very_much_तथ्य_to_write(ssh))
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
		अगर (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", म_त्रुटि(त्रुटि_सं));
		अगर (siginfo_received) {
			अक्षर ident[256];

			sshpkt_fmt_connection_id(ssh, ident, माप(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - start_time);
			siginfo_received = 0;
		}
		अगर (quit_pending)
			अवरोध;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_active, channel_did_enqueue, &osigset,
		    &conn_in_ready, &conn_out_ready);
		अगर (sigprocmask(SIG_SETMASK, &osigset, शून्य) == -1)
			error_f("osigset sigprocmask: %s", म_त्रुटि(त्रुटि_सं));

		अगर (quit_pending)
			अवरोध;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_active);

		/* Buffer input from the connection.  */
		अगर (conn_in_ready)
			client_process_net_निवेश(ssh);

		अगर (quit_pending)
			अवरोध;

		/* A timeout may have triggered rekeying */
		अगर ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		अगर (conn_out_ready) {
			अगर (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_set_interactive(ssh, interactive);
			}
			अगर ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		अगर (control_persist_exit_time > 0) {
			अगर (monotime() >= control_persist_exit_time) {
				debug("ControlPersist timeout expired");
				अवरोध;
			}
		}
	}
	मुक्त(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	अगर (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_message("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, संक_पूर्व);

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	अगर (have_pty)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	अगर (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == संक_इति) {
		received_signal = 0;
		exit_status = 0;
	}

	अगर (received_signal) {
		verbose("Killed by signal %d.", (पूर्णांक) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	योग_time = monotime_double() - start_time;
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (अचिन्हित दीर्घ दीर्घ)obytes, (अचिन्हित दीर्घ दीर्घ)ibytes, योग_time);
	अगर (योग_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / योग_time, ibytes / योग_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	वापस exit_status;
}

/*********/

अटल Channel *
client_request_forwarded_tcpip(काष्ठा ssh *ssh, स्थिर अक्षर *request_type,
    पूर्णांक rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = शून्य;
	काष्ठा sshbuf *b = शून्य;
	अक्षर *listen_address, *originator_address;
	u_int listen_port, originator_port;
	पूर्णांक r;

	/* Get rest of the packet */
	अगर ((r = sshpkt_get_cstring(ssh, &listen_address, शून्य)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_address, शून्य)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_address, listen_port, originator_address, originator_port);

	अगर (listen_port > 0xffff)
		error_f("invalid listen port");
	अन्यथा अगर (originator_port > 0xffff)
		error_f("invalid originator port");
	अन्यथा {
		c = channel_connect_by_listen_address(ssh,
		    listen_address, listen_port, "forwarded-tcpip",
		    originator_address);
	}

	अगर (c != शून्य && c->type == SSH_CHANNEL_MUX_CLIENT) {
		अगर ((b = sshbuf_new()) == शून्य) {
			error_f("alloc reply");
			जाओ out;
		}
		/* reconstruct and send to muxclient */
		अगर ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_संदेश_CHANNEL_OPEN)) != 0 ||
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
			जाओ out;
		}
	}

 out:
	sshbuf_free(b);
	मुक्त(originator_address);
	मुक्त(listen_address);
	वापस c;
}

अटल Channel *
client_request_forwarded_streamlocal(काष्ठा ssh *ssh,
    स्थिर अक्षर *request_type, पूर्णांक rchan)
{
	Channel *c = शून्य;
	अक्षर *listen_path;
	पूर्णांक r;

	/* Get the remote path. */
	अगर ((r = sshpkt_get_cstring(ssh, &listen_path, शून्य)) != 0 ||
	    (r = sshpkt_get_string(ssh, शून्य, शून्य)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_path);

	c = channel_connect_by_listen_path(ssh, listen_path,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	मुक्त(listen_path);
	वापस c;
}

अटल Channel *
client_request_x11(काष्ठा ssh *ssh, स्थिर अक्षर *request_type, पूर्णांक rchan)
{
	Channel *c = शून्य;
	अक्षर *originator;
	u_int originator_port;
	पूर्णांक r, sock;

	अगर (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		वापस शून्य;
	}
	अगर (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		वापस शून्य;
	}
	अगर ((r = sshpkt_get_cstring(ssh, &originator, शून्य)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_port);
	मुक्त(originator);
	sock = x11_connect_display(ssh);
	अगर (sock < 0)
		वापस शून्य;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	वापस c;
}

अटल Channel *
client_request_agent(काष्ठा ssh *ssh, स्थिर अक्षर *request_type, पूर्णांक rchan)
{
	Channel *c = शून्य;
	पूर्णांक r, sock;

	अगर (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		वापस शून्य;
	}
	अगर (forward_agent_sock_path == शून्य) {
		r = ssh_get_authentication_socket(&sock);
	} अन्यथा {
		r = ssh_get_authentication_socket_path(forward_agent_sock_path, &sock);
	}
	अगर (r != 0) {
		अगर (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		वापस शून्य;
	}
	अगर ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	अन्यथा
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	वापस c;
}

अक्षर *
client_request_tun_fwd(काष्ठा ssh *ssh, पूर्णांक tun_mode,
    पूर्णांक local_tun, पूर्णांक remote_tun, channel_open_fn *cb, व्योम *cbctx)
{
	Channel *c;
	पूर्णांक r, fd;
	अक्षर *ifname = शून्य;

	अगर (tun_mode == SSH_TUNMODE_NO)
		वापस शून्य;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	अगर ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		वापस शून्य;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#अगर defined(SSH_TUN_FILTER)
	अगर (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, शून्य, शून्य);
#पूर्ण_अगर

	अगर (cb != शून्य)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	वापस ifname;
}

/* XXXX move to generic input handler */
अटल पूर्णांक
client_निवेश_channel_open(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Channel *c = शून्य;
	अक्षर *ctype = शून्य;
	पूर्णांक r;
	u_int rchan;
	माप_प्रकार len;
	u_int rmaxpack, rwindow;

	अगर ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		जाओ out;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	अगर (म_भेद(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} अन्यथा अगर (म_भेद(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} अन्यथा अगर (म_भेद(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} अन्यथा अगर (म_भेद(ctype, "auth-agent@openssh.com") == 0 ||
	    म_भेद(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	अगर (c != शून्य && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} अन्यथा अगर (c != शून्य) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		अगर (c->type != SSH_CHANNEL_CONNECTING) {
			अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} अन्यथा {
		debug("failure %s", ctype);
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_OPEN_FAILURE)) != 0 ||
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
	वापस r;
}

अटल पूर्णांक
client_निवेश_channel_req(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Channel *c = शून्य;
	अक्षर *rtype = शून्य;
	u_char reply;
	u_int id, exitval;
	पूर्णांक r, success = 0;

	अगर ((r = sshpkt_get_u32(ssh, &id)) != 0)
		वापस r;
	अगर (id <= पूर्णांक_उच्च)
		c = channel_lookup(ssh, id);
	अगर (channel_proxy_upstream(c, type, seq, ssh))
		वापस 0;
	अगर ((r = sshpkt_get_cstring(ssh, &rtype, शून्य)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &reply)) != 0)
		जाओ out;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, reply);

	अगर (c == शून्य) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} अन्यथा अगर (म_भेद(rtype, "eow@openssh.com") == 0) {
		अगर ((r = sshpkt_get_end(ssh)) != 0)
			जाओ out;
		chan_rcvd_eow(ssh, c);
	} अन्यथा अगर (म_भेद(rtype, "exit-status") == 0) {
		अगर ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			जाओ out;
		अगर (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} अन्यथा अगर ((पूर्णांक)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} अन्यथा {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		अगर ((r = sshpkt_get_end(ssh)) != 0)
			जाओ out;
	}
	अगर (reply && c != शून्य && !(c->flags & CHAN_CLOSE_SENT)) {
		अगर (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		अगर ((r = sshpkt_start(ssh, success ?
		    SSH2_संदेश_CHANNEL_SUCCESS : SSH2_संदेश_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	मुक्त(rtype);
	वापस r;
}

काष्ठा hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	अक्षर *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	काष्ठा sshkey **कुंजियाँ;
	u_int *कुंजियाँ_match;	/* mask of HKF_MATCH_* from hostfile.h */
	पूर्णांक *कुंजियाँ_verified;	/* flag for new keys verified by server */
	माप_प्रकार nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	काष्ठा sshkey **old_कुंजियाँ;
	माप_प्रकार nold;

	/* Various special cases. */
	पूर्णांक complex_hostspec;	/* wildcard or manual pattern-list host name */
	पूर्णांक ca_available;	/* saw CA key for this host */
	पूर्णांक old_कुंजी_seen;	/* saw old key with other name/addr */
	पूर्णांक other_name_seen;	/* saw key with other name/addr */
};

अटल व्योम
hostkeys_update_ctx_free(काष्ठा hostkeys_update_ctx *ctx)
{
	माप_प्रकार i;

	अगर (ctx == शून्य)
		वापस;
	क्रम (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->कुंजियाँ[i]);
	मुक्त(ctx->कुंजियाँ);
	मुक्त(ctx->कुंजियाँ_match);
	मुक्त(ctx->कुंजियाँ_verified);
	क्रम (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_कुंजियाँ[i]);
	मुक्त(ctx->old_कुंजियाँ);
	मुक्त(ctx->host_str);
	मुक्त(ctx->ip_str);
	मुक्त(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
अटल पूर्णांक
hostspec_is_complex(स्थिर अक्षर *hosts)
{
	अक्षर *cp;

	/* wildcard */
	अगर (म_अक्षर(hosts, '*') != शून्य || म_अक्षर(hosts, '?') != शून्य)
		वापस 1;
	/* single host/ip = ok */
	अगर ((cp = म_अक्षर(hosts, ',')) == शून्य)
		वापस 0;
	/* more than two entries on the line */
	अगर (म_अक्षर(cp + 1, ',') != शून्य)
		वापस 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	वापस 0;
}

/* callback to search for ctx->keys in known_hosts */
अटल पूर्णांक
hostkeys_find(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *_ctx)
{
	काष्ठा hostkeys_update_ctx *ctx = (काष्ठा hostkeys_update_ctx *)_ctx;
	माप_प्रकार i;
	काष्ठा sshkey **tmp;

	अगर (l->कुंजी == शून्य)
		वापस 0;
	अगर (l->status != HKF_STATUS_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		क्रम (i = 0; i < ctx->nkeys; i++) {
			अगर (sshkey_equal(l->कुंजी, ctx->कुंजियाँ[i])) {
				ctx->other_name_seen = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->कुंजियाँ[i]),
				    l->path, l->linenum);
				वापस 0;
			}
		}
		वापस 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	अगर (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		वापस 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	अगर (ctx->ip_str != शून्य && म_अक्षर(l->hosts, ',') != शून्य) {
		अगर ((l->match & HKF_MATCH_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_seen = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->path, l->linenum);
			वापस 0;
		} अन्यथा अगर ((l->match & HKF_MATCH_IP) == 0) {
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
	अगर (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		वापस 0;
	}

	/* Mark off keys we've already seen for this host */
	क्रम (i = 0; i < ctx->nkeys; i++) {
		अगर (!sshkey_equal(l->कुंजी, ctx->कुंजियाँ[i]))
			जारी;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->कुंजियाँ[i]), l->path, l->linenum);
		ctx->कुंजियाँ_match[i] |= l->match;
		वापस 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->कुंजी),
	    l->path, l->linenum);
	अगर ((tmp = recallocarray(ctx->old_कुंजियाँ, ctx->nold, ctx->nold + 1,
	    माप(*ctx->old_कुंजियाँ))) == शून्य)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_कुंजियाँ = tmp;
	ctx->old_कुंजियाँ[ctx->nold++] = l->कुंजी;
	l->कुंजी = शून्य;

	वापस 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
अटल पूर्णांक
hostkeys_check_old(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *_ctx)
{
	काष्ठा hostkeys_update_ctx *ctx = (काष्ठा hostkeys_update_ctx *)_ctx;
	माप_प्रकार i;
	पूर्णांक hashed;

	/* only care about lines that *don't* match the active host spec */
	अगर (l->status == HKF_STATUS_MATCHED || l->कुंजी == शून्य)
		वापस 0;

	hashed = l->match & (HKF_MATCH_HOST_HASHED|HKF_MATCH_IP_HASHED);
	क्रम (i = 0; i < ctx->nold; i++) {
		अगर (!sshkey_equal(l->कुंजी, ctx->old_कुंजियाँ[i]))
			जारी;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_कुंजियाँ[i]), l->path, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_कुंजी_seen = 1;
		अवरोध;
	}
	वापस 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
अटल पूर्णांक
check_old_कुंजियाँ_othernames(काष्ठा hostkeys_update_ctx *ctx)
{
	माप_प्रकार i;
	पूर्णांक r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	क्रम (i = 0; i < options.अंक_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		अगर ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_कुंजी, 0)) != 0) {
			अगर (r == SSH_ERR_SYSTEM_ERROR && त्रुटि_सं == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				जारी;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			वापस -1;
		}
	}
	वापस 0;
}

अटल व्योम
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

अटल व्योम
update_known_hosts(काष्ठा hostkeys_update_ctx *ctx)
{
	पूर्णांक r, was_raw = 0, first = 1;
	पूर्णांक asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	अक्षर *fp, *response;
	माप_प्रकार i;
	काष्ठा stat sb;

	क्रम (i = 0; i < ctx->nkeys; i++) {
		अगर (!ctx->कुंजियाँ_verified[i])
			जारी;
		अगर ((fp = sshkey_fingerprint(ctx->कुंजियाँ[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य)
			fatal_f("sshkey_fingerprint failed");
		अगर (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->कुंजियाँ[i]), fp);
		first = 0;
		मुक्त(fp);
	}
	क्रम (i = 0; i < ctx->nold; i++) {
		अगर ((fp = sshkey_fingerprint(ctx->old_कुंजियाँ[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य)
			fatal_f("sshkey_fingerprint failed");
		अगर (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_कुंजियाँ[i]), fp);
		first = 0;
		मुक्त(fp);
	}
	अगर (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		अगर (get_saved_tio() != शून्य) {
			leave_raw_mode(1);
			was_raw = 1;
		}
		response = शून्य;
		क्रम (i = 0; !quit_pending && i < 3; i++) {
			मुक्त(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			अगर (response != शून्य && strcasecmp(response, "yes") == 0)
				अवरोध;
			अन्यथा अगर (quit_pending || response == शून्य ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				अवरोध;
			} अन्यथा {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		अगर (quit_pending || i >= 3 || response == शून्य)
			options.update_hostkeys = 0;
		मुक्त(response);
		अगर (was_raw)
			enter_raw_mode(1);
	}
	अगर (options.update_hostkeys == 0)
		वापस;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	क्रम (i = 0; i < options.अंक_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		अगर (stat(options.user_hostfiles[i], &sb) != 0) {
			अगर (त्रुटि_सं == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} अन्यथा {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], म_त्रुटि(त्रुटि_सं));
			}
			जारी;
		}
		अगर ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->कुंजियाँ : शून्य, i == 0 ? ctx->nkeys : 0,
		    options.hash_known_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

अटल व्योम
client_global_hostkeys_prove_confirm(काष्ठा ssh *ssh, पूर्णांक type,
    uint32_t seq, व्योम *_ctx)
{
	काष्ठा hostkeys_update_ctx *ctx = (काष्ठा hostkeys_update_ctx *)_ctx;
	माप_प्रकार i, ndone;
	काष्ठा sshbuf *signdata;
	पूर्णांक r, plaintype;
	स्थिर u_char *sig;
	स्थिर अक्षर *rsa_kexalg = शून्य;
	अक्षर *alg = शून्य;
	माप_प्रकार siglen;

	अगर (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	अगर (type != SSH2_संदेश_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		वापस;
	}
	अगर (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == कुंजी_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	अगर ((signdata = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	क्रम (ndone = i = 0; i < ctx->nkeys; i++) {
		अगर (ctx->कुंजियाँ_match[i])
			जारी;
		plaintype = sshkey_type_plain(ctx->कुंजियाँ[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		अगर ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->कुंजियाँ[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		अगर ((r = sshpkt_get_string_direct(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			जाओ out;
		}
		अगर ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->कुंजियाँ[i]), i);
			जाओ out;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		अगर (plaintype == कुंजी_RSA && rsa_kexalg == शून्य &&
		    match_pattern_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			मुक्त(alg);
			/* zap the key from the list */
			sshkey_free(ctx->कुंजियाँ[i]);
			ctx->कुंजियाँ[i] = शून्य;
			ndone++;
			जारी;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->कुंजियाँ[i]), i, alg);
		मुक्त(alg);
		अगर ((r = sshkey_verify(ctx->कुंजियाँ[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == कुंजी_RSA ? rsa_kexalg : शून्य, 0, शून्य)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->कुंजियाँ[i]), i);
			जाओ out;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->कुंजियाँ_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	अगर (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	अगर ((r = sshpkt_get_end(ssh)) != 0) {
		error_f("protocol error");
		जाओ out;
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
अटल पूर्णांक
client_निवेश_hostkeys(काष्ठा ssh *ssh)
{
	स्थिर u_char *blob = शून्य;
	माप_प्रकार i, len = 0;
	काष्ठा sshbuf *buf = शून्य;
	काष्ठा sshkey *कुंजी = शून्य, **tmp;
	पूर्णांक r, prove_sent = 0;
	अक्षर *fp;
	अटल पूर्णांक hostkeys_seen = 0; /* XXX use struct ssh */
	बाह्य काष्ठा sockaddr_storage hostaddr; /* XXX from ssh.c */
	काष्ठा hostkeys_update_ctx *ctx = शून्य;
	u_int want;

	अगर (hostkeys_seen)
		fatal_f("server already sent hostkeys");
	अगर (!can_update_hostkeys())
		वापस 1;
	hostkeys_seen = 1;

	ctx = xcalloc(1, माप(*ctx));
	जबतक (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(कुंजी);
		कुंजी = शून्य;
		अगर ((r = sshpkt_get_string_direct(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			जाओ out;
		}
		अगर ((r = sshkey_from_blob(blob, len, &कुंजी)) != 0) {
			do_log2_fr(r, r == SSH_ERR_कुंजी_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			जारी;
		}
		fp = sshkey_fingerprint(कुंजी, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(कुंजी), fp);
		मुक्त(fp);

		अगर (!hostkey_accepted_by_hostkeyalgs(कुंजी)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(कुंजी));
			जारी;
		}
		/* Skip certs */
		अगर (sshkey_is_cert(कुंजी)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(कुंजी));
			जारी;
		}
		/* Ensure keys are unique */
		क्रम (i = 0; i < ctx->nkeys; i++) {
			अगर (sshkey_equal(कुंजी, ctx->कुंजियाँ[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(कुंजी));
				जाओ out;
			}
		}
		/* Key is good, record it */
		अगर ((tmp = recallocarray(ctx->कुंजियाँ, ctx->nkeys, ctx->nkeys + 1,
		    माप(*ctx->कुंजियाँ))) == शून्य)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->कुंजियाँ = tmp;
		ctx->कुंजियाँ[ctx->nkeys++] = कुंजी;
		कुंजी = शून्य;
	}

	अगर (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		जाओ out;
	}

	अगर ((ctx->कुंजियाँ_match = सुस्मृति(ctx->nkeys,
	    माप(*ctx->कुंजियाँ_match))) == शून्य ||
	    (ctx->कुंजियाँ_verified = सुस्मृति(ctx->nkeys,
	    माप(*ctx->कुंजियाँ_verified))) == शून्य)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (काष्ठा sockaddr *)&hostaddr : शून्य,
	    options.port, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : शून्य);

	/* Find which keys we already know about. */
	क्रम (i = 0; i < options.अंक_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		अगर ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_कुंजी, 0)) != 0) {
			अगर (r == SSH_ERR_SYSTEM_ERROR && त्रुटि_सं == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				जारी;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			जाओ out;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_MATCH_HOST | ( options.check_host_ip ? HKF_MATCH_IP : 0);
	क्रम (i = 0; i < ctx->nkeys; i++) {
		अगर (ctx->कुंजियाँ_match[i] == 0)
			ctx->nnew++;
		अगर ((ctx->कुंजियाँ_match[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	अगर (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		जाओ out;
	}

	/* Various reasons why we cannot proceed with the update */
	अगर (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		जाओ out;
	}
	अगर (ctx->other_name_seen) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		जाओ out;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	अगर (ctx->nold != 0) {
		अगर (check_old_कुंजियाँ_othernames(ctx) != 0)
			जाओ out; /* error already logged */
		अगर (ctx->old_कुंजी_seen) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == शून्य ? "" : ",",
			    ctx->ip_str == शून्य ? "" : ctx->ip_str);
			जाओ out;
		}
	}

	अगर (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_known_hosts(ctx);
		जाओ out;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	अगर ((buf = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	क्रम (i = 0; i < ctx->nkeys; i++) {
		अगर (ctx->कुंजियाँ_match[i])
			जारी;
		sshbuf_reset(buf);
		अगर ((r = sshkey_putb(ctx->कुंजियाँ[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	अगर ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_register_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = शून्य;  /* will be freed in callback */
	prove_sent = 1;

	/* Success */
 out:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(कुंजी);
	sshbuf_free(buf);
	अगर (!prove_sent) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	वापस 1;
}

अटल पूर्णांक
client_निवेश_global_request(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	अक्षर *rtype;
	u_char want_reply;
	पूर्णांक r, success = 0;

	अगर ((r = sshpkt_get_cstring(ssh, &rtype, शून्य)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		जाओ out;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_reply);
	अगर (म_भेद(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_निवेश_hostkeys(ssh);
	अगर (want_reply) {
		अगर ((r = sshpkt_start(ssh, success ? SSH2_संदेश_REQUEST_SUCCESS :
		    SSH2_संदेश_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			जाओ out;
	}
	r = 0;
 out:
	मुक्त(rtype);
	वापस r;
}

अटल व्योम
client_send_env(काष्ठा ssh *ssh, पूर्णांक id, स्थिर अक्षर *name, स्थिर अक्षर *val)
{
	पूर्णांक r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	अगर ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

व्योम
client_session2_setup(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक want_tty, पूर्णांक want_subsystem,
    स्थिर अक्षर *term, काष्ठा termios *tiop, पूर्णांक in_fd, काष्ठा sshbuf *cmd,
    अक्षर **env)
{
	माप_प्रकार i, j, len;
	पूर्णांक matched, r;
	अक्षर *type = शून्य, *cmdstring = शून्य, *name, *val;
	Channel *c = शून्य;

	debug2_f("id %d", id);

	अगर ((c = channel_lookup(ssh, id)) == शून्य)
		fatal_f("channel %d: unknown channel", id);

	अगर (want_tty) {
		काष्ठा winsize ws;

		/* Store window size in the packet. */
		अगर (ioctl(in_fd, TIOCGWINSZ, &ws) == -1)
			स_रखो(&ws, 0, माप(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		अगर ((r = sshpkt_put_cstring(ssh, term != शून्य ? term : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		अगर (tiop == शून्य)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		अगर ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	अगर (options.अंक_send_env != 0 && env != शून्य) {
		debug("Sending environment.");
		क्रम (i = 0; env[i] != शून्य; i++) {
			/* Split */
			name = xstrdup(env[i]);
			अगर ((val = म_अक्षर(name, '=')) == शून्य) {
				मुक्त(name);
				जारी;
			}
			*val++ = '\0';

			matched = 0;
			क्रम (j = 0; j < options.अंक_send_env; j++) {
				अगर (match_pattern(name, options.send_env[j])) {
					matched = 1;
					अवरोध;
				}
			}
			अगर (!matched) {
				debug3("Ignored env %s", name);
				मुक्त(name);
				जारी;
			}
			client_send_env(ssh, id, name, val);
			मुक्त(name);
		}
	}
	क्रम (i = 0; i < options.अंक_setenv; i++) {
		/* Split */
		name = xstrdup(options.setenv[i]);
		अगर ((val = म_अक्षर(name, '=')) == शून्य) {
			मुक्त(name);
			जारी;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		मुक्त(name);
	}

	len = sshbuf_len(cmd);
	अगर (len > 0) {
		अगर ((cmdstring = sshbuf_dup_string(cmd)) == शून्य)
			fatal_f("sshbuf_dup_string failed");
		अगर (len > 900)
			len = 900;
		अगर (want_subsystem) {
			debug("Sending subsystem: %.*s", (पूर्णांक)len, cmdstring);
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} अन्यथा {
			debug("Sending command: %.*s", (पूर्णांक)len, cmdstring);
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		अगर ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} अन्यथा {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		अगर ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_set_xtype(ssh, id, type);
	मुक्त(cmdstring);
	मुक्त(type);

	session_setup_complete = 1;
	client_repledge();
}

व्योम
client_channel_request_agent_forwarding(काष्ठा ssh *ssh, पूर्णांक id)
{
	स्थिर अक्षर *req = "auth-agent-req@openssh.com";
	पूर्णांक r;

	अगर (ssh->kex != शून्य && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_start(ssh, id, req, 0);
	अगर ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

अटल व्योम
client_init_dispatch(काष्ठा ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_CLOSE, &channel_निवेश_oclose);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_तथ्य, &channel_निवेश_तथ्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_EOF, &channel_निवेश_ieof);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_EXTENDED_तथ्य, &channel_निवेश_extended_तथ्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_OPEN, &client_निवेश_channel_open);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION, &channel_निवेश_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_OPEN_FAILURE, &channel_निवेश_open_failure);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_REQUEST, &client_निवेश_channel_req);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_WINDOW_ADJUST, &channel_निवेश_window_adjust);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_SUCCESS, &channel_निवेश_status_confirm);
	ssh_dispatch_set(ssh, SSH2_संदेश_CHANNEL_FAILURE, &channel_निवेश_status_confirm);
	ssh_dispatch_set(ssh, SSH2_संदेश_GLOBAL_REQUEST, &client_निवेश_global_request);

	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_निवेश_kexinit);

	/* global request reply messages */
	ssh_dispatch_set(ssh, SSH2_संदेश_REQUEST_FAILURE, &client_global_request_reply);
	ssh_dispatch_set(ssh, SSH2_संदेश_REQUEST_SUCCESS, &client_global_request_reply);
}

व्योम
client_stop_mux(व्योम)
{
	अगर (options.control_path != शून्य && muxserver_sock != -1)
		unlink(options.control_path);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	अगर (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
व्योम
cleanup_exit(पूर्णांक i)
{
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	अगर (options.control_path != शून्य && muxserver_sock != -1)
		unlink(options.control_path);
	ssh_kill_proxy_command();
	_निकास(i);
}
