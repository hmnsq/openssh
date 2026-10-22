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

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <ctype.h>
#include <errno.h>
#include <paths.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "packet.h"
#include "sshbuf.h"
#include "compat.h"
#include "channels.h"
#include "dispatch.h"
#include "sshkey.h"
#include "kex.h"
#include "log.h"
#include "misc.h"
#include "readconf.h"
#include "clientloop.h"
#include "sshconnect.h"
#include "authfd.h"
#include "atomicio.h"
#include "sshpty.h"
#include "match.h"
#include "ssherr.h"
#include "hostfile.h"

/* Permitted RSA signature algorithms for UpdateHostkeys proofs */
#define HOSTKEY_PROOF_RSA_ALGS	"rsa-sha2-512,rsa-sha2-256"

/* Uncertainty (in percent) of keystroke timing intervals */
#define SSH_KEYSTROKE_TIMING_FUZZ 10

extern char *__progname;

/* import options */
extern Options options;

/* Control socket */
extern 정수 muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
extern char *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
extern char *forward_agent_sock_path;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
static volatile sig_atomic_t received_window_change_signal = 0;
static volatile sig_atomic_t siginfo_received = 0;
static volatile sig_atomic_t received_signal = 0; /* exit signals */

/* Time when backgrounded control master using ControlPersist should exit */
static time_t control_persist_exit_time = 0;

/* Common data for the client loop code. */
volatile sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
static 정수 last_was_cr;		/* Last character was a newline. */
static 정수 exit_status;		/* Used to store the command exit status. */
static 정수 connection_in;	/* Connection to server (input). */
static 정수 connection_out;	/* Connection to server (output). */
static 정수 need_rekeying;	/* Set to non-zero if rekeying is requested. */
static 정수 session_closed;	/* In SSH2: login session closed. */
static time_t x11_refuse_time;	/* If >0, refuse x11 opens after this time. */
static time_t server_alive_time;	/* Time to do server_alive_check */
static 정수 hostkeys_update_complete;
static 정수 session_setup_complete;

static void client_init_dispatch(struct ssh *ssh);
정수	session_ident = -1;

/* Track escape per proto2 channel */
struct escape_filter_ctx {
	정수 escape_pending;
	정수 escape_char;
};

/* Context for channel confirmation replies */
struct channel_reply_ctx {
	const char *request_type;
	정수 id;
	enum confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
struct global_confirm {
	TAILQ_ENTRY(global_confirm) entry;
	global_confirm_cb *cb;
	void *ctx;
	정수 ref_count;
};
TAILQ_HEAD(global_confirms, global_confirm);
static struct global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);

static void quit_message(const char *fmt, ...)
    __attribute__((__format__ (printf, 1, 2)));

static void
quit_message(const char *fmt, ...)
{
	char *msg, *fmt2;
	va_list args;
	xasprintf(&fmt2, "%s\r\n", fmt);

	va_start(args, fmt);
	xvasprintf(&msg, fmt2, args);
	va_end(args);

	(void)atomicio(vwrite, STDERR_FILENO, msg, strlen(msg));
	free(msg);
	free(fmt2);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
static void
window_change_handler(정수 sig)
{
	received_window_change_signal = 1;
}

#ifdef SIGINFO
/* Signal handler for SIGINFO */
static void
siginfo_handler(정수 sig)
{
	siginfo_received = 1;
}
#endif

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
static void
signal_handler(정수 sig)
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
static void
set_control_persist_exit_time(struct ssh *ssh)
{
	만약 (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} 아니면 만약 (channel_still_open(ssh)) {
		/* some client connections are still open */
		만약 (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} 아니면 만약 (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#define SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
static 정수
client_x11_display_valid(const char *display)
{
	size_t i, dlen;

	만약 (display == NULL)
		반환 0;

	dlen = strlen(display);
	위해 (i = 0; i < dlen; i++) {
		만약 (!isalnum((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == NULL) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			반환 0;
		}
	}
	반환 1;
}

#define SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#define X11_TIMEOUT_SLACK	60
정수
client_x11_get_proto(struct ssh *ssh, const char *display,
    const char *xauth_path, u_int trusted, u_int timeout,
    char **_proto, char **_data)
{
	char *cmd, line[512], xdisplay[512];
	char xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	static char proto[512], data[512];
	FILE *f;
	정수 got_data = 0, generated = 0, do_unlink = 0, r;
	struct stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*_data = data;
	proto[0] = data[0] = xauthfile[0] = xauthdir[0] = '\0';

	만약 (!client_x11_display_valid(display)) {
		만약 (display != NULL)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		반환 -1;
	}
	만약 (xauth_path != NULL && stat(xauth_path, &st) == -1) {
		debug("No xauth program.");
		xauth_path = NULL;
	}

	만약 (xauth_path != NULL) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		만약 (strncmp(display, "localhost:", 10) == 0) {
			만약 ((r = snprintf(xdisplay, sizeof(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (size_t)r >= sizeof(xdisplay)) {
				error_f("display name too long");
				반환 -1;
			}
			display = xdisplay;
		}
		만약 (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, sizeof(xauthdir));
			만약 (mkdtemp(xauthdir) == NULL) {
				error_f("mkdtemp: %s", strerror(errno));
				반환 -1;
			}
			do_unlink = 1;
			만약 ((r = snprintf(xauthfile, sizeof(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (size_t)r >= sizeof(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				반환 -1;
			}

			만약 (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} 아니면 {
				/* Add some slack to requested expiry */
				만약 (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				아니면 {
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

			만약 (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				만약 (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				아니면
					x11_refuse_time = now + timeout;
				channel_set_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			만약 (system(cmd) == 0)
				generated = 1;
			free(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		만약 (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_path,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2("x11_get_proto: %s", cmd);
			f = popen(cmd, "r");
			만약 (f && fgets(line, sizeof(line), f) &&
			    sscanf(line, "%*s %511s %511s", proto, data) == 2)
				got_data = 1;
			만약 (f)
				pclose(f);
			free(cmd);
		}
	}

	만약 (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	만약 (!trusted && !got_data) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		반환 -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	만약 (!got_data) {
		uint8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, sizeof proto);
		arc4random_buf(rnd, sizeof(rnd));
		위해 (i = 0; i < sizeof(rnd); i++) {
			snprintf(data + 2 * i, sizeof data - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	반환 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

static void
client_check_window_change(struct ssh *ssh)
{
	만약 (!received_window_change_signal)
		반환;
	received_window_change_signal = 0;
	debug2_f("changed");
	channel_send_window_changes(ssh);
}

static 정수
client_global_request_reply(정수 type, uint32_t seq, struct ssh *ssh)
{
	struct global_confirm *gc;

	만약 ((gc = TAILQ_FIRST(&global_confirms)) == NULL)
		반환 0;
	만약 (gc->cb != NULL)
		gc->cb(ssh, type, seq, gc->ctx);
	만약 (--gc->ref_count <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, entry);
		freezero(gc, sizeof(*gc));
	}

	ssh_packet_set_alive_timeouts(ssh, 0);
	반환 0;
}

static void
schedule_server_alive_check(void)
{
	만약 (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

static void
server_alive_check(struct ssh *ssh)
{
	정수 r;

	만약 (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_count_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	만약 ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_register_global_confirm(NULL, NULL);
	schedule_server_alive_check();
}

/* Try to send a dummy keystroke */
static 정수
send_chaff(struct ssh *ssh)
{
	정수 r;

	만약 (ssh->kex == NULL || (ssh->kex->flags & KEX_HAS_PING) == 0)
		반환 0;
	/* XXX probabilistically send chaff? */
	/*
	 * a SSH2_MSG_CHANNEL_DATA payload is 9 bytes:
	 *    4 bytes channel ID + 4 bytes string length + 1 byte string data
	 * simulate that here.
	 */
	만약 ((r = sshpkt_start(ssh, SSH2_MSG_PING)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "PING!")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	반환 1;
}

/* Sets the next interval to send a keystroke or chaff packet */
static void
set_next_interval(const struct timespec *now, struct timespec *next_interval,
    u_int interval_ms, 정수 starting)
{
	struct timespec tmp;
	long long interval_ns, fuzz_ns;
	static long long rate_fuzz;

	interval_ns = interval_ms * (1000LL * 1000);
	fuzz_ns = (interval_ns * SSH_KEYSTROKE_TIMING_FUZZ) / 100;
	/* Center fuzz around requested interval */
	만약 (fuzz_ns > INT_MAX)
		fuzz_ns = INT_MAX;
	만약 (fuzz_ns > interval_ns) {
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
	만약 (starting)
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
static 정수
obfuscate_keystroke_timing(struct ssh *ssh, struct timespec *timeout,
    정수 channel_did_enqueue)
{
	static 정수 active;
	static struct timespec next_interval, chaff_until;
	struct timespec now, tmp;
	정수 just_started = 0, had_keystroke = 0;
	static unsigned long long nchaff;
	char *stop_reason = NULL;
	long long n;

	monotime_ts(&now);

	만약 (options.obscure_keystroke_timing_interval <= 0)
		반환 1;	/* disabled in config */

	만약 (!channel_tty_open(ssh) || quit_pending) {
		/* Stop if no channels left of we're waiting for one to close */
		stop_reason = "no active channels";
	} 아니면 만약 (ssh_packet_is_rekeying(ssh)) {
		/* Stop if we're rekeying */
		stop_reason = "rekeying started";
	} 아니면 만약 (!ssh_packet_interactive_data_to_write(ssh) &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Stop if the output buffer has more than a few keystrokes */
		stop_reason = "output buffer filling";
	} 아니면 만약 (active && channel_did_enqueue &&
	    ssh_packet_have_data_to_write(ssh)) {
		/* Still in active mode and have a keystroke queued. */
		had_keystroke = 1;
	} 아니면 만약 (active) {
		만약 (timespeccmp(&now, &chaff_until, >=)) {
			/* Stop if there have been no keystrokes for a while */
			stop_reason = "chaff time expired";
		} 아니면 만약 (timespeccmp(&now, &next_interval, >=) &&
		    !ssh_packet_have_data_to_write(ssh)) {
			/* If due to send but have no data, then send chaff */
			만약 (send_chaff(ssh))
				nchaff++;
		}
	}

	만약 (stop_reason != NULL) {
		만약 (active) {
			debug3_f("stopping: %s (%llu chaff packets sent)",
			    stop_reason, nchaff);
			active = 0;
		}
		반환 1;
	}

	/*
	 * If we're in interactive mode, and only have a small amount
	 * of outbound data, then we assume that the user is typing
	 * interactively. In this case, start quantising outbound packets to
	 * fixed time intervals to hide inter-keystroke timing.
	 */
	만약 (!active && ssh_packet_interactive_data_to_write(ssh) &&
	    channel_did_enqueue && ssh_packet_have_data_to_write(ssh)) {
		debug3_f("starting: interval ~%dms",
		    options.obscure_keystroke_timing_interval);
		just_started = had_keystroke = active = 1;
		nchaff = 0;
		set_next_interval(&now, &next_interval,
		    options.obscure_keystroke_timing_interval, 1);
	}

	/* Don't hold off if obfuscation inactive */
	만약 (!active)
		반환 1;

	만약 (had_keystroke) {
		/*
		 * Arrange to send chaff packets for a random interval after
		 * the last keystroke was sent.
		 */
		ms_to_timespec(&tmp, SSH_KEYSTROKE_CHAFF_MIN_MS +
		    arc4random_uniform(SSH_KEYSTROKE_CHAFF_RNG_MS));
		timespecadd(&now, &tmp, &chaff_until);
	}

	ptimeout_deadline_monotime_tsp(timeout, &next_interval);

	만약 (just_started)
		반환 1;

	/* Don't arm output fd for poll until the timing interval has elapsed... */
	만약 (timespeccmp(&now, &next_interval, <))
		/* ...unless there's x11 communication happening */
		반환 x11_channel_used_recently(ssh);

	/* Calculate number of intervals missed since the last check */
	n = (now.tv_sec - next_interval.tv_sec) * 1000LL * 1000 * 1000;
	n += now.tv_nsec - next_interval.tv_nsec;
	n /= options.obscure_keystroke_timing_interval * 1000LL * 1000;
	n = (n < 0) ? 1 : n + 1;

	/* Advance to the next interval */
	set_next_interval(&now, &next_interval,
	    options.obscure_keystroke_timing_interval * n, 0);
	반환 1;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
static void
client_wait_until_can_do_something(struct ssh *ssh, struct pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, 정수 channel_did_enqueue,
    sigset_t *sigsetp, 정수 *conn_in_readyp, 정수 *conn_out_readyp)
{
	struct timespec timeout;
	정수 ret, oready;
	u_int p;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	만약 (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	만약 (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_data_to_write(ssh)) {
		/* clear events since we did not call poll() */
		위해 (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		반환;
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
	만약 (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	만약 (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	만약 (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh)) {
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));
	}

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	만약 (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		위해 (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		만약 (errno == EINTR)
			반환;
		/* Note: we might still have data in the buffers. */
		quit_message("poll: %s", strerror(errno));
		반환;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	만약 (options.server_alive_interval > 0 && !*conn_in_readyp &&
	    monotime() >= server_alive_time) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

static void
client_suspend_self(struct sshbuf *bin, struct sshbuf *bout, struct sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	만약 (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	만약 (sshbuf_len(berr) > 0)
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

static void
client_process_net_input(struct ssh *ssh)
{
	정수 r;

	/*
	 * Read input from the server, and add any such data to the buffer of
	 * the packet subsystem.
	 */
	schedule_server_alive_check();
	만약 ((r = ssh_packet_process_read(ssh, connection_in)) == 0)
		반환; /* success */
	만약 (r == SSH_ERR_SYSTEM_ERROR) {
		만약 (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			반환;
		만약 (errno == EPIPE) {
			quit_message("Connection to %s closed by remote host.",
			    host);
			반환;
		}
	}
	quit_message("Read from remote host %s: %s", host, ssh_err(r));
}

static void
client_status_confirm(struct ssh *ssh, 정수 type, Channel *c, void *ctx)
{
	struct channel_reply_ctx *cr = (struct channel_reply_ctx *)ctx;
	char errmsg[256];
	정수 r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	만약 (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	만약 (type == SSH2_MSG_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} 아니면 만약 (type == SSH2_MSG_CHANNEL_FAILURE) {
		만약 (tochan) {
			snprintf(errmsg, sizeof(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} 아니면 {
			snprintf(errmsg, sizeof(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		만약 (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		만약 (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			만약 ((r = sshbuf_put(c->extended, errmsg,
			    strlen(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} 아니면
			error("%s", errmsg);
		만약 (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			만약 (c->self == session_ident)
				leave_raw_mode(0);
			아니면
				mux_tty_alloc_failed(ssh, c);
		} 아니면 만약 (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	free(cr);
}

static void
client_abandon_status_confirm(struct ssh *ssh, Channel *c, void *ctx)
{
	free(ctx);
}

void
client_expect_confirm(struct ssh *ssh, 정수 id, const char *request,
    enum confirm_action action)
{
	struct channel_reply_ctx *cr = xcalloc(1, sizeof(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_register_status_confirm(ssh, id, client_status_confirm,
	    client_abandon_status_confirm, cr);
}

void
client_register_global_confirm(global_confirm_cb *cb, void *ctx)
{
	struct global_confirm *gc, *last_gc;

	/* Coalesce identical callbacks */
	last_gc = TAILQ_LAST(&global_confirms, global_confirms);
	만약 (last_gc && last_gc->cb == cb && last_gc->ctx == ctx) {
		만약 (++last_gc->ref_count >= INT_MAX)
			fatal_f("last_gc->ref_count = %d",
			    last_gc->ref_count);
		반환;
	}

	gc = xcalloc(1, sizeof(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_count = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, entry);
}

/*
 * Returns non-zero if the client is able to handle a hostkeys-00@openssh.com
 * hostkey update request.
 */
static 정수
can_update_hostkeys(void)
{
	만약 (hostkeys_update_complete)
		반환 0;
	만약 (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_mode)
		반환 0; /* won't ask in batchmode, so don't even try */
	만약 (!options.update_hostkeys || options.num_user_hostfiles <= 0)
		반환 0;
	반환 1;
}

static void
client_repledge(void)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	만약 (options.control_master || options.control_path != NULL ||
	    options.forward_x11 || options.fork_after_authentication ||
	    options.pkcs11_provider != NULL || can_update_hostkeys() ||
	    (session_ident != -1 && !session_setup_complete)) {
		/* Can't tighten */
		반환;
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
	만약 (options.num_local_forwards != 0 ||
	    options.num_remote_forwards != 0 ||
	    options.num_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		만약 (pledge("stdio unix inet dns proc tty", NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} 아니면 만약 (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		만약 (pledge(PLEDGE_EXTRA_INET "stdio unix proc tty", NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} 아니면 {
		debug("pledge: fork");
		만약 (pledge(PLEDGE_EXTRA_INET "stdio proc tty", NULL) == -1)
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

static void
process_cmdline(struct ssh *ssh)
{
	void (*handler)(정수);
	char *s, *cmd;
	정수 ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	struct Forward fwd;

	memset(&fwd, 0, sizeof(fwd));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	만약 (s == NULL)
		goto out;
	동안 (isspace((u_char)*s))
		s++;
	만약 (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	만약 (*s == '\0')
		goto out;

	만약 (*s == 'h' || *s == 'H' || *s == '?') {
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
		만약 (!options.permit_local_command)
			goto out;
		logit("      !args                                  "
		    "Execute local command");
		goto out;
	}

	만약 (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		goto out;
	}

	만약 (*s == 'K') {
		delete = 1;
		s++;
	}
	만약 (*s == 'L')
		local = 1;
	아니면 만약 (*s == 'R')
		remote = 1;
	아니면 만약 (*s == 'D')
		dynamic = 1;
	아니면 {
		logit("Invalid command.");
		goto out;
	}

	동안 (isspace((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	만약 (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		만약 (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			goto out;
		}
		만약 (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		아니면 만약 (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		아니면
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_PORT_STATIC,
			    &options.fwd_opts) > 0;
		만약 (!ok) {
			logit("Unknown port forwarding.");
			goto out;
		}
		logit("Canceled forwarding.");
	} 아니면 {
		/* -R specs can be both dynamic or not, so check both. */
		만약 (remote) {
			만약 (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				goto out;
			}
		} 아니면 만약 (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			goto out;
		}
		만약 (local || dynamic) {
			만약 (!channel_setup_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				goto out;
			}
		} 아니면 {
			만약 (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				goto out;
			}
		}
		logit("Forwarding port.");
	}

out:
	ssh_signal(SIGINT, handler);
	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	free(cmd);
	free(fwd.listen_host);
	free(fwd.listen_path);
	free(fwd.connect_host);
	free(fwd.connect_path);
}

/* reasons to suppress output of an escape command in help output */
#define SUPPRESS_NEVER		0	/* never suppress, always show */
#define SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#define SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#define SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#define SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
struct escape_help_text {
	const char *cmd;
	const char *text;
	unsigned 정수 flags;
};
static struct escape_help_text esc_txt[] = {
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

static void
print_escape_help(struct sshbuf *b, 정수 escape_char, 정수 mux_client,
    정수 using_stderr)
{
	unsigned 정수 i, suppress_flags;
	정수 r;

	만약 ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	위해 (i = 0; i < sizeof(esc_txt)/sizeof(esc_txt[0]); i++) {
		만약 (esc_txt[i].flags & suppress_flags)
			continue;
		만약 ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	만약 ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
static 정수
process_escapes(struct ssh *ssh, Channel *c,
    struct sshbuf *bin, struct sshbuf *bout, struct sshbuf *berr,
    char *buf, 정수 len)
{
	pid_t pid;
	정수 r, bytes = 0;
	u_int i;
	u_char ch;
	char *s;
	struct escape_filter_ctx *efc;

	만약 (c == NULL || c->filter_ctx == NULL || len <= 0)
		반환 0;

	efc = (struct escape_filter_ctx *)c->filter_ctx;

	위해 (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		만약 (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			switch (ch) {
			case '.':
				/* Terminate the connection. */
				만약 ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				만약 (c && c->ctl_chan != -1) {
					channel_force_close(ssh, c, 1);
					반환 0;
				} 아니면
					quit_pending = 1;
				반환 -1;

			case 'Z' - 64:
				/* XXX support this for mux clients */
				만약 (c && c->ctl_chan != -1) {
					char b[16];
 noescape:
					만약 (ch == 'Z' - 64)
						snprintf(b, sizeof b, "^Z");
					아니면
						snprintf(b, sizeof b, "%c", ch);
					만약 ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					continue;
				}
				/* Suspend the program. Inform the user */
				만약 ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				continue;

			case 'B':
				만약 ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				만약 ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				continue;

			case 'I':
				만약 ((r = sshbuf_putf(berr, "%cI\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = connection_info_message(ssh);
				만약 ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				free(s);
				continue;

			case 'R':
				만약 (ssh->compat & SSH_BUG_NOREKEY)
					logit("Server does not "
					    "support re-keying");
				아니면
					need_rekeying = 1;
				continue;

			case 'V':
				/* FALLTHROUGH */
			case 'v':
				만약 (c && c->ctl_chan != -1)
					goto noescape;
				만약 (!log_is_on_stderr()) {
					만약 ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					continue;
				}
				만약 (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				만약 (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				만약 ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				continue;

			case '&':
				만약 (c->ctl_chan != -1)
					goto noescape;
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

				만약 ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				만약 (pid == -1) {
					error("fork: %.100s", strerror(errno));
					continue;
				}
				만약 (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					exit(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				만약 ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				반환 -1;
			case '?':
				print_escape_help(berr, efc->escape_char,
				    (c && c->ctl_chan != -1),
				    log_is_on_stderr());
				continue;

			case '#':
				만약 ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_message(ssh);
				만약 ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				free(s);
				continue;

			case 'C':
				만약 (c && c->ctl_chan != -1)
					goto noescape;
				만약 (options.enable_escape_commandline == 0) {
					만약 ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					continue;
				}
				process_cmdline(ssh);
				continue;

			default:
				만약 (ch != efc->escape_char) {
					만약 ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					bytes++;
				}
				/* Escaped characters fall through here */
				break;
			}
		} 아니면 {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			만약 (last_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				continue;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		last_was_cr = (ch == '\r' || ch == '\n');
		만약 ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		bytes++;
	}
	반환 bytes;
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

static void
client_process_buffered_input_packets(struct ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
void *
client_new_escape_filter_ctx(정수 escape_char)
{
	struct escape_filter_ctx *ret;

	ret = xcalloc(1, sizeof(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	반환 (void *)ret;
}

/* Free the escape filter context on channel free */
void
client_filter_cleanup(struct ssh *ssh, 정수 cid, void *ctx)
{
	free(ctx);
}

정수
client_simple_escape_filter(struct ssh *ssh, Channel *c, char *buf, 정수 len)
{
	만약 (c->extended_usage != CHAN_EXTENDED_WRITE)
		반환 0;

	반환 process_escapes(ssh, c, c->input, c->output, c->extended,
	    buf, len);
}

static void
client_channel_closed(struct ssh *ssh, 정수 id, 정수 force, void *arg)
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
정수
client_loop(struct ssh *ssh, 정수 have_pty, 정수 escape_char_arg,
    정수 ssh2_chan_id)
{
	struct pollfd *pfd = NULL;
	u_int npfd_alloc = 0, npfd_active = 0;
	double start_time, total_time;
	정수 interactive = -1, channel_did_enqueue = 0, r;
	uint64_t ibytes, obytes;
	정수 conn_in_ready, conn_out_ready;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	만약 (options.pkcs11_provider != NULL)
		debug("pledge: disabled (PKCS11Provider active)");
	아니면 만약 (options.control_master &&
	    !option_clear_or_none(options.control_path)) {
		debug("pledge: id");
		만약 (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} 아니면 만약 (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		만약 (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} 아니면 만약 (options.update_hostkeys) {
		debug("pledge: filesystem");
		만약 (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} 아니면 만약 (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		만약 (pledge("stdio cpath unix inet dns proc tty", NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} 아니면 {
		debug("pledge: network");
		만약 (pledge("stdio unix inet dns proc tty", NULL) == -1)
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
	만약 (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	만약 (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	만약 (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	만약 (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, window_change_handler);
#ifdef SIGINFO
	ssh_signal(SIGINFO, siginfo_handler);
#endif

	만약 (have_pty)
		enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	만약 (session_ident != -1) {
		만약 (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, NULL,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_register_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	schedule_server_alive_check();

	만약 (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#ifdef SIGINFO
	만약 (sigaddset(&bsigset, SIGINFO) == -1)
		error_f("bsigset setup: %s", strerror(errno));
#endif

	/* Main loop of the client for the interactive session mode. */
	동안 (!quit_pending) {
		channel_did_enqueue = 0;

		/* Process buffered packets sent by the server. */
		client_process_buffered_input_packets(ssh);

		만약 (session_closed && !channel_still_open(ssh))
			break;

		만약 (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} 아니면 만약 (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			만약 ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} 아니면 {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			만약 (ssh_packet_not_very_much_data_to_write(ssh))
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
		만약 (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		만약 (siginfo_received) {
			char ident[256];

			sshpkt_fmt_connection_id(ssh, ident, sizeof(ident));
			logit("%s: connection to %s, up %.1f seconds",
			    __progname, ident, monotime_double() - start_time);
			siginfo_received = 0;
		}
		만약 (quit_pending)
			break;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_active, channel_did_enqueue, &osigset,
		    &conn_in_ready, &conn_out_ready);
		만약 (sigprocmask(SIG_SETMASK, &osigset, NULL) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		만약 (quit_pending)
			break;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_active);

		/* Buffer input from the connection.  */
		만약 (conn_in_ready)
			client_process_net_input(ssh);

		만약 (quit_pending)
			break;

		/* A timeout may have triggered rekeying */
		만약 ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		만약 (conn_out_ready) {
			만약 (interactive != !channel_has_bulk(ssh)) {
				interactive = !channel_has_bulk(ssh);
				debug2_f("session QoS is now %s", interactive ?
				    "interactive" : "non-interactive");
				ssh_packet_set_interactive(ssh, interactive);
			}
			만약 ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		만약 (control_persist_exit_time > 0) {
			만약 (monotime() >= control_persist_exit_time) {
				debug("ControlPersist timeout expired");
				break;
			}
		}
	}
	free(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	만약 (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_message("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	만약 ((r = sshpkt_start(ssh, SSH2_MSG_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	만약 (have_pty)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	만약 (options.session_type == SESSION_TYPE_NONE &&
	    received_signal == SIGTERM) {
		received_signal = 0;
		exit_status = 0;
	}

	만약 (received_signal) {
		verbose("Killed by signal %d.", (정수) received_signal);
		cleanup_exit(255);
	}

	/* Report bytes transferred, and transfer rates. */
	total_time = monotime_double() - start_time;
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (unsigned long long)obytes, (unsigned long long)ibytes, total_time);
	만약 (total_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / total_time, ibytes / total_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	반환 exit_status;
}

/*********/

static Channel *
client_request_forwarded_tcpip(struct ssh *ssh, const char *request_type,
    정수 rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = NULL;
	struct sshbuf *b = NULL;
	char *listen_address, *originator_address;
	u_int listen_port, originator_port;
	정수 r;

	/* Get rest of the packet */
	만약 ((r = sshpkt_get_cstring(ssh, &listen_address, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_address, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_address, listen_port, originator_address, originator_port);

	만약 (listen_port > 0xffff)
		error_f("invalid listen port");
	아니면 만약 (originator_port > 0xffff)
		error_f("invalid originator port");
	아니면 {
		c = channel_connect_by_listen_address(ssh,
		    listen_address, listen_port, "forwarded-tcpip",
		    originator_address);
	}

	만약 (c != NULL && c->type == SSH_CHANNEL_MUX_CLIENT) {
		만약 ((b = sshbuf_new()) == NULL) {
			error_f("alloc reply");
			goto out;
		}
		/* reconstruct and send to muxclient */
		만약 ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
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
			goto out;
		}
	}

 out:
	sshbuf_free(b);
	free(originator_address);
	free(listen_address);
	반환 c;
}

static Channel *
client_request_forwarded_streamlocal(struct ssh *ssh,
    const char *request_type, 정수 rchan)
{
	Channel *c = NULL;
	char *listen_path;
	정수 r;

	/* Get the remote path. */
	만약 ((r = sshpkt_get_cstring(ssh, &listen_path, NULL)) != 0 ||
	    (r = sshpkt_get_string(ssh, NULL, NULL)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_path);

	c = channel_connect_by_listen_path(ssh, listen_path,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	free(listen_path);
	반환 c;
}

static Channel *
client_request_x11(struct ssh *ssh, const char *request_type, 정수 rchan)
{
	Channel *c = NULL;
	char *originator;
	u_int originator_port;
	정수 r, sock;

	만약 (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		반환 NULL;
	}
	만약 (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		반환 NULL;
	}
	만약 ((r = sshpkt_get_cstring(ssh, &originator, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug("client_request_x11: request from %s %u", originator,
	    originator_port);
	free(originator);
	sock = x11_connect_display(ssh);
	만약 (sock < 0)
		반환 NULL;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11", 1);
	c->force_drain = 1;
	반환 c;
}

static Channel *
client_request_agent(struct ssh *ssh, const char *request_type, 정수 rchan)
{
	Channel *c = NULL;
	정수 r, sock;

	만약 (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		반환 NULL;
	}
	만약 (forward_agent_sock_path == NULL) {
		r = ssh_get_authentication_socket(&sock);
	} 아니면 {
		r = ssh_get_authentication_socket_path(forward_agent_sock_path, &sock);
	}
	만약 (r != 0) {
		만약 (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		반환 NULL;
	}
	만약 ((r = ssh_agent_bind_hostkey(sock, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 1)) == 0)
		debug_f("bound agent to hostkey");
	아니면
		debug2_fr(r, "ssh_agent_bind_hostkey");

	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", 1);
	c->force_drain = 1;
	반환 c;
}

char *
client_request_tun_fwd(struct ssh *ssh, 정수 tun_mode,
    정수 local_tun, 정수 remote_tun, channel_open_fn *cb, void *cbctx)
{
	Channel *c;
	정수 r, fd;
	char *ifname = NULL;

	만약 (tun_mode == SSH_TUNMODE_NO)
		반환 NULL;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	만약 ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		반환 NULL;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#만약 defined(SSH_TUN_FILTER)
	만약 (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, NULL, NULL);
#endif

	만약 (cb != NULL)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	만약 ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	반환 ifname;
}

/* XXXX move to generic input handler */
static 정수
client_input_channel_open(정수 type, uint32_t seq, struct ssh *ssh)
{
	Channel *c = NULL;
	char *ctype = NULL;
	정수 r;
	u_int rchan;
	size_t len;
	u_int rmaxpack, rwindow;

	만약 ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		goto out;

	debug("client_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	만약 (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} 아니면 만약 (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} 아니면 만약 (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} 아니면 만약 (strcmp(ctype, "auth-agent@openssh.com") == 0 ||
	    strcmp(ctype, "agent-connect") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	만약 (c != NULL && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} 아니면 만약 (c != NULL) {
		debug("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		만약 (c->type != SSH_CHANNEL_CONNECTING) {
			만약 ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} 아니면 {
		debug("failure %s", ctype);
		만약 ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	free(ctype);
	반환 r;
}

static 정수
client_input_channel_req(정수 type, uint32_t seq, struct ssh *ssh)
{
	Channel *c = NULL;
	char *rtype = NULL;
	u_char reply;
	u_int id, exitval;
	정수 r, success = 0;

	만약 ((r = sshpkt_get_u32(ssh, &id)) != 0)
		반환 r;
	만약 (id <= INT_MAX)
		c = channel_lookup(ssh, id);
	만약 (channel_proxy_upstream(c, type, seq, ssh))
		반환 0;
	만약 ((r = sshpkt_get_cstring(ssh, &rtype, NULL)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &reply)) != 0)
		goto out;

	debug("client_input_channel_req: channel %u rtype %s reply %d",
	    id, rtype, reply);

	만약 (c == NULL) {
		error("client_input_channel_req: channel %d: "
		    "unknown channel", id);
	} 아니면 만약 (strcmp(rtype, "eow@openssh.com") == 0) {
		만약 ((r = sshpkt_get_end(ssh)) != 0)
			goto out;
		chan_rcvd_eow(ssh, c);
	} 아니면 만약 (strcmp(rtype, "exit-status") == 0) {
		만약 ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			goto out;
		만약 (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} 아니면 만약 ((정수)id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} 아니면 {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d",
			    id);
		}
		만약 ((r = sshpkt_get_end(ssh)) != 0)
			goto out;
	}
	만약 (reply && c != NULL && !(c->flags & CHAN_CLOSE_SENT)) {
		만약 (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		만약 ((r = sshpkt_start(ssh, success ?
		    SSH2_MSG_CHANNEL_SUCCESS : SSH2_MSG_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}
	r = 0;
 out:
	free(rtype);
	반환 r;
}

struct hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	char *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	struct sshkey **keys;
	u_int *keys_match;	/* mask of HKF_MATCH_* from hostfile.h */
	정수 *keys_verified;	/* flag for new keys verified by server */
	size_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	struct sshkey **old_keys;
	size_t nold;

	/* Various special cases. */
	정수 complex_hostspec;	/* wildcard or manual pattern-list host name */
	정수 ca_available;	/* saw CA key for this host */
	정수 old_key_seen;	/* saw old key with other name/addr */
	정수 other_name_seen;	/* saw key with other name/addr */
};

static void
hostkeys_update_ctx_free(struct hostkeys_update_ctx *ctx)
{
	size_t i;

	만약 (ctx == NULL)
		반환;
	위해 (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->keys[i]);
	free(ctx->keys);
	free(ctx->keys_match);
	free(ctx->keys_verified);
	위해 (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_keys[i]);
	free(ctx->old_keys);
	free(ctx->host_str);
	free(ctx->ip_str);
	free(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
static 정수
hostspec_is_complex(const char *hosts)
{
	char *cp;

	/* wildcard */
	만약 (strchr(hosts, '*') != NULL || strchr(hosts, '?') != NULL)
		반환 1;
	/* single host/ip = ok */
	만약 ((cp = strchr(hosts, ',')) == NULL)
		반환 0;
	/* more than two entries on the line */
	만약 (strchr(cp + 1, ',') != NULL)
		반환 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	반환 0;
}

/* callback to search for ctx->keys in known_hosts */
static 정수
hostkeys_find(struct hostkey_foreach_line *l, void *_ctx)
{
	struct hostkeys_update_ctx *ctx = (struct hostkeys_update_ctx *)_ctx;
	size_t i;
	struct sshkey **tmp;

	만약 (l->key == NULL)
		반환 0;
	만약 (l->status != HKF_STATUS_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		위해 (i = 0; i < ctx->nkeys; i++) {
			만약 (sshkey_equal(l->key, ctx->keys[i])) {
				ctx->other_name_seen = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->keys[i]),
				    l->path, l->linenum);
				반환 0;
			}
		}
		반환 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	만약 (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		반환 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	만약 (ctx->ip_str != NULL && strchr(l->hosts, ',') != NULL) {
		만약 ((l->match & HKF_MATCH_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_seen = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->path, l->linenum);
			반환 0;
		} 아니면 만약 ((l->match & HKF_MATCH_IP) == 0) {
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
	만약 (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		반환 0;
	}

	/* Mark off keys we've already seen for this host */
	위해 (i = 0; i < ctx->nkeys; i++) {
		만약 (!sshkey_equal(l->key, ctx->keys[i]))
			continue;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->keys[i]), l->path, l->linenum);
		ctx->keys_match[i] |= l->match;
		반환 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->key),
	    l->path, l->linenum);
	만약 ((tmp = recallocarray(ctx->old_keys, ctx->nold, ctx->nold + 1,
	    sizeof(*ctx->old_keys))) == NULL)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_keys = tmp;
	ctx->old_keys[ctx->nold++] = l->key;
	l->key = NULL;

	반환 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
static 정수
hostkeys_check_old(struct hostkey_foreach_line *l, void *_ctx)
{
	struct hostkeys_update_ctx *ctx = (struct hostkeys_update_ctx *)_ctx;
	size_t i;
	정수 hashed;

	/* only care about lines that *don't* match the active host spec */
	만약 (l->status == HKF_STATUS_MATCHED || l->key == NULL)
		반환 0;

	hashed = l->match & (HKF_MATCH_HOST_HASHED|HKF_MATCH_IP_HASHED);
	위해 (i = 0; i < ctx->nold; i++) {
		만약 (!sshkey_equal(l->key, ctx->old_keys[i]))
			continue;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_keys[i]), l->path, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_key_seen = 1;
		break;
	}
	반환 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
static 정수
check_old_keys_othernames(struct hostkeys_update_ctx *ctx)
{
	size_t i;
	정수 r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	위해 (i = 0; i < options.num_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		만약 ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_KEY, 0)) != 0) {
			만약 (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				continue;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			반환 -1;
		}
	}
	반환 0;
}

static void
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

static void
update_known_hosts(struct hostkeys_update_ctx *ctx)
{
	정수 r, was_raw = 0, first = 1;
	정수 asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	char *fp, *response;
	size_t i;
	struct stat sb;

	위해 (i = 0; i < ctx->nkeys; i++) {
		만약 (!ctx->keys_verified[i])
			continue;
		만약 ((fp = sshkey_fingerprint(ctx->keys[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
			fatal_f("sshkey_fingerprint failed");
		만약 (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Learned new hostkey: %s %s",
		    sshkey_type(ctx->keys[i]), fp);
		first = 0;
		free(fp);
	}
	위해 (i = 0; i < ctx->nold; i++) {
		만약 ((fp = sshkey_fingerprint(ctx->old_keys[i],
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
			fatal_f("sshkey_fingerprint failed");
		만약 (first && asking)
			hostkey_change_preamble(loglevel);
		do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
		    sshkey_type(ctx->old_keys[i]), fp);
		first = 0;
		free(fp);
	}
	만약 (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		만약 (get_saved_tio() != NULL) {
			leave_raw_mode(1);
			was_raw = 1;
		}
		response = NULL;
		위해 (i = 0; !quit_pending && i < 3; i++) {
			free(response);
			response = read_passphrase("Accept updated hostkeys? "
			    "(yes/no): ", RP_ECHO);
			만약 (response != NULL && strcasecmp(response, "yes") == 0)
				break;
			아니면 만약 (quit_pending || response == NULL ||
			    strcasecmp(response, "no") == 0) {
				options.update_hostkeys = 0;
				break;
			} 아니면 {
				do_log2(loglevel, "Please enter "
				    "\"yes\" or \"no\"");
			}
		}
		만약 (quit_pending || i >= 3 || response == NULL)
			options.update_hostkeys = 0;
		free(response);
		만약 (was_raw)
			enter_raw_mode(1);
	}
	만약 (options.update_hostkeys == 0)
		반환;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	위해 (i = 0; i < options.num_user_hostfiles; i++) {
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		만약 (stat(options.user_hostfiles[i], &sb) != 0) {
			만약 (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", options.user_hostfiles[i]);
			} 아니면 {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    options.user_hostfiles[i], strerror(errno));
			}
			continue;
		}
		만약 ((r = hostfile_replace_entries(options.user_hostfiles[i],
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->keys : NULL, i == 0 ? ctx->nkeys : 0,
		    options.hash_known_hosts, 0,
		    options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    options.user_hostfiles[i]);
		}
	}
}

static void
client_global_hostkeys_prove_confirm(struct ssh *ssh, 정수 type,
    uint32_t seq, void *_ctx)
{
	struct hostkeys_update_ctx *ctx = (struct hostkeys_update_ctx *)_ctx;
	size_t i, ndone;
	struct sshbuf *signdata;
	정수 r, plaintype;
	const u_char *sig;
	const char *rsa_kexalg = NULL;
	char *alg = NULL;
	size_t siglen;

	만약 (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	만약 (type != SSH2_MSG_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		반환;
	}
	만약 (sshkey_type_plain(sshkey_type_from_name(
	    ssh->kex->hostkey_alg)) == KEY_RSA)
		rsa_kexalg = ssh->kex->hostkey_alg;
	만약 ((signdata = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	위해 (ndone = i = 0; i < ctx->nkeys; i++) {
		만약 (ctx->keys_match[i])
			continue;
		plaintype = sshkey_type_plain(ctx->keys[i]->type);
		/* Prepare data to be signed: session ID, unique string, key */
		sshbuf_reset(signdata);
		만약 ( (r = sshbuf_put_cstring(signdata,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
		    ssh->kex->session_id)) != 0 ||
		    (r = sshkey_puts(ctx->keys[i], signdata)) != 0)
			fatal_fr(r, "compose signdata");
		/* Extract and verify signature */
		만약 ((r = sshpkt_get_string_direct(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			goto out;
		}
		만약 ((r = sshkey_get_sigtype(sig, siglen, &alg)) != 0) {
			error_fr(r, "server gave unintelligible signature "
			    "for %s key %zu", sshkey_type(ctx->keys[i]), i);
			goto out;
		}
		/*
		 * Special case for RSA keys: if a RSA hostkey was negotiated,
		 * then use its signature type for verification of RSA hostkey
		 * proofs. Otherwise, accept only RSA-SHA256/512 signatures.
		 */
		만약 (plaintype == KEY_RSA && rsa_kexalg == NULL &&
		    match_pattern_list(alg, HOSTKEY_PROOF_RSA_ALGS, 0) != 1) {
			debug_f("server used untrusted RSA signature algorithm "
			    "%s for key %zu, disregarding", alg, i);
			free(alg);
			/* zap the key from the list */
			sshkey_free(ctx->keys[i]);
			ctx->keys[i] = NULL;
			ndone++;
			continue;
		}
		debug3_f("verify %s key %zu using sigalg %s",
		    sshkey_type(ctx->keys[i]), i, alg);
		free(alg);
		만약 ((r = sshkey_verify(ctx->keys[i], sig, siglen,
		    sshbuf_ptr(signdata), sshbuf_len(signdata),
		    plaintype == KEY_RSA ? rsa_kexalg : NULL, 0, NULL)) != 0) {
			error_fr(r, "server gave bad signature for %s key %zu",
			    sshkey_type(ctx->keys[i]), i);
			goto out;
		}
		/* Key is good. Mark it as 'seen' */
		ctx->keys_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	만약 (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	만약 ((r = sshpkt_get_end(ssh)) != 0) {
		error_f("protocol error");
		goto out;
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
static 정수
client_input_hostkeys(struct ssh *ssh)
{
	const u_char *blob = NULL;
	size_t i, len = 0;
	struct sshbuf *buf = NULL;
	struct sshkey *key = NULL, **tmp;
	정수 r, prove_sent = 0;
	char *fp;
	static 정수 hostkeys_seen = 0; /* XXX use struct ssh */
	extern struct sockaddr_storage hostaddr; /* XXX from ssh.c */
	struct hostkeys_update_ctx *ctx = NULL;
	u_int want;

	만약 (hostkeys_seen)
		fatal_f("server already sent hostkeys");
	만약 (!can_update_hostkeys())
		반환 1;
	hostkeys_seen = 1;

	ctx = xcalloc(1, sizeof(*ctx));
	동안 (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(key);
		key = NULL;
		만약 ((r = sshpkt_get_string_direct(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			goto out;
		}
		만약 ((r = sshkey_from_blob(blob, len, &key)) != 0) {
			do_log2_fr(r, r == SSH_ERR_KEY_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "convert key");
			continue;
		}
		fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received %s key %s", sshkey_type(key), fp);
		free(fp);

		만약 (!hostkey_accepted_by_hostkeyalgs(key)) {
			debug3_f("%s key not permitted by "
			    "HostkeyAlgorithms", sshkey_ssh_name(key));
			continue;
		}
		/* Skip certs */
		만약 (sshkey_is_cert(key)) {
			debug3_f("%s key is a certificate; skipping",
			    sshkey_ssh_name(key));
			continue;
		}
		/* Ensure keys are unique */
		위해 (i = 0; i < ctx->nkeys; i++) {
			만약 (sshkey_equal(key, ctx->keys[i])) {
				error_f("received duplicated %s host key",
				    sshkey_ssh_name(key));
				goto out;
			}
		}
		/* Key is good, record it */
		만약 ((tmp = recallocarray(ctx->keys, ctx->nkeys, ctx->nkeys + 1,
		    sizeof(*ctx->keys))) == NULL)
			fatal_f("recallocarray failed nkeys = %zu",
			    ctx->nkeys);
		ctx->keys = tmp;
		ctx->keys[ctx->nkeys++] = key;
		key = NULL;
	}

	만약 (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		goto out;
	}

	만약 ((ctx->keys_match = calloc(ctx->nkeys,
	    sizeof(*ctx->keys_match))) == NULL ||
	    (ctx->keys_verified = calloc(ctx->nkeys,
	    sizeof(*ctx->keys_verified))) == NULL)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (struct sockaddr *)&hostaddr : NULL,
	    options.port, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : NULL);

	/* Find which keys we already know about. */
	위해 (i = 0; i < options.num_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		만약 ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_KEY, 0)) != 0) {
			만약 (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				continue;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			goto out;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_MATCH_HOST | ( options.check_host_ip ? HKF_MATCH_IP : 0);
	위해 (i = 0; i < ctx->nkeys; i++) {
		만약 (ctx->keys_match[i] == 0)
			ctx->nnew++;
		만약 ((ctx->keys_match[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	만약 (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		goto out;
	}

	/* Various reasons why we cannot proceed with the update */
	만약 (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		goto out;
	}
	만약 (ctx->other_name_seen) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		goto out;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	만약 (ctx->nold != 0) {
		만약 (check_old_keys_othernames(ctx) != 0)
			goto out; /* error already logged */
		만약 (ctx->old_key_seen) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == NULL ? "" : ",",
			    ctx->ip_str == NULL ? "" : ctx->ip_str);
			goto out;
		}
	}

	만약 (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_known_hosts(ctx);
		goto out;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	만약 ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	만약 ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	위해 (i = 0; i < ctx->nkeys; i++) {
		만약 (ctx->keys_match[i])
			continue;
		sshbuf_reset(buf);
		만약 ((r = sshkey_putb(ctx->keys[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	만약 ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_register_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = NULL;  /* will be freed in callback */
	prove_sent = 1;

	/* Success */
 out:
	hostkeys_update_ctx_free(ctx);
	sshkey_free(key);
	sshbuf_free(buf);
	만약 (!prove_sent) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	반환 1;
}

static 정수
client_input_global_request(정수 type, uint32_t seq, struct ssh *ssh)
{
	char *rtype;
	u_char want_reply;
	정수 r, success = 0;

	만약 ((r = sshpkt_get_cstring(ssh, &rtype, NULL)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		goto out;
	debug("client_input_global_request: rtype %s want_reply %d",
	    rtype, want_reply);
	만약 (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_input_hostkeys(ssh);
	만약 (want_reply) {
		만약 ((r = sshpkt_start(ssh, success ? SSH2_MSG_REQUEST_SUCCESS :
		    SSH2_MSG_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			goto out;
	}
	r = 0;
 out:
	free(rtype);
	반환 r;
}

static void
client_send_env(struct ssh *ssh, 정수 id, const char *name, const char *val)
{
	정수 r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	만약 ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

void
client_session2_setup(struct ssh *ssh, 정수 id, 정수 want_tty, 정수 want_subsystem,
    const char *term, struct termios *tiop, 정수 in_fd, struct sshbuf *cmd,
    char **env)
{
	size_t i, j, len;
	정수 matched, r;
	char *type = NULL, *cmdstring = NULL, *name, *val;
	Channel *c = NULL;

	debug2_f("id %d", id);

	만약 ((c = channel_lookup(ssh, id)) == NULL)
		fatal_f("channel %d: unknown channel", id);

	만약 (want_tty) {
		struct winsize ws;

		/* Store window size in the packet. */
		만약 (ioctl(in_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, sizeof(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		만약 ((r = sshpkt_put_cstring(ssh, term != NULL ? term : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		만약 (tiop == NULL)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		만약 ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	만약 (options.num_send_env != 0 && env != NULL) {
		debug("Sending environment.");
		위해 (i = 0; env[i] != NULL; i++) {
			/* Split */
			name = xstrdup(env[i]);
			만약 ((val = strchr(name, '=')) == NULL) {
				free(name);
				continue;
			}
			*val++ = '\0';

			matched = 0;
			위해 (j = 0; j < options.num_send_env; j++) {
				만약 (match_pattern(name, options.send_env[j])) {
					matched = 1;
					break;
				}
			}
			만약 (!matched) {
				debug3("Ignored env %s", name);
				free(name);
				continue;
			}
			client_send_env(ssh, id, name, val);
			free(name);
		}
	}
	위해 (i = 0; i < options.num_setenv; i++) {
		/* Split */
		name = xstrdup(options.setenv[i]);
		만약 ((val = strchr(name, '=')) == NULL) {
			free(name);
			continue;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		free(name);
	}

	len = sshbuf_len(cmd);
	만약 (len > 0) {
		만약 ((cmdstring = sshbuf_dup_string(cmd)) == NULL)
			fatal_f("sshbuf_dup_string failed");
		만약 (len > 900)
			len = 900;
		만약 (want_subsystem) {
			debug("Sending subsystem: %.*s", (정수)len, cmdstring);
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
			xasprintf(&type, "session:subsystem:%s", cmdstring);
		} 아니면 {
			debug("Sending command: %.*s", (정수)len, cmdstring);
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
			xasprintf(&type, "session:command");
		}
		만약 ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} 아니면 {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		만약 ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
		xasprintf(&type, "session:shell");
	}
	channel_set_xtype(ssh, id, type);
	free(cmdstring);
	free(type);

	session_setup_complete = 1;
	client_repledge();
}

void
client_channel_request_agent_forwarding(struct ssh *ssh, 정수 id)
{
	const char *req = "auth-agent-req@openssh.com";
	정수 r;

	만약 (ssh->kex != NULL && (ssh->kex->flags & KEX_HAS_NEWAGENT) != 0)
		req = "agent-req"; /* RFC 9987 */
	debug("Requesting agent forwarding on channel %d via %s", id, req);
	channel_request_start(ssh, id, req, 0);
	만약 ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

static void
client_init_dispatch(struct ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_CLOSE, &channel_input_oclose);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_DATA, &channel_input_data);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_EOF, &channel_input_ieof);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_EXTENDED_DATA, &channel_input_extended_data);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_OPEN, &client_input_channel_open);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, &channel_input_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_OPEN_FAILURE, &channel_input_open_failure);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_REQUEST, &client_input_channel_req);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_WINDOW_ADJUST, &channel_input_window_adjust);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_SUCCESS, &channel_input_status_confirm);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_FAILURE, &channel_input_status_confirm);
	ssh_dispatch_set(ssh, SSH2_MSG_GLOBAL_REQUEST, &client_input_global_request);

	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);

	/* global request reply messages */
	ssh_dispatch_set(ssh, SSH2_MSG_REQUEST_FAILURE, &client_global_request_reply);
	ssh_dispatch_set(ssh, SSH2_MSG_REQUEST_SUCCESS, &client_global_request_reply);
}

void
client_stop_mux(void)
{
	만약 (options.control_path != NULL && muxserver_sock != -1)
		unlink(options.control_path);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	만약 (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
void
cleanup_exit(정수 i)
{
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	만약 (options.control_path != NULL && muxserver_sock != -1)
		unlink(options.control_path);
	ssh_kill_proxy_command();
	_exit(i);
}
