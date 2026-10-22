/* $OpenBSD: packet.c,v 1.346 2026/09/22 22:51:43 job Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains code implementing the packet protocol and communication
 * with the other side.  This same code is used both on client and server side.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * SSH2 packet format added by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <util.h>

/*
 * Explicitly include OpenSSL before zlib as some versions of OpenSSL have
 * "free_func" in their headers, which zlib typedefs.
 */
#ifdef WITH_OPENSSL
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/ec.h>
#endif

#ifdef WITH_ZLIB
#ଅନ୍ତର୍ଭାଵ <zlib.h>
#endif

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "mac.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "version.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#ଅନ୍ୟଥା
#define DBG(x)
#endif

#define PACKET_MAX_SIZE (256 * 1024)

ସଂରଚନା packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t blocks;
	uint64_t bytes;
};

ସଂରଚନା packet {
	TAILQ_ENTRY(packet) next;
	u_char type;
	ସଂରଚନା sshbuf *payload;
};

ସଂରଚନା session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା connection_in;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	ସଂରଚନା sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	ସଂରଚନା sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	ସଂରଚନା sshbuf *ନିବେଶ;

	/* Buffer for raw output data going to the socket. */
	ସଂରଚନା sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	ସଂରଚନା sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	ସଂରଚନା sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	ସଂରଚନା sshbuf *compression_buffer;

#ifdef WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_stream compression_in_stream;
	z_stream compression_out_stream;
#endif
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା compression_in_started;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା compression_out_started;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା compression_in_failures;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା compression_out_failures;

	/* default maximum packet size */
	u_int max_packet_size;

	/* Flag indicating whether this module has been initialized. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t start_time;

	/* Set to true if the connection is interactive. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା interactive_mode;

	/* Set to true if we are the server side. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା server_side;

	/* Set to true if we are authenticated. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା after_authentication;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	ସଂରଚନା newkeys *newkeys[MODE_MAX];
	ସଂରଚନା packet_state p_read, p_send;

	/* Volume-based rekeying */
	uint64_t hard_max_blocks_in, hard_max_blocks_out;
	uint64_t max_blocks_in, max_blocks_out, rekey_limit;

	/* Time-based rekeying */
	uint32_t rekey_interval;	/* how often in seconds */
	time_t rekey_time;	/* time of last rekeying */

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	size_t packet_discard_mac_already;
	ସଂରଚନା sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rekeying;

	/* Used in ssh_packet_send_mux() */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux;

	/* QoS handling */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା set_maxsize_called;

	/* One-off warning about weak ciphers */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cipher_warning_done;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା disconnecting;

	/* Nagle disabled on socket */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nodelay_set;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_in;
	ଶୂନ୍ୟ *hook_in_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

ସଂରଚନା ssh *
ssh_alloc_session_state(ଶୂନ୍ୟ)
{
	ସଂରଚନା ssh *ssh = ଖାଲି;
	ସଂରଚନା session_state *state = ଖାଲି;

	ଯଦି ((ssh = calloc(1, ଆକାର(*ssh))) == ଖାଲି ||
	    (state = calloc(1, ଆକାର(*state))) == ଖାଲି ||
	    (ssh->kex = kex_new()) == ଖାଲି ||
	    (state->ନିବେଶ = sshbuf_new()) == ଖାଲି ||
	    (state->output = sshbuf_new()) == ଖାଲି ||
	    (state->outgoing_packet = sshbuf_new()) == ଖାଲି ||
	    (state->incoming_packet = sshbuf_new()) == ଖାଲି)
		ଯାଅ fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->private_ଚାବିଗୁଡ଼ିକ);
	TAILQ_INIT(&ssh->public_ଚାବିଗୁଡ଼ିକ);
	state->connection_in = -1;
	state->connection_out = -1;
	state->max_packet_size = 32768;
	state->packet_timeout_ms = -1;
	state->interactive_mode = 1;
	state->qos_interactive = state->qos_other = -1;
	state->p_send.packets = state->p_read.packets = 0;
	state->initialized = 1;
	/*
	 * ssh_packet_send2() needs to queue packets until
	 * we've done the initial key exchange.
	 */
	state->rekeying = 1;
	ssh->state = state;
	ଫେରନ୍ତୁ ssh;
 fail:
	ଯଦି (ssh) {
		kex_free(ssh->kex);
		ମୁକ୍ତ(ssh);
	}
	ଯଦି (state) {
		sshbuf_free(state->ନିବେଶ);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		ମୁକ୍ତ(state);
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

ଶୂନ୍ୟ
ssh_packet_set_ନିବେଶ_hook(ସଂରଚନା ssh *ssh, ssh_packet_hook_fn *hook, ଶୂନ୍ୟ *ctx)
{
	ssh->state->hook_in = hook;
	ssh->state->hook_in_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_is_rekeying(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ssh->state->rekeying ||
	    (ssh->kex != ଖାଲି && ssh->kex->done == 0);
}

/*
 * Sets the descriptors used for communication.
 */
ସଂରଚନା ssh *
ssh_packet_set_connection(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd_in, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd_out)
{
	ସଂରଚନା session_state *state;
	ଅଚଳ ସଂରଚନା sshcipher *none = cipher_by_name("none");
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, wasnull = ssh == ଖାଲି;

	ଯଦି (none == ଖାଲି) {
		error_f("cannot load cipher 'none'");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (ssh == ଖାଲି)
		ssh = ssh_alloc_session_state();
	ଯଦି (ssh == ଖାଲି) {
		error_f("could not allocate state");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	state = ssh->state;
	state->start_time = monotime();
	state->connection_in = fd_in;
	state->connection_out = fd_out;
	ଯଦି ((r = cipher_init(&state->send_context, none,
	    (ଅଚଳ u_char *)"", 0, ଖାଲି, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (ଅଚଳ u_char *)"", 0, ଖାଲି, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		ଯଦି (wasnull)
			ମୁକ୍ତ(ssh); /* XXX need ssh_free_session_state? */
		ଫେରନ୍ତୁ ଖାଲି;
	}
	state->newkeys[MODE_IN] = state->newkeys[MODE_OUT] = ଖାଲି;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(ଶୂନ୍ୟ)ssh_remote_ipaddr(ssh);
	ଫେରନ୍ତୁ ssh;
}

ଶୂନ୍ୟ
ssh_packet_set_timeout(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା timeout, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଗଣନା_2)
{
	ସଂରଚନା session_state *state = ssh->state;

	ଯଦି (timeout <= 0 || ଗଣନା_2 <= 0) {
		state->packet_timeout_ms = -1;
		ଫେରନ୍ତୁ;
	}
	ଯଦି ((INT_MAX / 1000) / ଗଣନା_2 < timeout)
		state->packet_timeout_ms = INT_MAX;
	ଅନ୍ୟଥା
		state->packet_timeout_ms = timeout * ଗଣନା_2 * 1000;
}

ଶୂନ୍ୟ
ssh_packet_set_mux(ସଂରଚନା ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_get_mux(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ssh->state->mux;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_set_log_preamble(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list args;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ମୁକ୍ତ(ssh->log_preamble);
	ଯଦି (fmt == ଖାଲି)
		ssh->log_preamble = ଖାଲି;
	ଅନ୍ୟଥା {
		va_start(args, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, args);
		va_end(args);
		ଯଦି (r < 0 || ssh->log_preamble == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_stop_discard(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା session_state *state = ssh->state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (state->packet_discard_mac) {
		ଅକ୍ଷର buf[1024];
		size_t dlen = PACKET_MAX_SIZE;

		ଯଦି (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', ଆକାର(buf));
		ଯେତେବେଳେ (sshbuf_len(state->incoming_packet) < dlen)
			ଯଦି ((r = sshbuf_put(state->incoming_packet, buf,
			    ଆକାର(buf))) != 0)
				ଫେରନ୍ତୁ r;
		(ଶୂନ୍ୟ) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    ଖାଲି, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	ଫେରନ୍ତୁ SSH_ERR_MAC_INVALID;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_start_discard(ସଂରଚନା ssh *ssh, ସଂରଚନା sshenc *enc,
    ସଂରଚନା sshmac *mac, size_t mac_already, u_int discard)
{
	ସଂରଚନା session_state *state = ssh->state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (enc == ଖାଲି || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		ଯଦି ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			ଫେରନ୍ତୁ r;
		ଫେରନ୍ତୁ SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	ଯଦି (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	ଯଦି (sshbuf_len(state->ନିବେଶ) >= discard)
		ଫେରନ୍ତୁ ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->ନିବେଶ);
	ଫେରନ୍ତୁ 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_connection_is_on_socket(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା session_state *state;
	ସଂରଚନା sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	ଯଦି (ssh == ଖାଲି || ssh->state == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	state = ssh->state;
	ଯଦି (state->connection_in == -1 || state->connection_out == -1)
		ଫେରନ୍ତୁ 0;
	fromlen = ଆକାର(from);
	memset(&from, 0, ଆକାର(from));
	ଯଦି (getpeername(state->connection_in, (ସଂରଚନା sockaddr *)&from,
	    &fromlen) == -1)
		ଫେରନ୍ତୁ 0;
	ଯଦି (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ଫେରନ୍ତୁ 0;
	/* filedescriptors in and out are the same, so it's a socket */
	ଯଦି (state->connection_in == state->connection_out)
		ଫେରନ୍ତୁ 1;
	tolen = ଆକାର(to);
	memset(&to, 0, ଆକାର(to));
	ଯଦି (getpeername(state->connection_out, (ସଂରଚନା sockaddr *)&to,
	    &tolen) == -1)
		ଫେରନ୍ତୁ 0;
	ଯଦି (fromlen != tolen || memcmp(&from, &to, fromlen) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ଶୂନ୍ୟ
ssh_packet_get_bytes(ସଂରଚନା ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	ଯଦି (ibytes)
		*ibytes = ssh->state->p_read.bytes;
	ଯଦି (obytes)
		*obytes = ssh->state->p_send.bytes;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_connection_af(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ get_sock_af(ssh->state->connection_out);
}

/* Sets the connection into non-blocking mode. */

ଶୂନ୍ୟ
ssh_packet_set_nonblocking(ସଂରଚନା ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(ssh->state->connection_in);

	ଯଦି (ssh->state->connection_out != ssh->state->connection_in)
		set_nonblock(ssh->state->connection_out);
}

/* Returns the socket used for reading. */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_get_connection_in(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ssh->state->connection_in;
}

/* Returns the descriptor used for writing. */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_get_connection_out(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ssh->state->connection_out;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

ଅଚଳ ଅକ୍ଷର *
ssh_remote_ipaddr(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock;

	/* Check whether we have cached the ipaddr. */
	ଯଦି (ssh->remote_ipaddr == ଖାଲି) {
		ଯଦି (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_in;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_port = get_peer_port(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_port = get_local_port(sock);
		} ଅନ୍ୟଥା {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_port = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_port = 65535;
		}
	}
	ଫେରନ୍ତୁ ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

ଅକ୍ଷର *
ssh_remote_hostname(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା sockaddr_storage from;
	socklen_t fromlen;
	ସଂରଚନା addrinfo hints, *ai, *aitop;
	ଅକ୍ଷର name[NI_MAXHOST], ntop2[NI_MAXHOST];
	ଅଚଳ ଅକ୍ଷର *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = ଆକାର(from);
	memset(&from, 0, ଆକାର(from));
	ଯଦି (getpeername(ssh_packet_get_connection_in(ssh),
	    (ସଂରଚନା sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		ଫେରନ୍ତୁ xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	ଯଦି (from.ss_family == AF_INET6)
		fromlen = ଆକାର(ସଂରଚନା sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	ଯଦି (getnameinfo((ସଂରଚନା sockaddr *)&from, fromlen, name, ଆକାର(name),
	    ଖାଲି, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		ଫେରନ୍ତୁ xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, ଆକାର(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	ଯଦି (getaddrinfo(name, ଖାଲି, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		ଫେରନ୍ତୁ xstrdup(ntop);
	}

	/* Names are stored in lowercase. */
	lowercase(name);

	/*
	 * Map it back to an IP address and check that the given
	 * address actually is an address of this host.  This is
	 * necessary because anyone with access to a name server can
	 * define arbitrary names for an IP address. Mapping from
	 * name to IP address can be trusted better (but can still be
	 * fooled if the intruder has access to the name server of
	 * the domain).
	 */
	memset(&hints, 0, ଆକାର(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	ଯଦି (getaddrinfo(name, ଖାଲି, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		ଫେରନ୍ତୁ xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	ପାଇଁ (ai = aitop; ai; ai = ai->ai_next) {
		ଯଦି (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    ଆକାର(ntop2), ଖାଲି, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				ଭାଙ୍ଗ;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	ଯଦି (ai == ଖାଲି) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		ଫେରନ୍ତୁ xstrdup(ntop);
	}
	ଫେରନ୍ତୁ xstrdup(name);
}

/* Returns the port number of the remote host. */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_remote_port(ସଂରଚନା ssh *ssh)
{
	(ଶୂନ୍ୟ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ଫେରନ୍ତୁ ssh->remote_port;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

ଅଚଳ ଅକ୍ଷର *
ssh_local_ipaddr(ସଂରଚନା ssh *ssh)
{
	(ଶୂନ୍ୟ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ଫେରନ୍ତୁ ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_local_port(ସଂରଚନା ssh *ssh)
{
	(ଶୂନ୍ୟ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ଫେରନ୍ତୁ ssh->local_port;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
ଅଚଳ ଅକ୍ଷର *
ssh_packet_rdomain_in(ସଂରଚନା ssh *ssh)
{
	ଯଦି (ssh->rdomain_in != ଖାଲି)
		ଫେରନ୍ତୁ ssh->rdomain_in;
	ଯଦି (!ssh_packet_connection_is_on_socket(ssh))
		ଫେରନ୍ତୁ ଖାଲି;
	ssh->rdomain_in = get_rdomain(ssh->state->connection_in);
	ଫେରନ୍ତୁ ssh->rdomain_in;
}

/* Closes the connection and clears and frees internal data structures. */

ସ୍ଥିର ଶୂନ୍ୟ
ssh_packet_close_internal(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_close)
{
	ସଂରଚନା session_state *state = ssh->state;
	u_int mode;
	ସଂରଚନା packet *p;

	ଯଦି (!state->initialized)
		ଫେରନ୍ତୁ;
	state->initialized = 0;
	ଯଦି (do_close) {
		ଯଦି (state->connection_in == state->connection_out) {
			close(state->connection_out);
		} ଅନ୍ୟଥା {
			close(state->connection_in);
			close(state->connection_out);
		}
	}
	sshbuf_free(state->ନିବେଶ);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	ଯେତେବେଳେ ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, next);
		ମୁକ୍ତ(p);
	}
	ପାଇଁ (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(state->newkeys[mode]);	/* current keys */
		state->newkeys[mode] = ଖାଲି;
		ssh_clear_newkeys(ssh, mode);		/* next keys */
	}
#ifdef WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	ଯଦି (do_close && state->compression_buffer) {
		sshbuf_free(state->compression_buffer);
		ଯଦି (state->compression_out_started) {
			z_streamp stream = &state->compression_out_stream;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(unsigned long long)stream->total_in,
				(unsigned long long)stream->total_out,
				stream->total_in == 0 ? 0.0 :
				(ଦ୍ୱିଗୁଣ) stream->total_out / stream->total_in);
			ଯଦି (state->compression_out_failures == 0)
				deflateEnd(stream);
		}
		ଯଦି (state->compression_in_started) {
			z_streamp stream = &state->compression_in_stream;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (unsigned long long)stream->total_out,
			    (unsigned long long)stream->total_in,
			    stream->total_out == 0 ? 0.0 :
			    (ଦ୍ୱିଗୁଣ) stream->total_in / stream->total_out);
			ଯଦି (state->compression_in_failures == 0)
				inflateEnd(stream);
		}
	}
#endif	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = ଖାଲି;
	ଯଦି (do_close) {
		ମୁକ୍ତ(ssh->local_ipaddr);
		ssh->local_ipaddr = ଖାଲି;
		ମୁକ୍ତ(ssh->remote_ipaddr);
		ssh->remote_ipaddr = ଖାଲି;
		ମୁକ୍ତ(ssh->state);
		ssh->state = ଖାଲି;
		kex_free(ssh->kex);
		ssh->kex = ଖାଲି;
	}
}

ଶୂନ୍ୟ
ssh_packet_free(ସଂରଚନା ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
	freezero(ssh, ଆକାର(*ssh));
}

ଶୂନ୍ୟ
ssh_packet_close(ସଂରଚନା ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
}

ଶୂନ୍ୟ
ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା ssh *ssh)
{
	ssh_packet_close_internal(ssh, 0);
}

/* Sets remote side protocol flags. */

ଶୂନ୍ୟ
ssh_packet_set_protocol_flags(ସଂରଚନା ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_init_compression(ସଂରଚନା ssh *ssh)
{
	ଯଦି (!ssh->state->compression_buffer &&
	    ((ssh->state->compression_buffer = sshbuf_new()) == ଖାଲି))
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଫେରନ୍ତୁ 0;
}

#ifdef WITH_ZLIB
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
start_compression_out(ସଂରଚନା ssh *ssh)
{
	debug("Enabling compression.");
	ଯଦି (ssh->state->compression_out_started == 1)
		deflateEnd(&ssh->state->compression_out_stream);
	ବାଛ (deflateInit2(&ssh->state->compression_out_stream,
	    Z_BEST_SPEED, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	ସ୍ଥିତି Z_OK:
		ssh->state->compression_out_started = 1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି Z_MEM_ERROR:
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
start_compression_in(ସଂରଚନା ssh *ssh)
{
	ଯଦି (ssh->state->compression_in_started == 1)
		inflateEnd(&ssh->state->compression_in_stream);
	ବାଛ (inflateInit(&ssh->state->compression_in_stream)) {
	ସ୍ଥିତି Z_OK:
		ssh->state->compression_in_started = 1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି Z_MEM_ERROR:
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଫେରନ୍ତୁ 0;
}

/* XXX remove need for separate compression buffer */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
compress_buffer(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *in, ସଂରଚନା sshbuf *out)
{
	u_char buf[4096];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status;

	ଯଦି (ssh->state->compression_out_started != 1)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;

	/* This case is not handled below. */
	ଯଦି (sshbuf_len(in) == 0)
		ଫେରନ୍ତୁ 0;

	/* Input is the contents of the input buffer. */
	ଯଦି ((ssh->state->compression_out_stream.next_in =
	    sshbuf_mutable_ptr(in)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_out_stream.avail_in = sshbuf_len(in);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	କର {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_out_stream.next_out = buf;
		ssh->state->compression_out_stream.avail_out = ଆକାର(buf);

		/* Compress as much data into the buffer as possible. */
		status = deflate(&ssh->state->compression_out_stream,
		    Z_PARTIAL_FLUSH);
		ବାଛ (status) {
		ସ୍ଥିତି Z_MEM_ERROR:
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		ସ୍ଥିତି Z_OK:
			/* Append compressed data to output_buffer. */
			ଯଦି ((r = sshbuf_put(out, buf, ଆକାର(buf) -
			    ssh->state->compression_out_stream.avail_out)) != 0)
				ଫେରନ୍ତୁ r;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି Z_STREAM_ERROR:
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ssh->state->compression_out_failures++;
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		}
	} ଯେତେବେଳେ (ssh->state->compression_out_stream.avail_out == 0);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
uncompress_buffer(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *in, ସଂରଚନା sshbuf *out)
{
	u_char buf[4096];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status;

	ଯଦି (ssh->state->compression_in_started != 1)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;

	ଯଦି ((ssh->state->compression_in_stream.next_in =
	    sshbuf_mutable_ptr(in)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_in_stream.avail_in = sshbuf_len(in);

	ପାଇଁ (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_in_stream.next_out = buf;
		ssh->state->compression_in_stream.avail_out = ଆକାର(buf);

		status = inflate(&ssh->state->compression_in_stream,
		    Z_SYNC_FLUSH);
		ବାଛ (status) {
		ସ୍ଥିତି Z_OK:
			ଯଦି ((r = sshbuf_put(out, buf, ଆକାର(buf) -
			    ssh->state->compression_in_stream.avail_out)) != 0)
				ଫେରନ୍ତୁ r;
			ଯଦି (sshbuf_len(out) >= PACKET_MAX_SIZE)
				ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			ଫେରନ୍ତୁ 0;
		ସ୍ଥିତି Z_DATA_ERROR:
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		ସ୍ଥିତି Z_MEM_ERROR:
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		ସ୍ଥିତି Z_STREAM_ERROR:
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ssh->state->compression_in_failures++;
			ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
		}
	}
	/* NOTREACHED */
}

#ଅନ୍ୟଥା	/* WITH_ZLIB */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
start_compression_out(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
start_compression_in(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
compress_buffer(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *in, ସଂରଚନା sshbuf *out)
{
	ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
uncompress_buffer(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *in, ସଂରଚନା sshbuf *out)
{
	ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
}
#endif	/* WITH_ZLIB */

ଶୂନ୍ୟ
ssh_clear_newkeys(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode)
{
	ଯଦି (ssh->kex && ssh->kex->newkeys[mode]) {
		kex_free_newkeys(ssh->kex->newkeys[mode]);
		ssh->kex->newkeys[mode] = ଖାଲି;
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_set_newkeys(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode)
{
	ସଂରଚନା session_state *state = ssh->state;
	ସଂରଚନା sshenc *enc;
	ସଂରଚନା sshmac *mac;
	ସଂରଚନା sshcomp *comp;
	ସଂରଚନା sshcipher_ctx **ccp;
	ସଂରଚନା packet_state *ps;
	uint64_t *max_blocks, *hard_max_blocks;
	ଅଚଳ ଅକ୍ଷର *wmsg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, crypt_type;
	ଅଚଳ ଅକ୍ଷର *dir = mode == MODE_OUT ? "out" : "in";

	debug2_f("mode %d", mode);

	ଯଦି (mode == MODE_OUT) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_blocks = &state->hard_max_blocks_out;
		max_blocks = &state->max_blocks_out;
	} ଅନ୍ୟଥା {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_blocks = &state->hard_max_blocks_in;
		max_blocks = &state->max_blocks_in;
	}
	ଯଦି (state->newkeys[mode] != ଖାଲି) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (unsigned long long)state->p_read.bytes,
		    (unsigned long long)state->p_read.blocks,
		    (unsigned long long)state->p_send.bytes,
		    (unsigned long long)state->p_send.blocks);
		kex_free_newkeys(state->newkeys[mode]);
		state->newkeys[mode] = ଖାଲି;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->blocks = 0;
	/* move newkeys from kex to state */
	ଯଦି ((state->newkeys[mode] = ssh->kex->newkeys[mode]) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ssh->kex->newkeys[mode] = ଖାଲି;
	enc  = &state->newkeys[mode]->enc;
	mac  = &state->newkeys[mode]->mac;
	comp = &state->newkeys[mode]->comp;
	ଯଦି (cipher_authlen(enc->cipher) == 0) {
		ଯଦି ((r = mac_init(mac)) != 0)
			ଫେରନ୍ତୁ r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = ଖାଲି;
	ଯଦି ((r = cipher_init(ccp, enc->cipher, enc->ଚାବି, enc->ଚାବି_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (!state->cipher_warning_done &&
	    (wmsg = cipher_warning_message(*ccp)) != ଖାଲି) {
		error("Warning: %s", wmsg);
		state->cipher_warning_done = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	ଯଦି (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		ଯଦି ((r = ssh_packet_init_compression(ssh)) < 0)
			ଫେରନ୍ତୁ r;
		ଯଦି (mode == MODE_OUT) {
			ଯଦି ((r = start_compression_out(ssh)) != 0)
				ଫେରନ୍ତୁ r;
		} ଅନ୍ୟଥା {
			ଯଦି ((r = start_compression_in(ssh)) != 0)
				ଫେରନ୍ତୁ r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	ଯଦି (enc->block_size >= 16)
		*hard_max_blocks = (uint64_t)1 << (enc->block_size*2);
	ଅନ୍ୟଥା
		*hard_max_blocks = ((uint64_t)1 << 30) / enc->block_size;
	*max_blocks = *hard_max_blocks;
	ଯଦି (state->rekey_limit) {
		*max_blocks = MINIMUM(*max_blocks,
		    state->rekey_limit / enc->block_size);
	}
	debug("rekey %s after %llu blocks", dir,
	    (unsigned long long)*max_blocks);
	ଫେରନ୍ତୁ 0;
}

#define MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
ସ୍ଥିର ଧାଡ଼ିଭିତରେ ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_check_rekey_blocklimit(ସଂରଚନା ssh *ssh, u_int packet_len, ପୂର୍ଣ୍ଣସଂଖ୍ୟା hard)
{
	ସଂରଚନା session_state *state = ssh->state;
	uint32_t out_blocks;
	ଅଚଳ uint64_t max_blocks_in = hard ?
	    state->hard_max_blocks_in : state->max_blocks_in;
	ଅଚଳ uint64_t max_blocks_out = hard ?
	    state->hard_max_blocks_out : state->max_blocks_out;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	ଯଦି (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		ଫେରନ୍ତୁ 1;

	ଯଦି (state->newkeys[MODE_OUT] == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	/* Rekey after (cipher-specific) maximum blocks */
	out_blocks = ROUNDUP(packet_len,
	    state->newkeys[MODE_OUT]->enc.block_size);
	ଫେରନ୍ତୁ (max_blocks_out &&
	    (state->p_send.blocks + out_blocks > max_blocks_out)) ||
	    (max_blocks_in &&
	    (state->p_read.blocks > max_blocks_in));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_need_rekeying(ସଂରଚନା ssh *ssh, u_int outbound_packet_len)
{
	ସଂରଚନା session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	ଯଦି (!state->after_authentication)
		ଫେରନ୍ତୁ 0;

	/* Haven't keyed yet or KEX in progress. */
	ଯଦି (ssh_packet_is_rekeying(ssh))
		ଫେରନ୍ତୁ 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	ଯଦି (state->p_send.packets == 0 && state->p_read.packets == 0)
		ଫେରନ୍ତୁ 0;

	/* Time-based rekeying */
	ଯଦି (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_time + state->rekey_interval <= monotime())
		ଫେରନ୍ତୁ 1;

	ଫେରନ୍ତୁ ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_check_rekey_preauth(ସଂରଚନା ssh *ssh, u_int outgoing_packet_len)
{
	ଯଦି (ssh->state->after_authentication)
		ଫେରନ୍ତୁ 0;

	ଯଦି (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		ଫେରନ୍ତୁ SSH_ERR_NEED_REKEY;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_check_rekey(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (!ssh_packet_need_rekeying(ssh, 0))
		ଫେରନ୍ତୁ 0;
	debug3_f("rekex triggered");
	ଫେରନ୍ତୁ kex_start_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_enable_delayed_compress(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା session_state *state = ssh->state;
	ସଂରଚନା sshcomp *comp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	ପାଇଁ (mode = 0; mode < MODE_MAX; mode++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		ଯଦି (state->newkeys[mode] == ଖାଲି)
			ଜାରି;
		comp = &state->newkeys[mode]->comp;
		ଯଦି (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			ଯଦି ((r = ssh_packet_init_compression(ssh)) != 0)
				ଫେରନ୍ତୁ r;
			ଯଦି (mode == MODE_OUT) {
				ଯଦି ((r = start_compression_out(ssh)) != 0)
					ଫେରନ୍ତୁ r;
			} ଅନ୍ୟଥା {
				ଯଦି ((r = start_compression_in(ssh)) != 0)
					ଫେରନ୍ତୁ r;
			}
			comp->enabled = 1;
		}
	}
	ଫେରନ୍ତୁ 0;
}

/* Used to mute debug logging for noisy packet types */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_log_type(u_char type)
{
	ବାଛ (type) {
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_PING:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_PONG:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_DATA:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_EXTENDED_DATA:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_WINDOW_ADJUST:
		ଫେରନ୍ତୁ 0;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_send2_wrapped(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_LENGTH];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	ସଂରଚନା sshenc *enc   = ଖାଲି;
	ସଂରଚନା sshmac *mac   = ଖାଲି;
	ସଂରଚନା sshcomp *comp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, block_size;

	ଯଦି (state->newkeys[MODE_OUT] != ଖାଲି) {
		enc  = &state->newkeys[MODE_OUT]->enc;
		mac  = &state->newkeys[MODE_OUT]->mac;
		comp = &state->newkeys[MODE_OUT]->comp;
		/* disable mac for authenticated encryption */
		ଯଦି ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ଖାଲି;
	}
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	ଯଦି (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#endif

	ଯଦି (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		ଯଦି ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			ଯାଅ out;
		sshbuf_reset(state->compression_buffer);
		ଯଦି ((r = compress_buffer(ssh, state->outgoing_packet,
		    state->compression_buffer)) != 0)
			ଯାଅ out;
		sshbuf_reset(state->outgoing_packet);
		ଯଦି ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_buffer)) != 0)
			ଯାଅ out;
		DBG(debug("compression: raw %d compressed %zd", len,
		    sshbuf_len(state->outgoing_packet)));
	}

	/* sizeof (packet_len + pad_len + payload) */
	len = sshbuf_len(state->outgoing_packet);

	/*
	 * calc size of padding, alloc space, get random data,
	 * minimum padding is 4 bytes
	 */
	len -= aadlen; /* packet length is not encrypted for EtM modes */
	padlen = block_size - (len % block_size);
	ଯଦି (padlen < 4)
		padlen += block_size;
	ଯଦି (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, block_size);
		/* check if roundup overflowed */
		ଯଦି (state->extra_pad < tmp)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		ଯଦି (tmp > state->extra_pad)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		ଯଦି (padlen < tmp)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT; /* overflow */
		state->extra_pad = 0;
	}
	ଯଦି ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		ଯାଅ out;
	ଯଦି (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} ଅନ୍ୟଥା {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	ଯଦି (cp == ଖାଲି) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	ଯଦି (mac && mac->enabled && !mac->etm) {
		ଯଦି ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, ଆକାର(macbuf))) != 0)
			ଯାଅ out;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	ଯଦି ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		ଯାଅ out;
	ଯଦି ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		ଯାଅ out;
	/* append unencrypted MAC */
	ଯଦି (mac && mac->enabled) {
		ଯଦି (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			ଯଦି ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, ଆକାର(macbuf))) != 0)
				ଯାଅ out;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		ଯଦି ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			ଯାଅ out;
	}
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#endif
	/* increment sequence number for outgoing packets */
	ଯଦି (++state->p_send.seqnr == 0) {
		ଯଦି ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	ଯଦି (++state->p_send.packets == 0)
		ଫେରନ୍ତୁ SSH_ERR_NEED_REKEY;
	state->p_send.blocks += len / block_size;
	state->p_send.bytes += len;
	sshbuf_reset(state->outgoing_packet);

	ଯଦି (type == SSH2_ସନ୍ଦେଶ_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	ଯଦି (type == SSH2_ସନ୍ଦେଶ_NEWKEYS)
		r = ssh_set_newkeys(ssh, MODE_OUT);
	ଅନ୍ୟଥା ଯଦି (type == SSH2_ସନ୍ଦେଶ_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	ଅନ୍ୟଥା
		r = 0;
 out:
	ଫେରନ୍ତୁ r;
}

/* returns non-zero if the specified packet type is usec by KEX */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_type_is_kex(u_char type)
{
	ଫେରନ୍ତୁ
	    type >= SSH2_ସନ୍ଦେଶ_TRANSPORT_MIN &&
	    type <= SSH2_ସନ୍ଦେଶ_TRANSPORT_MAX &&
	    type != SSH2_ସନ୍ଦେଶ_SERVICE_REQUEST &&
	    type != SSH2_ସନ୍ଦେଶ_SERVICE_ACCEPT &&
	    type != SSH2_ସନ୍ଦେଶ_EXT_INFO;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_send2(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା session_state *state = ssh->state;
	ସଂରଚନା packet *p;
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, need_rekey;

	ଯଦି (sshbuf_len(state->outgoing_packet) < 6)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	ଯଦି (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		ଫେରନ୍ତୁ r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	ଯଦି ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		ଯଦି (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = calloc(1, ଆକାର(*p));
		ଯଦି (p == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, next);
		state->outgoing_packet = sshbuf_new();
		ଯଦି (state->outgoing_packet == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		ଯଦି (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			ଫେରନ୍ତୁ kex_start_rekex(ssh);
		}
		ଫେରନ୍ତୁ 0;
	}

	/* rekeying starts with sending KEXINIT */
	ଯଦି (type == SSH2_ସନ୍ଦେଶ_KEXINIT)
		state->rekeying = 1;

	ଯଦି ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		ଫେରନ୍ତୁ r;

	/* after a NEWKEYS message we can send the complete queue */
	ଯଦି (type == SSH2_ସନ୍ଦେଶ_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_time = monotime();
		ଯେତେବେଳେ ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			ଯଦି (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				ଫେରନ୍ତୁ kex_start_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, next);
			memset(p, 0, ଆକାର(*p));
			ମୁକ୍ତ(p);
			ଯଦି ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				ଫେରନ୍ତୁ r;
		}
	}
	ଫେରନ୍ତୁ 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_read_seqnr(ସଂରଚନା ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ସଂରଚନା session_state *state = ssh->state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା len, r, ms_remain = 0;
	ସଂରଚନା pollfd pfd;
	ଅକ୍ଷର buf[8192];
	ସଂରଚନା timeval start;
	ସଂରଚନା timespec timespec, *timespecp = ଖାଲି;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	ଯଦି ((r = ssh_packet_write_wait(ssh)) != 0)
		ଯାଅ out;

	/* Stay in the loop until we have received a complete packet. */
	ପାଇଁ (;;) {
		/* Try to read a packet from the buffer. */
		ଯଦି ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			ଭାଙ୍ଗ;
		/* If we got a packet, return it. */
		ଯଦି (*typep != SSH_ସନ୍ଦେଶ_NONE)
			ଭାଙ୍ଗ;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_in;
		pfd.events = POLLIN;

		ଯଦି (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		ପାଇଁ (;;) {
			ଯଦି (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			ଯଦି ((r = ppoll(&pfd, 1, timespecp, ଖାଲି)) >= 0)
				ଭାଙ୍ଗ;
			ଯଦି (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				ଯାଅ out;
			}
			ଯଦି (state->packet_timeout_ms <= 0)
				ଜାରି;
			ms_subtract_diff(&start, &ms_remain);
			ଯଦି (ms_remain <= 0) {
				r = 0;
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			ଯାଅ out;
		}
		/* Read data from the socket. */
		len = ପଠ(state->connection_in, buf, ଆକାର(buf));
		ଯଦି (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			ଯାଅ out;
		}
		ଯଦି (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			ଯାଅ out;
		}

		/* Append it to the buffer. */
		ଯଦି ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			ଯାଅ out;
	}
 out:
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_read(ସଂରଚନା ssh *ssh)
{
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = ssh_packet_read_seqnr(ssh, &type, ଖାଲି)) != 0)
		sshpkt_fatal(ssh, r, "read");
	ଫେରନ୍ତୁ type;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_read_poll2_mux(ସଂରଚନା ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ସଂରଚନା session_state *state = ssh->state;
	ଅଚଳ u_char *cp;
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ssh->kex)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	*typep = SSH_ସନ୍ଦେଶ_NONE;
	cp = sshbuf_ptr(state->ନିବେଶ);
	ଯଦି (state->packlen == 0) {
		ଯଦି (sshbuf_len(state->ନିବେଶ) < 4 + 1)
			ଫେରନ୍ତୁ 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		ଯଦି (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_SIZE)
			ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	need = state->packlen + 4;
	ଯଦି (sshbuf_len(state->ନିବେଶ) < need)
		ଫେରନ୍ତୁ 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	ଯଦି ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->ନିବେଶ, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_read_poll2(ସଂରଚନା ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ସଂରଚନା session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, block_size;
	ସଂରଚନା sshenc *enc   = ଖାଲି;
	ସଂରଚନା sshmac *mac   = ଖାଲି;
	ସଂରଚନା sshcomp *comp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (state->mux)
		ଫେରନ୍ତୁ ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_ସନ୍ଦେଶ_NONE;

	ଯଦି (state->packet_discard)
		ଫେରନ୍ତୁ 0;

	ଯଦି (state->newkeys[MODE_IN] != ଖାଲି) {
		enc  = &state->newkeys[MODE_IN]->enc;
		mac  = &state->newkeys[MODE_IN]->mac;
		comp = &state->newkeys[MODE_IN]->comp;
		/* disable mac for authenticated encryption */
		ଯଦି ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ଖାଲି;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	ଯଦି (aadlen && state->packlen == 0) {
		ଯଦି (cipher_get_length(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->ନିବେଶ), sshbuf_len(state->ନିବେଶ)) != 0)
			ଫେରନ୍ତୁ 0;
		ଯଦି (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			sshbuf_dump(state->ନିବେଶ, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			ଯଦି ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				ଫେରନ୍ତୁ r;
			ଫେରନ୍ତୁ SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} ଅନ୍ୟଥା ଯଦି (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		ଯଦି (sshbuf_len(state->ନିବେଶ) < block_size)
			ଫେରନ୍ତୁ 0;
		sshbuf_reset(state->incoming_packet);
		ଯଦି ((r = sshbuf_reserve(state->incoming_packet, block_size,
		    &cp)) != 0)
			ଯାଅ out;
		ଯଦି ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->ନିବେଶ),
		    block_size, 0, 0)) != 0)
			ଯାଅ out;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		ଯଦି (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->ନିବେଶ, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			ଫେରନ୍ତୁ ssh_packet_start_discard(ssh, enc, mac, 0,
			    PACKET_MAX_SIZE);
		}
		ଯଦି ((r = sshbuf_consume(state->ନିବେଶ, block_size)) != 0)
			ଯାଅ out;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	ଯଦି (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} ଅନ୍ୟଥା {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - block_size;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", block_size, need, maclen, authlen, aadlen));
	ଯଦି (need % block_size != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
		ଫେରନ୍ତୁ ssh_packet_start_discard(ssh, enc, mac, 0,
		    PACKET_MAX_SIZE - block_size);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet:
	 * 'aadlen' bytes are unencrypted, but authenticated.
	 * 'need' bytes are encrypted, followed by either
	 * 'authlen' bytes of authentication tag or
	 * 'maclen' bytes of message authentication code.
	 */
	ଯଦି (sshbuf_len(state->ନିବେଶ) < aadlen + need + authlen + maclen)
		ଫେରନ୍ତୁ 0; /* packet is incomplete */
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->ନିବେଶ, stderr);
#endif
	/* EtM: check mac over encrypted input */
	ଯଦି (mac && mac->enabled && mac->etm) {
		ଯଦି ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->ନିବେଶ), aadlen + need,
		    sshbuf_ptr(state->ନିବେଶ) + aadlen + need + authlen,
		    maclen)) != 0) {
			ଯଦି (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			ଯାଅ out;
		}
	}
	ଯଦି ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		ଯାଅ out;
	ଯଦି ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->ନିବେଶ), need, aadlen, authlen)) != 0)
		ଯାଅ out;
	ଯଦି ((r = sshbuf_consume(state->ନିବେଶ, aadlen + need + authlen)) != 0)
		ଯାଅ out;
	ଯଦି (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		ଯଦି (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->ନିବେଶ), maclen)) != 0) {
			ଯଦି (r != SSH_ERR_MAC_INVALID)
				ଯାଅ out;
			logit("Corrupted MAC on input.");
			ଯଦି (need + block_size > PACKET_MAX_SIZE)
				ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
			ଫେରନ୍ତୁ ssh_packet_start_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_SIZE - need - block_size);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		ଯଦି ((r = sshbuf_consume(state->ନିବେଶ, mac->mac_len)) != 0)
			ଯାଅ out;
	}

	ଯଦି (seqnr_p != ଖାଲି)
		*seqnr_p = state->p_read.seqnr;
	ଯଦି (++state->p_read.seqnr == 0) {
		ଯଦି ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	ଯଦି (++state->p_read.packets == 0)
		ଫେରନ୍ତୁ SSH_ERR_NEED_REKEY;
	state->p_read.blocks += (state->packlen + 4) / block_size;
	state->p_read.bytes += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	ଯଦି (padlen < 4)	{
		ଯଦି ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ଫେରନ୍ତୁ r;
		ଫେରନ୍ତୁ SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	ଯଦି ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_end(state->incoming_packet, padlen)) != 0))
		ଯାଅ out;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	ଯଦି (comp && comp->enabled) {
		sshbuf_reset(state->compression_buffer);
		ଯଦି ((r = uncompress_buffer(ssh, state->incoming_packet,
		    state->compression_buffer)) != 0)
			ଯାଅ out;
		sshbuf_reset(state->incoming_packet);
		ଯଦି ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_buffer)) != 0)
			ଯାଅ out;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	ଯଦି ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		ଯାଅ out;
	ଯଦି (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	ଯଦି (*typep < SSH2_ସନ୍ଦେଶ_MIN) {
		ଯଦି ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ଫେରନ୍ତୁ r;
		ଫେରନ୍ତୁ SSH_ERR_PROTOCOL_ERROR;
	}
	ଯଦି (state->hook_in != ଖାଲି &&
	    (r = state->hook_in(ssh, state->incoming_packet, typep,
	    state->hook_in_ctx)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (*typep == SSH2_ସନ୍ଦେଶ_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	ଅନ୍ୟଥା
		r = 0;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#endif
	/* reset for next packet */
	state->packlen = 0;
	ଯଦି (*typep == SSH2_ସନ୍ଦେଶ_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	ଯଦି ((r = ssh_packet_check_rekey(ssh)) != 0)
		ଫେରନ୍ତୁ r;
 out:
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_read_poll_seqnr(ସଂରଚନା ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ସଂରଚନା session_state *state = ssh->state;
	u_int reason, seqnr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char *ସନ୍ଦେଶ;
	ଅଚଳ u_char *d;
	size_t len;

	ପାଇଁ (;;) {
		ସନ୍ଦେଶ = ଖାଲି;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		ଯଦି (r != 0)
			ଫେରନ୍ତୁ r;
		ଯଦି (*typep == 0) {
			/* no message ready */
			ଫେରନ୍ତୁ 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		ଯଦି (*typep == SSH2_ସନ୍ଦେଶ_DISCONNECT) {
			ଯଦି ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &ସନ୍ଦେଶ, ଖାଲି)) != 0)
				ଫେରନ୍ତୁ r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh), reason, ସନ୍ଦେଶ);
			ମୁକ୍ତ(ସନ୍ଦେଶ);
			ଫେରନ୍ତୁ SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		ଯଦି (ssh->kex != ଖାଲି &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			ଫେରନ୍ତୁ 0;
		/* Implicitly handle transport-level messages */
		ବାଛ (*typep) {
		ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_DEBUG:
			ଯଦି ((r = sshpkt_get_u8(ssh, ଖାଲି)) != 0 ||
			    (r = sshpkt_get_string(ssh, &ସନ୍ଦେଶ, ଖାଲି)) != 0 ||
			    (r = sshpkt_get_string(ssh, ଖାଲି, ଖାଲି)) != 0) {
				ମୁକ୍ତ(ସନ୍ଦେଶ);
				ଫେରନ୍ତୁ r;
			}
			debug("Remote: %.900s", ସନ୍ଦେଶ);
			ମୁକ୍ତ(ସନ୍ଦେଶ);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_UNIMPLEMENTED:
			ଯଦି ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				ଫେରନ୍ତୁ r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_PING:
			ଯଦି ((r = sshpkt_get_string_direct(ssh, &d, &len)) != 0)
				ଫେରନ୍ତୁ r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			ଯଦି (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				ଭାଙ୍ଗ;
			}
			ଯଦି (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				ଭାଙ୍ଗ;
			}
			ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				ଫେରନ୍ତୁ r;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_PONG:
			ଯଦି ((r = sshpkt_get_string_direct(ssh,
			    ଖାଲି, &len)) != 0)
				ଫେରନ୍ତୁ r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଯଦି (ssh->kex != ଖାଲି &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				ଫେରନ୍ତୁ SSH_ERR_PROTOCOL_ERROR;
			}
			ଫେରନ୍ତୁ 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_process_incoming(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *buf, u_int len)
{
	ସଂରଚନା session_state *state = ssh->state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		ଯଦି (len >= state->packet_discard) {
			ଯଦି ((r = ssh_packet_stop_discard(ssh)) != 0)
				ଫେରନ୍ତୁ r;
		}
		state->packet_discard -= len;
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((r = sshbuf_put(state->ନିବେଶ, buf, len)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

/* Reads and buffers data from the specified fd */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_process_read(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା session_state *state = ssh->state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t rlen;

	ଯଦି ((r = sshbuf_read(fd, state->ନିବେଶ, PACKET_MAX_SIZE, &rlen)) != 0)
		ଫେରନ୍ତୁ r;

	ଯଦି (state->packet_discard) {
		ଯଦି ((r = sshbuf_consume_end(state->ନିବେଶ, rlen)) != 0)
			ଫେରନ୍ତୁ r;
		state->keep_alive_timeouts = 0; /* ?? */
		ଯଦି (rlen >= state->packet_discard) {
			ଯଦି ((r = ssh_packet_stop_discard(ssh)) != 0)
				ଫେରନ୍ତୁ r;
		}
		state->packet_discard -= rlen;
		ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_remaining(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
ଶୂନ୍ୟ
ssh_packet_send_debug(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *fmt,...)
{
	ଅକ୍ଷର buf[1024];
	va_list args;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ssh->compat & SSH_BUG_DEBUG))
		ଫେରନ୍ତୁ;

	va_start(args, fmt);
	vsnprintf(buf, ଆକାର(buf), fmt, args);
	va_end(args);

	debug3("sending debug message: %s", buf);

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

ଶୂନ୍ୟ
sshpkt_fmt_connection_id(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *s, size_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
ସ୍ଥିର ଶୂନ୍ୟ
sshpkt_vfatal(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ଅଚଳ ଅକ୍ଷର *fmt, va_list ap)
{
	ଅକ୍ଷର *tag = ଖାଲି, remote_id[512];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, ଆକାର(remote_id));

	ବାଛ (r) {
	ସ୍ଥିତି SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ssh);
		logdie("Connection closed by %s", remote_id);
	ସ୍ଥିତି SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	ସ୍ଥିତି SSH_ERR_DISCONNECTED:
		ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ssh);
		logdie("Disconnected from %s", remote_id);
	ସ୍ଥିତି SSH_ERR_SYSTEM_ERROR:
		ଯଦି (errno == ECONNRESET) {
			ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	ସ୍ଥିତି SSH_ERR_NO_CIPHER_ALG_MATCH:
	ସ୍ଥିତି SSH_ERR_NO_MAC_ALG_MATCH:
	ସ୍ଥିତି SSH_ERR_NO_COMPRESS_ALG_MATCH:
	ସ୍ଥିତି SSH_ERR_NO_KEX_ALG_MATCH:
	ସ୍ଥିତି SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ଯଦି (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଯଦି (vasprintf(&tag, fmt, ap) == -1) {
			ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    tag != ଖାଲି ? tag : "", tag != ଖାଲି ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

ଶୂନ୍ୟ
sshpkt_fatal(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sshpkt_vfatal(ssh, r, fmt, ap);
	/* NOTREACHED */
	va_end(ap);
	logdie_f("should have exited");
}

/*
 * Logs the error plus constructs and sends a disconnect packet, closes the
 * connection, and exits.  This function never returns. The error message
 * should not contain a newline.  The length of the formatted message must
 * not exceed 1024 bytes.
 */
ଶୂନ୍ୟ
ssh_packet_disconnect(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *fmt,...)
{
	ଅକ୍ଷର buf[1024], remote_id[512];
	va_list args;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* Guard against recursive invocations. */
	ଯଦି (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, ଆକାର(remote_id));
	va_start(args, fmt);
	vsnprintf(buf, ଆକାର(buf), fmt, args);
	va_end(args);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	ଯଦି ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	ଯଦି ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_write_poll(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା session_state *state = ssh->state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା len = sshbuf_len(state->output);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (len > 0) {
		len = ଲିଖ(state->connection_out,
		    sshbuf_ptr(state->output), len);
		ଯଦି (len == -1) {
			ଯଦି (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				ଫେରନ୍ତୁ 0;
			ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
		}
		ଯଦି (len == 0)
			ଫେରନ୍ତୁ SSH_ERR_CONN_CLOSED;
		ଯଦି ((r = sshbuf_consume(state->output, len)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_write_wait(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret, r, ms_remain = 0;
	ସଂରଚନା timeval start;
	ସଂରଚନା timespec timespec, *timespecp = ଖାଲି;
	ସଂରଚନା session_state *state = ssh->state;
	ସଂରଚନା pollfd pfd;

	ଯଦି ((r = ssh_packet_write_poll(ssh)) != 0)
		ଫେରନ୍ତୁ r;
	ଯେତେବେଳେ (ssh_packet_have_data_to_write(ssh)) {
		pfd.fd = state->connection_out;
		pfd.events = POLLOUT;

		ଯଦି (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		ପାଇଁ (;;) {
			ଯଦି (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			ଯଦି ((ret = ppoll(&pfd, 1, timespecp, ଖାଲି)) >= 0)
				ଭାଙ୍ଗ;
			ଯଦି (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				ଭାଙ୍ଗ;
			ଯଦି (state->packet_timeout_ms <= 0)
				ଜାରି;
			ms_subtract_diff(&start, &ms_remain);
			ଯଦି (ms_remain <= 0) {
				ret = 0;
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (ret == 0)
			ଫେରନ୍ତୁ SSH_ERR_CONN_TIMEOUT;
		ଯଦି ((r = ssh_packet_write_poll(ssh)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

/* Returns true if there is buffered data to write to the connection. */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_have_data_to_write(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_not_very_much_data_to_write(ସଂରଚନା ssh *ssh)
{
	ଯଦି (ssh->state->interactive_mode)
		ଫେରନ୍ତୁ sshbuf_len(ssh->state->output) < 16384;
	ଅନ୍ୟଥା
		ଫେରନ୍ତୁ sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_interactive_data_to_write(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ssh->state->interactive_mode &&
	    sshbuf_len(ssh->state->output) < 256;
}

ସ୍ଥିର ଶୂନ୍ୟ
apply_qos(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା session_state *state = ssh->state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା qos = state->interactive_mode ?
	    state->qos_interactive : state->qos_other;

	ଯଦି (!ssh_packet_connection_is_on_socket(ssh))
		ଫେରନ୍ତୁ;
	ଯଦି (!state->nodelay_set) {
		set_nodelay(state->connection_in);
		state->nodelay_set = 1;
	}
	set_sock_tos(ssh->state->connection_in, qos);
}

/* Informs that the current session is interactive. */
ଶୂନ୍ୟ
ssh_packet_set_interactive(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା interactive)
{
	ସଂରଚନା session_state *state = ssh->state;

	state->interactive_mode = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
ଶୂନ୍ୟ
ssh_packet_set_qos(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା qos_interactive, ପୂର୍ଣ୍ଣସଂଖ୍ୟା qos_other)
{
	ସଂରଚନା session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_set_maxsize(ସଂରଚନା ssh *ssh, u_int s)
{
	ସଂରଚନା session_state *state = ssh->state;

	ଯଦି (state->set_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_size, s);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		ଫେରନ୍ତୁ -1;
	}
	state->set_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_size = s;
	ଫେରନ୍ତୁ s;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_inc_alive_timeouts(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ++ssh->state->keep_alive_timeouts;
}

ଶୂନ୍ୟ
ssh_packet_set_alive_timeouts(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ssh->state->max_packet_size;
}

ଶୂନ୍ୟ
ssh_packet_set_rekey_limits(ସଂରଚନା ssh *ssh, uint64_t bytes, uint32_t seconds)
{
	ଯଦି (bytes == 0 && seconds == 0)
		ଫେରନ୍ତୁ;

	debug3("rekey after %llu bytes, %u seconds", (unsigned long long)bytes,
	    (unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା)seconds);
	ssh->state->rekey_limit = bytes;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(ସଂରଚନା ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_time + ssh->state->rekey_interval -
	    monotime();
	ଫେରନ୍ତୁ (seconds <= 0 ? 1 : seconds);
}

ଶୂନ୍ୟ
ssh_packet_set_server(ସଂରଚନା ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

ଶୂନ୍ୟ
ssh_packet_set_authenticated(ସଂରଚନା ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

ଶୂନ୍ୟ *
ssh_packet_get_ନିବେଶ(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ (ଶୂନ୍ୟ *)ssh->state->ନିବେଶ;
}

ଶୂନ୍ୟ *
ssh_packet_get_output(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ (ଶୂନ୍ୟ *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_set_postauth(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	ଯଦି ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_to_blob(ସଂରଚନା sshbuf *m, ସଂରଚନା kex *kex)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
	    (r = sshbuf_put_cstring(m, kex->hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_strict)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->client_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->flags)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->non_pq_kex_warned)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

/* turn key exchange results into a blob for packet state serialization */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
newkeys_to_blob(ସଂରଚନା sshbuf *m, ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode)
{
	ସଂରଚନା sshbuf *b;
	ସଂରଚନା sshcipher_ctx *cc;
	ସଂରଚନା sshcomp *comp;
	ସଂରଚନା sshenc *enc;
	ସଂରଚନା sshmac *mac;
	ସଂରଚନା newkeys *newkey;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((newkey = ssh->state->newkeys[mode]) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (mode == MODE_OUT) ? ssh->state->send_context :
	    ssh->state->receive_context;
	ଯଦି ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->block_size)) != 0 ||
	    (r = sshbuf_put_string(b, enc->ଚାବି, enc->ଚାବି_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		ଯାଅ out;
	ଯଦି (cipher_authlen(enc->cipher) == 0) {
		ଯଦି ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->ଚାବି, mac->ଚାବି_len)) != 0)
			ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		ଯାଅ out;
	r = sshbuf_put_stringb(m, b);
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

/* serialize packet state into a blob */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_get_state(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *m)
{
	ସଂରଚନା session_state *state = ssh->state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

#define ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	ଯଦି ((r = kex_to_blob(m, ssh->kex)) != 0 ||
	    (r = newkeys_to_blob(m, ssh, MODE_OUT)) != 0 ||
	    (r = newkeys_to_blob(m, ssh, MODE_IN)) != 0 ||
	    (r = sshbuf_put_u64(m, state->rekey_limit)) != 0 ||
	    (r = sshbuf_put_u32(m, state->rekey_interval)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.blocks)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.bytes)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.blocks)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.bytes)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->ନିବେଶ)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_mode))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		ଫେରନ୍ତୁ r;
#undef ENCODE_INT
	ଫେରନ୍ତୁ 0;
}

/* restore key exchange results from blob for packet state de-serialization */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
newkeys_from_blob(ସଂରଚନା sshbuf *m, ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ସଂରଚନା sshcomp *comp;
	ସଂରଚନା sshenc *enc;
	ସଂରଚନା sshmac *mac;
	ସଂରଚନା newkeys *newkey = ଖାଲି;
	size_t keylen, ivlen, maclen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((newkey = calloc(1, ଆକାର(*newkey))) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_froms(m, &b)) != 0)
		ଯାଅ out;
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	ଯଦି ((r = sshbuf_get_cstring(b, &enc->name, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->block_size)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->ଚାବି, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		ଯାଅ out;
	ଯଦି ((enc->cipher = cipher_by_name(enc->name)) == ଖାଲି ||
	    enc->block_size != cipher_blocksize(enc->cipher) ||
	    cipher_is_internal(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (cipher_authlen(enc->cipher) == 0) {
		ଯଦି ((r = sshbuf_get_cstring(b, &mac->name, ଖାଲି)) != 0)
			ଯାଅ out;
		ଯଦି ((r = mac_setup(mac, mac->name)) != 0)
			ଯାଅ out;
		ଯଦି ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->ଚାବି, &maclen)) != 0)
			ଯାଅ out;
		ଯଦି (maclen != mac->ଚାବି_len) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		mac->ଚାବି_len = maclen;
	}
	ଯଦି ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, ଖାଲି)) != 0)
		ଯାଅ out;
	ଯଦି (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	enc->ଚାବି_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[mode] = newkey;
	newkey = ଖାଲି;
	r = 0;
 out:
	ମୁକ୍ତ(newkey);
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

/* restore kex from blob for packet state de-serialization */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_from_blob(ସଂରଚନା sshbuf *m, ସଂରଚନା kex **kexp)
{
	ସଂରଚନା kex *kex;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((kex = kex_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_type)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_type)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_strict)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->client_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->server_version)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->flags)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->non_pq_kex_warned)) != 0)
		ଯାଅ out;
	ଯଦି (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	kex->server = 1;
	kex->done = 1;
	r = 0;
 out:
	ଯଦି (r != 0 || kexp == ଖାଲି) {
		kex_free(kex);
		ଯଦି (kexp != ଖାଲି)
			*kexp = ଖାଲି;
	} ଅନ୍ୟଥା {
		kex_free(*kexp);
		*kexp = kex;
	}
	ଫେରନ୍ତୁ r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_set_state(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *m)
{
	ସଂରଚନା session_state *state = ssh->state;
	ଅଚଳ u_char *ନିବେଶ, *output;
	size_t ilen, olen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int interactive, qos_interactive, qos_other;

	ଯଦି ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, MODE_OUT)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, MODE_IN)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->rekey_limit)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->rekey_interval)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.blocks)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.bytes)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.blocks)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.bytes)) != 0)
		ଫେରନ୍ତୁ r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_time = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	ଯଦି ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0 ||
	    (r = ssh_set_newkeys(ssh, MODE_OUT)) != 0)
		ଫେରନ୍ତୁ r;

	ଯଦି ((r = ssh_packet_set_postauth(ssh)) != 0)
		ଫେରନ୍ତୁ r;

	sshbuf_reset(state->ନିବେଶ);
	sshbuf_reset(state->output);
	ଯଦି ((r = sshbuf_get_string_direct(m, &ନିବେଶ, &ilen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->ନିବେଶ, ନିବେଶ, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		ଫେରନ୍ତୁ r;

	ଯଦି ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		ଫେରନ୍ତୁ r;
#define DECODE_INT(v) ((v) > INT_MAX ? -1 : (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)(v))
	state->interactive_mode = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#undef DECODE_INT

	ଯଦି (sshbuf_len(m))
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	ଫେରନ୍ତୁ 0;
}

/* NEW API */

/* put data to the outgoing packet */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put(ସଂରଚନା ssh *ssh, ଅଚଳ ଶୂନ୍ୟ *v, size_t len)
{
	ଫେରନ୍ତୁ sshbuf_put(ssh->state->outgoing_packet, v, len);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_putb(ସଂରଚନା ssh *ssh, ଅଚଳ ସଂରଚନା sshbuf *b)
{
	ଫେରନ୍ତୁ sshbuf_putb(ssh->state->outgoing_packet, b);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put_u8(ସଂରଚନା ssh *ssh, u_char val)
{
	ଫେରନ୍ତୁ sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put_u32(ସଂରଚନା ssh *ssh, uint32_t val)
{
	ଫେରନ୍ତୁ sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put_u64(ସଂରଚନା ssh *ssh, uint64_t val)
{
	ଫେରନ୍ତୁ sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put_string(ସଂରଚନା ssh *ssh, ଅଚଳ ଶୂନ୍ୟ *v, size_t len)
{
	ଫେରନ୍ତୁ sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put_cstring(ସଂରଚନା ssh *ssh, ଅଚଳ ଶୂନ୍ୟ *v)
{
	ଫେରନ୍ତୁ sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put_stringb(ସଂରଚନା ssh *ssh, ଅଚଳ ସଂରଚନା sshbuf *v)
{
	ଫେରନ୍ତୁ sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#ifdef WITH_OPENSSL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put_ec(ସଂରଚନା ssh *ssh, ଅଚଳ EC_POINT *v, ଅଚଳ EC_GROUP *g)
{
	ଫେରନ୍ତୁ sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put_ec_pkey(ସଂରଚନା ssh *ssh, EVP_PKEY *pkey)
{
	ଫେରନ୍ତୁ sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_put_bignum2(ସଂରଚନା ssh *ssh, ଅଚଳ BIGNUM *v)
{
	ଫେରନ୍ତୁ sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#endif /* WITH_OPENSSL */

/* fetch data from the incoming packet */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get(ସଂରଚନା ssh *ssh, ଶୂନ୍ୟ *valp, size_t len)
{
	ଫେରନ୍ତୁ sshbuf_get(ssh->state->incoming_packet, valp, len);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get_u8(ସଂରଚନା ssh *ssh, u_char *valp)
{
	ଫେରନ୍ତୁ sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get_u32(ସଂରଚନା ssh *ssh, uint32_t *valp)
{
	ଫେରନ୍ତୁ sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get_u64(ସଂରଚନା ssh *ssh, uint64_t *valp)
{
	ଫେରନ୍ତୁ sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get_string(ସଂରଚନା ssh *ssh, u_char **valp, size_t *lenp)
{
	ଫେରନ୍ତୁ sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get_string_direct(ସଂରଚନା ssh *ssh, ଅଚଳ u_char **valp, size_t *lenp)
{
	ଫେରନ୍ତୁ sshbuf_get_string_direct(ssh->state->incoming_packet, valp, lenp);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_peek_string_direct(ସଂରଚନା ssh *ssh, ଅଚଳ u_char **valp, size_t *lenp)
{
	ଫେରନ୍ତୁ sshbuf_peek_string_direct(ssh->state->incoming_packet, valp, lenp);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get_cstring(ସଂରଚନା ssh *ssh, ଅକ୍ଷର **valp, size_t *lenp)
{
	ଫେରନ୍ତୁ sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_getb_froms(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf **valp)
{
	ଫେରନ୍ତୁ sshbuf_froms(ssh->state->incoming_packet, valp);
}

#ifdef WITH_OPENSSL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get_ec(ସଂରଚନା ssh *ssh, EC_POINT *v, ଅଚଳ EC_GROUP *g)
{
	ଫେରନ୍ତୁ sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get_bignum2(ସଂରଚନା ssh *ssh, BIGNUM **valp)
{
	ଫେରନ୍ତୁ sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#endif /* WITH_OPENSSL */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_get_end(ସଂରଚନା ssh *ssh)
{
	ଯଦି (sshbuf_len(ssh->state->incoming_packet) > 0)
		ଫେରନ୍ତୁ SSH_ERR_UNEXPECTED_TRAILING_DATA;
	ଫେରନ୍ତୁ 0;
}

ଅଚଳ u_char *
sshpkt_ptr(ସଂରଚନା ssh *ssh, size_t *lenp)
{
	ଯଦି (lenp != ଖାଲି)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	ଫେରନ୍ତୁ sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_start(ସଂରଚନା ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, ଆକାର(buf));
	buf[ଆକାର(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	ଫେରନ୍ତୁ sshbuf_put(ssh->state->outgoing_packet, buf, ଆକାର(buf));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_send_mux(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା session_state *state = ssh->state;
	u_char type, *cp;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ssh->kex)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	ଯଦି (len < 6)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	ଯଦି (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	ଯଦି (type >= SSH2_ସନ୍ଦେଶ_CONNECTION_MIN &&
	    type <= SSH2_ସନ୍ଦେଶ_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		ଯଦି ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			ଫେରନ୍ତୁ r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	ଫେରନ୍ତୁ 0;
}

/*
 * 9.2.  Ignored Data Message
 *
 *   byte      SSH_MSG_IGNORE
 *   string    data
 *
 * All implementations MUST understand (and ignore) this message at any
 * time (after receiving the protocol version). No implementation is
 * required to send them. This message can be used as an additional
 * protection measure against advanced traffic analysis techniques.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_ସନ୍ଦେଶ_ignore(ସଂରଚନା ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		ଫେରନ୍ତୁ r;
	ପାଇଁ (i = 0; i < nbytes; i++) {
		ଯଦି (i % 4 == 0)
			rnd = arc4random();
		ଯଦି ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			ଫେରନ୍ତୁ r;
		rnd >>= 8;
	}
	ଫେରନ୍ତୁ 0;
}

/* send it */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_send(ସଂରଚନା ssh *ssh)
{
	ଯଦି (ssh->state && ssh->state->mux)
		ଫେରନ୍ତୁ ssh_packet_send_mux(ssh);
	ଫେରନ୍ତୁ ssh_packet_send2(ssh);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_disconnect(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *fmt,...)
{
	ଅକ୍ଷର buf[1024];
	va_list args;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	va_start(args, fmt);
	vsnprintf(buf, ଆକାର(buf), fmt, args);
	va_end(args);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

/* roundup current message to pad bytes */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpkt_add_padding(ସଂରଚନା ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଅକ୍ଷର *
format_traffic_stats(ସଂରଚନା packet_state *ps)
{
	ଅକ୍ଷର *stats = ଖାଲି, bytes[FMT_SCALED_STRSIZE];

	ଯଦି (ps->bytes > LLONG_MAX || fmt_scaled(ps->bytes, bytes) != 0)
		strlcpy(bytes, "OVERFLOW", ଆକାର(bytes));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (unsigned long)ps->packets, (unsigned long long)ps->blocks, bytes);
	ଫେରନ୍ତୁ stats;
}

ସ୍ଥିର ଅକ୍ଷର *
dedupe_alg_names(ଅଚଳ ଅକ୍ଷର *in, ଅଚଳ ଅକ୍ଷର *out)
{
	ଅକ୍ଷର *names = ଖାଲି;

	ଯଦି (in == ଖାଲି)
		in = "<implicit>";
	ଯଦି (out == ଖାଲି)
		out = "<implicit>";

	ଯଦି (strcmp(in, out) == 0) {
		names = xstrdup(in);
	} ଅନ୍ୟଥା {
		xasprintf(&names, "%s in, %s out", in, out);
	}
	ଫେରନ୍ତୁ names;
}

ସ୍ଥିର ଅକ୍ଷର *
comp_status_message(ସଂରଚନା ssh *ssh)
{
#ifdef WITH_ZLIB
	ଅକ୍ଷର *ret = ଖାଲି;
	ସଂରଚନା session_state *state = ssh->state;
	unsigned long long iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	ଅକ୍ଷର iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	ଅକ୍ଷର icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	ଯଦି (state->compression_buffer) {
		ଯଦି (state->compression_in_started) {
			iraw = state->compression_in_stream.total_out;
			icmp = state->compression_in_stream.total_in;
			ଯଦି (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", ଆକାର(iraw_f));
			ଯଦି (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", ଆକାର(icmp_f));
		}
		ଯଦି (state->compression_out_started) {
			oraw = state->compression_out_stream.total_in;
			ocmp = state->compression_out_stream.total_out;
			ଯଦି (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", ଆକାର(oraw_f));
			ଯଦି (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", ଆକାର(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (ଦ୍ୱିଗୁଣ)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (ଦ୍ୱିଗୁଣ)ocmp / oraw);
		ଫେରନ୍ତୁ ret;
	}
#endif	/* WITH_ZLIB */
	ଫେରନ୍ତୁ xstrdup("");
}

ଅକ୍ଷର *
connection_info_message(ସଂରଚନା ssh *ssh)
{
	ଅକ୍ଷର *ret = ଖାଲି, *cipher = ଖାଲି, *mac = ଖାଲି, *comp = ଖାଲି;
	ଅକ୍ଷର *rekey_volume = ଖାଲି, *rekey_time = ଖାଲି, *comp_info = ଖାଲି;
	ଅକ୍ଷର thishost[NI_MAXHOST] = "unknown", *tcp_info = ଖାଲି;
	ସଂରଚନା kex *kex;
	ସଂରଚନା session_state *state;
	ସଂରଚନା newkeys *nk_in, *nk_out;
	ଅକ୍ଷର *stats_in = ଖାଲି, *stats_out = ଖାଲି;
	uint64_t epoch = (uint64_t)time(ଖାଲି) - monotime();

	ଯଦି (ssh == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	state = ssh->state;
	kex = ssh->kex;

	(ଶୂନ୍ୟ)gethostname(thishost, ଆକାର(thishost));

	ଯଦି (ssh_local_port(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	} ଅନ୍ୟଥା {
		tcp_info = xstrdup("");
	}

	nk_in = ssh->state->newkeys[MODE_IN];
	nk_out = ssh->state->newkeys[MODE_OUT];
	stats_in = format_traffic_stats(&ssh->state->p_read);
	stats_out = format_traffic_stats(&ssh->state->p_send);

	cipher = dedupe_alg_names(nk_in->enc.name, nk_out->enc.name);
	mac = dedupe_alg_names(nk_in->mac.name, nk_out->mac.name);
	comp = dedupe_alg_names(nk_in->comp.name, nk_out->comp.name);

	/* Volume based rekeying. */
	ଯଦି (state->rekey_limit == 0) {
		xasprintf(&rekey_volume, "limit none");
	} ଅନ୍ୟଥା {
		ଅକ୍ଷର *volumes = ଖାଲି, in[32], out[32];

		snprintf(in, ଆକାର(in), "%llu",
		   (unsigned long long)state->max_blocks_in);
		snprintf(out, ଆକାର(out), "%llu",
		   (unsigned long long)state->max_blocks_out);
		volumes = dedupe_alg_names(in, out);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		ମୁକ୍ତ(volumes);
	}

	/* Time based rekeying. */
	ଯଦି (state->rekey_interval == 0) {
		rekey_time = xstrdup("interval none");
	} ଅନ୍ୟଥା {
		ଅକ୍ଷର rekey_next[64];

		format_absolute_time(epoch + state->rekey_time +
		    state->rekey_interval, rekey_next, ଆକାର(rekey_next));
		xasprintf(&rekey_time, "interval %s, next %s",
		    fmt_timeframe(state->rekey_interval), rekey_next);
	}
	comp_info = comp_status_message(ssh);

	xasprintf(&ret, "Connection information for %s pid %lld\r\n"
	    "  versions %s -> %s\r\n"
	    "%s"
	    "  duration %s\r\n"
	    "  kexalgorithm %s\r\n  hostkeyalgorithm %s\r\n"
	    "  cipher %s\r\n  mac %s\r\n  compression %s\r\n"
	    "  rekey %s %s\r\n"
	    "  traffic %s in, %s out\r\n"
	    "%s",
	    thishost, (long long)getpid(),
	    SSH_RELEASE, ssh->remote_version,
	    tcp_info,
	    fmt_timeframe(monotime() - state->start_time),
	    kex->name, kex->hostkey_alg,
	    cipher, mac, comp,
	    rekey_volume, rekey_time,
	    stats_in, stats_out,
	    comp_info
	);
	ମୁକ୍ତ(tcp_info);
	ମୁକ୍ତ(cipher);
	ମୁକ୍ତ(mac);
	ମୁକ୍ତ(comp);
	ମୁକ୍ତ(stats_in);
	ମୁକ୍ତ(stats_out);
	ମୁକ୍ତ(rekey_volume);
	ମୁକ୍ତ(rekey_time);
	ମୁକ୍ତ(comp_info);
	ଫେରନ୍ତୁ ret;
}

