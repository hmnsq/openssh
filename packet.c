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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>

/*
 * Explicitly include OpenSSL before zlib as some versions of OpenSSL have
 * "free_func" in their headers, which zlib typedefs.
 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/ec.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
#ਅਨ੍ਤਰ੍ਭਾਵ <zlib.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "mac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PACKET_DEBUG
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DBG(x) x
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DBG(x)
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PACKET_MAX_ਮਾਪ (256 * 1024)

ਬਣਤਰ packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t ਖੰਡਾਂ;
	uint64_t ਬਾਈਟਾਂ;
};

ਬਣਤਰ packet {
	TAILQ_ENTRY(packet) ਅਗਲਾ;
	u_char type;
	ਬਣਤਰ sshbuf *payload;
};

ਬਣਤਰ session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	ਪੂਰਨ connection_ਵਿੱਚ;
	ਪੂਰਨ connection_ਬਾਹਰਲਾ;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	ਬਣਤਰ sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	ਬਣਤਰ sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	ਬਣਤਰ sshbuf *ਨਿਵੇਸ਼;

	/* Buffer for raw output data going to the socket. */
	ਬਣਤਰ sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	ਬਣਤਰ sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	ਬਣਤਰ sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	ਬਣਤਰ sshbuf *compression_ਬਫਰ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_ਧਾਰਾ compression_ਵਿੱਚ_ਧਾਰਾ;
	z_ਧਾਰਾ compression_ਬਾਹਰਲਾ_ਧਾਰਾ;
#ਜੇ_ਅੰਤ
	ਪੂਰਨ compression_ਵਿੱਚ_started;
	ਪੂਰਨ compression_ਬਾਹਰਲਾ_started;
	ਪੂਰਨ compression_ਵਿੱਚ_failures;
	ਪੂਰਨ compression_ਬਾਹਰਲਾ_failures;

	/* default maximum packet size */
	u_int max_packet_ਮਾਪ;

	/* Flag indicating whether this module has been initialized. */
	ਪੂਰਨ initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t ਸ਼ੁਰੂ_ਸਮਾਂ;

	/* Set to true if the connection is interactive. */
	ਪੂਰਨ interactive_ਬਹੁਲਕ;

	/* Set to true if we are the server side. */
	ਪੂਰਨ server_side;

	/* Set to true if we are authenticated. */
	ਪੂਰਨ after_authentication;

	ਪੂਰਨ keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	ਪੂਰਨ packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	ਬਣਤਰ newkeys *newkeys[ਬਹੁਲਕ_MAX];
	ਬਣਤਰ packet_state p_read, p_send;

	/* Volume-based rekeying */
	uint64_t hard_max_ਖੰਡਾਂ_ਵਿੱਚ, hard_max_ਖੰਡਾਂ_ਬਾਹਰਲਾ;
	uint64_t max_ਖੰਡਾਂ_ਵਿੱਚ, max_ਖੰਡਾਂ_ਬਾਹਰਲਾ, rekey_ਹੱਦਬੰਦੀ;

	/* Time-based rekeying */
	uint32_t rekey_interval;	/* how often in seconds */
	time_t rekey_ਸਮਾਂ;	/* time of last rekeying */

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	ਮਾਪ_t packet_discard_mac_already;
	ਬਣਤਰ sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	ਪੂਰਨ rekeying;

	/* Used in ssh_packet_send_mux() */
	ਪੂਰਨ mux;

	/* QoS handling */
	ਪੂਰਨ qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	ਪੂਰਨ ਸੈੱਟ_maxsize_called;

	/* One-off warning about weak ciphers */
	ਪੂਰਨ cipher_warning_ਪੂਰਾ;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	ਪੂਰਨ disconnecting;

	/* Nagle disabled on socket */
	ਪੂਰਨ nodelay_ਸੈੱਟ;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_ਵਿੱਚ;
	ਖਾਲੀ *hook_ਵਿੱਚ_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

ਬਣਤਰ ssh *
ssh_alloc_session_state(ਖਾਲੀ)
{
	ਬਣਤਰ ssh *ssh = ਨਿਰਾ;
	ਬਣਤਰ session_state *state = ਨਿਰਾ;

	ਜੇ ((ssh = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ssh))) == ਨਿਰਾ ||
	    (state = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*state))) == ਨਿਰਾ ||
	    (ssh->kex = kex_new()) == ਨਿਰਾ ||
	    (state->ਨਿਵੇਸ਼ = sshbuf_new()) == ਨਿਰਾ ||
	    (state->output = sshbuf_new()) == ਨਿਰਾ ||
	    (state->outgoing_packet = sshbuf_new()) == ਨਿਰਾ ||
	    (state->incoming_packet = sshbuf_new()) == ਨਿਰਾ)
		ਜਾਓ fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->ਨਿੱਜੀ_ਕੁੰਜੀਆਂ);
	TAILQ_INIT(&ssh->ਜਨਤਕ_ਕੁੰਜੀਆਂ);
	state->connection_ਵਿੱਚ = -1;
	state->connection_ਬਾਹਰਲਾ = -1;
	state->max_packet_ਮਾਪ = 32768;
	state->packet_timeout_ms = -1;
	state->interactive_ਬਹੁਲਕ = 1;
	state->qos_interactive = state->qos_other = -1;
	state->p_send.packets = state->p_read.packets = 0;
	state->initialized = 1;
	/*
	 * ssh_packet_send2() needs to queue packets until
	 * we've done the initial key exchange.
	 */
	state->rekeying = 1;
	ssh->state = state;
	ਵਾਪਸ ssh;
 fail:
	ਜੇ (ssh) {
		kex_free(ssh->kex);
		ਮੁਕਤ(ssh);
	}
	ਜੇ (state) {
		sshbuf_free(state->ਨਿਵੇਸ਼);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		ਮੁਕਤ(state);
	}
	ਵਾਪਸ ਨਿਰਾ;
}

ਖਾਲੀ
ssh_packet_ਸੈੱਟ_ਨਿਵੇਸ਼_hook(ਬਣਤਰ ssh *ssh, ssh_packet_hook_fn *hook, ਖਾਲੀ *ctx)
{
	ssh->state->hook_ਵਿੱਚ = hook;
	ssh->state->hook_ਵਿੱਚ_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
ਪੂਰਨ
ssh_packet_is_rekeying(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ssh->state->rekeying ||
	    (ssh->kex != ਨਿਰਾ && ssh->kex->ਪੂਰਾ == 0);
}

/*
 * Sets the descriptors used for communication.
 */
ਬਣਤਰ ssh *
ssh_packet_ਸੈੱਟ_connection(ਬਣਤਰ ssh *ssh, ਪੂਰਨ fd_ਵਿੱਚ, ਪੂਰਨ fd_ਬਾਹਰਲਾ)
{
	ਬਣਤਰ session_state *state;
	ਅਚਲ ਬਣਤਰ sshcipher *none = cipher_by_name("none");
	ਪੂਰਨ r, wasnull = ssh == ਨਿਰਾ;

	ਜੇ (none == ਨਿਰਾ) {
		error_f("cannot load cipher 'none'");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (ssh == ਨਿਰਾ)
		ssh = ssh_alloc_session_state();
	ਜੇ (ssh == ਨਿਰਾ) {
		error_f("could not allocate state");
		ਵਾਪਸ ਨਿਰਾ;
	}
	state = ssh->state;
	state->ਸ਼ੁਰੂ_ਸਮਾਂ = monotime();
	state->connection_ਵਿੱਚ = fd_ਵਿੱਚ;
	state->connection_ਬਾਹਰਲਾ = fd_ਬਾਹਰਲਾ;
	ਜੇ ((r = cipher_init(&state->send_context, none,
	    (ਅਚਲ u_char *)"", 0, ਨਿਰਾ, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (ਅਚਲ u_char *)"", 0, ਨਿਰਾ, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		ਜੇ (wasnull)
			ਮੁਕਤ(ssh); /* XXX need ssh_free_session_state? */
		ਵਾਪਸ ਨਿਰਾ;
	}
	state->newkeys[ਬਹੁਲਕ_ਵਿੱਚ] = state->newkeys[ਬਹੁਲਕ_ਬਾਹਰਲਾ] = ਨਿਰਾ;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(ਖਾਲੀ)ssh_remote_ipaddr(ssh);
	ਵਾਪਸ ssh;
}

ਖਾਲੀ
ssh_packet_ਸੈੱਟ_timeout(ਬਣਤਰ ssh *ssh, ਪੂਰਨ timeout, ਪੂਰਨ ਗਿਣਤੀ_2)
{
	ਬਣਤਰ session_state *state = ssh->state;

	ਜੇ (timeout <= 0 || ਗਿਣਤੀ_2 <= 0) {
		state->packet_timeout_ms = -1;
		ਵਾਪਸ;
	}
	ਜੇ ((ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ / 1000) / ਗਿਣਤੀ_2 < timeout)
		state->packet_timeout_ms = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
	ਨਹੀਂਤਾਂ
		state->packet_timeout_ms = timeout * ਗਿਣਤੀ_2 * 1000;
}

ਖਾਲੀ
ssh_packet_ਸੈੱਟ_mux(ਬਣਤਰ ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = ਨਿਰਾ;
}

ਪੂਰਨ
ssh_packet_get_mux(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ssh->state->mux;
}

ਪੂਰਨ
ssh_packet_ਸੈੱਟ_log_preamble(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;
	ਪੂਰਨ r;

	ਮੁਕਤ(ssh->log_preamble);
	ਜੇ (fmt == ਨਿਰਾ)
		ssh->log_preamble = ਨਿਰਾ;
	ਨਹੀਂਤਾਂ {
		va_start(ਦਲੀਲਾਂ, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, ਦਲੀਲਾਂ);
		va_end(ਦਲੀਲਾਂ);
		ਜੇ (r < 0 || ssh->log_preamble == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_packet_stop_discard(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਪੂਰਨ r;

	ਜੇ (state->packet_discard_mac) {
		ਅੱਖਰ buf[1024];
		ਮਾਪ_t dlen = PACKET_MAX_ਮਾਪ;

		ਜੇ (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', ਆਕਾਰ(buf));
		ਜਦੋਂ (sshbuf_len(state->incoming_packet) < dlen)
			ਜੇ ((r = sshbuf_put(state->incoming_packet, buf,
			    ਆਕਾਰ(buf))) != 0)
				ਵਾਪਸ r;
		(ਖਾਲੀ) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    ਨਿਰਾ, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
	ਵਾਪਸ SSH_ERR_MAC_INVALID;
}

ਸਥਿਰ ਪੂਰਨ
ssh_packet_ਸ਼ੁਰੂ_discard(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshenc *enc,
    ਬਣਤਰ sshmac *mac, ਮਾਪ_t mac_already, u_int discard)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਪੂਰਨ r;

	ਜੇ (enc == ਨਿਰਾ || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		ਜੇ ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			ਵਾਪਸ r;
		ਵਾਪਸ SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	ਜੇ (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	ਜੇ (sshbuf_len(state->ਨਿਵੇਸ਼) >= discard)
		ਵਾਪਸ ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->ਨਿਵੇਸ਼);
	ਵਾਪਸ 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

ਪੂਰਨ
ssh_packet_connection_is_on_socket(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ session_state *state;
	ਬਣਤਰ sockaddr_storage from, ਮੰਜ਼ਿਲ;
	socklen_t fromlen, tolen;

	ਜੇ (ssh == ਨਿਰਾ || ssh->state == ਨਿਰਾ)
		ਵਾਪਸ 0;

	state = ssh->state;
	ਜੇ (state->connection_ਵਿੱਚ == -1 || state->connection_ਬਾਹਰਲਾ == -1)
		ਵਾਪਸ 0;
	fromlen = ਆਕਾਰ(from);
	memset(&from, 0, ਆਕਾਰ(from));
	ਜੇ (getpeername(state->connection_ਵਿੱਚ, (ਬਣਤਰ sockaddr *)&from,
	    &fromlen) == -1)
		ਵਾਪਸ 0;
	ਜੇ (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ਵਾਪਸ 0;
	/* filedescriptors in and out are the same, so it's a socket */
	ਜੇ (state->connection_ਵਿੱਚ == state->connection_ਬਾਹਰਲਾ)
		ਵਾਪਸ 1;
	tolen = ਆਕਾਰ(ਮੰਜ਼ਿਲ);
	memset(&ਮੰਜ਼ਿਲ, 0, ਆਕਾਰ(ਮੰਜ਼ਿਲ));
	ਜੇ (getpeername(state->connection_ਬਾਹਰਲਾ, (ਬਣਤਰ sockaddr *)&ਮੰਜ਼ਿਲ,
	    &tolen) == -1)
		ਵਾਪਸ 0;
	ਜੇ (fromlen != tolen || memcmp(&from, &ਮੰਜ਼ਿਲ, fromlen) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਖਾਲੀ
ssh_packet_get_ਬਾਈਟਾਂ(ਬਣਤਰ ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	ਜੇ (ibytes)
		*ibytes = ssh->state->p_read.ਬਾਈਟਾਂ;
	ਜੇ (obytes)
		*obytes = ssh->state->p_send.ਬਾਈਟਾਂ;
}

ਪੂਰਨ
ssh_packet_connection_af(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ get_sock_af(ssh->state->connection_ਬਾਹਰਲਾ);
}

/* Sets the connection into non-blocking mode. */

ਖਾਲੀ
ssh_packet_ਸੈੱਟ_nonblocking(ਬਣਤਰ ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	ਸੈੱਟ_nonblock(ssh->state->connection_ਵਿੱਚ);

	ਜੇ (ssh->state->connection_ਬਾਹਰਲਾ != ssh->state->connection_ਵਿੱਚ)
		ਸੈੱਟ_nonblock(ssh->state->connection_ਬਾਹਰਲਾ);
}

/* Returns the socket used for reading. */

ਪੂਰਨ
ssh_packet_get_connection_ਵਿੱਚ(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ssh->state->connection_ਵਿੱਚ;
}

/* Returns the descriptor used for writing. */

ਪੂਰਨ
ssh_packet_get_connection_ਬਾਹਰਲਾ(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ssh->state->connection_ਬਾਹਰਲਾ;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

ਅਚਲ ਅੱਖਰ *
ssh_remote_ipaddr(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ sock;

	/* Check whether we have cached the ipaddr. */
	ਜੇ (ssh->remote_ipaddr == ਨਿਰਾ) {
		ਜੇ (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_ਵਿੱਚ;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_ਪੋਰਟ = get_peer_ਪੋਰਟ(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_ਪੋਰਟ = get_local_ਪੋਰਟ(sock);
		} ਨਹੀਂਤਾਂ {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_ਪੋਰਟ = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_ਪੋਰਟ = 65535;
		}
	}
	ਵਾਪਸ ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

ਅੱਖਰ *
ssh_remote_hostname(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ sockaddr_storage from;
	socklen_t fromlen;
	ਬਣਤਰ addrinfo hints, *ai, *aitop;
	ਅੱਖਰ name[NI_MAXHOST], ntop2[NI_MAXHOST];
	ਅਚਲ ਅੱਖਰ *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = ਆਕਾਰ(from);
	memset(&from, 0, ਆਕਾਰ(from));
	ਜੇ (getpeername(ssh_packet_get_connection_ਵਿੱਚ(ssh),
	    (ਬਣਤਰ sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		ਵਾਪਸ xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	ਜੇ (from.ss_family == AF_INET6)
		fromlen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	ਜੇ (getnameinfo((ਬਣਤਰ sockaddr *)&from, fromlen, name, ਆਕਾਰ(name),
	    ਨਿਰਾ, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		ਵਾਪਸ xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	ਜੇ (getaddrinfo(name, ਨਿਰਾ, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		ਵਾਪਸ xstrdup(ntop);
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
	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	ਜੇ (getaddrinfo(name, ਨਿਰਾ, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		ਵਾਪਸ xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	ਲਈ (ai = aitop; ai; ai = ai->ai_next) {
		ਜੇ (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    ਆਕਾਰ(ntop2), ਨਿਰਾ, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				ਰੋਕੋ;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	ਜੇ (ai == ਨਿਰਾ) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		ਵਾਪਸ xstrdup(ntop);
	}
	ਵਾਪਸ xstrdup(name);
}

/* Returns the port number of the remote host. */

ਪੂਰਨ
ssh_remote_ਪੋਰਟ(ਬਣਤਰ ssh *ssh)
{
	(ਖਾਲੀ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ਵਾਪਸ ssh->remote_ਪੋਰਟ;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

ਅਚਲ ਅੱਖਰ *
ssh_local_ipaddr(ਬਣਤਰ ssh *ssh)
{
	(ਖਾਲੀ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ਵਾਪਸ ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

ਪੂਰਨ
ssh_local_ਪੋਰਟ(ਬਣਤਰ ssh *ssh)
{
	(ਖਾਲੀ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ਵਾਪਸ ssh->local_ਪੋਰਟ;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
ਅਚਲ ਅੱਖਰ *
ssh_packet_rdomain_ਵਿੱਚ(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (ssh->rdomain_ਵਿੱਚ != ਨਿਰਾ)
		ਵਾਪਸ ssh->rdomain_ਵਿੱਚ;
	ਜੇ (!ssh_packet_connection_is_on_socket(ssh))
		ਵਾਪਸ ਨਿਰਾ;
	ssh->rdomain_ਵਿੱਚ = get_rdomain(ssh->state->connection_ਵਿੱਚ);
	ਵਾਪਸ ssh->rdomain_ਵਿੱਚ;
}

/* Closes the connection and clears and frees internal data structures. */

ਸਥਿਰ ਖਾਲੀ
ssh_packet_close_ਅੰਦਰੂਨੀ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ do_close)
{
	ਬਣਤਰ session_state *state = ssh->state;
	u_int ਬਹੁਲਕ;
	ਬਣਤਰ packet *p;

	ਜੇ (!state->initialized)
		ਵਾਪਸ;
	state->initialized = 0;
	ਜੇ (do_close) {
		ਜੇ (state->connection_ਵਿੱਚ == state->connection_ਬਾਹਰਲਾ) {
			close(state->connection_ਬਾਹਰਲਾ);
		} ਨਹੀਂਤਾਂ {
			close(state->connection_ਵਿੱਚ);
			close(state->connection_ਬਾਹਰਲਾ);
		}
	}
	sshbuf_free(state->ਨਿਵੇਸ਼);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	ਜਦੋਂ ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, ਅਗਲਾ);
		ਮੁਕਤ(p);
	}
	ਲਈ (ਬਹੁਲਕ = 0; ਬਹੁਲਕ < ਬਹੁਲਕ_MAX; ਬਹੁਲਕ++) {
		kex_free_newkeys(state->newkeys[ਬਹੁਲਕ]);	/* current keys */
		state->newkeys[ਬਹੁਲਕ] = ਨਿਰਾ;
		ssh_clear_newkeys(ssh, ਬਹੁਲਕ);		/* next keys */
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	ਜੇ (do_close && state->compression_ਬਫਰ) {
		sshbuf_free(state->compression_ਬਫਰ);
		ਜੇ (state->compression_ਬਾਹਰਲਾ_started) {
			z_streamp ਧਾਰਾ = &state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਧਾਰਾ->ਕੁੱਲ_ਵਿੱਚ,
				(ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਧਾਰਾ->ਕੁੱਲ_ਬਾਹਰਲਾ,
				ਧਾਰਾ->ਕੁੱਲ_ਵਿੱਚ == 0 ? 0.0 :
				(ਦੁੱਗਣਾ) ਧਾਰਾ->ਕੁੱਲ_ਬਾਹਰਲਾ / ਧਾਰਾ->ਕੁੱਲ_ਵਿੱਚ);
			ਜੇ (state->compression_ਬਾਹਰਲਾ_failures == 0)
				deflate_ਸਿਰਾ(ਧਾਰਾ);
		}
		ਜੇ (state->compression_ਵਿੱਚ_started) {
			z_streamp ਧਾਰਾ = &state->compression_ਵਿੱਚ_ਧਾਰਾ;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਧਾਰਾ->ਕੁੱਲ_ਬਾਹਰਲਾ,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਧਾਰਾ->ਕੁੱਲ_ਵਿੱਚ,
			    ਧਾਰਾ->ਕੁੱਲ_ਬਾਹਰਲਾ == 0 ? 0.0 :
			    (ਦੁੱਗਣਾ) ਧਾਰਾ->ਕੁੱਲ_ਵਿੱਚ / ਧਾਰਾ->ਕੁੱਲ_ਬਾਹਰਲਾ);
			ਜੇ (state->compression_ਵਿੱਚ_failures == 0)
				inflate_ਸਿਰਾ(ਧਾਰਾ);
		}
	}
#ਜੇ_ਅੰਤ	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = ਨਿਰਾ;
	ਜੇ (do_close) {
		ਮੁਕਤ(ssh->local_ipaddr);
		ssh->local_ipaddr = ਨਿਰਾ;
		ਮੁਕਤ(ssh->remote_ipaddr);
		ssh->remote_ipaddr = ਨਿਰਾ;
		ਮੁਕਤ(ssh->state);
		ssh->state = ਨਿਰਾ;
		kex_free(ssh->kex);
		ssh->kex = ਨਿਰਾ;
	}
}

ਖਾਲੀ
ssh_packet_free(ਬਣਤਰ ssh *ssh)
{
	ssh_packet_close_ਅੰਦਰੂਨੀ(ssh, 1);
	freezero(ssh, ਆਕਾਰ(*ssh));
}

ਖਾਲੀ
ssh_packet_close(ਬਣਤਰ ssh *ssh)
{
	ssh_packet_close_ਅੰਦਰੂਨੀ(ssh, 1);
}

ਖਾਲੀ
ssh_packet_clear_ਕੁੰਜੀਆਂ(ਬਣਤਰ ssh *ssh)
{
	ssh_packet_close_ਅੰਦਰੂਨੀ(ssh, 0);
}

/* Sets remote side protocol flags. */

ਖਾਲੀ
ssh_packet_ਸੈੱਟ_protocol_flags(ਬਣਤਰ ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

ਸਥਿਰ ਪੂਰਨ
ssh_packet_init_compression(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (!ssh->state->compression_ਬਫਰ &&
	    ((ssh->state->compression_ਬਫਰ = sshbuf_new()) == ਨਿਰਾ))
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਵਾਪਸ 0;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
ਸਥਿਰ ਪੂਰਨ
ਸ਼ੁਰੂ_compression_ਬਾਹਰਲਾ(ਬਣਤਰ ssh *ssh)
{
	debug("Enabling compression.");
	ਜੇ (ssh->state->compression_ਬਾਹਰਲਾ_started == 1)
		deflate_ਸਿਰਾ(&ssh->state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ);
	ਚੋਣ (deflateInit2(&ssh->state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ,
	    Z_ਉੱਤਮ_ਰਫਤਾਰ, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	ਹਾਲਤ Z_OK:
		ssh->state->compression_ਬਾਹਰਲਾ_started = 1;
		ਰੋਕੋ;
	ਹਾਲਤ Z_MEM_ERROR:
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਸ਼ੁਰੂ_compression_ਵਿੱਚ(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (ssh->state->compression_ਵਿੱਚ_started == 1)
		inflate_ਸਿਰਾ(&ssh->state->compression_ਵਿੱਚ_ਧਾਰਾ);
	ਚੋਣ (inflateInit(&ssh->state->compression_ਵਿੱਚ_ਧਾਰਾ)) {
	ਹਾਲਤ Z_OK:
		ssh->state->compression_ਵਿੱਚ_started = 1;
		ਰੋਕੋ;
	ਹਾਲਤ Z_MEM_ERROR:
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਵਾਪਸ 0;
}

/* XXX remove need for separate compression buffer */
ਸਥਿਰ ਪੂਰਨ
compress_ਬਫਰ(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *ਵਿੱਚ, ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ)
{
	u_char buf[4096];
	ਪੂਰਨ r, ਸਥਿਤੀ;

	ਜੇ (ssh->state->compression_ਬਾਹਰਲਾ_started != 1)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	/* This case is not handled below. */
	ਜੇ (sshbuf_len(ਵਿੱਚ) == 0)
		ਵਾਪਸ 0;

	/* Input is the contents of the input buffer. */
	ਜੇ ((ssh->state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ.ਅਗਲਾ_ਵਿੱਚ =
	    sshbuf_mutable_ptr(ਵਿੱਚ)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ssh->state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ.avail_ਵਿੱਚ = sshbuf_len(ਵਿੱਚ);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	ਕਰੋ {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ.ਅਗਲਾ_ਬਾਹਰਲਾ = buf;
		ssh->state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ.avail_ਬਾਹਰਲਾ = ਆਕਾਰ(buf);

		/* Compress as much data into the buffer as possible. */
		ਸਥਿਤੀ = deflate(&ssh->state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ,
		    Z_PARTIAL_FLUSH);
		ਚੋਣ (ਸਥਿਤੀ) {
		ਹਾਲਤ Z_MEM_ERROR:
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		ਹਾਲਤ Z_OK:
			/* Append compressed data to output_buffer. */
			ਜੇ ((r = sshbuf_put(ਬਾਹਰਲਾ, buf, ਆਕਾਰ(buf) -
			    ssh->state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ.avail_ਬਾਹਰਲਾ)) != 0)
				ਵਾਪਸ r;
			ਰੋਕੋ;
		ਹਾਲਤ Z_ਧਾਰਾ_ERROR:
		ਮੂਲ:
			ssh->state->compression_ਬਾਹਰਲਾ_failures++;
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		}
	} ਜਦੋਂ (ssh->state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ.avail_ਬਾਹਰਲਾ == 0);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
uncompress_ਬਫਰ(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *ਵਿੱਚ, ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ)
{
	u_char buf[4096];
	ਪੂਰਨ r, ਸਥਿਤੀ;

	ਜੇ (ssh->state->compression_ਵਿੱਚ_started != 1)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ ((ssh->state->compression_ਵਿੱਚ_ਧਾਰਾ.ਅਗਲਾ_ਵਿੱਚ =
	    sshbuf_mutable_ptr(ਵਿੱਚ)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ssh->state->compression_ਵਿੱਚ_ਧਾਰਾ.avail_ਵਿੱਚ = sshbuf_len(ਵਿੱਚ);

	ਲਈ (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_ਵਿੱਚ_ਧਾਰਾ.ਅਗਲਾ_ਬਾਹਰਲਾ = buf;
		ssh->state->compression_ਵਿੱਚ_ਧਾਰਾ.avail_ਬਾਹਰਲਾ = ਆਕਾਰ(buf);

		ਸਥਿਤੀ = inflate(&ssh->state->compression_ਵਿੱਚ_ਧਾਰਾ,
		    Z_SYNC_FLUSH);
		ਚੋਣ (ਸਥਿਤੀ) {
		ਹਾਲਤ Z_OK:
			ਜੇ ((r = sshbuf_put(ਬਾਹਰਲਾ, buf, ਆਕਾਰ(buf) -
			    ssh->state->compression_ਵਿੱਚ_ਧਾਰਾ.avail_ਬਾਹਰਲਾ)) != 0)
				ਵਾਪਸ r;
			ਜੇ (sshbuf_len(ਬਾਹਰਲਾ) >= PACKET_MAX_ਮਾਪ)
				ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
			ਰੋਕੋ;
		ਹਾਲਤ Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			ਵਾਪਸ 0;
		ਹਾਲਤ Z_ਅੰਕੜੇ_ERROR:
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		ਹਾਲਤ Z_MEM_ERROR:
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		ਹਾਲਤ Z_ਧਾਰਾ_ERROR:
		ਮੂਲ:
			ssh->state->compression_ਵਿੱਚ_failures++;
			ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		}
	}
	/* NOTREACHED */
}

#ਨਹੀਂਤਾਂ	/* WITH_ZLIB */

ਸਥਿਰ ਪੂਰਨ
ਸ਼ੁਰੂ_compression_ਬਾਹਰਲਾ(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
}

ਸਥਿਰ ਪੂਰਨ
ਸ਼ੁਰੂ_compression_ਵਿੱਚ(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
}

ਸਥਿਰ ਪੂਰਨ
compress_ਬਫਰ(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *ਵਿੱਚ, ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ)
{
	ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
}

ਸਥਿਰ ਪੂਰਨ
uncompress_ਬਫਰ(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *ਵਿੱਚ, ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ)
{
	ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
}
#ਜੇ_ਅੰਤ	/* WITH_ZLIB */

ਖਾਲੀ
ssh_clear_newkeys(ਬਣਤਰ ssh *ssh, ਪੂਰਨ ਬਹੁਲਕ)
{
	ਜੇ (ssh->kex && ssh->kex->newkeys[ਬਹੁਲਕ]) {
		kex_free_newkeys(ssh->kex->newkeys[ਬਹੁਲਕ]);
		ssh->kex->newkeys[ਬਹੁਲਕ] = ਨਿਰਾ;
	}
}

ਪੂਰਨ
ssh_ਸੈੱਟ_newkeys(ਬਣਤਰ ssh *ssh, ਪੂਰਨ ਬਹੁਲਕ)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਬਣਤਰ sshenc *enc;
	ਬਣਤਰ sshmac *mac;
	ਬਣਤਰ sshcomp *comp;
	ਬਣਤਰ sshcipher_ctx **ccp;
	ਬਣਤਰ packet_state *ps;
	uint64_t *max_ਖੰਡਾਂ, *hard_max_ਖੰਡਾਂ;
	ਅਚਲ ਅੱਖਰ *wmsg;
	ਪੂਰਨ r, crypt_type;
	ਅਚਲ ਅੱਖਰ *dir = ਬਹੁਲਕ == ਬਹੁਲਕ_ਬਾਹਰਲਾ ? "out" : "in";

	debug2_f("mode %d", ਬਹੁਲਕ);

	ਜੇ (ਬਹੁਲਕ == ਬਹੁਲਕ_ਬਾਹਰਲਾ) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_ਖੰਡਾਂ = &state->hard_max_ਖੰਡਾਂ_ਬਾਹਰਲਾ;
		max_ਖੰਡਾਂ = &state->max_ਖੰਡਾਂ_ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_ਖੰਡਾਂ = &state->hard_max_ਖੰਡਾਂ_ਵਿੱਚ;
		max_ਖੰਡਾਂ = &state->max_ਖੰਡਾਂ_ਵਿੱਚ;
	}
	ਜੇ (state->newkeys[ਬਹੁਲਕ] != ਨਿਰਾ) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)state->p_read.ਬਾਈਟਾਂ,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)state->p_read.ਖੰਡਾਂ,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)state->p_send.ਬਾਈਟਾਂ,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)state->p_send.ਖੰਡਾਂ);
		kex_free_newkeys(state->newkeys[ਬਹੁਲਕ]);
		state->newkeys[ਬਹੁਲਕ] = ਨਿਰਾ;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->ਖੰਡਾਂ = 0;
	/* move newkeys from kex to state */
	ਜੇ ((state->newkeys[ਬਹੁਲਕ] = ssh->kex->newkeys[ਬਹੁਲਕ]) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ssh->kex->newkeys[ਬਹੁਲਕ] = ਨਿਰਾ;
	enc  = &state->newkeys[ਬਹੁਲਕ]->enc;
	mac  = &state->newkeys[ਬਹੁਲਕ]->mac;
	comp = &state->newkeys[ਬਹੁਲਕ]->comp;
	ਜੇ (cipher_authlen(enc->cipher) == 0) {
		ਜੇ ((r = mac_init(mac)) != 0)
			ਵਾਪਸ r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = ਨਿਰਾ;
	ਜੇ ((r = cipher_init(ccp, enc->cipher, enc->ਕੁੰਜੀ, enc->ਕੁੰਜੀ_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		ਵਾਪਸ r;
	ਜੇ (!state->cipher_warning_ਪੂਰਾ &&
	    (wmsg = cipher_warning_ਸੁਨੇਹਾ(*ccp)) != ਨਿਰਾ) {
		error("Warning: %s", wmsg);
		state->cipher_warning_ਪੂਰਾ = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	ਜੇ (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		ਜੇ ((r = ssh_packet_init_compression(ssh)) < 0)
			ਵਾਪਸ r;
		ਜੇ (ਬਹੁਲਕ == ਬਹੁਲਕ_ਬਾਹਰਲਾ) {
			ਜੇ ((r = ਸ਼ੁਰੂ_compression_ਬਾਹਰਲਾ(ssh)) != 0)
				ਵਾਪਸ r;
		} ਨਹੀਂਤਾਂ {
			ਜੇ ((r = ਸ਼ੁਰੂ_compression_ਵਿੱਚ(ssh)) != 0)
				ਵਾਪਸ r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	ਜੇ (enc->ਖੰਡ_ਮਾਪ >= 16)
		*hard_max_ਖੰਡਾਂ = (uint64_t)1 << (enc->ਖੰਡ_ਮਾਪ*2);
	ਨਹੀਂਤਾਂ
		*hard_max_ਖੰਡਾਂ = ((uint64_t)1 << 30) / enc->ਖੰਡ_ਮਾਪ;
	*max_ਖੰਡਾਂ = *hard_max_ਖੰਡਾਂ;
	ਜੇ (state->rekey_ਹੱਦਬੰਦੀ) {
		*max_ਖੰਡਾਂ = MINIMUM(*max_ਖੰਡਾਂ,
		    state->rekey_ਹੱਦਬੰਦੀ / enc->ਖੰਡ_ਮਾਪ);
	}
	debug("rekey %s after %llu blocks", dir,
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)*max_ਖੰਡਾਂ);
	ਵਾਪਸ 0;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
ਸਥਿਰ ਸਤਰਅੰਦਰ ਪੂਰਨ
ssh_packet_check_rekey_blocklimit(ਬਣਤਰ ssh *ssh, u_int packet_len, ਪੂਰਨ hard)
{
	ਬਣਤਰ session_state *state = ssh->state;
	uint32_t ਬਾਹਰਲਾ_ਖੰਡਾਂ;
	ਅਚਲ uint64_t max_ਖੰਡਾਂ_ਵਿੱਚ = hard ?
	    state->hard_max_ਖੰਡਾਂ_ਵਿੱਚ : state->max_ਖੰਡਾਂ_ਵਿੱਚ;
	ਅਚਲ uint64_t max_ਖੰਡਾਂ_ਬਾਹਰਲਾ = hard ?
	    state->hard_max_ਖੰਡਾਂ_ਬਾਹਰਲਾ : state->max_ਖੰਡਾਂ_ਬਾਹਰਲਾ;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	ਜੇ (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		ਵਾਪਸ 1;

	ਜੇ (state->newkeys[ਬਹੁਲਕ_ਬਾਹਰਲਾ] == ਨਿਰਾ)
		ਵਾਪਸ 0;

	/* Rekey after (cipher-specific) maximum blocks */
	ਬਾਹਰਲਾ_ਖੰਡਾਂ = ROUNDUP(packet_len,
	    state->newkeys[ਬਹੁਲਕ_ਬਾਹਰਲਾ]->enc.ਖੰਡ_ਮਾਪ);
	ਵਾਪਸ (max_ਖੰਡਾਂ_ਬਾਹਰਲਾ &&
	    (state->p_send.ਖੰਡਾਂ + ਬਾਹਰਲਾ_ਖੰਡਾਂ > max_ਖੰਡਾਂ_ਬਾਹਰਲਾ)) ||
	    (max_ਖੰਡਾਂ_ਵਿੱਚ &&
	    (state->p_read.ਖੰਡਾਂ > max_ਖੰਡਾਂ_ਵਿੱਚ));
}

ਸਥਿਰ ਪੂਰਨ
ssh_packet_need_rekeying(ਬਣਤਰ ssh *ssh, u_int outbound_packet_len)
{
	ਬਣਤਰ session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	ਜੇ (!state->after_authentication)
		ਵਾਪਸ 0;

	/* Haven't keyed yet or KEX in progress. */
	ਜੇ (ssh_packet_is_rekeying(ssh))
		ਵਾਪਸ 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	ਜੇ (state->p_send.packets == 0 && state->p_read.packets == 0)
		ਵਾਪਸ 0;

	/* Time-based rekeying */
	ਜੇ (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_ਸਮਾਂ + state->rekey_interval <= monotime())
		ਵਾਪਸ 1;

	ਵਾਪਸ ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
ਸਥਿਰ ਪੂਰਨ
ssh_packet_check_rekey_preauth(ਬਣਤਰ ssh *ssh, u_int outgoing_packet_len)
{
	ਜੇ (ssh->state->after_authentication)
		ਵਾਪਸ 0;

	ਜੇ (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		ਵਾਪਸ SSH_ERR_NEED_REKEY;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_packet_check_rekey(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	ਜੇ ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		ਵਾਪਸ r;
	ਜੇ (!ssh_packet_need_rekeying(ssh, 0))
		ਵਾਪਸ 0;
	debug3_f("rekex triggered");
	ਵਾਪਸ kex_ਸ਼ੁਰੂ_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
ਸਥਿਰ ਪੂਰਨ
ssh_packet_enable_delayed_compress(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਬਣਤਰ sshcomp *comp = ਨਿਰਾ;
	ਪੂਰਨ r, ਬਹੁਲਕ;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	ਲਈ (ਬਹੁਲਕ = 0; ਬਹੁਲਕ < ਬਹੁਲਕ_MAX; ਬਹੁਲਕ++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		ਜੇ (state->newkeys[ਬਹੁਲਕ] == ਨਿਰਾ)
			ਜਾਰੀ;
		comp = &state->newkeys[ਬਹੁਲਕ]->comp;
		ਜੇ (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			ਜੇ ((r = ssh_packet_init_compression(ssh)) != 0)
				ਵਾਪਸ r;
			ਜੇ (ਬਹੁਲਕ == ਬਹੁਲਕ_ਬਾਹਰਲਾ) {
				ਜੇ ((r = ਸ਼ੁਰੂ_compression_ਬਾਹਰਲਾ(ssh)) != 0)
					ਵਾਪਸ r;
			} ਨਹੀਂਤਾਂ {
				ਜੇ ((r = ਸ਼ੁਰੂ_compression_ਵਿੱਚ(ssh)) != 0)
					ਵਾਪਸ r;
			}
			comp->enabled = 1;
		}
	}
	ਵਾਪਸ 0;
}

/* Used to mute debug logging for noisy packet types */
ਪੂਰਨ
ssh_packet_log_type(u_char type)
{
	ਚੋਣ (type) {
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_PING:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_PONG:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_EXTENDED_ਅੰਕੜੇ:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_ਖਿੜਕੀ_ADJUST:
		ਵਾਪਸ 0;
	ਮੂਲ:
		ਵਾਪਸ 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
ਪੂਰਨ
ssh_packet_send2_wrapped(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	ਬਣਤਰ sshenc *enc   = ਨਿਰਾ;
	ਬਣਤਰ sshmac *mac   = ਨਿਰਾ;
	ਬਣਤਰ sshcomp *comp = ਨਿਰਾ;
	ਪੂਰਨ r, ਖੰਡ_ਮਾਪ;

	ਜੇ (state->newkeys[ਬਹੁਲਕ_ਬਾਹਰਲਾ] != ਨਿਰਾ) {
		enc  = &state->newkeys[ਬਹੁਲਕ_ਬਾਹਰਲਾ]->enc;
		mac  = &state->newkeys[ਬਹੁਲਕ_ਬਾਹਰਲਾ]->mac;
		comp = &state->newkeys[ਬਹੁਲਕ_ਬਾਹਰਲਾ]->comp;
		/* disable mac for authenticated encryption */
		ਜੇ ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ਨਿਰਾ;
	}
	ਖੰਡ_ਮਾਪ = enc ? enc->ਖੰਡ_ਮਾਪ : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	ਜੇ (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#ਜੇ_ਅੰਤ

	ਜੇ (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		ਜੇ ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		sshbuf_reset(state->compression_ਬਫਰ);
		ਜੇ ((r = compress_ਬਫਰ(ssh, state->outgoing_packet,
		    state->compression_ਬਫਰ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		sshbuf_reset(state->outgoing_packet);
		ਜੇ ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_ਬਫਰ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
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
	padlen = ਖੰਡ_ਮਾਪ - (len % ਖੰਡ_ਮਾਪ);
	ਜੇ (padlen < 4)
		padlen += ਖੰਡ_ਮਾਪ;
	ਜੇ (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, ਖੰਡ_ਮਾਪ);
		/* check if roundup overflowed */
		ਜੇ (state->extra_pad < tmp)
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		ਜੇ (tmp > state->extra_pad)
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		ਜੇ (padlen < tmp)
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ; /*ਉਛਾਲ*/
		state->extra_pad = 0;
	}
	ਜੇ ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} ਨਹੀਂਤਾਂ {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	ਜੇ (cp == ਨਿਰਾ) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	ਜੇ (mac && mac->enabled && !mac->etm) {
		ਜੇ ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, ਆਕਾਰ(macbuf))) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	ਜੇ ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* append unencrypted MAC */
	ਜੇ (mac && mac->enabled) {
		ਜੇ (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			ਜੇ ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, ਆਕਾਰ(macbuf))) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		ਜੇ ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#ਜੇ_ਅੰਤ
	/* increment sequence number for outgoing packets */
	ਜੇ (++state->p_send.seqnr == 0) {
		ਜੇ ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	ਜੇ (++state->p_send.packets == 0)
		ਵਾਪਸ SSH_ERR_NEED_REKEY;
	state->p_send.ਖੰਡਾਂ += len / ਖੰਡ_ਮਾਪ;
	state->p_send.ਬਾਈਟਾਂ += len;
	sshbuf_reset(state->outgoing_packet);

	ਜੇ (type == SSH2_ਸੁਨੇਹਾ_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	ਜੇ (type == SSH2_ਸੁਨੇਹਾ_NEWKEYS)
		r = ssh_ਸੈੱਟ_newkeys(ssh, ਬਹੁਲਕ_ਬਾਹਰਲਾ);
	ਨਹੀਂਤਾਂ ਜੇ (type == SSH2_ਸੁਨੇਹਾ_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	ਨਹੀਂਤਾਂ
		r = 0;
 ਬਾਹਰਲਾ:
	ਵਾਪਸ r;
}

/* returns non-zero if the specified packet type is usec by KEX */
ਸਥਿਰ ਪੂਰਨ
ssh_packet_type_is_kex(u_char type)
{
	ਵਾਪਸ
	    type >= SSH2_ਸੁਨੇਹਾ_TRANSPORT_MIN &&
	    type <= SSH2_ਸੁਨੇਹਾ_TRANSPORT_MAX &&
	    type != SSH2_ਸੁਨੇਹਾ_SERVICE_REQUEST &&
	    type != SSH2_ਸੁਨੇਹਾ_SERVICE_ACCEPT &&
	    type != SSH2_ਸੁਨੇਹਾ_EXT_INFO;
}

ਪੂਰਨ
ssh_packet_send2(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਬਣਤਰ packet *p;
	u_char type;
	ਪੂਰਨ r, need_rekey;

	ਜੇ (sshbuf_len(state->outgoing_packet) < 6)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	ਜੇ (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		ਵਾਪਸ r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	ਜੇ ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		ਜੇ (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*p));
		ਜੇ (p == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, ਅਗਲਾ);
		state->outgoing_packet = sshbuf_new();
		ਜੇ (state->outgoing_packet == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		ਜੇ (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			ਵਾਪਸ kex_ਸ਼ੁਰੂ_rekex(ssh);
		}
		ਵਾਪਸ 0;
	}

	/* rekeying starts with sending KEXINIT */
	ਜੇ (type == SSH2_ਸੁਨੇਹਾ_KEXINIT)
		state->rekeying = 1;

	ਜੇ ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		ਵਾਪਸ r;

	/* after a NEWKEYS message we can send the complete queue */
	ਜੇ (type == SSH2_ਸੁਨੇਹਾ_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_ਸਮਾਂ = monotime();
		ਜਦੋਂ ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			ਜੇ (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				ਵਾਪਸ kex_ਸ਼ੁਰੂ_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, ਅਗਲਾ);
			memset(p, 0, ਆਕਾਰ(*p));
			ਮੁਕਤ(p);
			ਜੇ ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				ਵਾਪਸ r;
		}
	}
	ਵਾਪਸ 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

ਪੂਰਨ
ssh_packet_read_seqnr(ਬਣਤਰ ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਪੂਰਨ len, r, ms_remain = 0;
	ਬਣਤਰ pollfd pfd;
	ਅੱਖਰ buf[8192];
	ਬਣਤਰ timeval ਸ਼ੁਰੂ;
	ਬਣਤਰ timespec timespec, *timespecp = ਨਿਰਾ;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	ਜੇ ((r = ssh_packet_write_wait(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Stay in the loop until we have received a complete packet. */
	ਲਈ (;;) {
		/* Try to read a packet from the buffer. */
		ਜੇ ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			ਰੋਕੋ;
		/* If we got a packet, return it. */
		ਜੇ (*typep != SSH_ਸੁਨੇਹਾ_NONE)
			ਰੋਕੋ;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_ਵਿੱਚ;
		pfd.events = POLLIN;

		ਜੇ (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		ਲਈ (;;) {
			ਜੇ (state->packet_timeout_ms > 0) {
				ms_ਮੰਜ਼ਿਲ_timespec(&timespec, ms_remain);
				monotime_tv(&ਸ਼ੁਰੂ);
			}
			ਜੇ ((r = ppoll(&pfd, 1, timespecp, ਨਿਰਾ)) >= 0)
				ਰੋਕੋ;
			ਜੇ (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (state->packet_timeout_ms <= 0)
				ਜਾਰੀ;
			ms_ਘਟਾਓ_diff(&ਸ਼ੁਰੂ, &ms_remain);
			ਜੇ (ms_remain <= 0) {
				r = 0;
				ਰੋਕੋ;
			}
		}
		ਜੇ (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Read data from the socket. */
		len = ਪਠ(state->connection_ਵਿੱਚ, buf, ਆਕਾਰ(buf));
		ਜੇ (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		/* Append it to the buffer. */
		ਜੇ ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
 ਬਾਹਰਲਾ:
	ਵਾਪਸ r;
}

ਪੂਰਨ
ssh_packet_read(ਬਣਤਰ ssh *ssh)
{
	u_char type;
	ਪੂਰਨ r;

	ਜੇ ((r = ssh_packet_read_seqnr(ssh, &type, ਨਿਰਾ)) != 0)
		sshpkt_fatal(ssh, r, "read");
	ਵਾਪਸ type;
}

ਸਥਿਰ ਪੂਰਨ
ssh_packet_read_poll2_mux(ਬਣਤਰ ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਅਚਲ u_char *cp;
	ਮਾਪ_t need;
	ਪੂਰਨ r;

	ਜੇ (ssh->kex)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	*typep = SSH_ਸੁਨੇਹਾ_NONE;
	cp = sshbuf_ptr(state->ਨਿਵੇਸ਼);
	ਜੇ (state->packlen == 0) {
		ਜੇ (sshbuf_len(state->ਨਿਵੇਸ਼) < 4 + 1)
			ਵਾਪਸ 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		ਜੇ (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_ਮਾਪ)
			ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	}
	need = state->packlen + 4;
	ਜੇ (sshbuf_len(state->ਨਿਵੇਸ਼) < need)
		ਵਾਪਸ 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	ਜੇ ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->ਨਿਵੇਸ਼, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		ਵਾਪਸ r;
	ਜੇ (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	ਵਾਪਸ r;
}

ਪੂਰਨ
ssh_packet_read_poll2(ਬਣਤਰ ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ਬਣਤਰ session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, ਖੰਡ_ਮਾਪ;
	ਬਣਤਰ sshenc *enc   = ਨਿਰਾ;
	ਬਣਤਰ sshmac *mac   = ਨਿਰਾ;
	ਬਣਤਰ sshcomp *comp = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (state->mux)
		ਵਾਪਸ ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_ਸੁਨੇਹਾ_NONE;

	ਜੇ (state->packet_discard)
		ਵਾਪਸ 0;

	ਜੇ (state->newkeys[ਬਹੁਲਕ_ਵਿੱਚ] != ਨਿਰਾ) {
		enc  = &state->newkeys[ਬਹੁਲਕ_ਵਿੱਚ]->enc;
		mac  = &state->newkeys[ਬਹੁਲਕ_ਵਿੱਚ]->mac;
		comp = &state->newkeys[ਬਹੁਲਕ_ਵਿੱਚ]->comp;
		/* disable mac for authenticated encryption */
		ਜੇ ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ਨਿਰਾ;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	ਖੰਡ_ਮਾਪ = enc ? enc->ਖੰਡ_ਮਾਪ : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	ਜੇ (aadlen && state->packlen == 0) {
		ਜੇ (cipher_get_ਲੰਮਾਈ(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->ਨਿਵੇਸ਼), sshbuf_len(state->ਨਿਵੇਸ਼)) != 0)
			ਵਾਪਸ 0;
		ਜੇ (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_ਮਾਪ) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PACKET_DEBUG
			sshbuf_dump(state->ਨਿਵੇਸ਼, stderr);
#ਜੇ_ਅੰਤ
			logit("Bad packet length %u.", state->packlen);
			ਜੇ ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				ਵਾਪਸ r;
			ਵਾਪਸ SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} ਨਹੀਂਤਾਂ ਜੇ (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		ਜੇ (sshbuf_len(state->ਨਿਵੇਸ਼) < ਖੰਡ_ਮਾਪ)
			ਵਾਪਸ 0;
		sshbuf_reset(state->incoming_packet);
		ਜੇ ((r = sshbuf_reserve(state->incoming_packet, ਖੰਡ_ਮਾਪ,
		    &cp)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->ਨਿਵੇਸ਼),
		    ਖੰਡ_ਮਾਪ, 0, 0)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		ਜੇ (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_ਮਾਪ) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->ਨਿਵੇਸ਼, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#ਜੇ_ਅੰਤ
			logit("Bad packet length %u.", state->packlen);
			ਵਾਪਸ ssh_packet_ਸ਼ੁਰੂ_discard(ssh, enc, mac, 0,
			    PACKET_MAX_ਮਾਪ);
		}
		ਜੇ ((r = sshbuf_consume(state->ਨਿਵੇਸ਼, ਖੰਡ_ਮਾਪ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	ਜੇ (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} ਨਹੀਂਤਾਂ {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - ਖੰਡ_ਮਾਪ;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", ਖੰਡ_ਮਾਪ, need, maclen, authlen, aadlen));
	ਜੇ (need % ਖੰਡ_ਮਾਪ != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, ਖੰਡ_ਮਾਪ, need % ਖੰਡ_ਮਾਪ);
		ਵਾਪਸ ssh_packet_ਸ਼ੁਰੂ_discard(ssh, enc, mac, 0,
		    PACKET_MAX_ਮਾਪ - ਖੰਡ_ਮਾਪ);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet:
	 * 'aadlen' bytes are unencrypted, but authenticated.
	 * 'need' bytes are encrypted, followed by either
	 * 'authlen' bytes of authentication tag or
	 * 'maclen' bytes of message authentication code.
	 */
	ਜੇ (sshbuf_len(state->ਨਿਵੇਸ਼) < aadlen + need + authlen + maclen)
		ਵਾਪਸ 0; /* packet is incomplete */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->ਨਿਵੇਸ਼, stderr);
#ਜੇ_ਅੰਤ
	/* EtM: check mac over encrypted input */
	ਜੇ (mac && mac->enabled && mac->etm) {
		ਜੇ ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->ਨਿਵੇਸ਼), aadlen + need,
		    sshbuf_ptr(state->ਨਿਵੇਸ਼) + aadlen + need + authlen,
		    maclen)) != 0) {
			ਜੇ (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->ਨਿਵੇਸ਼), need, aadlen, authlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = sshbuf_consume(state->ਨਿਵੇਸ਼, aadlen + need + authlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		ਜੇ (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->ਨਿਵੇਸ਼), maclen)) != 0) {
			ਜੇ (r != SSH_ERR_MAC_INVALID)
				ਜਾਓ ਬਾਹਰਲਾ;
			logit("Corrupted MAC on input.");
			ਜੇ (need + ਖੰਡ_ਮਾਪ > PACKET_MAX_ਮਾਪ)
				ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
			ਵਾਪਸ ssh_packet_ਸ਼ੁਰੂ_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_ਮਾਪ - need - ਖੰਡ_ਮਾਪ);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		ਜੇ ((r = sshbuf_consume(state->ਨਿਵੇਸ਼, mac->mac_len)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (seqnr_p != ਨਿਰਾ)
		*seqnr_p = state->p_read.seqnr;
	ਜੇ (++state->p_read.seqnr == 0) {
		ਜੇ ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	ਜੇ (++state->p_read.packets == 0)
		ਵਾਪਸ SSH_ERR_NEED_REKEY;
	state->p_read.ਖੰਡਾਂ += (state->packlen + 4) / ਖੰਡ_ਮਾਪ;
	state->p_read.ਬਾਈਟਾਂ += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	ਜੇ (padlen < 4)	{
		ਜੇ ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ਵਾਪਸ r;
		ਵਾਪਸ SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	ਜੇ ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_ਸਿਰਾ(state->incoming_packet, padlen)) != 0))
		ਜਾਓ ਬਾਹਰਲਾ;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	ਜੇ (comp && comp->enabled) {
		sshbuf_reset(state->compression_ਬਫਰ);
		ਜੇ ((r = uncompress_ਬਫਰ(ssh, state->incoming_packet,
		    state->compression_ਬਫਰ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		sshbuf_reset(state->incoming_packet);
		ਜੇ ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_ਬਫਰ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	ਜੇ ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	ਜੇ (*typep < SSH2_ਸੁਨੇਹਾ_MIN) {
		ਜੇ ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ਵਾਪਸ r;
		ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
	}
	ਜੇ (state->hook_ਵਿੱਚ != ਨਿਰਾ &&
	    (r = state->hook_ਵਿੱਚ(ssh, state->incoming_packet, typep,
	    state->hook_ਵਿੱਚ_ctx)) != 0)
		ਵਾਪਸ r;
	ਜੇ (*typep == SSH2_ਸੁਨੇਹਾ_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	ਨਹੀਂਤਾਂ
		r = 0;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#ਜੇ_ਅੰਤ
	/* reset for next packet */
	state->packlen = 0;
	ਜੇ (*typep == SSH2_ਸੁਨੇਹਾ_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	ਜੇ ((r = ssh_packet_check_rekey(ssh)) != 0)
		ਵਾਪਸ r;
 ਬਾਹਰਲਾ:
	ਵਾਪਸ r;
}

ਪੂਰਨ
ssh_packet_read_poll_seqnr(ਬਣਤਰ ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ਬਣਤਰ session_state *state = ssh->state;
	u_int reason, seqnr;
	ਪੂਰਨ r;
	u_char *ਸੁਨੇਹਾ;
	ਅਚਲ u_char *d;
	ਮਾਪ_t len;

	ਲਈ (;;) {
		ਸੁਨੇਹਾ = ਨਿਰਾ;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		ਜੇ (r != 0)
			ਵਾਪਸ r;
		ਜੇ (*typep == 0) {
			/* no message ready */
			ਵਾਪਸ 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		ਜੇ (*typep == SSH2_ਸੁਨੇਹਾ_DISCONNECT) {
			ਜੇ ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &ਸੁਨੇਹਾ, ਨਿਰਾ)) != 0)
				ਵਾਪਸ r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_ਪੋਰਟ(ssh), reason, ਸੁਨੇਹਾ);
			ਮੁਕਤ(ਸੁਨੇਹਾ);
			ਵਾਪਸ SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		ਜੇ (ssh->kex != ਨਿਰਾ &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			ਵਾਪਸ 0;
		/* Implicitly handle transport-level messages */
		ਚੋਣ (*typep) {
		ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			ਰੋਕੋ;
		ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_DEBUG:
			ਜੇ ((r = sshpkt_get_u8(ssh, ਨਿਰਾ)) != 0 ||
			    (r = sshpkt_get_string(ssh, &ਸੁਨੇਹਾ, ਨਿਰਾ)) != 0 ||
			    (r = sshpkt_get_string(ssh, ਨਿਰਾ, ਨਿਰਾ)) != 0) {
				ਮੁਕਤ(ਸੁਨੇਹਾ);
				ਵਾਪਸ r;
			}
			debug("Remote: %.900s", ਸੁਨੇਹਾ);
			ਮੁਕਤ(ਸੁਨੇਹਾ);
			ਰੋਕੋ;
		ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_UNIMPLEMENTED:
			ਜੇ ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				ਵਾਪਸ r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			ਰੋਕੋ;
		ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_PING:
			ਜੇ ((r = sshpkt_get_string_ਸਿੱਧਾ(ssh, &d, &len)) != 0)
				ਵਾਪਸ r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			ਜੇ (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				ਰੋਕੋ;
			}
			ਜੇ (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				ਰੋਕੋ;
			}
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				ਵਾਪਸ r;
			ਰੋਕੋ;
		ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_PONG:
			ਜੇ ((r = sshpkt_get_string_ਸਿੱਧਾ(ssh,
			    ਨਿਰਾ, &len)) != 0)
				ਵਾਪਸ r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			ਰੋਕੋ;
		ਮੂਲ:
			ਜੇ (ssh->kex != ਨਿਰਾ &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
			}
			ਵਾਪਸ 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
ਪੂਰਨ
ssh_packet_process_incoming(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *buf, u_int len)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਪੂਰਨ r;

	ਜੇ (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		ਜੇ (len >= state->packet_discard) {
			ਜੇ ((r = ssh_packet_stop_discard(ssh)) != 0)
				ਵਾਪਸ r;
		}
		state->packet_discard -= len;
		ਵਾਪਸ 0;
	}
	ਜੇ ((r = sshbuf_put(state->ਨਿਵੇਸ਼, buf, len)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

/* Reads and buffers data from the specified fd */
ਪੂਰਨ
ssh_packet_process_read(ਬਣਤਰ ssh *ssh, ਪੂਰਨ fd)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਪੂਰਨ r;
	ਮਾਪ_t rlen;

	ਜੇ ((r = sshbuf_read(fd, state->ਨਿਵੇਸ਼, PACKET_MAX_ਮਾਪ, &rlen)) != 0)
		ਵਾਪਸ r;

	ਜੇ (state->packet_discard) {
		ਜੇ ((r = sshbuf_consume_ਸਿਰਾ(state->ਨਿਵੇਸ਼, rlen)) != 0)
			ਵਾਪਸ r;
		state->keep_alive_timeouts = 0; /* ?? */
		ਜੇ (rlen >= state->packet_discard) {
			ਜੇ ((r = ssh_packet_stop_discard(ssh)) != 0)
				ਵਾਪਸ r;
		}
		state->packet_discard -= rlen;
		ਵਾਪਸ 0;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_packet_ਬਚਿਆ(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
ਖਾਲੀ
ssh_packet_send_debug(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *fmt,...)
{
	ਅੱਖਰ buf[1024];
	va_list ਦਲੀਲਾਂ;
	ਪੂਰਨ r;

	ਜੇ ((ssh->compat & SSH_BUG_DEBUG))
		ਵਾਪਸ;

	va_start(ਦਲੀਲਾਂ, fmt);
	vsnprintf(buf, ਆਕਾਰ(buf), fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);

	debug3("sending debug message: %s", buf);

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

ਖਾਲੀ
sshpkt_fmt_connection_id(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *s, ਮਾਪ_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
ਸਥਿਰ ਖਾਲੀ
sshpkt_vfatal(ਬਣਤਰ ssh *ssh, ਪੂਰਨ r, ਅਚਲ ਅੱਖਰ *fmt, va_list ap)
{
	ਅੱਖਰ *ਟੈਗ = ਨਿਰਾ, remote_id[512];
	ਪੂਰਨ oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, ਆਕਾਰ(remote_id));

	ਚੋਣ (r) {
	ਹਾਲਤ SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_ਕੁੰਜੀਆਂ(ssh);
		logdie("Connection closed by %s", remote_id);
	ਹਾਲਤ SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_ਕੁੰਜੀਆਂ(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	ਹਾਲਤ SSH_ERR_DISCONNECTED:
		ssh_packet_clear_ਕੁੰਜੀਆਂ(ssh);
		logdie("Disconnected from %s", remote_id);
	ਹਾਲਤ SSH_ERR_SYSTEM_ERROR:
		ਜੇ (errno == ECONNRESET) {
			ssh_packet_clear_ਕੁੰਜੀਆਂ(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	ਹਾਲਤ SSH_ERR_NO_CIPHER_ALG_ਮੇਲ:
	ਹਾਲਤ SSH_ERR_NO_MAC_ALG_ਮੇਲ:
	ਹਾਲਤ SSH_ERR_NO_COMPRESS_ALG_ਮੇਲ:
	ਹਾਲਤ SSH_ERR_NO_KEX_ALG_ਮੇਲ:
	ਹਾਲਤ SSH_ERR_NO_HOSTKEY_ALG_ਮੇਲ:
		ਜੇ (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_ਕੁੰਜੀਆਂ(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	ਮੂਲ:
		ਜੇ (vasprintf(&ਟੈਗ, fmt, ap) == -1) {
			ssh_packet_clear_ਕੁੰਜੀਆਂ(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_ਕੁੰਜੀਆਂ(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    ਟੈਗ != ਨਿਰਾ ? ਟੈਗ : "", ਟੈਗ != ਨਿਰਾ ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

ਖਾਲੀ
sshpkt_fatal(ਬਣਤਰ ssh *ssh, ਪੂਰਨ r, ਅਚਲ ਅੱਖਰ *fmt, ...)
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
ਖਾਲੀ
ssh_packet_disconnect(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *fmt,...)
{
	ਅੱਖਰ buf[1024], remote_id[512];
	va_list ਦਲੀਲਾਂ;
	ਪੂਰਨ r;

	/* Guard against recursive invocations. */
	ਜੇ (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, ਆਕਾਰ(remote_id));
	va_start(ਦਲੀਲਾਂ, fmt);
	vsnprintf(buf, ਆਕਾਰ(buf), fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	ਜੇ ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	ਜੇ ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
ਪੂਰਨ
ssh_packet_write_poll(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਪੂਰਨ len = sshbuf_len(state->output);
	ਪੂਰਨ r;

	ਜੇ (len > 0) {
		len = ਲਿਖ(state->connection_ਬਾਹਰਲਾ,
		    sshbuf_ptr(state->output), len);
		ਜੇ (len == -1) {
			ਜੇ (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				ਵਾਪਸ 0;
			ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
		}
		ਜੇ (len == 0)
			ਵਾਪਸ SSH_ERR_CONN_CLOSED;
		ਜੇ ((r = sshbuf_consume(state->output, len)) != 0)
			ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
ਪੂਰਨ
ssh_packet_write_wait(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ ret, r, ms_remain = 0;
	ਬਣਤਰ timeval ਸ਼ੁਰੂ;
	ਬਣਤਰ timespec timespec, *timespecp = ਨਿਰਾ;
	ਬਣਤਰ session_state *state = ssh->state;
	ਬਣਤਰ pollfd pfd;

	ਜੇ ((r = ssh_packet_write_poll(ssh)) != 0)
		ਵਾਪਸ r;
	ਜਦੋਂ (ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ssh)) {
		pfd.fd = state->connection_ਬਾਹਰਲਾ;
		pfd.events = POLLOUT;

		ਜੇ (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		ਲਈ (;;) {
			ਜੇ (state->packet_timeout_ms > 0) {
				ms_ਮੰਜ਼ਿਲ_timespec(&timespec, ms_remain);
				monotime_tv(&ਸ਼ੁਰੂ);
			}
			ਜੇ ((ret = ppoll(&pfd, 1, timespecp, ਨਿਰਾ)) >= 0)
				ਰੋਕੋ;
			ਜੇ (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				ਰੋਕੋ;
			ਜੇ (state->packet_timeout_ms <= 0)
				ਜਾਰੀ;
			ms_ਘਟਾਓ_diff(&ਸ਼ੁਰੂ, &ms_remain);
			ਜੇ (ms_remain <= 0) {
				ret = 0;
				ਰੋਕੋ;
			}
		}
		ਜੇ (ret == 0)
			ਵਾਪਸ SSH_ERR_CONN_TIMEOUT;
		ਜੇ ((r = ssh_packet_write_poll(ssh)) != 0)
			ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

/* Returns true if there is buffered data to write to the connection. */

ਪੂਰਨ
ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

ਪੂਰਨ
ssh_packet_not_very_much_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (ssh->state->interactive_ਬਹੁਲਕ)
		ਵਾਪਸ sshbuf_len(ssh->state->output) < 16384;
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

ਪੂਰਨ
ssh_packet_interactive_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ssh->state->interactive_ਬਹੁਲਕ &&
	    sshbuf_len(ssh->state->output) < 256;
}

ਸਥਿਰ ਖਾਲੀ
apply_qos(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਪੂਰਨ qos = state->interactive_ਬਹੁਲਕ ?
	    state->qos_interactive : state->qos_other;

	ਜੇ (!ssh_packet_connection_is_on_socket(ssh))
		ਵਾਪਸ;
	ਜੇ (!state->nodelay_ਸੈੱਟ) {
		ਸੈੱਟ_nodelay(state->connection_ਵਿੱਚ);
		state->nodelay_ਸੈੱਟ = 1;
	}
	ਸੈੱਟ_sock_tos(ssh->state->connection_ਵਿੱਚ, qos);
}

/* Informs that the current session is interactive. */
ਖਾਲੀ
ssh_packet_ਸੈੱਟ_interactive(ਬਣਤਰ ssh *ssh, ਪੂਰਨ interactive)
{
	ਬਣਤਰ session_state *state = ssh->state;

	state->interactive_ਬਹੁਲਕ = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
ਖਾਲੀ
ssh_packet_ਸੈੱਟ_qos(ਬਣਤਰ ssh *ssh, ਪੂਰਨ qos_interactive, ਪੂਰਨ qos_other)
{
	ਬਣਤਰ session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

ਪੂਰਨ
ssh_packet_ਸੈੱਟ_maxsize(ਬਣਤਰ ssh *ssh, u_int s)
{
	ਬਣਤਰ session_state *state = ssh->state;

	ਜੇ (state->ਸੈੱਟ_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_ਮਾਪ, s);
		ਵਾਪਸ -1;
	}
	ਜੇ (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		ਵਾਪਸ -1;
	}
	state->ਸੈੱਟ_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_ਮਾਪ = s;
	ਵਾਪਸ s;
}

ਪੂਰਨ
ssh_packet_inc_alive_timeouts(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ++ssh->state->keep_alive_timeouts;
}

ਖਾਲੀ
ssh_packet_ਸੈੱਟ_alive_timeouts(ਬਣਤਰ ssh *ssh, ਪੂਰਨ ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ssh->state->max_packet_ਮਾਪ;
}

ਖਾਲੀ
ssh_packet_ਸੈੱਟ_rekey_limits(ਬਣਤਰ ssh *ssh, uint64_t ਬਾਈਟਾਂ, uint32_t seconds)
{
	ਜੇ (ਬਾਈਟਾਂ == 0 && seconds == 0)
		ਵਾਪਸ;

	debug3("rekey after %llu bytes, %u seconds", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਬਾਈਟਾਂ,
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ)seconds);
	ssh->state->rekey_ਹੱਦਬੰਦੀ = ਬਾਈਟਾਂ;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(ਬਣਤਰ ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_ਸਮਾਂ + ssh->state->rekey_interval -
	    monotime();
	ਵਾਪਸ (seconds <= 0 ? 1 : seconds);
}

ਖਾਲੀ
ssh_packet_ਸੈੱਟ_server(ਬਣਤਰ ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

ਖਾਲੀ
ssh_packet_ਸੈੱਟ_authenticated(ਬਣਤਰ ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

ਖਾਲੀ *
ssh_packet_get_ਨਿਵੇਸ਼(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ (ਖਾਲੀ *)ssh->state->ਨਿਵੇਸ਼;
}

ਖਾਲੀ *
ssh_packet_get_output(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ (ਖਾਲੀ *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
ਸਥਿਰ ਪੂਰਨ
ssh_packet_ਸੈੱਟ_postauth(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	ਜੇ ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
ਸਥਿਰ ਪੂਰਨ
kex_ਮੰਜ਼ਿਲ_blob(ਬਣਤਰ sshbuf *m, ਬਣਤਰ kex *kex)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
	    (r = sshbuf_put_cstring(m, kex->hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_strict)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->client_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->server_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->flags)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->non_pq_kex_warned)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

/* turn key exchange results into a blob for packet state serialization */
ਸਥਿਰ ਪੂਰਨ
newkeys_ਮੰਜ਼ਿਲ_blob(ਬਣਤਰ sshbuf *m, ਬਣਤਰ ssh *ssh, ਪੂਰਨ ਬਹੁਲਕ)
{
	ਬਣਤਰ sshbuf *b;
	ਬਣਤਰ sshcipher_ctx *cc;
	ਬਣਤਰ sshcomp *comp;
	ਬਣਤਰ sshenc *enc;
	ਬਣਤਰ sshmac *mac;
	ਬਣਤਰ newkeys *newkey;
	ਪੂਰਨ r;

	ਜੇ ((newkey = ssh->state->newkeys[ਬਹੁਲਕ]) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (ਬਹੁਲਕ == ਬਹੁਲਕ_ਬਾਹਰਲਾ) ? ssh->state->send_context :
	    ssh->state->receive_context;
	ਜੇ ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->ਖੰਡ_ਮਾਪ)) != 0 ||
	    (r = sshbuf_put_string(b, enc->ਕੁੰਜੀ, enc->ਕੁੰਜੀ_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (cipher_authlen(enc->cipher) == 0) {
		ਜੇ ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->ਕੁੰਜੀ, mac->ਕੁੰਜੀ_len)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	r = sshbuf_put_stringb(m, b);
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

/* serialize packet state into a blob */
ਪੂਰਨ
ssh_packet_get_state(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *m)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਪੂਰਨ r;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	ਜੇ ((r = kex_ਮੰਜ਼ਿਲ_blob(m, ssh->kex)) != 0 ||
	    (r = newkeys_ਮੰਜ਼ਿਲ_blob(m, ssh, ਬਹੁਲਕ_ਬਾਹਰਲਾ)) != 0 ||
	    (r = newkeys_ਮੰਜ਼ਿਲ_blob(m, ssh, ਬਹੁਲਕ_ਵਿੱਚ)) != 0 ||
	    (r = sshbuf_put_u64(m, state->rekey_ਹੱਦਬੰਦੀ)) != 0 ||
	    (r = sshbuf_put_u32(m, state->rekey_interval)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.ਖੰਡਾਂ)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.ਬਾਈਟਾਂ)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.ਖੰਡਾਂ)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.ਬਾਈਟਾਂ)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->ਨਿਵੇਸ਼)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_ਬਹੁਲਕ))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		ਵਾਪਸ r;
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ENCODE_INT
	ਵਾਪਸ 0;
}

/* restore key exchange results from blob for packet state de-serialization */
ਸਥਿਰ ਪੂਰਨ
newkeys_from_blob(ਬਣਤਰ sshbuf *m, ਬਣਤਰ ssh *ssh, ਪੂਰਨ ਬਹੁਲਕ)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਬਣਤਰ sshcomp *comp;
	ਬਣਤਰ sshenc *enc;
	ਬਣਤਰ sshmac *mac;
	ਬਣਤਰ newkeys *newkey = ਨਿਰਾ;
	ਮਾਪ_t keylen, ivlen, maclen;
	ਪੂਰਨ r;

	ਜੇ ((newkey = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*newkey))) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_froms(m, &b)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	sshbuf_dump(b, stderr);
#ਜੇ_ਅੰਤ
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	ਜੇ ((r = sshbuf_get_cstring(b, &enc->name, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->ਖੰਡ_ਮਾਪ)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->ਕੁੰਜੀ, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((enc->cipher = cipher_by_name(enc->name)) == ਨਿਰਾ ||
	    enc->ਖੰਡ_ਮਾਪ != cipher_blocksize(enc->cipher) ||
	    cipher_is_ਅੰਦਰੂਨੀ(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (cipher_authlen(enc->cipher) == 0) {
		ਜੇ ((r = sshbuf_get_cstring(b, &mac->name, ਨਿਰਾ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ ((r = mac_ਤਿਆਰੀ(mac, mac->name)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->ਕੁੰਜੀ, &maclen)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (maclen != mac->ਕੁੰਜੀ_len) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		mac->ਕੁੰਜੀ_len = maclen;
	}
	ਜੇ ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	enc->ਕੁੰਜੀ_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[ਬਹੁਲਕ] = newkey;
	newkey = ਨਿਰਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(newkey);
	sshbuf_free(b);
	ਵਾਪਸ r;
}

/* restore kex from blob for packet state de-serialization */
ਸਥਿਰ ਪੂਰਨ
kex_from_blob(ਬਣਤਰ sshbuf *m, ਬਣਤਰ kex **kexp)
{
	ਬਣਤਰ kex *kex;
	ਪੂਰਨ r;

	ਜੇ ((kex = kex_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_type)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_type)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_strict)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->client_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->server_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->flags)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->non_pq_kex_warned)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	kex->server = 1;
	kex->ਪੂਰਾ = 1;
	r = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (r != 0 || kexp == ਨਿਰਾ) {
		kex_free(kex);
		ਜੇ (kexp != ਨਿਰਾ)
			*kexp = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ {
		kex_free(*kexp);
		*kexp = kex;
	}
	ਵਾਪਸ r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
ਪੂਰਨ
ssh_packet_ਸੈੱਟ_state(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *m)
{
	ਬਣਤਰ session_state *state = ssh->state;
	ਅਚਲ u_char *ਨਿਵੇਸ਼, *output;
	ਮਾਪ_t ilen, olen;
	ਪੂਰਨ r;
	u_int interactive, qos_interactive, qos_other;

	ਜੇ ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, ਬਹੁਲਕ_ਬਾਹਰਲਾ)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, ਬਹੁਲਕ_ਵਿੱਚ)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->rekey_ਹੱਦਬੰਦੀ)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->rekey_interval)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.ਖੰਡਾਂ)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.ਬਾਈਟਾਂ)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.ਖੰਡਾਂ)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.ਬਾਈਟਾਂ)) != 0)
		ਵਾਪਸ r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_ਸਮਾਂ = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	ਜੇ ((r = ssh_ਸੈੱਟ_newkeys(ssh, ਬਹੁਲਕ_ਵਿੱਚ)) != 0 ||
	    (r = ssh_ਸੈੱਟ_newkeys(ssh, ਬਹੁਲਕ_ਬਾਹਰਲਾ)) != 0)
		ਵਾਪਸ r;

	ਜੇ ((r = ssh_packet_ਸੈੱਟ_postauth(ssh)) != 0)
		ਵਾਪਸ r;

	sshbuf_reset(state->ਨਿਵੇਸ਼);
	sshbuf_reset(state->output);
	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(m, &ਨਿਵੇਸ਼, &ilen)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->ਨਿਵੇਸ਼, ਨਿਵੇਸ਼, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		ਵਾਪਸ r;

	ਜੇ ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		ਵਾਪਸ r;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DECODE_INT(v) ((v) > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ ? -1 : (ਪੂਰਨ)(v))
	state->interactive_ਬਹੁਲਕ = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ DECODE_INT

	ਜੇ (sshbuf_len(m))
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	ਵਾਪਸ 0;
}

/* NEW API */

/* put data to the outgoing packet */

ਪੂਰਨ
sshpkt_put(ਬਣਤਰ ssh *ssh, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len)
{
	ਵਾਪਸ sshbuf_put(ssh->state->outgoing_packet, v, len);
}

ਪੂਰਨ
sshpkt_putb(ਬਣਤਰ ssh *ssh, ਅਚਲ ਬਣਤਰ sshbuf *b)
{
	ਵਾਪਸ sshbuf_putb(ssh->state->outgoing_packet, b);
}

ਪੂਰਨ
sshpkt_put_u8(ਬਣਤਰ ssh *ssh, u_char val)
{
	ਵਾਪਸ sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

ਪੂਰਨ
sshpkt_put_u32(ਬਣਤਰ ssh *ssh, uint32_t val)
{
	ਵਾਪਸ sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

ਪੂਰਨ
sshpkt_put_u64(ਬਣਤਰ ssh *ssh, uint64_t val)
{
	ਵਾਪਸ sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

ਪੂਰਨ
sshpkt_put_string(ਬਣਤਰ ssh *ssh, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len)
{
	ਵਾਪਸ sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

ਪੂਰਨ
sshpkt_put_cstring(ਬਣਤਰ ssh *ssh, ਅਚਲ ਖਾਲੀ *v)
{
	ਵਾਪਸ sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

ਪੂਰਨ
sshpkt_put_stringb(ਬਣਤਰ ssh *ssh, ਅਚਲ ਬਣਤਰ sshbuf *v)
{
	ਵਾਪਸ sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਪੂਰਨ
sshpkt_put_ec(ਬਣਤਰ ssh *ssh, ਅਚਲ EC_ਬਿੰਦੂ *v, ਅਚਲ EC_ਸਮੂਹ *g)
{
	ਵਾਪਸ sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

ਪੂਰਨ
sshpkt_put_ec_pkey(ਬਣਤਰ ssh *ssh, EVP_PKEY *pkey)
{
	ਵਾਪਸ sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

ਪੂਰਨ
sshpkt_put_bignum2(ਬਣਤਰ ssh *ssh, ਅਚਲ BIGNUM *v)
{
	ਵਾਪਸ sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

/* fetch data from the incoming packet */

ਪੂਰਨ
sshpkt_get(ਬਣਤਰ ssh *ssh, ਖਾਲੀ *valp, ਮਾਪ_t len)
{
	ਵਾਪਸ sshbuf_get(ssh->state->incoming_packet, valp, len);
}

ਪੂਰਨ
sshpkt_get_u8(ਬਣਤਰ ssh *ssh, u_char *valp)
{
	ਵਾਪਸ sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

ਪੂਰਨ
sshpkt_get_u32(ਬਣਤਰ ssh *ssh, uint32_t *valp)
{
	ਵਾਪਸ sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

ਪੂਰਨ
sshpkt_get_u64(ਬਣਤਰ ssh *ssh, uint64_t *valp)
{
	ਵਾਪਸ sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

ਪੂਰਨ
sshpkt_get_string(ਬਣਤਰ ssh *ssh, u_char **valp, ਮਾਪ_t *lenp)
{
	ਵਾਪਸ sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

ਪੂਰਨ
sshpkt_get_string_ਸਿੱਧਾ(ਬਣਤਰ ssh *ssh, ਅਚਲ u_char **valp, ਮਾਪ_t *lenp)
{
	ਵਾਪਸ sshbuf_get_string_ਸਿੱਧਾ(ssh->state->incoming_packet, valp, lenp);
}

ਪੂਰਨ
sshpkt_peek_string_ਸਿੱਧਾ(ਬਣਤਰ ssh *ssh, ਅਚਲ u_char **valp, ਮਾਪ_t *lenp)
{
	ਵਾਪਸ sshbuf_peek_string_ਸਿੱਧਾ(ssh->state->incoming_packet, valp, lenp);
}

ਪੂਰਨ
sshpkt_get_cstring(ਬਣਤਰ ssh *ssh, ਅੱਖਰ **valp, ਮਾਪ_t *lenp)
{
	ਵਾਪਸ sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

ਪੂਰਨ
sshpkt_getb_froms(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf **valp)
{
	ਵਾਪਸ sshbuf_froms(ssh->state->incoming_packet, valp);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਪੂਰਨ
sshpkt_get_ec(ਬਣਤਰ ssh *ssh, EC_ਬਿੰਦੂ *v, ਅਚਲ EC_ਸਮੂਹ *g)
{
	ਵਾਪਸ sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

ਪੂਰਨ
sshpkt_get_bignum2(ਬਣਤਰ ssh *ssh, BIGNUM **valp)
{
	ਵਾਪਸ sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਪੂਰਨ
sshpkt_get_ਸਿਰਾ(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (sshbuf_len(ssh->state->incoming_packet) > 0)
		ਵਾਪਸ SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ;
	ਵਾਪਸ 0;
}

ਅਚਲ u_char *
sshpkt_ptr(ਬਣਤਰ ssh *ssh, ਮਾਪ_t *lenp)
{
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	ਵਾਪਸ sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

ਪੂਰਨ
sshpkt_ਸ਼ੁਰੂ(ਬਣਤਰ ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, ਆਕਾਰ(buf));
	buf[ਆਕਾਰ(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	ਵਾਪਸ sshbuf_put(ssh->state->outgoing_packet, buf, ਆਕਾਰ(buf));
}

ਸਥਿਰ ਪੂਰਨ
ssh_packet_send_mux(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ session_state *state = ssh->state;
	u_char type, *cp;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	ਜੇ (ssh->kex)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	ਜੇ (len < 6)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	ਜੇ (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	ਜੇ (type >= SSH2_ਸੁਨੇਹਾ_CONNECTION_MIN &&
	    type <= SSH2_ਸੁਨੇਹਾ_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		ਜੇ ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			ਵਾਪਸ r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	ਵਾਪਸ 0;
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
ਪੂਰਨ
sshpkt_ਸੁਨੇਹਾ_ignore(ਬਣਤਰ ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	ਪੂਰਨ r;
	u_int i;

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		ਵਾਪਸ r;
	ਲਈ (i = 0; i < nbytes; i++) {
		ਜੇ (i % 4 == 0)
			rnd = arc4random();
		ਜੇ ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			ਵਾਪਸ r;
		rnd >>= 8;
	}
	ਵਾਪਸ 0;
}

/* send it */

ਪੂਰਨ
sshpkt_send(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (ssh->state && ssh->state->mux)
		ਵਾਪਸ ssh_packet_send_mux(ssh);
	ਵਾਪਸ ssh_packet_send2(ssh);
}

ਪੂਰਨ
sshpkt_disconnect(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *fmt,...)
{
	ਅੱਖਰ buf[1024];
	va_list ਦਲੀਲਾਂ;
	ਪੂਰਨ r;

	va_start(ਦਲੀਲਾਂ, fmt);
	vsnprintf(buf, ਆਕਾਰ(buf), fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

/* roundup current message to pad bytes */
ਪੂਰਨ
sshpkt_ਜੋੜੋ_padding(ਬਣਤਰ ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਅੱਖਰ *
format_traffic_stats(ਬਣਤਰ packet_state *ps)
{
	ਅੱਖਰ *stats = ਨਿਰਾ, ਬਾਈਟਾਂ[FMT_SCALED_STRSIZE];

	ਜੇ (ps->ਬਾਈਟਾਂ > LLONG_MAX || fmt_scaled(ps->ਬਾਈਟਾਂ, ਬਾਈਟਾਂ) != 0)
		strlcpy(ਬਾਈਟਾਂ, "OVERFLOW", ਆਕਾਰ(ਬਾਈਟਾਂ));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)ps->packets, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ps->ਖੰਡਾਂ, ਬਾਈਟਾਂ);
	ਵਾਪਸ stats;
}

ਸਥਿਰ ਅੱਖਰ *
dedupe_alg_ਨਾਂ(ਅਚਲ ਅੱਖਰ *ਵਿੱਚ, ਅਚਲ ਅੱਖਰ *ਬਾਹਰਲਾ)
{
	ਅੱਖਰ *ਨਾਂ = ਨਿਰਾ;

	ਜੇ (ਵਿੱਚ == ਨਿਰਾ)
		ਵਿੱਚ = "<implicit>";
	ਜੇ (ਬਾਹਰਲਾ == ਨਿਰਾ)
		ਬਾਹਰਲਾ = "<implicit>";

	ਜੇ (strcmp(ਵਿੱਚ, ਬਾਹਰਲਾ) == 0) {
		ਨਾਂ = xstrdup(ਵਿੱਚ);
	} ਨਹੀਂਤਾਂ {
		xasprintf(&ਨਾਂ, "%s in, %s out", ਵਿੱਚ, ਬਾਹਰਲਾ);
	}
	ਵਾਪਸ ਨਾਂ;
}

ਸਥਿਰ ਅੱਖਰ *
comp_ਸਥਿਤੀ_ਸੁਨੇਹਾ(ਬਣਤਰ ssh *ssh)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
	ਅੱਖਰ *ret = ਨਿਰਾ;
	ਬਣਤਰ session_state *state = ssh->state;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	ਅੱਖਰ iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	ਅੱਖਰ icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	ਜੇ (state->compression_ਬਫਰ) {
		ਜੇ (state->compression_ਵਿੱਚ_started) {
			iraw = state->compression_ਵਿੱਚ_ਧਾਰਾ.ਕੁੱਲ_ਬਾਹਰਲਾ;
			icmp = state->compression_ਵਿੱਚ_ਧਾਰਾ.ਕੁੱਲ_ਵਿੱਚ;
			ਜੇ (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", ਆਕਾਰ(iraw_f));
			ਜੇ (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", ਆਕਾਰ(icmp_f));
		}
		ਜੇ (state->compression_ਬਾਹਰਲਾ_started) {
			oraw = state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ.ਕੁੱਲ_ਵਿੱਚ;
			ocmp = state->compression_ਬਾਹਰਲਾ_ਧਾਰਾ.ਕੁੱਲ_ਬਾਹਰਲਾ;
			ਜੇ (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", ਆਕਾਰ(oraw_f));
			ਜੇ (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", ਆਕਾਰ(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (ਦੁੱਗਣਾ)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (ਦੁੱਗਣਾ)ocmp / oraw);
		ਵਾਪਸ ret;
	}
#ਜੇ_ਅੰਤ	/* WITH_ZLIB */
	ਵਾਪਸ xstrdup("");
}

ਅੱਖਰ *
connection_info_ਸੁਨੇਹਾ(ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ *ret = ਨਿਰਾ, *cipher = ਨਿਰਾ, *mac = ਨਿਰਾ, *comp = ਨਿਰਾ;
	ਅੱਖਰ *rekey_volume = ਨਿਰਾ, *rekey_ਸਮਾਂ = ਨਿਰਾ, *comp_info = ਨਿਰਾ;
	ਅੱਖਰ thishost[NI_MAXHOST] = "unknown", *tcp_info = ਨਿਰਾ;
	ਬਣਤਰ kex *kex;
	ਬਣਤਰ session_state *state;
	ਬਣਤਰ newkeys *nk_ਵਿੱਚ, *nk_ਬਾਹਰਲਾ;
	ਅੱਖਰ *stats_ਵਿੱਚ = ਨਿਰਾ, *stats_ਬਾਹਰਲਾ = ਨਿਰਾ;
	uint64_t epoch = (uint64_t)time(ਨਿਰਾ) - monotime();

	ਜੇ (ssh == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	state = ssh->state;
	kex = ssh->kex;

	(ਖਾਲੀ)gethostname(thishost, ਆਕਾਰ(thishost));

	ਜੇ (ssh_local_ਪੋਰਟ(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_ਪੋਰਟ(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
	} ਨਹੀਂਤਾਂ {
		tcp_info = xstrdup("");
	}

	nk_ਵਿੱਚ = ssh->state->newkeys[ਬਹੁਲਕ_ਵਿੱਚ];
	nk_ਬਾਹਰਲਾ = ssh->state->newkeys[ਬਹੁਲਕ_ਬਾਹਰਲਾ];
	stats_ਵਿੱਚ = format_traffic_stats(&ssh->state->p_read);
	stats_ਬਾਹਰਲਾ = format_traffic_stats(&ssh->state->p_send);

	cipher = dedupe_alg_ਨਾਂ(nk_ਵਿੱਚ->enc.name, nk_ਬਾਹਰਲਾ->enc.name);
	mac = dedupe_alg_ਨਾਂ(nk_ਵਿੱਚ->mac.name, nk_ਬਾਹਰਲਾ->mac.name);
	comp = dedupe_alg_ਨਾਂ(nk_ਵਿੱਚ->comp.name, nk_ਬਾਹਰਲਾ->comp.name);

	/* Volume based rekeying. */
	ਜੇ (state->rekey_ਹੱਦਬੰਦੀ == 0) {
		xasprintf(&rekey_volume, "limit none");
	} ਨਹੀਂਤਾਂ {
		ਅੱਖਰ *volumes = ਨਿਰਾ, ਵਿੱਚ[32], ਬਾਹਰਲਾ[32];

		snprintf(ਵਿੱਚ, ਆਕਾਰ(ਵਿੱਚ), "%llu",
		   (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)state->max_ਖੰਡਾਂ_ਵਿੱਚ);
		snprintf(ਬਾਹਰਲਾ, ਆਕਾਰ(ਬਾਹਰਲਾ), "%llu",
		   (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)state->max_ਖੰਡਾਂ_ਬਾਹਰਲਾ);
		volumes = dedupe_alg_ਨਾਂ(ਵਿੱਚ, ਬਾਹਰਲਾ);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		ਮੁਕਤ(volumes);
	}

	/* Time based rekeying. */
	ਜੇ (state->rekey_interval == 0) {
		rekey_ਸਮਾਂ = xstrdup("interval none");
	} ਨਹੀਂਤਾਂ {
		ਅੱਖਰ rekey_ਅਗਲਾ[64];

		format_absolute_ਸਮਾਂ(epoch + state->rekey_ਸਮਾਂ +
		    state->rekey_interval, rekey_ਅਗਲਾ, ਆਕਾਰ(rekey_ਅਗਲਾ));
		xasprintf(&rekey_ਸਮਾਂ, "interval %s, next %s",
		    fmt_timeframe(state->rekey_interval), rekey_ਅਗਲਾ);
	}
	comp_info = comp_ਸਥਿਤੀ_ਸੁਨੇਹਾ(ssh);

	xasprintf(&ret, "Connection information for %s pid %lld\r\n"
	    "  versions %s -> %s\r\n"
	    "%s"
	    "  duration %s\r\n"
	    "  kexalgorithm %s\r\n  hostkeyalgorithm %s\r\n"
	    "  cipher %s\r\n  mac %s\r\n  compression %s\r\n"
	    "  rekey %s %s\r\n"
	    "  traffic %s in, %s out\r\n"
	    "%s",
	    thishost, (ਲੰਮਾ ਲੰਮਾ)getpid(),
	    SSH_RELEASE, ssh->remote_ਸੰਸਕਰਣ,
	    tcp_info,
	    fmt_timeframe(monotime() - state->ਸ਼ੁਰੂ_ਸਮਾਂ),
	    kex->name, kex->hostkey_alg,
	    cipher, mac, comp,
	    rekey_volume, rekey_ਸਮਾਂ,
	    stats_ਵਿੱਚ, stats_ਬਾਹਰਲਾ,
	    comp_info
	);
	ਮੁਕਤ(tcp_info);
	ਮੁਕਤ(cipher);
	ਮੁਕਤ(mac);
	ਮੁਕਤ(comp);
	ਮੁਕਤ(stats_ਵਿੱਚ);
	ਮੁਕਤ(stats_ਬਾਹਰਲਾ);
	ਮੁਕਤ(rekey_volume);
	ਮੁਕਤ(rekey_ਸਮਾਂ);
	ਮੁਕਤ(comp_info);
	ਵਾਪਸ ret;
}

