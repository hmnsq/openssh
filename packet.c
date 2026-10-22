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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <util.h>

/*
 * Explicitly include OpenSSL before zlib as some versions of OpenSSL have
 * "free_func" in their headers, which zlib typedefs.
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/ec.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
#ಅನ್ತರ್ಭಾವ <zlib.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "mac.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "version.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PACKET_DEBUG
#ವ್ಯಾಖ್ಯಾನಿಸು DBG(x) x
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು DBG(x)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು PACKET_MAX_ಗಾತ್ರ (256 * 1024)

ರಚನೆ packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t ಖಂಡಗಳು;
	uint64_t ಬೈಟುಗಳು;
};

ರಚನೆ packet {
	TAILQ_ENTRY(packet) ಮುಂದಿನ;
	u_char type;
	ರಚನೆ sshbuf *payload;
};

ರಚನೆ session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	ಪೂರ್ಣಾಂಕ connection_ಒಳ;
	ಪೂರ್ಣಾಂಕ connection_ಹೊರಹೋಗು;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	ರಚನೆ sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	ರಚನೆ sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	ರಚನೆ sshbuf *ಒಳಹರಿವು;

	/* Buffer for raw output data going to the socket. */
	ರಚನೆ sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	ರಚನೆ sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	ರಚನೆ sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	ರಚನೆ sshbuf *compression_ಬಫರ್;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_ಹರಿವು compression_ಒಳ_ಹರಿವು;
	z_ಹರಿವು compression_ಹೊರಹೋಗು_ಹರಿವು;
#ಆದರೆ_ಅಂತ್ಯ
	ಪೂರ್ಣಾಂಕ compression_ಒಳ_started;
	ಪೂರ್ಣಾಂಕ compression_ಹೊರಹೋಗು_started;
	ಪೂರ್ಣಾಂಕ compression_ಒಳ_failures;
	ಪೂರ್ಣಾಂಕ compression_ಹೊರಹೋಗು_failures;

	/* default maximum packet size */
	u_int max_packet_ಗಾತ್ರ;

	/* Flag indicating whether this module has been initialized. */
	ಪೂರ್ಣಾಂಕ initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t ಆರಂಭ_ಸಮಯ;

	/* Set to true if the connection is interactive. */
	ಪೂರ್ಣಾಂಕ interactive_ಬಹುಲಕ;

	/* Set to true if we are the server side. */
	ಪೂರ್ಣಾಂಕ server_side;

	/* Set to true if we are authenticated. */
	ಪೂರ್ಣಾಂಕ after_authentication;

	ಪೂರ್ಣಾಂಕ keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	ಪೂರ್ಣಾಂಕ packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	ರಚನೆ newkeys *newkeys[ಬಹುಲಕ_MAX];
	ರಚನೆ packet_state p_read, p_send;

	/* Volume-based rekeying */
	uint64_t hard_max_ಖಂಡಗಳು_ಒಳ, hard_max_ಖಂಡಗಳು_ಹೊರಹೋಗು;
	uint64_t max_ಖಂಡಗಳು_ಒಳ, max_ಖಂಡಗಳು_ಹೊರಹೋಗು, rekey_ಎಲ್ಲೆ;

	/* Time-based rekeying */
	uint32_t rekey_interval;	/* how often in seconds */
	time_t rekey_ಸಮಯ;	/* time of last rekeying */

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	ಗಾತ್ರ_t packet_discard_mac_already;
	ರಚನೆ sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	ಪೂರ್ಣಾಂಕ rekeying;

	/* Used in ssh_packet_send_mux() */
	ಪೂರ್ಣಾಂಕ mux;

	/* QoS handling */
	ಪೂರ್ಣಾಂಕ qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	ಪೂರ್ಣಾಂಕ ಗಣ_maxsize_called;

	/* One-off warning about weak ciphers */
	ಪೂರ್ಣಾಂಕ cipher_warning_ಮುಗಿದ;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	ಪೂರ್ಣಾಂಕ disconnecting;

	/* Nagle disabled on socket */
	ಪೂರ್ಣಾಂಕ nodelay_ಗಣ;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_ಒಳ;
	ಶೂನ್ಯ *hook_ಒಳ_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

ರಚನೆ ssh *
ssh_alloc_session_state(ಶೂನ್ಯ)
{
	ರಚನೆ ssh *ssh = ಖಾಲಿ;
	ರಚನೆ session_state *state = ಖಾಲಿ;

	ಆದರೆ ((ssh = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ssh))) == ಖಾಲಿ ||
	    (state = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*state))) == ಖಾಲಿ ||
	    (ssh->kex = kex_new()) == ಖಾಲಿ ||
	    (state->ಒಳಹರಿವು = sshbuf_new()) == ಖಾಲಿ ||
	    (state->output = sshbuf_new()) == ಖಾಲಿ ||
	    (state->outgoing_packet = sshbuf_new()) == ಖಾಲಿ ||
	    (state->incoming_packet = sshbuf_new()) == ಖಾಲಿ)
		ಹೋಗು fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->ಖಾಸಗಿ_ಕೀಲಿಗಳು);
	TAILQ_INIT(&ssh->ಬಹಿರಂಗ_ಕೀಲಿಗಳು);
	state->connection_ಒಳ = -1;
	state->connection_ಹೊರಹೋಗು = -1;
	state->max_packet_ಗಾತ್ರ = 32768;
	state->packet_timeout_ms = -1;
	state->interactive_ಬಹುಲಕ = 1;
	state->qos_interactive = state->qos_other = -1;
	state->p_send.packets = state->p_read.packets = 0;
	state->initialized = 1;
	/*
	 * ssh_packet_send2() needs to queue packets until
	 * we've done the initial key exchange.
	 */
	state->rekeying = 1;
	ssh->state = state;
	ಹಿಂತಿರುಗಿ ssh;
 fail:
	ಆದರೆ (ssh) {
		kex_free(ssh->kex);
		ಬಿಡುಗಡೆ(ssh);
	}
	ಆದರೆ (state) {
		sshbuf_free(state->ಒಳಹರಿವು);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		ಬಿಡುಗಡೆ(state);
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಶೂನ್ಯ
ssh_packet_ಗಣ_ಒಳಹರಿವು_hook(ರಚನೆ ssh *ssh, ssh_packet_hook_fn *hook, ಶೂನ್ಯ *ctx)
{
	ssh->state->hook_ಒಳ = hook;
	ssh->state->hook_ಒಳ_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
ಪೂರ್ಣಾಂಕ
ssh_packet_is_rekeying(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ssh->state->rekeying ||
	    (ssh->kex != ಖಾಲಿ && ssh->kex->ಮುಗಿದ == 0);
}

/*
 * Sets the descriptors used for communication.
 */
ರಚನೆ ssh *
ssh_packet_ಗಣ_connection(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ fd_ಒಳ, ಪೂರ್ಣಾಂಕ fd_ಹೊರಹೋಗು)
{
	ರಚನೆ session_state *state;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *none = cipher_by_name("none");
	ಪೂರ್ಣಾಂಕ r, wasnull = ssh == ಖಾಲಿ;

	ಆದರೆ (none == ಖಾಲಿ) {
		error_f("cannot load cipher 'none'");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (ssh == ಖಾಲಿ)
		ssh = ssh_alloc_session_state();
	ಆದರೆ (ssh == ಖಾಲಿ) {
		error_f("could not allocate state");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	state = ssh->state;
	state->ಆರಂಭ_ಸಮಯ = monotime();
	state->connection_ಒಳ = fd_ಒಳ;
	state->connection_ಹೊರಹೋಗು = fd_ಹೊರಹೋಗು;
	ಆದರೆ ((r = cipher_init(&state->send_context, none,
	    (ಸ್ಥಿರಾಂಕ u_char *)"", 0, ಖಾಲಿ, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (ಸ್ಥಿರಾಂಕ u_char *)"", 0, ಖಾಲಿ, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		ಆದರೆ (wasnull)
			ಬಿಡುಗಡೆ(ssh); /* XXX need ssh_free_session_state? */
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	state->newkeys[ಬಹುಲಕ_ಒಳ] = state->newkeys[ಬಹುಲಕ_ಹೊರಹೋಗು] = ಖಾಲಿ;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(ಶೂನ್ಯ)ssh_remote_ipaddr(ssh);
	ಹಿಂತಿರುಗಿ ssh;
}

ಶೂನ್ಯ
ssh_packet_ಗಣ_timeout(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ timeout, ಪೂರ್ಣಾಂಕ ಎಣಿಕೆ_2)
{
	ರಚನೆ session_state *state = ssh->state;

	ಆದರೆ (timeout <= 0 || ಎಣಿಕೆ_2 <= 0) {
		state->packet_timeout_ms = -1;
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ / 1000) / ಎಣಿಕೆ_2 < timeout)
		state->packet_timeout_ms = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
	ಇಲ್ಲದಿದ್ದರೆ
		state->packet_timeout_ms = timeout * ಎಣಿಕೆ_2 * 1000;
}

ಶೂನ್ಯ
ssh_packet_ಗಣ_mux(ರಚನೆ ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_get_mux(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ssh->state->mux;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_ಗಣ_log_preamble(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ವಾದಗಳು;
	ಪೂರ್ಣಾಂಕ r;

	ಬಿಡುಗಡೆ(ssh->log_preamble);
	ಆದರೆ (fmt == ಖಾಲಿ)
		ssh->log_preamble = ಖಾಲಿ;
	ಇಲ್ಲದಿದ್ದರೆ {
		va_start(ವಾದಗಳು, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, ವಾದಗಳು);
		va_end(ವಾದಗಳು);
		ಆದರೆ (r < 0 || ssh->log_preamble == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_stop_discard(ರಚನೆ ssh *ssh)
{
	ರಚನೆ session_state *state = ssh->state;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (state->packet_discard_mac) {
		ಅಕ್ಷರ buf[1024];
		ಗಾತ್ರ_t dlen = PACKET_MAX_ಗಾತ್ರ;

		ಆದರೆ (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', ಗಾತ್ರ(buf));
		ಆಗ (sshbuf_len(state->incoming_packet) < dlen)
			ಆದರೆ ((r = sshbuf_put(state->incoming_packet, buf,
			    ಗಾತ್ರ(buf))) != 0)
				ಹಿಂತಿರುಗಿ r;
		(ಶೂನ್ಯ) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    ಖಾಲಿ, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
	ಹಿಂತಿರುಗಿ SSH_ERR_MAC_INVALID;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_packet_ಆರಂಭ_discard(ರಚನೆ ssh *ssh, ರಚನೆ sshenc *enc,
    ರಚನೆ sshmac *mac, ಗಾತ್ರ_t mac_already, u_int discard)
{
	ರಚನೆ session_state *state = ssh->state;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (enc == ಖಾಲಿ || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		ಆದರೆ ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಹಿಂತಿರುಗಿ SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	ಆದರೆ (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	ಆದರೆ (sshbuf_len(state->ಒಳಹರಿವು) >= discard)
		ಹಿಂತಿರುಗಿ ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->ಒಳಹರಿವು);
	ಹಿಂತಿರುಗಿ 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

ಪೂರ್ಣಾಂಕ
ssh_packet_connection_is_on_socket(ರಚನೆ ssh *ssh)
{
	ರಚನೆ session_state *state;
	ರಚನೆ sockaddr_storage from, ಗಮ್ಯ;
	socklen_t fromlen, tolen;

	ಆದರೆ (ssh == ಖಾಲಿ || ssh->state == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	state = ssh->state;
	ಆದರೆ (state->connection_ಒಳ == -1 || state->connection_ಹೊರಹೋಗು == -1)
		ಹಿಂತಿರುಗಿ 0;
	fromlen = ಗಾತ್ರ(from);
	memset(&from, 0, ಗಾತ್ರ(from));
	ಆದರೆ (getpeername(state->connection_ಒಳ, (ರಚನೆ sockaddr *)&from,
	    &fromlen) == -1)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ಹಿಂತಿರುಗಿ 0;
	/* filedescriptors in and out are the same, so it's a socket */
	ಆದರೆ (state->connection_ಒಳ == state->connection_ಹೊರಹೋಗು)
		ಹಿಂತಿರುಗಿ 1;
	tolen = ಗಾತ್ರ(ಗಮ್ಯ);
	memset(&ಗಮ್ಯ, 0, ಗಾತ್ರ(ಗಮ್ಯ));
	ಆದರೆ (getpeername(state->connection_ಹೊರಹೋಗು, (ರಚನೆ sockaddr *)&ಗಮ್ಯ,
	    &tolen) == -1)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (fromlen != tolen || memcmp(&from, &ಗಮ್ಯ, fromlen) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಶೂನ್ಯ
ssh_packet_get_ಬೈಟುಗಳು(ರಚನೆ ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	ಆದರೆ (ibytes)
		*ibytes = ssh->state->p_read.ಬೈಟುಗಳು;
	ಆದರೆ (obytes)
		*obytes = ssh->state->p_send.ಬೈಟುಗಳು;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_connection_af(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ get_sock_af(ssh->state->connection_ಹೊರಹೋಗು);
}

/* Sets the connection into non-blocking mode. */

ಶೂನ್ಯ
ssh_packet_ಗಣ_nonblocking(ರಚನೆ ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	ಗಣ_nonblock(ssh->state->connection_ಒಳ);

	ಆದರೆ (ssh->state->connection_ಹೊರಹೋಗು != ssh->state->connection_ಒಳ)
		ಗಣ_nonblock(ssh->state->connection_ಹೊರಹೋಗು);
}

/* Returns the socket used for reading. */

ಪೂರ್ಣಾಂಕ
ssh_packet_get_connection_ಒಳ(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ssh->state->connection_ಒಳ;
}

/* Returns the descriptor used for writing. */

ಪೂರ್ಣಾಂಕ
ssh_packet_get_connection_ಹೊರಹೋಗು(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ssh->state->connection_ಹೊರಹೋಗು;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ssh_remote_ipaddr(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ sock;

	/* Check whether we have cached the ipaddr. */
	ಆದರೆ (ssh->remote_ipaddr == ಖಾಲಿ) {
		ಆದರೆ (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_ಒಳ;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_ಪೋರ್ಟ್ = get_peer_ಪೋರ್ಟ್(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_ಪೋರ್ಟ್ = get_local_ಪೋರ್ಟ್(sock);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_ಪೋರ್ಟ್ = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_ಪೋರ್ಟ್ = 65535;
		}
	}
	ಹಿಂತಿರುಗಿ ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

ಅಕ್ಷರ *
ssh_remote_hostname(ರಚನೆ ssh *ssh)
{
	ರಚನೆ sockaddr_storage from;
	socklen_t fromlen;
	ರಚನೆ addrinfo hints, *ai, *aitop;
	ಅಕ್ಷರ name[NI_MAXHOST], ntop2[NI_MAXHOST];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = ಗಾತ್ರ(from);
	memset(&from, 0, ಗಾತ್ರ(from));
	ಆದರೆ (getpeername(ssh_packet_get_connection_ಒಳ(ssh),
	    (ರಚನೆ sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		ಹಿಂತಿರುಗಿ xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	ಆದರೆ (from.ss_family == AF_INET6)
		fromlen = ಗಾತ್ರ(ರಚನೆ sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	ಆದರೆ (getnameinfo((ರಚನೆ sockaddr *)&from, fromlen, name, ಗಾತ್ರ(name),
	    ಖಾಲಿ, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		ಹಿಂತಿರುಗಿ xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	ಆದರೆ (getaddrinfo(name, ಖಾಲಿ, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		ಹಿಂತಿರುಗಿ xstrdup(ntop);
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
	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	ಆದರೆ (getaddrinfo(name, ಖಾಲಿ, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		ಹಿಂತಿರುಗಿ xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	ಗಾಗಿ (ai = aitop; ai; ai = ai->ai_next) {
		ಆದರೆ (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    ಗಾತ್ರ(ntop2), ಖಾಲಿ, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				ನಿಲ್ಲಿಸು;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	ಆದರೆ (ai == ಖಾಲಿ) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		ಹಿಂತಿರುಗಿ xstrdup(ntop);
	}
	ಹಿಂತಿರುಗಿ xstrdup(name);
}

/* Returns the port number of the remote host. */

ಪೂರ್ಣಾಂಕ
ssh_remote_ಪೋರ್ಟ್(ರಚನೆ ssh *ssh)
{
	(ಶೂನ್ಯ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ಹಿಂತಿರುಗಿ ssh->remote_ಪೋರ್ಟ್;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ssh_local_ipaddr(ರಚನೆ ssh *ssh)
{
	(ಶೂನ್ಯ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ಹಿಂತಿರುಗಿ ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

ಪೂರ್ಣಾಂಕ
ssh_local_ಪೋರ್ಟ್(ರಚನೆ ssh *ssh)
{
	(ಶೂನ್ಯ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ಹಿಂತಿರುಗಿ ssh->local_ಪೋರ್ಟ್;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ssh_packet_rdomain_ಒಳ(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (ssh->rdomain_ಒಳ != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ssh->rdomain_ಒಳ;
	ಆದರೆ (!ssh_packet_connection_is_on_socket(ssh))
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ssh->rdomain_ಒಳ = get_rdomain(ssh->state->connection_ಒಳ);
	ಹಿಂತಿರುಗಿ ssh->rdomain_ಒಳ;
}

/* Closes the connection and clears and frees internal data structures. */

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_packet_close_ಆಂತರಿಕ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ do_close)
{
	ರಚನೆ session_state *state = ssh->state;
	u_int ಬಹುಲಕ;
	ರಚನೆ packet *p;

	ಆದರೆ (!state->initialized)
		ಹಿಂತಿರುಗಿ;
	state->initialized = 0;
	ಆದರೆ (do_close) {
		ಆದರೆ (state->connection_ಒಳ == state->connection_ಹೊರಹೋಗು) {
			close(state->connection_ಹೊರಹೋಗು);
		} ಇಲ್ಲದಿದ್ದರೆ {
			close(state->connection_ಒಳ);
			close(state->connection_ಹೊರಹೋಗು);
		}
	}
	sshbuf_free(state->ಒಳಹರಿವು);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	ಆಗ ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, ಮುಂದಿನ);
		ಬಿಡುಗಡೆ(p);
	}
	ಗಾಗಿ (ಬಹುಲಕ = 0; ಬಹುಲಕ < ಬಹುಲಕ_MAX; ಬಹುಲಕ++) {
		kex_free_newkeys(state->newkeys[ಬಹುಲಕ]);	/* current keys */
		state->newkeys[ಬಹುಲಕ] = ಖಾಲಿ;
		ssh_clear_newkeys(ssh, ಬಹುಲಕ);		/* next keys */
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	ಆದರೆ (do_close && state->compression_ಬಫರ್) {
		sshbuf_free(state->compression_ಬಫರ್);
		ಆದರೆ (state->compression_ಹೊರಹೋಗು_started) {
			z_streamp ಹರಿವು = &state->compression_ಹೊರಹೋಗು_ಹರಿವು;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಹರಿವು->ಒಟ್ಟು_ಒಳ,
				(ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಹರಿವು->ಒಟ್ಟು_ಹೊರಹೋಗು,
				ಹರಿವು->ಒಟ್ಟು_ಒಳ == 0 ? 0.0 :
				(ದ್ವಿಗುಣ) ಹರಿವು->ಒಟ್ಟು_ಹೊರಹೋಗು / ಹರಿವು->ಒಟ್ಟು_ಒಳ);
			ಆದರೆ (state->compression_ಹೊರಹೋಗು_failures == 0)
				deflate_ಕೊನೆ(ಹರಿವು);
		}
		ಆದರೆ (state->compression_ಒಳ_started) {
			z_streamp ಹರಿವು = &state->compression_ಒಳ_ಹರಿವು;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಹರಿವು->ಒಟ್ಟು_ಹೊರಹೋಗು,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಹರಿವು->ಒಟ್ಟು_ಒಳ,
			    ಹರಿವು->ಒಟ್ಟು_ಹೊರಹೋಗು == 0 ? 0.0 :
			    (ದ್ವಿಗುಣ) ಹರಿವು->ಒಟ್ಟು_ಒಳ / ಹರಿವು->ಒಟ್ಟು_ಹೊರಹೋಗು);
			ಆದರೆ (state->compression_ಒಳ_failures == 0)
				inflate_ಕೊನೆ(ಹರಿವು);
		}
	}
#ಆದರೆ_ಅಂತ್ಯ	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = ಖಾಲಿ;
	ಆದರೆ (do_close) {
		ಬಿಡುಗಡೆ(ssh->local_ipaddr);
		ssh->local_ipaddr = ಖಾಲಿ;
		ಬಿಡುಗಡೆ(ssh->remote_ipaddr);
		ssh->remote_ipaddr = ಖಾಲಿ;
		ಬಿಡುಗಡೆ(ssh->state);
		ssh->state = ಖಾಲಿ;
		kex_free(ssh->kex);
		ssh->kex = ಖಾಲಿ;
	}
}

ಶೂನ್ಯ
ssh_packet_free(ರಚನೆ ssh *ssh)
{
	ssh_packet_close_ಆಂತರಿಕ(ssh, 1);
	freezero(ssh, ಗಾತ್ರ(*ssh));
}

ಶೂನ್ಯ
ssh_packet_close(ರಚನೆ ssh *ssh)
{
	ssh_packet_close_ಆಂತರಿಕ(ssh, 1);
}

ಶೂನ್ಯ
ssh_packet_clear_ಕೀಲಿಗಳು(ರಚನೆ ssh *ssh)
{
	ssh_packet_close_ಆಂತರಿಕ(ssh, 0);
}

/* Sets remote side protocol flags. */

ಶೂನ್ಯ
ssh_packet_ಗಣ_protocol_flags(ರಚನೆ ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_packet_init_compression(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (!ssh->state->compression_ಬಫರ್ &&
	    ((ssh->state->compression_ಬಫರ್ = sshbuf_new()) == ಖಾಲಿ))
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಹಿಂತಿರುಗಿ 0;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಂಭ_compression_ಹೊರಹೋಗು(ರಚನೆ ssh *ssh)
{
	debug("Enabling compression.");
	ಆದರೆ (ssh->state->compression_ಹೊರಹೋಗು_started == 1)
		deflate_ಕೊನೆ(&ssh->state->compression_ಹೊರಹೋಗು_ಹರಿವು);
	ಆಯ್ಕೆ (deflateInit2(&ssh->state->compression_ಹೊರಹೋಗು_ಹರಿವು,
	    Z_ಉತ್ತಮ_ವೇಗ, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	ಸ್ಥಿತಿ Z_OK:
		ssh->state->compression_ಹೊರಹೋಗು_started = 1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ Z_MEM_ERROR:
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಂಭ_compression_ಒಳ(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (ssh->state->compression_ಒಳ_started == 1)
		inflate_ಕೊನೆ(&ssh->state->compression_ಒಳ_ಹರಿವು);
	ಆಯ್ಕೆ (inflateInit(&ssh->state->compression_ಒಳ_ಹರಿವು)) {
	ಸ್ಥಿತಿ Z_OK:
		ssh->state->compression_ಒಳ_started = 1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ Z_MEM_ERROR:
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* XXX remove need for separate compression buffer */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
compress_ಬಫರ್(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *ಒಳ, ರಚನೆ sshbuf *ಹೊರಹೋಗು)
{
	u_char buf[4096];
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2;

	ಆದರೆ (ssh->state->compression_ಹೊರಹೋಗು_started != 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;

	/* This case is not handled below. */
	ಆದರೆ (sshbuf_len(ಒಳ) == 0)
		ಹಿಂತಿರುಗಿ 0;

	/* Input is the contents of the input buffer. */
	ಆದರೆ ((ssh->state->compression_ಹೊರಹೋಗು_ಹರಿವು.ಮುಂದಿನ_ಒಳ =
	    sshbuf_mutable_ptr(ಒಳ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ssh->state->compression_ಹೊರಹೋಗು_ಹರಿವು.avail_ಒಳ = sshbuf_len(ಒಳ);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	ಮಾಡು {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_ಹೊರಹೋಗು_ಹರಿವು.ಮುಂದಿನ_ಹೊರಹೋಗು = buf;
		ssh->state->compression_ಹೊರಹೋಗು_ಹರಿವು.avail_ಹೊರಹೋಗು = ಗಾತ್ರ(buf);

		/* Compress as much data into the buffer as possible. */
		ಸ್ಥಿತಿ_2 = deflate(&ssh->state->compression_ಹೊರಹೋಗು_ಹರಿವು,
		    Z_PARTIAL_FLUSH);
		ಆಯ್ಕೆ (ಸ್ಥಿತಿ_2) {
		ಸ್ಥಿತಿ Z_MEM_ERROR:
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		ಸ್ಥಿತಿ Z_OK:
			/* Append compressed data to output_buffer. */
			ಆದರೆ ((r = sshbuf_put(ಹೊರಹೋಗು, buf, ಗಾತ್ರ(buf) -
			    ssh->state->compression_ಹೊರಹೋಗು_ಹರಿವು.avail_ಹೊರಹೋಗು)) != 0)
				ಹಿಂತಿರುಗಿ r;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ Z_ಹರಿವು_ERROR:
		ಪೂರ್ವನಿಯೋಜಿತ:
			ssh->state->compression_ಹೊರಹೋಗು_failures++;
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		}
	} ಆಗ (ssh->state->compression_ಹೊರಹೋಗು_ಹರಿವು.avail_ಹೊರಹೋಗು == 0);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
uncompress_ಬಫರ್(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *ಒಳ, ರಚನೆ sshbuf *ಹೊರಹೋಗು)
{
	u_char buf[4096];
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2;

	ಆದರೆ (ssh->state->compression_ಒಳ_started != 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ ((ssh->state->compression_ಒಳ_ಹರಿವು.ಮುಂದಿನ_ಒಳ =
	    sshbuf_mutable_ptr(ಒಳ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ssh->state->compression_ಒಳ_ಹರಿವು.avail_ಒಳ = sshbuf_len(ಒಳ);

	ಗಾಗಿ (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_ಒಳ_ಹರಿವು.ಮುಂದಿನ_ಹೊರಹೋಗು = buf;
		ssh->state->compression_ಒಳ_ಹರಿವು.avail_ಹೊರಹೋಗು = ಗಾತ್ರ(buf);

		ಸ್ಥಿತಿ_2 = inflate(&ssh->state->compression_ಒಳ_ಹರಿವು,
		    Z_SYNC_FLUSH);
		ಆಯ್ಕೆ (ಸ್ಥಿತಿ_2) {
		ಸ್ಥಿತಿ Z_OK:
			ಆದರೆ ((r = sshbuf_put(ಹೊರಹೋಗು, buf, ಗಾತ್ರ(buf) -
			    ssh->state->compression_ಒಳ_ಹರಿವು.avail_ಹೊರಹೋಗು)) != 0)
				ಹಿಂತಿರುಗಿ r;
			ಆದರೆ (sshbuf_len(ಹೊರಹೋಗು) >= PACKET_MAX_ಗಾತ್ರ)
				ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			ಹಿಂತಿರುಗಿ 0;
		ಸ್ಥಿತಿ Z_ದತ್ತಾಂಶ_ERROR:
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		ಸ್ಥಿತಿ Z_MEM_ERROR:
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		ಸ್ಥಿತಿ Z_ಹರಿವು_ERROR:
		ಪೂರ್ವನಿಯೋಜಿತ:
			ssh->state->compression_ಒಳ_failures++;
			ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
		}
	}
	/* NOTREACHED */
}

#ಇಲ್ಲದಿದ್ದರೆ	/* WITH_ZLIB */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಂಭ_compression_ಹೊರಹೋಗು(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಂಭ_compression_ಒಳ(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
compress_ಬಫರ್(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *ಒಳ, ರಚನೆ sshbuf *ಹೊರಹೋಗು)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
uncompress_ಬಫರ್(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *ಒಳ, ರಚನೆ sshbuf *ಹೊರಹೋಗು)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
}
#ಆದರೆ_ಅಂತ್ಯ	/* WITH_ZLIB */

ಶೂನ್ಯ
ssh_clear_newkeys(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ)
{
	ಆದರೆ (ssh->kex && ssh->kex->newkeys[ಬಹುಲಕ]) {
		kex_free_newkeys(ssh->kex->newkeys[ಬಹುಲಕ]);
		ssh->kex->newkeys[ಬಹುಲಕ] = ಖಾಲಿ;
	}
}

ಪೂರ್ಣಾಂಕ
ssh_ಗಣ_newkeys(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ)
{
	ರಚನೆ session_state *state = ssh->state;
	ರಚನೆ sshenc *enc;
	ರಚನೆ sshmac *mac;
	ರಚನೆ sshcomp *comp;
	ರಚನೆ sshcipher_ctx **ccp;
	ರಚನೆ packet_state *ps;
	uint64_t *max_ಖಂಡಗಳು, *hard_max_ಖಂಡಗಳು;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *wmsg;
	ಪೂರ್ಣಾಂಕ r, crypt_type;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dir = ಬಹುಲಕ == ಬಹುಲಕ_ಹೊರಹೋಗು ? "out" : "in";

	debug2_f("mode %d", ಬಹುಲಕ);

	ಆದರೆ (ಬಹುಲಕ == ಬಹುಲಕ_ಹೊರಹೋಗು) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_ಖಂಡಗಳು = &state->hard_max_ಖಂಡಗಳು_ಹೊರಹೋಗು;
		max_ಖಂಡಗಳು = &state->max_ಖಂಡಗಳು_ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_ಖಂಡಗಳು = &state->hard_max_ಖಂಡಗಳು_ಒಳ;
		max_ಖಂಡಗಳು = &state->max_ಖಂಡಗಳು_ಒಳ;
	}
	ಆದರೆ (state->newkeys[ಬಹುಲಕ] != ಖಾಲಿ) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)state->p_read.ಬೈಟುಗಳು,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)state->p_read.ಖಂಡಗಳು,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)state->p_send.ಬೈಟುಗಳು,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)state->p_send.ಖಂಡಗಳು);
		kex_free_newkeys(state->newkeys[ಬಹುಲಕ]);
		state->newkeys[ಬಹುಲಕ] = ಖಾಲಿ;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->ಖಂಡಗಳು = 0;
	/* move newkeys from kex to state */
	ಆದರೆ ((state->newkeys[ಬಹುಲಕ] = ssh->kex->newkeys[ಬಹುಲಕ]) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ssh->kex->newkeys[ಬಹುಲಕ] = ಖಾಲಿ;
	enc  = &state->newkeys[ಬಹುಲಕ]->enc;
	mac  = &state->newkeys[ಬಹುಲಕ]->mac;
	comp = &state->newkeys[ಬಹುಲಕ]->comp;
	ಆದರೆ (cipher_authlen(enc->cipher) == 0) {
		ಆದರೆ ((r = mac_init(mac)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = ಖಾಲಿ;
	ಆದರೆ ((r = cipher_init(ccp, enc->cipher, enc->ಕೀಲಿ, enc->ಕೀಲಿ_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (!state->cipher_warning_ಮುಗಿದ &&
	    (wmsg = cipher_warning_ಸಂದೇಶ(*ccp)) != ಖಾಲಿ) {
		error("Warning: %s", wmsg);
		state->cipher_warning_ಮುಗಿದ = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	ಆದರೆ (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		ಆದರೆ ((r = ssh_packet_init_compression(ssh)) < 0)
			ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (ಬಹುಲಕ == ಬಹುಲಕ_ಹೊರಹೋಗು) {
			ಆದರೆ ((r = ಆರಂಭ_compression_ಹೊರಹೋಗು(ssh)) != 0)
				ಹಿಂತಿರುಗಿ r;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((r = ಆರಂಭ_compression_ಒಳ(ssh)) != 0)
				ಹಿಂತಿರುಗಿ r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	ಆದರೆ (enc->ಖಂಡ_ಗಾತ್ರ >= 16)
		*hard_max_ಖಂಡಗಳು = (uint64_t)1 << (enc->ಖಂಡ_ಗಾತ್ರ*2);
	ಇಲ್ಲದಿದ್ದರೆ
		*hard_max_ಖಂಡಗಳು = ((uint64_t)1 << 30) / enc->ಖಂಡ_ಗಾತ್ರ;
	*max_ಖಂಡಗಳು = *hard_max_ಖಂಡಗಳು;
	ಆದರೆ (state->rekey_ಎಲ್ಲೆ) {
		*max_ಖಂಡಗಳು = MINIMUM(*max_ಖಂಡಗಳು,
		    state->rekey_ಎಲ್ಲೆ / enc->ಖಂಡ_ಗಾತ್ರ);
	}
	debug("rekey %s after %llu blocks", dir,
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)*max_ಖಂಡಗಳು);
	ಹಿಂತಿರುಗಿ 0;
}

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಪೂರ್ಣಾಂಕ
ssh_packet_check_rekey_blocklimit(ರಚನೆ ssh *ssh, u_int packet_len, ಪೂರ್ಣಾಂಕ hard)
{
	ರಚನೆ session_state *state = ssh->state;
	uint32_t ಹೊರಹೋಗು_ಖಂಡಗಳು;
	ಸ್ಥಿರಾಂಕ uint64_t max_ಖಂಡಗಳು_ಒಳ = hard ?
	    state->hard_max_ಖಂಡಗಳು_ಒಳ : state->max_ಖಂಡಗಳು_ಒಳ;
	ಸ್ಥಿರಾಂಕ uint64_t max_ಖಂಡಗಳು_ಹೊರಹೋಗು = hard ?
	    state->hard_max_ಖಂಡಗಳು_ಹೊರಹೋಗು : state->max_ಖಂಡಗಳು_ಹೊರಹೋಗು;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	ಆದರೆ (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		ಹಿಂತಿರುಗಿ 1;

	ಆದರೆ (state->newkeys[ಬಹುಲಕ_ಹೊರಹೋಗು] == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	/* Rekey after (cipher-specific) maximum blocks */
	ಹೊರಹೋಗು_ಖಂಡಗಳು = ROUNDUP(packet_len,
	    state->newkeys[ಬಹುಲಕ_ಹೊರಹೋಗು]->enc.ಖಂಡ_ಗಾತ್ರ);
	ಹಿಂತಿರುಗಿ (max_ಖಂಡಗಳು_ಹೊರಹೋಗು &&
	    (state->p_send.ಖಂಡಗಳು + ಹೊರಹೋಗು_ಖಂಡಗಳು > max_ಖಂಡಗಳು_ಹೊರಹೋಗು)) ||
	    (max_ಖಂಡಗಳು_ಒಳ &&
	    (state->p_read.ಖಂಡಗಳು > max_ಖಂಡಗಳು_ಒಳ));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_packet_need_rekeying(ರಚನೆ ssh *ssh, u_int outbound_packet_len)
{
	ರಚನೆ session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	ಆದರೆ (!state->after_authentication)
		ಹಿಂತಿರುಗಿ 0;

	/* Haven't keyed yet or KEX in progress. */
	ಆದರೆ (ssh_packet_is_rekeying(ssh))
		ಹಿಂತಿರುಗಿ 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	ಆದರೆ (state->p_send.packets == 0 && state->p_read.packets == 0)
		ಹಿಂತಿರುಗಿ 0;

	/* Time-based rekeying */
	ಆದರೆ (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_ಸಮಯ + state->rekey_interval <= monotime())
		ಹಿಂತಿರುಗಿ 1;

	ಹಿಂತಿರುಗಿ ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_packet_check_rekey_preauth(ರಚನೆ ssh *ssh, u_int outgoing_packet_len)
{
	ಆದರೆ (ssh->state->after_authentication)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		ಹಿಂತಿರುಗಿ SSH_ERR_NEED_REKEY;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_check_rekey(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (!ssh_packet_need_rekeying(ssh, 0))
		ಹಿಂತಿರುಗಿ 0;
	debug3_f("rekex triggered");
	ಹಿಂತಿರುಗಿ kex_ಆರಂಭ_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_packet_enable_delayed_compress(ರಚನೆ ssh *ssh)
{
	ರಚನೆ session_state *state = ssh->state;
	ರಚನೆ sshcomp *comp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ಬಹುಲಕ;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	ಗಾಗಿ (ಬಹುಲಕ = 0; ಬಹುಲಕ < ಬಹುಲಕ_MAX; ಬಹುಲಕ++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		ಆದರೆ (state->newkeys[ಬಹುಲಕ] == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		comp = &state->newkeys[ಬಹುಲಕ]->comp;
		ಆದರೆ (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			ಆದರೆ ((r = ssh_packet_init_compression(ssh)) != 0)
				ಹಿಂತಿರುಗಿ r;
			ಆದರೆ (ಬಹುಲಕ == ಬಹುಲಕ_ಹೊರಹೋಗು) {
				ಆದರೆ ((r = ಆರಂಭ_compression_ಹೊರಹೋಗು(ssh)) != 0)
					ಹಿಂತಿರುಗಿ r;
			} ಇಲ್ಲದಿದ್ದರೆ {
				ಆದರೆ ((r = ಆರಂಭ_compression_ಒಳ(ssh)) != 0)
					ಹಿಂತಿರುಗಿ r;
			}
			comp->enabled = 1;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Used to mute debug logging for noisy packet types */
ಪೂರ್ಣಾಂಕ
ssh_packet_log_type(u_char type)
{
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_PING:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_PONG:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_ದತ್ತಾಂಶ:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_ಕಿಟಕಿ_ADJUST:
		ಹಿಂತಿರುಗಿ 0;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
ಪೂರ್ಣಾಂಕ
ssh_packet_send2_wrapped(ರಚನೆ ssh *ssh)
{
	ರಚನೆ session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	ರಚನೆ sshenc *enc   = ಖಾಲಿ;
	ರಚನೆ sshmac *mac   = ಖಾಲಿ;
	ರಚನೆ sshcomp *comp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ಖಂಡ_ಗಾತ್ರ;

	ಆದರೆ (state->newkeys[ಬಹುಲಕ_ಹೊರಹೋಗು] != ಖಾಲಿ) {
		enc  = &state->newkeys[ಬಹುಲಕ_ಹೊರಹೋಗು]->enc;
		mac  = &state->newkeys[ಬಹುಲಕ_ಹೊರಹೋಗು]->mac;
		comp = &state->newkeys[ಬಹುಲಕ_ಹೊರಹೋಗು]->comp;
		/* disable mac for authenticated encryption */
		ಆದರೆ ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ಖಾಲಿ;
	}
	ಖಂಡ_ಗಾತ್ರ = enc ? enc->ಖಂಡ_ಗಾತ್ರ : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	ಆದರೆ (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		ಆದರೆ ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		sshbuf_reset(state->compression_ಬಫರ್);
		ಆದರೆ ((r = compress_ಬಫರ್(ssh, state->outgoing_packet,
		    state->compression_ಬಫರ್)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		sshbuf_reset(state->outgoing_packet);
		ಆದರೆ ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_ಬಫರ್)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
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
	padlen = ಖಂಡ_ಗಾತ್ರ - (len % ಖಂಡ_ಗಾತ್ರ);
	ಆದರೆ (padlen < 4)
		padlen += ಖಂಡ_ಗಾತ್ರ;
	ಆದರೆ (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, ಖಂಡ_ಗಾತ್ರ);
		/* check if roundup overflowed */
		ಆದರೆ (state->extra_pad < tmp)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		ಆದರೆ (tmp > state->extra_pad)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		ಆದರೆ (padlen < tmp)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ; /*ಅತಿಪ್ರವಾಹ*/
		state->extra_pad = 0;
	}
	ಆದರೆ ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	ಆದರೆ (cp == ಖಾಲಿ) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	ಆದರೆ (mac && mac->enabled && !mac->etm) {
		ಆದರೆ ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, ಗಾತ್ರ(macbuf))) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	ಆದರೆ ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* append unencrypted MAC */
	ಆದರೆ (mac && mac->enabled) {
		ಆದರೆ (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			ಆದರೆ ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, ಗಾತ್ರ(macbuf))) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		ಆದರೆ ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	/* increment sequence number for outgoing packets */
	ಆದರೆ (++state->p_send.seqnr == 0) {
		ಆದರೆ ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	ಆದರೆ (++state->p_send.packets == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_NEED_REKEY;
	state->p_send.ಖಂಡಗಳು += len / ಖಂಡ_ಗಾತ್ರ;
	state->p_send.ಬೈಟುಗಳು += len;
	sshbuf_reset(state->outgoing_packet);

	ಆದರೆ (type == SSH2_ಸಂದೇಶ_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	ಆದರೆ (type == SSH2_ಸಂದೇಶ_NEWKEYS)
		r = ssh_ಗಣ_newkeys(ssh, ಬಹುಲಕ_ಹೊರಹೋಗು);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type == SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	ಇಲ್ಲದಿದ್ದರೆ
		r = 0;
 ಹೊರಹೋಗು:
	ಹಿಂತಿರುಗಿ r;
}

/* returns non-zero if the specified packet type is usec by KEX */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_packet_type_is_kex(u_char type)
{
	ಹಿಂತಿರುಗಿ
	    type >= SSH2_ಸಂದೇಶ_TRANSPORT_MIN &&
	    type <= SSH2_ಸಂದೇಶ_TRANSPORT_MAX &&
	    type != SSH2_ಸಂದೇಶ_SERVICE_REQUEST &&
	    type != SSH2_ಸಂದೇಶ_SERVICE_ACCEPT &&
	    type != SSH2_ಸಂದೇಶ_EXT_INFO;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_send2(ರಚನೆ ssh *ssh)
{
	ರಚನೆ session_state *state = ssh->state;
	ರಚನೆ packet *p;
	u_char type;
	ಪೂರ್ಣಾಂಕ r, need_rekey;

	ಆದರೆ (sshbuf_len(state->outgoing_packet) < 6)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	ಆದರೆ (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		ಹಿಂತಿರುಗಿ r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	ಆದರೆ ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		ಆದರೆ (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*p));
		ಆದರೆ (p == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, ಮುಂದಿನ);
		state->outgoing_packet = sshbuf_new();
		ಆದರೆ (state->outgoing_packet == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		ಆದರೆ (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			ಹಿಂತಿರುಗಿ kex_ಆರಂಭ_rekex(ssh);
		}
		ಹಿಂತಿರುಗಿ 0;
	}

	/* rekeying starts with sending KEXINIT */
	ಆದರೆ (type == SSH2_ಸಂದೇಶ_KEXINIT)
		state->rekeying = 1;

	ಆದರೆ ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;

	/* after a NEWKEYS message we can send the complete queue */
	ಆದರೆ (type == SSH2_ಸಂದೇಶ_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_ಸಮಯ = monotime();
		ಆಗ ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			ಆದರೆ (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				ಹಿಂತಿರುಗಿ kex_ಆರಂಭ_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, ಮುಂದಿನ);
			memset(p, 0, ಗಾತ್ರ(*p));
			ಬಿಡುಗಡೆ(p);
			ಆದರೆ ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				ಹಿಂತಿರುಗಿ r;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

ಪೂರ್ಣಾಂಕ
ssh_packet_read_seqnr(ರಚನೆ ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ರಚನೆ session_state *state = ssh->state;
	ಪೂರ್ಣಾಂಕ len, r, ms_remain = 0;
	ರಚನೆ pollfd pfd;
	ಅಕ್ಷರ buf[8192];
	ರಚನೆ timeval ಆರಂಭ;
	ರಚನೆ timespec timespec, *timespecp = ಖಾಲಿ;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	ಆದರೆ ((r = ssh_packet_write_wait(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Stay in the loop until we have received a complete packet. */
	ಗಾಗಿ (;;) {
		/* Try to read a packet from the buffer. */
		ಆದರೆ ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			ನಿಲ್ಲಿಸು;
		/* If we got a packet, return it. */
		ಆದರೆ (*typep != SSH_ಸಂದೇಶ_NONE)
			ನಿಲ್ಲಿಸು;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_ಒಳ;
		pfd.events = POLLIN;

		ಆದರೆ (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		ಗಾಗಿ (;;) {
			ಆದರೆ (state->packet_timeout_ms > 0) {
				ms_ಗಮ್ಯ_timespec(&timespec, ms_remain);
				monotime_tv(&ಆರಂಭ);
			}
			ಆದರೆ ((r = ppoll(&pfd, 1, timespecp, ಖಾಲಿ)) >= 0)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (state->packet_timeout_ms <= 0)
				ಮುಂದುವರಿ;
			ms_ಕಳೆ_diff(&ಆರಂಭ, &ms_remain);
			ಆದರೆ (ms_remain <= 0) {
				r = 0;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Read data from the socket. */
		len = ಪಠ(state->connection_ಒಳ, buf, ಗಾತ್ರ(buf));
		ಆದರೆ (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}

		/* Append it to the buffer. */
		ಆದರೆ ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
 ಹೊರಹೋಗು:
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_read(ರಚನೆ ssh *ssh)
{
	u_char type;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = ssh_packet_read_seqnr(ssh, &type, ಖಾಲಿ)) != 0)
		sshpkt_fatal(ssh, r, "read");
	ಹಿಂತಿರುಗಿ type;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_packet_read_poll2_mux(ರಚನೆ ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ರಚನೆ session_state *state = ssh->state;
	ಸ್ಥಿರಾಂಕ u_char *cp;
	ಗಾತ್ರ_t need;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ssh->kex)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	*typep = SSH_ಸಂದೇಶ_NONE;
	cp = sshbuf_ptr(state->ಒಳಹರಿವು);
	ಆದರೆ (state->packlen == 0) {
		ಆದರೆ (sshbuf_len(state->ಒಳಹರಿವು) < 4 + 1)
			ಹಿಂತಿರುಗಿ 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		ಆದರೆ (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_ಗಾತ್ರ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	}
	need = state->packlen + 4;
	ಆದರೆ (sshbuf_len(state->ಒಳಹರಿವು) < need)
		ಹಿಂತಿರುಗಿ 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	ಆದರೆ ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->ಒಳಹರಿವು, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_read_poll2(ರಚನೆ ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ರಚನೆ session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, ಖಂಡ_ಗಾತ್ರ;
	ರಚನೆ sshenc *enc   = ಖಾಲಿ;
	ರಚನೆ sshmac *mac   = ಖಾಲಿ;
	ರಚನೆ sshcomp *comp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (state->mux)
		ಹಿಂತಿರುಗಿ ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_ಸಂದೇಶ_NONE;

	ಆದರೆ (state->packet_discard)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ (state->newkeys[ಬಹುಲಕ_ಒಳ] != ಖಾಲಿ) {
		enc  = &state->newkeys[ಬಹುಲಕ_ಒಳ]->enc;
		mac  = &state->newkeys[ಬಹುಲಕ_ಒಳ]->mac;
		comp = &state->newkeys[ಬಹುಲಕ_ಒಳ]->comp;
		/* disable mac for authenticated encryption */
		ಆದರೆ ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ಖಾಲಿ;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	ಖಂಡ_ಗಾತ್ರ = enc ? enc->ಖಂಡ_ಗಾತ್ರ : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	ಆದರೆ (aadlen && state->packlen == 0) {
		ಆದರೆ (cipher_get_ಉದ್ದಳತೆ(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->ಒಳಹರಿವು), sshbuf_len(state->ಒಳಹರಿವು)) != 0)
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_ಗಾತ್ರ) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PACKET_DEBUG
			sshbuf_dump(state->ಒಳಹರಿವು, stderr);
#ಆದರೆ_ಅಂತ್ಯ
			logit("Bad packet length %u.", state->packlen);
			ಆದರೆ ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				ಹಿಂತಿರುಗಿ r;
			ಹಿಂತಿರುಗಿ SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		ಆದರೆ (sshbuf_len(state->ಒಳಹರಿವು) < ಖಂಡ_ಗಾತ್ರ)
			ಹಿಂತಿರುಗಿ 0;
		sshbuf_reset(state->incoming_packet);
		ಆದರೆ ((r = sshbuf_reserve(state->incoming_packet, ಖಂಡ_ಗಾತ್ರ,
		    &cp)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->ಒಳಹರಿವು),
		    ಖಂಡ_ಗಾತ್ರ, 0, 0)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		ಆದರೆ (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_ಗಾತ್ರ) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->ಒಳಹರಿವು, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#ಆದರೆ_ಅಂತ್ಯ
			logit("Bad packet length %u.", state->packlen);
			ಹಿಂತಿರುಗಿ ssh_packet_ಆರಂಭ_discard(ssh, enc, mac, 0,
			    PACKET_MAX_ಗಾತ್ರ);
		}
		ಆದರೆ ((r = sshbuf_consume(state->ಒಳಹರಿವು, ಖಂಡ_ಗಾತ್ರ)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	ಆದರೆ (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - ಖಂಡ_ಗಾತ್ರ;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", ಖಂಡ_ಗಾತ್ರ, need, maclen, authlen, aadlen));
	ಆದರೆ (need % ಖಂಡ_ಗಾತ್ರ != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, ಖಂಡ_ಗಾತ್ರ, need % ಖಂಡ_ಗಾತ್ರ);
		ಹಿಂತಿರುಗಿ ssh_packet_ಆರಂಭ_discard(ssh, enc, mac, 0,
		    PACKET_MAX_ಗಾತ್ರ - ಖಂಡ_ಗಾತ್ರ);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet:
	 * 'aadlen' bytes are unencrypted, but authenticated.
	 * 'need' bytes are encrypted, followed by either
	 * 'authlen' bytes of authentication tag or
	 * 'maclen' bytes of message authentication code.
	 */
	ಆದರೆ (sshbuf_len(state->ಒಳಹರಿವು) < aadlen + need + authlen + maclen)
		ಹಿಂತಿರುಗಿ 0; /* packet is incomplete */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->ಒಳಹರಿವು, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	/* EtM: check mac over encrypted input */
	ಆದರೆ (mac && mac->enabled && mac->etm) {
		ಆದರೆ ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->ಒಳಹರಿವು), aadlen + need,
		    sshbuf_ptr(state->ಒಳಹರಿವು) + aadlen + need + authlen,
		    maclen)) != 0) {
			ಆದರೆ (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->ಒಳಹರಿವು), need, aadlen, authlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = sshbuf_consume(state->ಒಳಹರಿವು, aadlen + need + authlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		ಆದರೆ (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->ಒಳಹರಿವು), maclen)) != 0) {
			ಆದರೆ (r != SSH_ERR_MAC_INVALID)
				ಹೋಗು ಹೊರಹೋಗು;
			logit("Corrupted MAC on input.");
			ಆದರೆ (need + ಖಂಡ_ಗಾತ್ರ > PACKET_MAX_ಗಾತ್ರ)
				ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
			ಹಿಂತಿರುಗಿ ssh_packet_ಆರಂಭ_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_ಗಾತ್ರ - need - ಖಂಡ_ಗಾತ್ರ);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		ಆದರೆ ((r = sshbuf_consume(state->ಒಳಹರಿವು, mac->mac_len)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (seqnr_p != ಖಾಲಿ)
		*seqnr_p = state->p_read.seqnr;
	ಆದರೆ (++state->p_read.seqnr == 0) {
		ಆದರೆ ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	ಆದರೆ (++state->p_read.packets == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_NEED_REKEY;
	state->p_read.ಖಂಡಗಳು += (state->packlen + 4) / ಖಂಡ_ಗಾತ್ರ;
	state->p_read.ಬೈಟುಗಳು += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	ಆದರೆ (padlen < 4)	{
		ಆದರೆ ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಹಿಂತಿರುಗಿ SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	ಆದರೆ ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_ಕೊನೆ(state->incoming_packet, padlen)) != 0))
		ಹೋಗು ಹೊರಹೋಗು;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	ಆದರೆ (comp && comp->enabled) {
		sshbuf_reset(state->compression_ಬಫರ್);
		ಆದರೆ ((r = uncompress_ಬಫರ್(ssh, state->incoming_packet,
		    state->compression_ಬಫರ್)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		sshbuf_reset(state->incoming_packet);
		ಆದರೆ ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_ಬಫರ್)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	ಆದರೆ ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	ಆದರೆ (*typep < SSH2_ಸಂದೇಶ_MIN) {
		ಆದರೆ ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
	}
	ಆದರೆ (state->hook_ಒಳ != ಖಾಲಿ &&
	    (r = state->hook_ಒಳ(ssh, state->incoming_packet, typep,
	    state->hook_ಒಳ_ctx)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (*typep == SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	ಇಲ್ಲದಿದ್ದರೆ
		r = 0;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	/* reset for next packet */
	state->packlen = 0;
	ಆದರೆ (*typep == SSH2_ಸಂದೇಶ_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	ಆದರೆ ((r = ssh_packet_check_rekey(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
 ಹೊರಹೋಗು:
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_read_poll_seqnr(ರಚನೆ ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ರಚನೆ session_state *state = ssh->state;
	u_int reason, seqnr;
	ಪೂರ್ಣಾಂಕ r;
	u_char *ಸಂದೇಶ;
	ಸ್ಥಿರಾಂಕ u_char *d;
	ಗಾತ್ರ_t len;

	ಗಾಗಿ (;;) {
		ಸಂದೇಶ = ಖಾಲಿ;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		ಆದರೆ (r != 0)
			ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (*typep == 0) {
			/* no message ready */
			ಹಿಂತಿರುಗಿ 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		ಆದರೆ (*typep == SSH2_ಸಂದೇಶ_DISCONNECT) {
			ಆದರೆ ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &ಸಂದೇಶ, ಖಾಲಿ)) != 0)
				ಹಿಂತಿರುಗಿ r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_ಪೋರ್ಟ್(ssh), reason, ಸಂದೇಶ);
			ಬಿಡುಗಡೆ(ಸಂದೇಶ);
			ಹಿಂತಿರುಗಿ SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		ಆದರೆ (ssh->kex != ಖಾಲಿ &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			ಹಿಂತಿರುಗಿ 0;
		/* Implicitly handle transport-level messages */
		ಆಯ್ಕೆ (*typep) {
		ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_DEBUG:
			ಆದರೆ ((r = sshpkt_get_u8(ssh, ಖಾಲಿ)) != 0 ||
			    (r = sshpkt_get_string(ssh, &ಸಂದೇಶ, ಖಾಲಿ)) != 0 ||
			    (r = sshpkt_get_string(ssh, ಖಾಲಿ, ಖಾಲಿ)) != 0) {
				ಬಿಡುಗಡೆ(ಸಂದೇಶ);
				ಹಿಂತಿರುಗಿ r;
			}
			debug("Remote: %.900s", ಸಂದೇಶ);
			ಬಿಡುಗಡೆ(ಸಂದೇಶ);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_UNIMPLEMENTED:
			ಆದರೆ ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				ಹಿಂತಿರುಗಿ r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_PING:
			ಆದರೆ ((r = sshpkt_get_string_ನೇರ(ssh, &d, &len)) != 0)
				ಹಿಂತಿರುಗಿ r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			ಆದರೆ (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				ಹಿಂತಿರುಗಿ r;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_PONG:
			ಆದರೆ ((r = sshpkt_get_string_ನೇರ(ssh,
			    ಖಾಲಿ, &len)) != 0)
				ಹಿಂತಿರುಗಿ r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಆದರೆ (ssh->kex != ಖಾಲಿ &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
			}
			ಹಿಂತಿರುಗಿ 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
ಪೂರ್ಣಾಂಕ
ssh_packet_process_incoming(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *buf, u_int len)
{
	ರಚನೆ session_state *state = ssh->state;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		ಆದರೆ (len >= state->packet_discard) {
			ಆದರೆ ((r = ssh_packet_stop_discard(ssh)) != 0)
				ಹಿಂತಿರುಗಿ r;
		}
		state->packet_discard -= len;
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((r = sshbuf_put(state->ಒಳಹರಿವು, buf, len)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

/* Reads and buffers data from the specified fd */
ಪೂರ್ಣಾಂಕ
ssh_packet_process_read(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ session_state *state = ssh->state;
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t rlen;

	ಆದರೆ ((r = sshbuf_read(fd, state->ಒಳಹರಿವು, PACKET_MAX_ಗಾತ್ರ, &rlen)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಆದರೆ (state->packet_discard) {
		ಆದರೆ ((r = sshbuf_consume_ಕೊನೆ(state->ಒಳಹರಿವು, rlen)) != 0)
			ಹಿಂತಿರುಗಿ r;
		state->keep_alive_timeouts = 0; /* ?? */
		ಆದರೆ (rlen >= state->packet_discard) {
			ಆದರೆ ((r = ssh_packet_stop_discard(ssh)) != 0)
				ಹಿಂತಿರುಗಿ r;
		}
		state->packet_discard -= rlen;
		ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_ಉಳಿದ(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
ಶೂನ್ಯ
ssh_packet_send_debug(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt,...)
{
	ಅಕ್ಷರ buf[1024];
	va_list ವಾದಗಳು;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ssh->compat & SSH_BUG_DEBUG))
		ಹಿಂತಿರುಗಿ;

	va_start(ವಾದಗಳು, fmt);
	vsnprintf(buf, ಗಾತ್ರ(buf), fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);

	debug3("sending debug message: %s", buf);

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

ಶೂನ್ಯ
sshpkt_fmt_connection_id(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *s, ಗಾತ್ರ_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
sshpkt_vfatal(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ap)
{
	ಅಕ್ಷರ *ಟ್ಯಾಗ್ = ಖಾಲಿ, remote_id[512];
	ಪೂರ್ಣಾಂಕ oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, ಗಾತ್ರ(remote_id));

	ಆಯ್ಕೆ (r) {
	ಸ್ಥಿತಿ SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_ಕೀಲಿಗಳು(ssh);
		logdie("Connection closed by %s", remote_id);
	ಸ್ಥಿತಿ SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_ಕೀಲಿಗಳು(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	ಸ್ಥಿತಿ SSH_ERR_DISCONNECTED:
		ssh_packet_clear_ಕೀಲಿಗಳು(ssh);
		logdie("Disconnected from %s", remote_id);
	ಸ್ಥಿತಿ SSH_ERR_SYSTEM_ERROR:
		ಆದರೆ (errno == ECONNRESET) {
			ssh_packet_clear_ಕೀಲಿಗಳು(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	ಸ್ಥಿತಿ SSH_ERR_NO_CIPHER_ALG_ಹೊಂದಿಕೆ:
	ಸ್ಥಿತಿ SSH_ERR_NO_MAC_ALG_ಹೊಂದಿಕೆ:
	ಸ್ಥಿತಿ SSH_ERR_NO_COMPRESS_ALG_ಹೊಂದಿಕೆ:
	ಸ್ಥಿತಿ SSH_ERR_NO_KEX_ALG_ಹೊಂದಿಕೆ:
	ಸ್ಥಿತಿ SSH_ERR_NO_HOSTKEY_ALG_ಹೊಂದಿಕೆ:
		ಆದರೆ (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_ಕೀಲಿಗಳು(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಆದರೆ (vasprintf(&ಟ್ಯಾಗ್, fmt, ap) == -1) {
			ssh_packet_clear_ಕೀಲಿಗಳು(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_ಕೀಲಿಗಳು(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    ಟ್ಯಾಗ್ != ಖಾಲಿ ? ಟ್ಯಾಗ್ : "", ಟ್ಯಾಗ್ != ಖಾಲಿ ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

ಶೂನ್ಯ
sshpkt_fatal(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
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
ಶೂನ್ಯ
ssh_packet_disconnect(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt,...)
{
	ಅಕ್ಷರ buf[1024], remote_id[512];
	va_list ವಾದಗಳು;
	ಪೂರ್ಣಾಂಕ r;

	/* Guard against recursive invocations. */
	ಆದರೆ (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, ಗಾತ್ರ(remote_id));
	va_start(ವಾದಗಳು, fmt);
	vsnprintf(buf, ಗಾತ್ರ(buf), fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	ಆದರೆ ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	ಆದರೆ ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
ಪೂರ್ಣಾಂಕ
ssh_packet_write_poll(ರಚನೆ ssh *ssh)
{
	ರಚನೆ session_state *state = ssh->state;
	ಪೂರ್ಣಾಂಕ len = sshbuf_len(state->output);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (len > 0) {
		len = ಲಿಖ(state->connection_ಹೊರಹೋಗು,
		    sshbuf_ptr(state->output), len);
		ಆದರೆ (len == -1) {
			ಆದರೆ (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				ಹಿಂತಿರುಗಿ 0;
			ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
		}
		ಆದರೆ (len == 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_CONN_CLOSED;
		ಆದರೆ ((r = sshbuf_consume(state->output, len)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
ಪೂರ್ಣಾಂಕ
ssh_packet_write_wait(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ ret, r, ms_remain = 0;
	ರಚನೆ timeval ಆರಂಭ;
	ರಚನೆ timespec timespec, *timespecp = ಖಾಲಿ;
	ರಚನೆ session_state *state = ssh->state;
	ರಚನೆ pollfd pfd;

	ಆದರೆ ((r = ssh_packet_write_poll(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆಗ (ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ssh)) {
		pfd.fd = state->connection_ಹೊರಹೋಗು;
		pfd.events = POLLOUT;

		ಆದರೆ (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		ಗಾಗಿ (;;) {
			ಆದರೆ (state->packet_timeout_ms > 0) {
				ms_ಗಮ್ಯ_timespec(&timespec, ms_remain);
				monotime_tv(&ಆರಂಭ);
			}
			ಆದರೆ ((ret = ppoll(&pfd, 1, timespecp, ಖಾಲಿ)) >= 0)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (state->packet_timeout_ms <= 0)
				ಮುಂದುವರಿ;
			ms_ಕಳೆ_diff(&ಆರಂಭ, &ms_remain);
			ಆದರೆ (ms_remain <= 0) {
				ret = 0;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (ret == 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_CONN_TIMEOUT;
		ಆದರೆ ((r = ssh_packet_write_poll(ssh)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Returns true if there is buffered data to write to the connection. */

ಪೂರ್ಣಾಂಕ
ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

ಪೂರ್ಣಾಂಕ
ssh_packet_not_very_much_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (ssh->state->interactive_ಬಹುಲಕ)
		ಹಿಂತಿರುಗಿ sshbuf_len(ssh->state->output) < 16384;
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

ಪೂರ್ಣಾಂಕ
ssh_packet_interactive_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ssh->state->interactive_ಬಹುಲಕ &&
	    sshbuf_len(ssh->state->output) < 256;
}

ಸ್ಥಿರ ಶೂನ್ಯ
apply_qos(ರಚನೆ ssh *ssh)
{
	ರಚನೆ session_state *state = ssh->state;
	ಪೂರ್ಣಾಂಕ qos = state->interactive_ಬಹುಲಕ ?
	    state->qos_interactive : state->qos_other;

	ಆದರೆ (!ssh_packet_connection_is_on_socket(ssh))
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (!state->nodelay_ಗಣ) {
		ಗಣ_nodelay(state->connection_ಒಳ);
		state->nodelay_ಗಣ = 1;
	}
	ಗಣ_sock_tos(ssh->state->connection_ಒಳ, qos);
}

/* Informs that the current session is interactive. */
ಶೂನ್ಯ
ssh_packet_ಗಣ_interactive(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ interactive)
{
	ರಚನೆ session_state *state = ssh->state;

	state->interactive_ಬಹುಲಕ = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
ಶೂನ್ಯ
ssh_packet_ಗಣ_qos(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ qos_interactive, ಪೂರ್ಣಾಂಕ qos_other)
{
	ರಚನೆ session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

ಪೂರ್ಣಾಂಕ
ssh_packet_ಗಣ_maxsize(ರಚನೆ ssh *ssh, u_int s)
{
	ರಚನೆ session_state *state = ssh->state;

	ಆದರೆ (state->ಗಣ_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_ಗಾತ್ರ, s);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		ಹಿಂತಿರುಗಿ -1;
	}
	state->ಗಣ_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_ಗಾತ್ರ = s;
	ಹಿಂತಿರುಗಿ s;
}

ಪೂರ್ಣಾಂಕ
ssh_packet_inc_alive_timeouts(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ++ssh->state->keep_alive_timeouts;
}

ಶೂನ್ಯ
ssh_packet_ಗಣ_alive_timeouts(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ssh->state->max_packet_ಗಾತ್ರ;
}

ಶೂನ್ಯ
ssh_packet_ಗಣ_rekey_limits(ರಚನೆ ssh *ssh, uint64_t ಬೈಟುಗಳು, uint32_t seconds)
{
	ಆದರೆ (ಬೈಟುಗಳು == 0 && seconds == 0)
		ಹಿಂತಿರುಗಿ;

	debug3("rekey after %llu bytes, %u seconds", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಬೈಟುಗಳು,
	    (ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ)seconds);
	ssh->state->rekey_ಎಲ್ಲೆ = ಬೈಟುಗಳು;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(ರಚನೆ ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_ಸಮಯ + ssh->state->rekey_interval -
	    monotime();
	ಹಿಂತಿರುಗಿ (seconds <= 0 ? 1 : seconds);
}

ಶೂನ್ಯ
ssh_packet_ಗಣ_server(ರಚನೆ ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

ಶೂನ್ಯ
ssh_packet_ಗಣ_authenticated(ರಚನೆ ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

ಶೂನ್ಯ *
ssh_packet_get_ಒಳಹರಿವು(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ (ಶೂನ್ಯ *)ssh->state->ಒಳಹರಿವು;
}

ಶೂನ್ಯ *
ssh_packet_get_output(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ (ಶೂನ್ಯ *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_packet_ಗಣ_postauth(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	ಆದರೆ ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_ಗಮ್ಯ_blob(ರಚನೆ sshbuf *m, ರಚನೆ kex *kex)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
	    (r = sshbuf_put_cstring(m, kex->hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_strict)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->client_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->server_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->flags)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->non_pq_kex_warned)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

/* turn key exchange results into a blob for packet state serialization */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
newkeys_ಗಮ್ಯ_blob(ರಚನೆ sshbuf *m, ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ)
{
	ರಚನೆ sshbuf *b;
	ರಚನೆ sshcipher_ctx *cc;
	ರಚನೆ sshcomp *comp;
	ರಚನೆ sshenc *enc;
	ರಚನೆ sshmac *mac;
	ರಚನೆ newkeys *newkey;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((newkey = ssh->state->newkeys[ಬಹುಲಕ]) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (ಬಹುಲಕ == ಬಹುಲಕ_ಹೊರಹೋಗು) ? ssh->state->send_context :
	    ssh->state->receive_context;
	ಆದರೆ ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->ಖಂಡ_ಗಾತ್ರ)) != 0 ||
	    (r = sshbuf_put_string(b, enc->ಕೀಲಿ, enc->ಕೀಲಿ_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (cipher_authlen(enc->cipher) == 0) {
		ಆದರೆ ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->ಕೀಲಿ, mac->ಕೀಲಿ_len)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	r = sshbuf_put_stringb(m, b);
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

/* serialize packet state into a blob */
ಪೂರ್ಣಾಂಕ
ssh_packet_get_state(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *m)
{
	ರಚನೆ session_state *state = ssh->state;
	ಪೂರ್ಣಾಂಕ r;

#ವ್ಯಾಖ್ಯಾನಿಸು ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	ಆದರೆ ((r = kex_ಗಮ್ಯ_blob(m, ssh->kex)) != 0 ||
	    (r = newkeys_ಗಮ್ಯ_blob(m, ssh, ಬಹುಲಕ_ಹೊರಹೋಗು)) != 0 ||
	    (r = newkeys_ಗಮ್ಯ_blob(m, ssh, ಬಹುಲಕ_ಒಳ)) != 0 ||
	    (r = sshbuf_put_u64(m, state->rekey_ಎಲ್ಲೆ)) != 0 ||
	    (r = sshbuf_put_u32(m, state->rekey_interval)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.ಖಂಡಗಳು)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.ಬೈಟುಗಳು)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.ಖಂಡಗಳು)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.ಬೈಟುಗಳು)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->ಒಳಹರಿವು)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_ಬಹುಲಕ))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		ಹಿಂತಿರುಗಿ r;
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ENCODE_INT
	ಹಿಂತಿರುಗಿ 0;
}

/* restore key exchange results from blob for packet state de-serialization */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
newkeys_from_blob(ರಚನೆ sshbuf *m, ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ರಚನೆ sshcomp *comp;
	ರಚನೆ sshenc *enc;
	ರಚನೆ sshmac *mac;
	ರಚನೆ newkeys *newkey = ಖಾಲಿ;
	ಗಾತ್ರ_t keylen, ivlen, maclen;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((newkey = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*newkey))) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_froms(m, &b)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	sshbuf_dump(b, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	ಆದರೆ ((r = sshbuf_get_cstring(b, &enc->name, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->ಖಂಡ_ಗಾತ್ರ)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->ಕೀಲಿ, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((enc->cipher = cipher_by_name(enc->name)) == ಖಾಲಿ ||
	    enc->ಖಂಡ_ಗಾತ್ರ != cipher_blocksize(enc->cipher) ||
	    cipher_is_ಆಂತರಿಕ(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (cipher_authlen(enc->cipher) == 0) {
		ಆದರೆ ((r = sshbuf_get_cstring(b, &mac->name, ಖಾಲಿ)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ ((r = mac_ಸಿದ್ಧತೆ(mac, mac->name)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->ಕೀಲಿ, &maclen)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (maclen != mac->ಕೀಲಿ_len) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		mac->ಕೀಲಿ_len = maclen;
	}
	ಆದರೆ ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	enc->ಕೀಲಿ_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[ಬಹುಲಕ] = newkey;
	newkey = ಖಾಲಿ;
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(newkey);
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

/* restore kex from blob for packet state de-serialization */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_from_blob(ರಚನೆ sshbuf *m, ರಚನೆ kex **kexp)
{
	ರಚನೆ kex *kex;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((kex = kex_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_type)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_type)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_strict)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->client_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->server_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->flags)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->non_pq_kex_warned)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	kex->server = 1;
	kex->ಮುಗಿದ = 1;
	r = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (r != 0 || kexp == ಖಾಲಿ) {
		kex_free(kex);
		ಆದರೆ (kexp != ಖಾಲಿ)
			*kexp = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ {
		kex_free(*kexp);
		*kexp = kex;
	}
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
ಪೂರ್ಣಾಂಕ
ssh_packet_ಗಣ_state(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *m)
{
	ರಚನೆ session_state *state = ssh->state;
	ಸ್ಥಿರಾಂಕ u_char *ಒಳಹರಿವು, *output;
	ಗಾತ್ರ_t ilen, olen;
	ಪೂರ್ಣಾಂಕ r;
	u_int interactive, qos_interactive, qos_other;

	ಆದರೆ ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, ಬಹುಲಕ_ಹೊರಹೋಗು)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, ಬಹುಲಕ_ಒಳ)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->rekey_ಎಲ್ಲೆ)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->rekey_interval)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.ಖಂಡಗಳು)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.ಬೈಟುಗಳು)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.ಖಂಡಗಳು)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.ಬೈಟುಗಳು)) != 0)
		ಹಿಂತಿರುಗಿ r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_ಸಮಯ = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	ಆದರೆ ((r = ssh_ಗಣ_newkeys(ssh, ಬಹುಲಕ_ಒಳ)) != 0 ||
	    (r = ssh_ಗಣ_newkeys(ssh, ಬಹುಲಕ_ಹೊರಹೋಗು)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಆದರೆ ((r = ssh_packet_ಗಣ_postauth(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;

	sshbuf_reset(state->ಒಳಹರಿವು);
	sshbuf_reset(state->output);
	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(m, &ಒಳಹರಿವು, &ilen)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->ಒಳಹರಿವು, ಒಳಹರಿವು, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಆದರೆ ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		ಹಿಂತಿರುಗಿ r;
#ವ್ಯಾಖ್ಯಾನಿಸು DECODE_INT(v) ((v) > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ ? -1 : (ಪೂರ್ಣಾಂಕ)(v))
	state->interactive_ಬಹುಲಕ = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು DECODE_INT

	ಆದರೆ (sshbuf_len(m))
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	ಹಿಂತಿರುಗಿ 0;
}

/* NEW API */

/* put data to the outgoing packet */

ಪೂರ್ಣಾಂಕ
sshpkt_put(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len)
{
	ಹಿಂತಿರುಗಿ sshbuf_put(ssh->state->outgoing_packet, v, len);
}

ಪೂರ್ಣಾಂಕ
sshpkt_putb(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b)
{
	ಹಿಂತಿರುಗಿ sshbuf_putb(ssh->state->outgoing_packet, b);
}

ಪೂರ್ಣಾಂಕ
sshpkt_put_u8(ರಚನೆ ssh *ssh, u_char val)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

ಪೂರ್ಣಾಂಕ
sshpkt_put_u32(ರಚನೆ ssh *ssh, uint32_t val)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

ಪೂರ್ಣಾಂಕ
sshpkt_put_u64(ರಚನೆ ssh *ssh, uint64_t val)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

ಪೂರ್ಣಾಂಕ
sshpkt_put_string(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

ಪೂರ್ಣಾಂಕ
sshpkt_put_cstring(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

ಪೂರ್ಣಾಂಕ
sshpkt_put_stringb(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *v)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಪೂರ್ಣಾಂಕ
sshpkt_put_ec(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *v, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

ಪೂರ್ಣಾಂಕ
sshpkt_put_ec_pkey(ರಚನೆ ssh *ssh, EVP_PKEY *pkey)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

ಪೂರ್ಣಾಂಕ
sshpkt_put_bignum2(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ BIGNUM *v)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

/* fetch data from the incoming packet */

ಪೂರ್ಣಾಂಕ
sshpkt_get(ರಚನೆ ssh *ssh, ಶೂನ್ಯ *valp, ಗಾತ್ರ_t len)
{
	ಹಿಂತಿರುಗಿ sshbuf_get(ssh->state->incoming_packet, valp, len);
}

ಪೂರ್ಣಾಂಕ
sshpkt_get_u8(ರಚನೆ ssh *ssh, u_char *valp)
{
	ಹಿಂತಿರುಗಿ sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

ಪೂರ್ಣಾಂಕ
sshpkt_get_u32(ರಚನೆ ssh *ssh, uint32_t *valp)
{
	ಹಿಂತಿರುಗಿ sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

ಪೂರ್ಣಾಂಕ
sshpkt_get_u64(ರಚನೆ ssh *ssh, uint64_t *valp)
{
	ಹಿಂತಿರುಗಿ sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

ಪೂರ್ಣಾಂಕ
sshpkt_get_string(ರಚನೆ ssh *ssh, u_char **valp, ಗಾತ್ರ_t *lenp)
{
	ಹಿಂತಿರುಗಿ sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

ಪೂರ್ಣಾಂಕ
sshpkt_get_string_ನೇರ(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ u_char **valp, ಗಾತ್ರ_t *lenp)
{
	ಹಿಂತಿರುಗಿ sshbuf_get_string_ನೇರ(ssh->state->incoming_packet, valp, lenp);
}

ಪೂರ್ಣಾಂಕ
sshpkt_peek_string_ನೇರ(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ u_char **valp, ಗಾತ್ರ_t *lenp)
{
	ಹಿಂತಿರುಗಿ sshbuf_peek_string_ನೇರ(ssh->state->incoming_packet, valp, lenp);
}

ಪೂರ್ಣಾಂಕ
sshpkt_get_cstring(ರಚನೆ ssh *ssh, ಅಕ್ಷರ **valp, ಗಾತ್ರ_t *lenp)
{
	ಹಿಂತಿರುಗಿ sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

ಪೂರ್ಣಾಂಕ
sshpkt_getb_froms(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf **valp)
{
	ಹಿಂತಿರುಗಿ sshbuf_froms(ssh->state->incoming_packet, valp);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಪೂರ್ಣಾಂಕ
sshpkt_get_ec(ರಚನೆ ssh *ssh, EC_ಬಿಂದು *v, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g)
{
	ಹಿಂತಿರುಗಿ sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

ಪೂರ್ಣಾಂಕ
sshpkt_get_bignum2(ರಚನೆ ssh *ssh, BIGNUM **valp)
{
	ಹಿಂತಿರುಗಿ sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಪೂರ್ಣಾಂಕ
sshpkt_get_ಕೊನೆ(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (sshbuf_len(ssh->state->incoming_packet) > 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರಾಂಕ u_char *
sshpkt_ptr(ರಚನೆ ssh *ssh, ಗಾತ್ರ_t *lenp)
{
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	ಹಿಂತಿರುಗಿ sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

ಪೂರ್ಣಾಂಕ
sshpkt_ಆರಂಭ(ರಚನೆ ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, ಗಾತ್ರ(buf));
	buf[ಗಾತ್ರ(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	ಹಿಂತಿರುಗಿ sshbuf_put(ssh->state->outgoing_packet, buf, ಗಾತ್ರ(buf));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_packet_send_mux(ರಚನೆ ssh *ssh)
{
	ರಚನೆ session_state *state = ssh->state;
	u_char type, *cp;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ssh->kex)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	ಆದರೆ (len < 6)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	ಆದರೆ (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	ಆದರೆ (type >= SSH2_ಸಂದೇಶ_CONNECTION_MIN &&
	    type <= SSH2_ಸಂದೇಶ_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		ಆದರೆ ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			ಹಿಂತಿರುಗಿ r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	ಹಿಂತಿರುಗಿ 0;
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
ಪೂರ್ಣಾಂಕ
sshpkt_ಸಂದೇಶ_ignore(ರಚನೆ ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಗಾಗಿ (i = 0; i < nbytes; i++) {
		ಆದರೆ (i % 4 == 0)
			rnd = arc4random();
		ಆದರೆ ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			ಹಿಂತಿರುಗಿ r;
		rnd >>= 8;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* send it */

ಪೂರ್ಣಾಂಕ
sshpkt_send(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (ssh->state && ssh->state->mux)
		ಹಿಂತಿರುಗಿ ssh_packet_send_mux(ssh);
	ಹಿಂತಿರುಗಿ ssh_packet_send2(ssh);
}

ಪೂರ್ಣಾಂಕ
sshpkt_disconnect(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt,...)
{
	ಅಕ್ಷರ buf[1024];
	va_list ವಾದಗಳು;
	ಪೂರ್ಣಾಂಕ r;

	va_start(ವಾದಗಳು, fmt);
	vsnprintf(buf, ಗಾತ್ರ(buf), fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

/* roundup current message to pad bytes */
ಪೂರ್ಣಾಂಕ
sshpkt_ಕೂಡಿಸು_padding(ರಚನೆ ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
format_traffic_stats(ರಚನೆ packet_state *ps)
{
	ಅಕ್ಷರ *stats = ಖಾಲಿ, ಬೈಟುಗಳು[FMT_SCALED_STRSIZE];

	ಆದರೆ (ps->ಬೈಟುಗಳು > LLONG_MAX || fmt_scaled(ps->ಬೈಟುಗಳು, ಬೈಟುಗಳು) != 0)
		strlcpy(ಬೈಟುಗಳು, "OVERFLOW", ಗಾತ್ರ(ಬೈಟುಗಳು));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)ps->packets, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ps->ಖಂಡಗಳು, ಬೈಟುಗಳು);
	ಹಿಂತಿರುಗಿ stats;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
dedupe_alg_ಹೆಸರುಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಒಳ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಹೊರಹೋಗು)
{
	ಅಕ್ಷರ *ಹೆಸರುಗಳು = ಖಾಲಿ;

	ಆದರೆ (ಒಳ == ಖಾಲಿ)
		ಒಳ = "<implicit>";
	ಆದರೆ (ಹೊರಹೋಗು == ಖಾಲಿ)
		ಹೊರಹೋಗು = "<implicit>";

	ಆದರೆ (strcmp(ಒಳ, ಹೊರಹೋಗು) == 0) {
		ಹೆಸರುಗಳು = xstrdup(ಒಳ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		xasprintf(&ಹೆಸರುಗಳು, "%s in, %s out", ಒಳ, ಹೊರಹೋಗು);
	}
	ಹಿಂತಿರುಗಿ ಹೆಸರುಗಳು;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
comp_ಸ್ಥಿತಿ_ಸಂದೇಶ(ರಚನೆ ssh *ssh)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
	ಅಕ್ಷರ *ret = ಖಾಲಿ;
	ರಚನೆ session_state *state = ssh->state;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	ಅಕ್ಷರ iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	ಅಕ್ಷರ icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	ಆದರೆ (state->compression_ಬಫರ್) {
		ಆದರೆ (state->compression_ಒಳ_started) {
			iraw = state->compression_ಒಳ_ಹರಿವು.ಒಟ್ಟು_ಹೊರಹೋಗು;
			icmp = state->compression_ಒಳ_ಹರಿವು.ಒಟ್ಟು_ಒಳ;
			ಆದರೆ (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", ಗಾತ್ರ(iraw_f));
			ಆದರೆ (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", ಗಾತ್ರ(icmp_f));
		}
		ಆದರೆ (state->compression_ಹೊರಹೋಗು_started) {
			oraw = state->compression_ಹೊರಹೋಗು_ಹರಿವು.ಒಟ್ಟು_ಒಳ;
			ocmp = state->compression_ಹೊರಹೋಗು_ಹರಿವು.ಒಟ್ಟು_ಹೊರಹೋಗು;
			ಆದರೆ (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", ಗಾತ್ರ(oraw_f));
			ಆದರೆ (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", ಗಾತ್ರ(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (ದ್ವಿಗುಣ)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (ದ್ವಿಗುಣ)ocmp / oraw);
		ಹಿಂತಿರುಗಿ ret;
	}
#ಆದರೆ_ಅಂತ್ಯ	/* WITH_ZLIB */
	ಹಿಂತಿರುಗಿ xstrdup("");
}

ಅಕ್ಷರ *
connection_info_ಸಂದೇಶ(ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ *ret = ಖಾಲಿ, *cipher = ಖಾಲಿ, *mac = ಖಾಲಿ, *comp = ಖಾಲಿ;
	ಅಕ್ಷರ *rekey_volume = ಖಾಲಿ, *rekey_ಸಮಯ = ಖಾಲಿ, *comp_info = ಖಾಲಿ;
	ಅಕ್ಷರ thishost[NI_MAXHOST] = "unknown", *tcp_info = ಖಾಲಿ;
	ರಚನೆ kex *kex;
	ರಚನೆ session_state *state;
	ರಚನೆ newkeys *nk_ಒಳ, *nk_ಹೊರಹೋಗು;
	ಅಕ್ಷರ *stats_ಒಳ = ಖಾಲಿ, *stats_ಹೊರಹೋಗು = ಖಾಲಿ;
	uint64_t epoch = (uint64_t)time(ಖಾಲಿ) - monotime();

	ಆದರೆ (ssh == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	state = ssh->state;
	kex = ssh->kex;

	(ಶೂನ್ಯ)gethostname(thishost, ಗಾತ್ರ(thishost));

	ಆದರೆ (ssh_local_ಪೋರ್ಟ್(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_ಪೋರ್ಟ್(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
	} ಇಲ್ಲದಿದ್ದರೆ {
		tcp_info = xstrdup("");
	}

	nk_ಒಳ = ssh->state->newkeys[ಬಹುಲಕ_ಒಳ];
	nk_ಹೊರಹೋಗು = ssh->state->newkeys[ಬಹುಲಕ_ಹೊರಹೋಗು];
	stats_ಒಳ = format_traffic_stats(&ssh->state->p_read);
	stats_ಹೊರಹೋಗು = format_traffic_stats(&ssh->state->p_send);

	cipher = dedupe_alg_ಹೆಸರುಗಳು(nk_ಒಳ->enc.name, nk_ಹೊರಹೋಗು->enc.name);
	mac = dedupe_alg_ಹೆಸರುಗಳು(nk_ಒಳ->mac.name, nk_ಹೊರಹೋಗು->mac.name);
	comp = dedupe_alg_ಹೆಸರುಗಳು(nk_ಒಳ->comp.name, nk_ಹೊರಹೋಗು->comp.name);

	/* Volume based rekeying. */
	ಆದರೆ (state->rekey_ಎಲ್ಲೆ == 0) {
		xasprintf(&rekey_volume, "limit none");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಅಕ್ಷರ *volumes = ಖಾಲಿ, ಒಳ[32], ಹೊರಹೋಗು[32];

		snprintf(ಒಳ, ಗಾತ್ರ(ಒಳ), "%llu",
		   (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)state->max_ಖಂಡಗಳು_ಒಳ);
		snprintf(ಹೊರಹೋಗು, ಗಾತ್ರ(ಹೊರಹೋಗು), "%llu",
		   (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)state->max_ಖಂಡಗಳು_ಹೊರಹೋಗು);
		volumes = dedupe_alg_ಹೆಸರುಗಳು(ಒಳ, ಹೊರಹೋಗು);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		ಬಿಡುಗಡೆ(volumes);
	}

	/* Time based rekeying. */
	ಆದರೆ (state->rekey_interval == 0) {
		rekey_ಸಮಯ = xstrdup("interval none");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಅಕ್ಷರ rekey_ಮುಂದಿನ[64];

		format_absolute_ಸಮಯ(epoch + state->rekey_ಸಮಯ +
		    state->rekey_interval, rekey_ಮುಂದಿನ, ಗಾತ್ರ(rekey_ಮುಂದಿನ));
		xasprintf(&rekey_ಸಮಯ, "interval %s, next %s",
		    fmt_timeframe(state->rekey_interval), rekey_ಮುಂದಿನ);
	}
	comp_info = comp_ಸ್ಥಿತಿ_ಸಂದೇಶ(ssh);

	xasprintf(&ret, "Connection information for %s pid %lld\r\n"
	    "  versions %s -> %s\r\n"
	    "%s"
	    "  duration %s\r\n"
	    "  kexalgorithm %s\r\n  hostkeyalgorithm %s\r\n"
	    "  cipher %s\r\n  mac %s\r\n  compression %s\r\n"
	    "  rekey %s %s\r\n"
	    "  traffic %s in, %s out\r\n"
	    "%s",
	    thishost, (ದೀರ್ಘ ದೀರ್ಘ)getpid(),
	    SSH_RELEASE, ssh->remote_ಆವೃತ್ತಿ,
	    tcp_info,
	    fmt_timeframe(monotime() - state->ಆರಂಭ_ಸಮಯ),
	    kex->name, kex->hostkey_alg,
	    cipher, mac, comp,
	    rekey_volume, rekey_ಸಮಯ,
	    stats_ಒಳ, stats_ಹೊರಹೋಗು,
	    comp_info
	);
	ಬಿಡುಗಡೆ(tcp_info);
	ಬಿಡುಗಡೆ(cipher);
	ಬಿಡುಗಡೆ(mac);
	ಬಿಡುಗಡೆ(comp);
	ಬಿಡುಗಡೆ(stats_ಒಳ);
	ಬಿಡುಗಡೆ(stats_ಹೊರಹೋಗು);
	ಬಿಡುಗಡೆ(rekey_volume);
	ಬಿಡುಗಡೆ(rekey_ಸಮಯ);
	ಬಿಡುಗಡೆ(comp_info);
	ಹಿಂತಿರುಗಿ ret;
}

