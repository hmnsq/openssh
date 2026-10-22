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

#include "includes.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <util.h>

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
#include <zlib.h>
#endif

#include "xmalloc.h"
#include "compat.h"
#include "ssh2.h"
#include "cipher.h"
#include "kex.h"
#include "digest.h"
#include "mac.h"
#include "log.h"
#include "canohost.h"
#include "misc.h"
#include "packet.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "version.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#아니면
#define DBG(x)
#endif

#define PACKET_MAX_SIZE (256 * 1024)

struct packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t blocks;
	uint64_t bytes;
};

struct packet {
	TAILQ_ENTRY(packet) next;
	u_char type;
	struct sshbuf *payload;
};

struct session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	정수 connection_in;
	정수 connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	struct sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	struct sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	struct sshbuf *input;

	/* Buffer for raw output data going to the socket. */
	struct sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	struct sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	struct sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	struct sshbuf *compression_buffer;

#ifdef WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_stream compression_in_stream;
	z_stream compression_out_stream;
#endif
	정수 compression_in_started;
	정수 compression_out_started;
	정수 compression_in_failures;
	정수 compression_out_failures;

	/* default maximum packet size */
	u_int max_packet_size;

	/* Flag indicating whether this module has been initialized. */
	정수 initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t start_time;

	/* Set to true if the connection is interactive. */
	정수 interactive_mode;

	/* Set to true if we are the server side. */
	정수 server_side;

	/* Set to true if we are authenticated. */
	정수 after_authentication;

	정수 keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	정수 packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	struct newkeys *newkeys[MODE_MAX];
	struct packet_state p_read, p_send;

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
	struct sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	정수 rekeying;

	/* Used in ssh_packet_send_mux() */
	정수 mux;

	/* QoS handling */
	정수 qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	정수 set_maxsize_called;

	/* One-off warning about weak ciphers */
	정수 cipher_warning_done;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	정수 disconnecting;

	/* Nagle disabled on socket */
	정수 nodelay_set;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_in;
	void *hook_in_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

struct ssh *
ssh_alloc_session_state(void)
{
	struct ssh *ssh = NULL;
	struct session_state *state = NULL;

	만약 ((ssh = calloc(1, sizeof(*ssh))) == NULL ||
	    (state = calloc(1, sizeof(*state))) == NULL ||
	    (ssh->kex = kex_new()) == NULL ||
	    (state->input = sshbuf_new()) == NULL ||
	    (state->output = sshbuf_new()) == NULL ||
	    (state->outgoing_packet = sshbuf_new()) == NULL ||
	    (state->incoming_packet = sshbuf_new()) == NULL)
		goto fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->private_keys);
	TAILQ_INIT(&ssh->public_keys);
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
	반환 ssh;
 fail:
	만약 (ssh) {
		kex_free(ssh->kex);
		free(ssh);
	}
	만약 (state) {
		sshbuf_free(state->input);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		free(state);
	}
	반환 NULL;
}

void
ssh_packet_set_input_hook(struct ssh *ssh, ssh_packet_hook_fn *hook, void *ctx)
{
	ssh->state->hook_in = hook;
	ssh->state->hook_in_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
정수
ssh_packet_is_rekeying(struct ssh *ssh)
{
	반환 ssh->state->rekeying ||
	    (ssh->kex != NULL && ssh->kex->done == 0);
}

/*
 * Sets the descriptors used for communication.
 */
struct ssh *
ssh_packet_set_connection(struct ssh *ssh, 정수 fd_in, 정수 fd_out)
{
	struct session_state *state;
	const struct sshcipher *none = cipher_by_name("none");
	정수 r, wasnull = ssh == NULL;

	만약 (none == NULL) {
		error_f("cannot load cipher 'none'");
		반환 NULL;
	}
	만약 (ssh == NULL)
		ssh = ssh_alloc_session_state();
	만약 (ssh == NULL) {
		error_f("could not allocate state");
		반환 NULL;
	}
	state = ssh->state;
	state->start_time = monotime();
	state->connection_in = fd_in;
	state->connection_out = fd_out;
	만약 ((r = cipher_init(&state->send_context, none,
	    (const u_char *)"", 0, NULL, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (const u_char *)"", 0, NULL, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		만약 (wasnull)
			free(ssh); /* XXX need ssh_free_session_state? */
		반환 NULL;
	}
	state->newkeys[MODE_IN] = state->newkeys[MODE_OUT] = NULL;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(void)ssh_remote_ipaddr(ssh);
	반환 ssh;
}

void
ssh_packet_set_timeout(struct ssh *ssh, 정수 timeout, 정수 count)
{
	struct session_state *state = ssh->state;

	만약 (timeout <= 0 || count <= 0) {
		state->packet_timeout_ms = -1;
		반환;
	}
	만약 ((INT_MAX / 1000) / count < timeout)
		state->packet_timeout_ms = INT_MAX;
	아니면
		state->packet_timeout_ms = timeout * count * 1000;
}

void
ssh_packet_set_mux(struct ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = NULL;
}

정수
ssh_packet_get_mux(struct ssh *ssh)
{
	반환 ssh->state->mux;
}

정수
ssh_packet_set_log_preamble(struct ssh *ssh, const char *fmt, ...)
{
	va_list args;
	정수 r;

	free(ssh->log_preamble);
	만약 (fmt == NULL)
		ssh->log_preamble = NULL;
	아니면 {
		va_start(args, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, args);
		va_end(args);
		만약 (r < 0 || ssh->log_preamble == NULL)
			반환 SSH_ERR_ALLOC_FAIL;
	}
	반환 0;
}

정수
ssh_packet_stop_discard(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	정수 r;

	만약 (state->packet_discard_mac) {
		char buf[1024];
		size_t dlen = PACKET_MAX_SIZE;

		만약 (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', sizeof(buf));
		동안 (sshbuf_len(state->incoming_packet) < dlen)
			만약 ((r = sshbuf_put(state->incoming_packet, buf,
			    sizeof(buf))) != 0)
				반환 r;
		(void) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    NULL, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	반환 SSH_ERR_MAC_INVALID;
}

static 정수
ssh_packet_start_discard(struct ssh *ssh, struct sshenc *enc,
    struct sshmac *mac, size_t mac_already, u_int discard)
{
	struct session_state *state = ssh->state;
	정수 r;

	만약 (enc == NULL || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		만약 ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			반환 r;
		반환 SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	만약 (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	만약 (sshbuf_len(state->input) >= discard)
		반환 ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->input);
	반환 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

정수
ssh_packet_connection_is_on_socket(struct ssh *ssh)
{
	struct session_state *state;
	struct sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	만약 (ssh == NULL || ssh->state == NULL)
		반환 0;

	state = ssh->state;
	만약 (state->connection_in == -1 || state->connection_out == -1)
		반환 0;
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	만약 (getpeername(state->connection_in, (struct sockaddr *)&from,
	    &fromlen) == -1)
		반환 0;
	만약 (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		반환 0;
	/* filedescriptors in and out are the same, so it's a socket */
	만약 (state->connection_in == state->connection_out)
		반환 1;
	tolen = sizeof(to);
	memset(&to, 0, sizeof(to));
	만약 (getpeername(state->connection_out, (struct sockaddr *)&to,
	    &tolen) == -1)
		반환 0;
	만약 (fromlen != tolen || memcmp(&from, &to, fromlen) != 0)
		반환 0;
	반환 1;
}

void
ssh_packet_get_bytes(struct ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	만약 (ibytes)
		*ibytes = ssh->state->p_read.bytes;
	만약 (obytes)
		*obytes = ssh->state->p_send.bytes;
}

정수
ssh_packet_connection_af(struct ssh *ssh)
{
	반환 get_sock_af(ssh->state->connection_out);
}

/* Sets the connection into non-blocking mode. */

void
ssh_packet_set_nonblocking(struct ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(ssh->state->connection_in);

	만약 (ssh->state->connection_out != ssh->state->connection_in)
		set_nonblock(ssh->state->connection_out);
}

/* Returns the socket used for reading. */

정수
ssh_packet_get_connection_in(struct ssh *ssh)
{
	반환 ssh->state->connection_in;
}

/* Returns the descriptor used for writing. */

정수
ssh_packet_get_connection_out(struct ssh *ssh)
{
	반환 ssh->state->connection_out;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

const char *
ssh_remote_ipaddr(struct ssh *ssh)
{
	정수 sock;

	/* Check whether we have cached the ipaddr. */
	만약 (ssh->remote_ipaddr == NULL) {
		만약 (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_in;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_port = get_peer_port(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_port = get_local_port(sock);
		} 아니면 {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_port = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_port = 65535;
		}
	}
	반환 ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

char *
ssh_remote_hostname(struct ssh *ssh)
{
	struct sockaddr_storage from;
	socklen_t fromlen;
	struct addrinfo hints, *ai, *aitop;
	char name[NI_MAXHOST], ntop2[NI_MAXHOST];
	const char *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	만약 (getpeername(ssh_packet_get_connection_in(ssh),
	    (struct sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		반환 xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	만약 (from.ss_family == AF_INET6)
		fromlen = sizeof(struct sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	만약 (getnameinfo((struct sockaddr *)&from, fromlen, name, sizeof(name),
	    NULL, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		반환 xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	만약 (getaddrinfo(name, NULL, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		반환 xstrdup(ntop);
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
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	만약 (getaddrinfo(name, NULL, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		반환 xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	위해 (ai = aitop; ai; ai = ai->ai_next) {
		만약 (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    sizeof(ntop2), NULL, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				break;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	만약 (ai == NULL) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		반환 xstrdup(ntop);
	}
	반환 xstrdup(name);
}

/* Returns the port number of the remote host. */

정수
ssh_remote_port(struct ssh *ssh)
{
	(void)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	반환 ssh->remote_port;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

const char *
ssh_local_ipaddr(struct ssh *ssh)
{
	(void)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	반환 ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

정수
ssh_local_port(struct ssh *ssh)
{
	(void)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	반환 ssh->local_port;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
const char *
ssh_packet_rdomain_in(struct ssh *ssh)
{
	만약 (ssh->rdomain_in != NULL)
		반환 ssh->rdomain_in;
	만약 (!ssh_packet_connection_is_on_socket(ssh))
		반환 NULL;
	ssh->rdomain_in = get_rdomain(ssh->state->connection_in);
	반환 ssh->rdomain_in;
}

/* Closes the connection and clears and frees internal data structures. */

static void
ssh_packet_close_internal(struct ssh *ssh, 정수 do_close)
{
	struct session_state *state = ssh->state;
	u_int mode;
	struct packet *p;

	만약 (!state->initialized)
		반환;
	state->initialized = 0;
	만약 (do_close) {
		만약 (state->connection_in == state->connection_out) {
			close(state->connection_out);
		} 아니면 {
			close(state->connection_in);
			close(state->connection_out);
		}
	}
	sshbuf_free(state->input);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	동안 ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, next);
		free(p);
	}
	위해 (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(state->newkeys[mode]);	/* current keys */
		state->newkeys[mode] = NULL;
		ssh_clear_newkeys(ssh, mode);		/* next keys */
	}
#ifdef WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	만약 (do_close && state->compression_buffer) {
		sshbuf_free(state->compression_buffer);
		만약 (state->compression_out_started) {
			z_streamp stream = &state->compression_out_stream;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(unsigned long long)stream->total_in,
				(unsigned long long)stream->total_out,
				stream->total_in == 0 ? 0.0 :
				(double) stream->total_out / stream->total_in);
			만약 (state->compression_out_failures == 0)
				deflateEnd(stream);
		}
		만약 (state->compression_in_started) {
			z_streamp stream = &state->compression_in_stream;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (unsigned long long)stream->total_out,
			    (unsigned long long)stream->total_in,
			    stream->total_out == 0 ? 0.0 :
			    (double) stream->total_in / stream->total_out);
			만약 (state->compression_in_failures == 0)
				inflateEnd(stream);
		}
	}
#endif	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = NULL;
	만약 (do_close) {
		free(ssh->local_ipaddr);
		ssh->local_ipaddr = NULL;
		free(ssh->remote_ipaddr);
		ssh->remote_ipaddr = NULL;
		free(ssh->state);
		ssh->state = NULL;
		kex_free(ssh->kex);
		ssh->kex = NULL;
	}
}

void
ssh_packet_free(struct ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
	freezero(ssh, sizeof(*ssh));
}

void
ssh_packet_close(struct ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
}

void
ssh_packet_clear_keys(struct ssh *ssh)
{
	ssh_packet_close_internal(ssh, 0);
}

/* Sets remote side protocol flags. */

void
ssh_packet_set_protocol_flags(struct ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(struct ssh *ssh)
{
	반환 ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

static 정수
ssh_packet_init_compression(struct ssh *ssh)
{
	만약 (!ssh->state->compression_buffer &&
	    ((ssh->state->compression_buffer = sshbuf_new()) == NULL))
		반환 SSH_ERR_ALLOC_FAIL;
	반환 0;
}

#ifdef WITH_ZLIB
static 정수
start_compression_out(struct ssh *ssh)
{
	debug("Enabling compression.");
	만약 (ssh->state->compression_out_started == 1)
		deflateEnd(&ssh->state->compression_out_stream);
	switch (deflateInit2(&ssh->state->compression_out_stream,
	    Z_BEST_SPEED, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	case Z_OK:
		ssh->state->compression_out_started = 1;
		break;
	case Z_MEM_ERROR:
		반환 SSH_ERR_ALLOC_FAIL;
	default:
		반환 SSH_ERR_INTERNAL_ERROR;
	}
	반환 0;
}

static 정수
start_compression_in(struct ssh *ssh)
{
	만약 (ssh->state->compression_in_started == 1)
		inflateEnd(&ssh->state->compression_in_stream);
	switch (inflateInit(&ssh->state->compression_in_stream)) {
	case Z_OK:
		ssh->state->compression_in_started = 1;
		break;
	case Z_MEM_ERROR:
		반환 SSH_ERR_ALLOC_FAIL;
	default:
		반환 SSH_ERR_INTERNAL_ERROR;
	}
	반환 0;
}

/* XXX remove need for separate compression buffer */
static 정수
compress_buffer(struct ssh *ssh, struct sshbuf *in, struct sshbuf *out)
{
	u_char buf[4096];
	정수 r, status;

	만약 (ssh->state->compression_out_started != 1)
		반환 SSH_ERR_INTERNAL_ERROR;

	/* This case is not handled below. */
	만약 (sshbuf_len(in) == 0)
		반환 0;

	/* Input is the contents of the input buffer. */
	만약 ((ssh->state->compression_out_stream.next_in =
	    sshbuf_mutable_ptr(in)) == NULL)
		반환 SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_out_stream.avail_in = sshbuf_len(in);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	do {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_out_stream.next_out = buf;
		ssh->state->compression_out_stream.avail_out = sizeof(buf);

		/* Compress as much data into the buffer as possible. */
		status = deflate(&ssh->state->compression_out_stream,
		    Z_PARTIAL_FLUSH);
		switch (status) {
		case Z_MEM_ERROR:
			반환 SSH_ERR_ALLOC_FAIL;
		case Z_OK:
			/* Append compressed data to output_buffer. */
			만약 ((r = sshbuf_put(out, buf, sizeof(buf) -
			    ssh->state->compression_out_stream.avail_out)) != 0)
				반환 r;
			break;
		case Z_STREAM_ERROR:
		default:
			ssh->state->compression_out_failures++;
			반환 SSH_ERR_INVALID_FORMAT;
		}
	} 동안 (ssh->state->compression_out_stream.avail_out == 0);
	반환 0;
}

static 정수
uncompress_buffer(struct ssh *ssh, struct sshbuf *in, struct sshbuf *out)
{
	u_char buf[4096];
	정수 r, status;

	만약 (ssh->state->compression_in_started != 1)
		반환 SSH_ERR_INTERNAL_ERROR;

	만약 ((ssh->state->compression_in_stream.next_in =
	    sshbuf_mutable_ptr(in)) == NULL)
		반환 SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_in_stream.avail_in = sshbuf_len(in);

	위해 (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_in_stream.next_out = buf;
		ssh->state->compression_in_stream.avail_out = sizeof(buf);

		status = inflate(&ssh->state->compression_in_stream,
		    Z_SYNC_FLUSH);
		switch (status) {
		case Z_OK:
			만약 ((r = sshbuf_put(out, buf, sizeof(buf) -
			    ssh->state->compression_in_stream.avail_out)) != 0)
				반환 r;
			만약 (sshbuf_len(out) >= PACKET_MAX_SIZE)
				반환 SSH_ERR_INVALID_FORMAT;
			break;
		case Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			반환 0;
		case Z_DATA_ERROR:
			반환 SSH_ERR_INVALID_FORMAT;
		case Z_MEM_ERROR:
			반환 SSH_ERR_ALLOC_FAIL;
		case Z_STREAM_ERROR:
		default:
			ssh->state->compression_in_failures++;
			반환 SSH_ERR_INTERNAL_ERROR;
		}
	}
	/* NOTREACHED */
}

#아니면	/* WITH_ZLIB */

static 정수
start_compression_out(struct ssh *ssh)
{
	반환 SSH_ERR_INTERNAL_ERROR;
}

static 정수
start_compression_in(struct ssh *ssh)
{
	반환 SSH_ERR_INTERNAL_ERROR;
}

static 정수
compress_buffer(struct ssh *ssh, struct sshbuf *in, struct sshbuf *out)
{
	반환 SSH_ERR_INTERNAL_ERROR;
}

static 정수
uncompress_buffer(struct ssh *ssh, struct sshbuf *in, struct sshbuf *out)
{
	반환 SSH_ERR_INTERNAL_ERROR;
}
#endif	/* WITH_ZLIB */

void
ssh_clear_newkeys(struct ssh *ssh, 정수 mode)
{
	만약 (ssh->kex && ssh->kex->newkeys[mode]) {
		kex_free_newkeys(ssh->kex->newkeys[mode]);
		ssh->kex->newkeys[mode] = NULL;
	}
}

정수
ssh_set_newkeys(struct ssh *ssh, 정수 mode)
{
	struct session_state *state = ssh->state;
	struct sshenc *enc;
	struct sshmac *mac;
	struct sshcomp *comp;
	struct sshcipher_ctx **ccp;
	struct packet_state *ps;
	uint64_t *max_blocks, *hard_max_blocks;
	const char *wmsg;
	정수 r, crypt_type;
	const char *dir = mode == MODE_OUT ? "out" : "in";

	debug2_f("mode %d", mode);

	만약 (mode == MODE_OUT) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_blocks = &state->hard_max_blocks_out;
		max_blocks = &state->max_blocks_out;
	} 아니면 {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_blocks = &state->hard_max_blocks_in;
		max_blocks = &state->max_blocks_in;
	}
	만약 (state->newkeys[mode] != NULL) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (unsigned long long)state->p_read.bytes,
		    (unsigned long long)state->p_read.blocks,
		    (unsigned long long)state->p_send.bytes,
		    (unsigned long long)state->p_send.blocks);
		kex_free_newkeys(state->newkeys[mode]);
		state->newkeys[mode] = NULL;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->blocks = 0;
	/* move newkeys from kex to state */
	만약 ((state->newkeys[mode] = ssh->kex->newkeys[mode]) == NULL)
		반환 SSH_ERR_INTERNAL_ERROR;
	ssh->kex->newkeys[mode] = NULL;
	enc  = &state->newkeys[mode]->enc;
	mac  = &state->newkeys[mode]->mac;
	comp = &state->newkeys[mode]->comp;
	만약 (cipher_authlen(enc->cipher) == 0) {
		만약 ((r = mac_init(mac)) != 0)
			반환 r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = NULL;
	만약 ((r = cipher_init(ccp, enc->cipher, enc->key, enc->key_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		반환 r;
	만약 (!state->cipher_warning_done &&
	    (wmsg = cipher_warning_message(*ccp)) != NULL) {
		error("Warning: %s", wmsg);
		state->cipher_warning_done = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	만약 (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		만약 ((r = ssh_packet_init_compression(ssh)) < 0)
			반환 r;
		만약 (mode == MODE_OUT) {
			만약 ((r = start_compression_out(ssh)) != 0)
				반환 r;
		} 아니면 {
			만약 ((r = start_compression_in(ssh)) != 0)
				반환 r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	만약 (enc->block_size >= 16)
		*hard_max_blocks = (uint64_t)1 << (enc->block_size*2);
	아니면
		*hard_max_blocks = ((uint64_t)1 << 30) / enc->block_size;
	*max_blocks = *hard_max_blocks;
	만약 (state->rekey_limit) {
		*max_blocks = MINIMUM(*max_blocks,
		    state->rekey_limit / enc->block_size);
	}
	debug("rekey %s after %llu blocks", dir,
	    (unsigned long long)*max_blocks);
	반환 0;
}

#define MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
static inline 정수
ssh_packet_check_rekey_blocklimit(struct ssh *ssh, u_int packet_len, 정수 hard)
{
	struct session_state *state = ssh->state;
	uint32_t out_blocks;
	const uint64_t max_blocks_in = hard ?
	    state->hard_max_blocks_in : state->max_blocks_in;
	const uint64_t max_blocks_out = hard ?
	    state->hard_max_blocks_out : state->max_blocks_out;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	만약 (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		반환 1;

	만약 (state->newkeys[MODE_OUT] == NULL)
		반환 0;

	/* Rekey after (cipher-specific) maximum blocks */
	out_blocks = ROUNDUP(packet_len,
	    state->newkeys[MODE_OUT]->enc.block_size);
	반환 (max_blocks_out &&
	    (state->p_send.blocks + out_blocks > max_blocks_out)) ||
	    (max_blocks_in &&
	    (state->p_read.blocks > max_blocks_in));
}

static 정수
ssh_packet_need_rekeying(struct ssh *ssh, u_int outbound_packet_len)
{
	struct session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	만약 (!state->after_authentication)
		반환 0;

	/* Haven't keyed yet or KEX in progress. */
	만약 (ssh_packet_is_rekeying(ssh))
		반환 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	만약 (state->p_send.packets == 0 && state->p_read.packets == 0)
		반환 0;

	/* Time-based rekeying */
	만약 (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_time + state->rekey_interval <= monotime())
		반환 1;

	반환 ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
static 정수
ssh_packet_check_rekey_preauth(struct ssh *ssh, u_int outgoing_packet_len)
{
	만약 (ssh->state->after_authentication)
		반환 0;

	만약 (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		반환 SSH_ERR_NEED_REKEY;
	}
	반환 0;
}

정수
ssh_packet_check_rekey(struct ssh *ssh)
{
	정수 r;

	만약 ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		반환 r;
	만약 (!ssh_packet_need_rekeying(ssh, 0))
		반환 0;
	debug3_f("rekex triggered");
	반환 kex_start_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
static 정수
ssh_packet_enable_delayed_compress(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	struct sshcomp *comp = NULL;
	정수 r, mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	위해 (mode = 0; mode < MODE_MAX; mode++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		만약 (state->newkeys[mode] == NULL)
			continue;
		comp = &state->newkeys[mode]->comp;
		만약 (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			만약 ((r = ssh_packet_init_compression(ssh)) != 0)
				반환 r;
			만약 (mode == MODE_OUT) {
				만약 ((r = start_compression_out(ssh)) != 0)
					반환 r;
			} 아니면 {
				만약 ((r = start_compression_in(ssh)) != 0)
					반환 r;
			}
			comp->enabled = 1;
		}
	}
	반환 0;
}

/* Used to mute debug logging for noisy packet types */
정수
ssh_packet_log_type(u_char type)
{
	switch (type) {
	case SSH2_MSG_PING:
	case SSH2_MSG_PONG:
	case SSH2_MSG_CHANNEL_DATA:
	case SSH2_MSG_CHANNEL_EXTENDED_DATA:
	case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
		반환 0;
	default:
		반환 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
정수
ssh_packet_send2_wrapped(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_LENGTH];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	struct sshenc *enc   = NULL;
	struct sshmac *mac   = NULL;
	struct sshcomp *comp = NULL;
	정수 r, block_size;

	만약 (state->newkeys[MODE_OUT] != NULL) {
		enc  = &state->newkeys[MODE_OUT]->enc;
		mac  = &state->newkeys[MODE_OUT]->mac;
		comp = &state->newkeys[MODE_OUT]->comp;
		/* disable mac for authenticated encryption */
		만약 ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = NULL;
	}
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	만약 (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#endif

	만약 (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		만약 ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			goto out;
		sshbuf_reset(state->compression_buffer);
		만약 ((r = compress_buffer(ssh, state->outgoing_packet,
		    state->compression_buffer)) != 0)
			goto out;
		sshbuf_reset(state->outgoing_packet);
		만약 ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_buffer)) != 0)
			goto out;
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
	만약 (padlen < 4)
		padlen += block_size;
	만약 (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, block_size);
		/* check if roundup overflowed */
		만약 (state->extra_pad < tmp)
			반환 SSH_ERR_INVALID_ARGUMENT;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		만약 (tmp > state->extra_pad)
			반환 SSH_ERR_INVALID_ARGUMENT;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		만약 (padlen < tmp)
			반환 SSH_ERR_INVALID_ARGUMENT; /* overflow */
		state->extra_pad = 0;
	}
	만약 ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		goto out;
	만약 (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} 아니면 {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	만약 (cp == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	만약 (mac && mac->enabled && !mac->etm) {
		만약 ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, sizeof(macbuf))) != 0)
			goto out;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	만약 ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		goto out;
	만약 ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		goto out;
	/* append unencrypted MAC */
	만약 (mac && mac->enabled) {
		만약 (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			만약 ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, sizeof(macbuf))) != 0)
				goto out;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		만약 ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			goto out;
	}
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#endif
	/* increment sequence number for outgoing packets */
	만약 (++state->p_send.seqnr == 0) {
		만약 ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	만약 (++state->p_send.packets == 0)
		반환 SSH_ERR_NEED_REKEY;
	state->p_send.blocks += len / block_size;
	state->p_send.bytes += len;
	sshbuf_reset(state->outgoing_packet);

	만약 (type == SSH2_MSG_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	만약 (type == SSH2_MSG_NEWKEYS)
		r = ssh_set_newkeys(ssh, MODE_OUT);
	아니면 만약 (type == SSH2_MSG_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	아니면
		r = 0;
 out:
	반환 r;
}

/* returns non-zero if the specified packet type is usec by KEX */
static 정수
ssh_packet_type_is_kex(u_char type)
{
	반환
	    type >= SSH2_MSG_TRANSPORT_MIN &&
	    type <= SSH2_MSG_TRANSPORT_MAX &&
	    type != SSH2_MSG_SERVICE_REQUEST &&
	    type != SSH2_MSG_SERVICE_ACCEPT &&
	    type != SSH2_MSG_EXT_INFO;
}

정수
ssh_packet_send2(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	struct packet *p;
	u_char type;
	정수 r, need_rekey;

	만약 (sshbuf_len(state->outgoing_packet) < 6)
		반환 SSH_ERR_INTERNAL_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	만약 (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		반환 r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	만약 ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		만약 (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = calloc(1, sizeof(*p));
		만약 (p == NULL)
			반환 SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, next);
		state->outgoing_packet = sshbuf_new();
		만약 (state->outgoing_packet == NULL)
			반환 SSH_ERR_ALLOC_FAIL;
		만약 (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			반환 kex_start_rekex(ssh);
		}
		반환 0;
	}

	/* rekeying starts with sending KEXINIT */
	만약 (type == SSH2_MSG_KEXINIT)
		state->rekeying = 1;

	만약 ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		반환 r;

	/* after a NEWKEYS message we can send the complete queue */
	만약 (type == SSH2_MSG_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_time = monotime();
		동안 ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			만약 (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				반환 kex_start_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, next);
			memset(p, 0, sizeof(*p));
			free(p);
			만약 ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				반환 r;
		}
	}
	반환 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

정수
ssh_packet_read_seqnr(struct ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	정수 len, r, ms_remain = 0;
	struct pollfd pfd;
	char buf[8192];
	struct timeval start;
	struct timespec timespec, *timespecp = NULL;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	만약 ((r = ssh_packet_write_wait(ssh)) != 0)
		goto out;

	/* Stay in the loop until we have received a complete packet. */
	위해 (;;) {
		/* Try to read a packet from the buffer. */
		만약 ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			break;
		/* If we got a packet, return it. */
		만약 (*typep != SSH_MSG_NONE)
			break;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_in;
		pfd.events = POLLIN;

		만약 (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		위해 (;;) {
			만약 (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			만약 ((r = ppoll(&pfd, 1, timespecp, NULL)) >= 0)
				break;
			만약 (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				goto out;
			}
			만약 (state->packet_timeout_ms <= 0)
				continue;
			ms_subtract_diff(&start, &ms_remain);
			만약 (ms_remain <= 0) {
				r = 0;
				break;
			}
		}
		만약 (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			goto out;
		}
		/* Read data from the socket. */
		len = read(state->connection_in, buf, sizeof(buf));
		만약 (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			goto out;
		}
		만약 (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			goto out;
		}

		/* Append it to the buffer. */
		만약 ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			goto out;
	}
 out:
	반환 r;
}

정수
ssh_packet_read(struct ssh *ssh)
{
	u_char type;
	정수 r;

	만약 ((r = ssh_packet_read_seqnr(ssh, &type, NULL)) != 0)
		sshpkt_fatal(ssh, r, "read");
	반환 type;
}

static 정수
ssh_packet_read_poll2_mux(struct ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	const u_char *cp;
	size_t need;
	정수 r;

	만약 (ssh->kex)
		반환 SSH_ERR_INTERNAL_ERROR;
	*typep = SSH_MSG_NONE;
	cp = sshbuf_ptr(state->input);
	만약 (state->packlen == 0) {
		만약 (sshbuf_len(state->input) < 4 + 1)
			반환 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		만약 (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_SIZE)
			반환 SSH_ERR_MESSAGE_INCOMPLETE;
	}
	need = state->packlen + 4;
	만약 (sshbuf_len(state->input) < need)
		반환 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	만약 ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->input, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, NULL)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		반환 r;
	만약 (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	반환 r;
}

정수
ssh_packet_read_poll2(struct ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, block_size;
	struct sshenc *enc   = NULL;
	struct sshmac *mac   = NULL;
	struct sshcomp *comp = NULL;
	정수 r;

	만약 (state->mux)
		반환 ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_MSG_NONE;

	만약 (state->packet_discard)
		반환 0;

	만약 (state->newkeys[MODE_IN] != NULL) {
		enc  = &state->newkeys[MODE_IN]->enc;
		mac  = &state->newkeys[MODE_IN]->mac;
		comp = &state->newkeys[MODE_IN]->comp;
		/* disable mac for authenticated encryption */
		만약 ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = NULL;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	만약 (aadlen && state->packlen == 0) {
		만약 (cipher_get_length(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->input), sshbuf_len(state->input)) != 0)
			반환 0;
		만약 (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			sshbuf_dump(state->input, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			만약 ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				반환 r;
			반환 SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} 아니면 만약 (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		만약 (sshbuf_len(state->input) < block_size)
			반환 0;
		sshbuf_reset(state->incoming_packet);
		만약 ((r = sshbuf_reserve(state->incoming_packet, block_size,
		    &cp)) != 0)
			goto out;
		만약 ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->input),
		    block_size, 0, 0)) != 0)
			goto out;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		만약 (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->input, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			반환 ssh_packet_start_discard(ssh, enc, mac, 0,
			    PACKET_MAX_SIZE);
		}
		만약 ((r = sshbuf_consume(state->input, block_size)) != 0)
			goto out;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	만약 (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} 아니면 {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - block_size;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", block_size, need, maclen, authlen, aadlen));
	만약 (need % block_size != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
		반환 ssh_packet_start_discard(ssh, enc, mac, 0,
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
	만약 (sshbuf_len(state->input) < aadlen + need + authlen + maclen)
		반환 0; /* packet is incomplete */
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->input, stderr);
#endif
	/* EtM: check mac over encrypted input */
	만약 (mac && mac->enabled && mac->etm) {
		만약 ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->input), aadlen + need,
		    sshbuf_ptr(state->input) + aadlen + need + authlen,
		    maclen)) != 0) {
			만약 (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			goto out;
		}
	}
	만약 ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		goto out;
	만약 ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->input), need, aadlen, authlen)) != 0)
		goto out;
	만약 ((r = sshbuf_consume(state->input, aadlen + need + authlen)) != 0)
		goto out;
	만약 (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		만약 (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->input), maclen)) != 0) {
			만약 (r != SSH_ERR_MAC_INVALID)
				goto out;
			logit("Corrupted MAC on input.");
			만약 (need + block_size > PACKET_MAX_SIZE)
				반환 SSH_ERR_INTERNAL_ERROR;
			반환 ssh_packet_start_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_SIZE - need - block_size);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		만약 ((r = sshbuf_consume(state->input, mac->mac_len)) != 0)
			goto out;
	}

	만약 (seqnr_p != NULL)
		*seqnr_p = state->p_read.seqnr;
	만약 (++state->p_read.seqnr == 0) {
		만약 ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	만약 (++state->p_read.packets == 0)
		반환 SSH_ERR_NEED_REKEY;
	state->p_read.blocks += (state->packlen + 4) / block_size;
	state->p_read.bytes += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	만약 (padlen < 4)	{
		만약 ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			반환 r;
		반환 SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	만약 ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_end(state->incoming_packet, padlen)) != 0))
		goto out;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	만약 (comp && comp->enabled) {
		sshbuf_reset(state->compression_buffer);
		만약 ((r = uncompress_buffer(ssh, state->incoming_packet,
		    state->compression_buffer)) != 0)
			goto out;
		sshbuf_reset(state->incoming_packet);
		만약 ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_buffer)) != 0)
			goto out;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	만약 ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		goto out;
	만약 (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	만약 (*typep < SSH2_MSG_MIN) {
		만약 ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			반환 r;
		반환 SSH_ERR_PROTOCOL_ERROR;
	}
	만약 (state->hook_in != NULL &&
	    (r = state->hook_in(ssh, state->incoming_packet, typep,
	    state->hook_in_ctx)) != 0)
		반환 r;
	만약 (*typep == SSH2_MSG_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	아니면
		r = 0;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#endif
	/* reset for next packet */
	state->packlen = 0;
	만약 (*typep == SSH2_MSG_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	만약 ((r = ssh_packet_check_rekey(ssh)) != 0)
		반환 r;
 out:
	반환 r;
}

정수
ssh_packet_read_poll_seqnr(struct ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	struct session_state *state = ssh->state;
	u_int reason, seqnr;
	정수 r;
	u_char *msg;
	const u_char *d;
	size_t len;

	위해 (;;) {
		msg = NULL;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		만약 (r != 0)
			반환 r;
		만약 (*typep == 0) {
			/* no message ready */
			반환 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		만약 (*typep == SSH2_MSG_DISCONNECT) {
			만약 ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &msg, NULL)) != 0)
				반환 r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh), reason, msg);
			free(msg);
			반환 SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		만약 (ssh->kex != NULL &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			반환 0;
		/* Implicitly handle transport-level messages */
		switch (*typep) {
		case SSH2_MSG_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			break;
		case SSH2_MSG_DEBUG:
			만약 ((r = sshpkt_get_u8(ssh, NULL)) != 0 ||
			    (r = sshpkt_get_string(ssh, &msg, NULL)) != 0 ||
			    (r = sshpkt_get_string(ssh, NULL, NULL)) != 0) {
				free(msg);
				반환 r;
			}
			debug("Remote: %.900s", msg);
			free(msg);
			break;
		case SSH2_MSG_UNIMPLEMENTED:
			만약 ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				반환 r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			break;
		case SSH2_MSG_PING:
			만약 ((r = sshpkt_get_string_direct(ssh, &d, &len)) != 0)
				반환 r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			만약 (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				break;
			}
			만약 (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				break;
			}
			만약 ((r = sshpkt_start(ssh, SSH2_MSG_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				반환 r;
			break;
		case SSH2_MSG_PONG:
			만약 ((r = sshpkt_get_string_direct(ssh,
			    NULL, &len)) != 0)
				반환 r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			break;
		default:
			만약 (ssh->kex != NULL &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				반환 SSH_ERR_PROTOCOL_ERROR;
			}
			반환 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
정수
ssh_packet_process_incoming(struct ssh *ssh, const char *buf, u_int len)
{
	struct session_state *state = ssh->state;
	정수 r;

	만약 (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		만약 (len >= state->packet_discard) {
			만약 ((r = ssh_packet_stop_discard(ssh)) != 0)
				반환 r;
		}
		state->packet_discard -= len;
		반환 0;
	}
	만약 ((r = sshbuf_put(state->input, buf, len)) != 0)
		반환 r;

	반환 0;
}

/* Reads and buffers data from the specified fd */
정수
ssh_packet_process_read(struct ssh *ssh, 정수 fd)
{
	struct session_state *state = ssh->state;
	정수 r;
	size_t rlen;

	만약 ((r = sshbuf_read(fd, state->input, PACKET_MAX_SIZE, &rlen)) != 0)
		반환 r;

	만약 (state->packet_discard) {
		만약 ((r = sshbuf_consume_end(state->input, rlen)) != 0)
			반환 r;
		state->keep_alive_timeouts = 0; /* ?? */
		만약 (rlen >= state->packet_discard) {
			만약 ((r = ssh_packet_stop_discard(ssh)) != 0)
				반환 r;
		}
		state->packet_discard -= rlen;
		반환 0;
	}
	반환 0;
}

정수
ssh_packet_remaining(struct ssh *ssh)
{
	반환 sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
void
ssh_packet_send_debug(struct ssh *ssh, const char *fmt,...)
{
	char buf[1024];
	va_list args;
	정수 r;

	만약 ((ssh->compat & SSH_BUG_DEBUG))
		반환;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	debug3("sending debug message: %s", buf);

	만약 ((r = sshpkt_start(ssh, SSH2_MSG_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

void
sshpkt_fmt_connection_id(struct ssh *ssh, char *s, size_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
static void
sshpkt_vfatal(struct ssh *ssh, 정수 r, const char *fmt, va_list ap)
{
	char *tag = NULL, remote_id[512];
	정수 oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, sizeof(remote_id));

	switch (r) {
	case SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_keys(ssh);
		logdie("Connection closed by %s", remote_id);
	case SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_keys(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	case SSH_ERR_DISCONNECTED:
		ssh_packet_clear_keys(ssh);
		logdie("Disconnected from %s", remote_id);
	case SSH_ERR_SYSTEM_ERROR:
		만약 (errno == ECONNRESET) {
			ssh_packet_clear_keys(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
	case SSH_ERR_NO_MAC_ALG_MATCH:
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
	case SSH_ERR_NO_KEX_ALG_MATCH:
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		만약 (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_keys(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	default:
		만약 (vasprintf(&tag, fmt, ap) == -1) {
			ssh_packet_clear_keys(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_keys(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    tag != NULL ? tag : "", tag != NULL ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

void
sshpkt_fatal(struct ssh *ssh, 정수 r, const char *fmt, ...)
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
void
ssh_packet_disconnect(struct ssh *ssh, const char *fmt,...)
{
	char buf[1024], remote_id[512];
	va_list args;
	정수 r;

	/* Guard against recursive invocations. */
	만약 (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, sizeof(remote_id));
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	만약 ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	만약 ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
정수
ssh_packet_write_poll(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	정수 len = sshbuf_len(state->output);
	정수 r;

	만약 (len > 0) {
		len = write(state->connection_out,
		    sshbuf_ptr(state->output), len);
		만약 (len == -1) {
			만약 (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				반환 0;
			반환 SSH_ERR_SYSTEM_ERROR;
		}
		만약 (len == 0)
			반환 SSH_ERR_CONN_CLOSED;
		만약 ((r = sshbuf_consume(state->output, len)) != 0)
			반환 r;
	}
	반환 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
정수
ssh_packet_write_wait(struct ssh *ssh)
{
	정수 ret, r, ms_remain = 0;
	struct timeval start;
	struct timespec timespec, *timespecp = NULL;
	struct session_state *state = ssh->state;
	struct pollfd pfd;

	만약 ((r = ssh_packet_write_poll(ssh)) != 0)
		반환 r;
	동안 (ssh_packet_have_data_to_write(ssh)) {
		pfd.fd = state->connection_out;
		pfd.events = POLLOUT;

		만약 (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		위해 (;;) {
			만약 (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			만약 ((ret = ppoll(&pfd, 1, timespecp, NULL)) >= 0)
				break;
			만약 (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				break;
			만약 (state->packet_timeout_ms <= 0)
				continue;
			ms_subtract_diff(&start, &ms_remain);
			만약 (ms_remain <= 0) {
				ret = 0;
				break;
			}
		}
		만약 (ret == 0)
			반환 SSH_ERR_CONN_TIMEOUT;
		만약 ((r = ssh_packet_write_poll(ssh)) != 0)
			반환 r;
	}
	반환 0;
}

/* Returns true if there is buffered data to write to the connection. */

정수
ssh_packet_have_data_to_write(struct ssh *ssh)
{
	반환 sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

정수
ssh_packet_not_very_much_data_to_write(struct ssh *ssh)
{
	만약 (ssh->state->interactive_mode)
		반환 sshbuf_len(ssh->state->output) < 16384;
	아니면
		반환 sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

정수
ssh_packet_interactive_data_to_write(struct ssh *ssh)
{
	반환 ssh->state->interactive_mode &&
	    sshbuf_len(ssh->state->output) < 256;
}

static void
apply_qos(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	정수 qos = state->interactive_mode ?
	    state->qos_interactive : state->qos_other;

	만약 (!ssh_packet_connection_is_on_socket(ssh))
		반환;
	만약 (!state->nodelay_set) {
		set_nodelay(state->connection_in);
		state->nodelay_set = 1;
	}
	set_sock_tos(ssh->state->connection_in, qos);
}

/* Informs that the current session is interactive. */
void
ssh_packet_set_interactive(struct ssh *ssh, 정수 interactive)
{
	struct session_state *state = ssh->state;

	state->interactive_mode = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
void
ssh_packet_set_qos(struct ssh *ssh, 정수 qos_interactive, 정수 qos_other)
{
	struct session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

정수
ssh_packet_set_maxsize(struct ssh *ssh, u_int s)
{
	struct session_state *state = ssh->state;

	만약 (state->set_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_size, s);
		반환 -1;
	}
	만약 (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		반환 -1;
	}
	state->set_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_size = s;
	반환 s;
}

정수
ssh_packet_inc_alive_timeouts(struct ssh *ssh)
{
	반환 ++ssh->state->keep_alive_timeouts;
}

void
ssh_packet_set_alive_timeouts(struct ssh *ssh, 정수 ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(struct ssh *ssh)
{
	반환 ssh->state->max_packet_size;
}

void
ssh_packet_set_rekey_limits(struct ssh *ssh, uint64_t bytes, uint32_t seconds)
{
	만약 (bytes == 0 && seconds == 0)
		반환;

	debug3("rekey after %llu bytes, %u seconds", (unsigned long long)bytes,
	    (unsigned 정수)seconds);
	ssh->state->rekey_limit = bytes;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(struct ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_time + ssh->state->rekey_interval -
	    monotime();
	반환 (seconds <= 0 ? 1 : seconds);
}

void
ssh_packet_set_server(struct ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

void
ssh_packet_set_authenticated(struct ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

void *
ssh_packet_get_input(struct ssh *ssh)
{
	반환 (void *)ssh->state->input;
}

void *
ssh_packet_get_output(struct ssh *ssh)
{
	반환 (void *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
static 정수
ssh_packet_set_postauth(struct ssh *ssh)
{
	정수 r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	만약 ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		반환 r;
	반환 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
static 정수
kex_to_blob(struct sshbuf *m, struct kex *kex)
{
	정수 r;

	만약 ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
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
		반환 r;
	반환 0;
}

/* turn key exchange results into a blob for packet state serialization */
static 정수
newkeys_to_blob(struct sshbuf *m, struct ssh *ssh, 정수 mode)
{
	struct sshbuf *b;
	struct sshcipher_ctx *cc;
	struct sshcomp *comp;
	struct sshenc *enc;
	struct sshmac *mac;
	struct newkeys *newkey;
	정수 r;

	만약 ((newkey = ssh->state->newkeys[mode]) == NULL)
		반환 SSH_ERR_INTERNAL_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (mode == MODE_OUT) ? ssh->state->send_context :
	    ssh->state->receive_context;
	만약 ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		반환 r;
	만약 ((b = sshbuf_new()) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	만약 ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->block_size)) != 0 ||
	    (r = sshbuf_put_string(b, enc->key, enc->key_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		goto out;
	만약 (cipher_authlen(enc->cipher) == 0) {
		만약 ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->key, mac->key_len)) != 0)
			goto out;
	}
	만약 ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		goto out;
	r = sshbuf_put_stringb(m, b);
 out:
	sshbuf_free(b);
	반환 r;
}

/* serialize packet state into a blob */
정수
ssh_packet_get_state(struct ssh *ssh, struct sshbuf *m)
{
	struct session_state *state = ssh->state;
	정수 r;

#define ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	만약 ((r = kex_to_blob(m, ssh->kex)) != 0 ||
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
	    (r = sshbuf_put_stringb(m, state->input)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_mode))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		반환 r;
#undef ENCODE_INT
	반환 0;
}

/* restore key exchange results from blob for packet state de-serialization */
static 정수
newkeys_from_blob(struct sshbuf *m, struct ssh *ssh, 정수 mode)
{
	struct sshbuf *b = NULL;
	struct sshcomp *comp;
	struct sshenc *enc;
	struct sshmac *mac;
	struct newkeys *newkey = NULL;
	size_t keylen, ivlen, maclen;
	정수 r;

	만약 ((newkey = calloc(1, sizeof(*newkey))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 ((r = sshbuf_froms(m, &b)) != 0)
		goto out;
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	만약 ((r = sshbuf_get_cstring(b, &enc->name, NULL)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->block_size)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->key, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		goto out;
	만약 ((enc->cipher = cipher_by_name(enc->name)) == NULL ||
	    enc->block_size != cipher_blocksize(enc->cipher) ||
	    cipher_is_internal(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	만약 (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	만약 (cipher_authlen(enc->cipher) == 0) {
		만약 ((r = sshbuf_get_cstring(b, &mac->name, NULL)) != 0)
			goto out;
		만약 ((r = mac_setup(mac, mac->name)) != 0)
			goto out;
		만약 ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->key, &maclen)) != 0)
			goto out;
		만약 (maclen != mac->key_len) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		mac->key_len = maclen;
	}
	만약 ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, NULL)) != 0)
		goto out;
	만약 (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	enc->key_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[mode] = newkey;
	newkey = NULL;
	r = 0;
 out:
	free(newkey);
	sshbuf_free(b);
	반환 r;
}

/* restore kex from blob for packet state de-serialization */
static 정수
kex_from_blob(struct sshbuf *m, struct kex **kexp)
{
	struct kex *kex;
	정수 r;

	만약 ((kex = kex_new()) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	만약 ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, NULL)) != 0 ||
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
		goto out;
	만약 (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	kex->server = 1;
	kex->done = 1;
	r = 0;
 out:
	만약 (r != 0 || kexp == NULL) {
		kex_free(kex);
		만약 (kexp != NULL)
			*kexp = NULL;
	} 아니면 {
		kex_free(*kexp);
		*kexp = kex;
	}
	반환 r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
정수
ssh_packet_set_state(struct ssh *ssh, struct sshbuf *m)
{
	struct session_state *state = ssh->state;
	const u_char *input, *output;
	size_t ilen, olen;
	정수 r;
	u_int interactive, qos_interactive, qos_other;

	만약 ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
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
		반환 r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_time = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	만약 ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0 ||
	    (r = ssh_set_newkeys(ssh, MODE_OUT)) != 0)
		반환 r;

	만약 ((r = ssh_packet_set_postauth(ssh)) != 0)
		반환 r;

	sshbuf_reset(state->input);
	sshbuf_reset(state->output);
	만약 ((r = sshbuf_get_string_direct(m, &input, &ilen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->input, input, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		반환 r;

	만약 ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		반환 r;
#define DECODE_INT(v) ((v) > INT_MAX ? -1 : (정수)(v))
	state->interactive_mode = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#undef DECODE_INT

	만약 (sshbuf_len(m))
		반환 SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	반환 0;
}

/* NEW API */

/* put data to the outgoing packet */

정수
sshpkt_put(struct ssh *ssh, const void *v, size_t len)
{
	반환 sshbuf_put(ssh->state->outgoing_packet, v, len);
}

정수
sshpkt_putb(struct ssh *ssh, const struct sshbuf *b)
{
	반환 sshbuf_putb(ssh->state->outgoing_packet, b);
}

정수
sshpkt_put_u8(struct ssh *ssh, u_char val)
{
	반환 sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

정수
sshpkt_put_u32(struct ssh *ssh, uint32_t val)
{
	반환 sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

정수
sshpkt_put_u64(struct ssh *ssh, uint64_t val)
{
	반환 sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

정수
sshpkt_put_string(struct ssh *ssh, const void *v, size_t len)
{
	반환 sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

정수
sshpkt_put_cstring(struct ssh *ssh, const void *v)
{
	반환 sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

정수
sshpkt_put_stringb(struct ssh *ssh, const struct sshbuf *v)
{
	반환 sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#ifdef WITH_OPENSSL
정수
sshpkt_put_ec(struct ssh *ssh, const EC_POINT *v, const EC_GROUP *g)
{
	반환 sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

정수
sshpkt_put_ec_pkey(struct ssh *ssh, EVP_PKEY *pkey)
{
	반환 sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

정수
sshpkt_put_bignum2(struct ssh *ssh, const BIGNUM *v)
{
	반환 sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#endif /* WITH_OPENSSL */

/* fetch data from the incoming packet */

정수
sshpkt_get(struct ssh *ssh, void *valp, size_t len)
{
	반환 sshbuf_get(ssh->state->incoming_packet, valp, len);
}

정수
sshpkt_get_u8(struct ssh *ssh, u_char *valp)
{
	반환 sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

정수
sshpkt_get_u32(struct ssh *ssh, uint32_t *valp)
{
	반환 sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

정수
sshpkt_get_u64(struct ssh *ssh, uint64_t *valp)
{
	반환 sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

정수
sshpkt_get_string(struct ssh *ssh, u_char **valp, size_t *lenp)
{
	반환 sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

정수
sshpkt_get_string_direct(struct ssh *ssh, const u_char **valp, size_t *lenp)
{
	반환 sshbuf_get_string_direct(ssh->state->incoming_packet, valp, lenp);
}

정수
sshpkt_peek_string_direct(struct ssh *ssh, const u_char **valp, size_t *lenp)
{
	반환 sshbuf_peek_string_direct(ssh->state->incoming_packet, valp, lenp);
}

정수
sshpkt_get_cstring(struct ssh *ssh, char **valp, size_t *lenp)
{
	반환 sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

정수
sshpkt_getb_froms(struct ssh *ssh, struct sshbuf **valp)
{
	반환 sshbuf_froms(ssh->state->incoming_packet, valp);
}

#ifdef WITH_OPENSSL
정수
sshpkt_get_ec(struct ssh *ssh, EC_POINT *v, const EC_GROUP *g)
{
	반환 sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

정수
sshpkt_get_bignum2(struct ssh *ssh, BIGNUM **valp)
{
	반환 sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#endif /* WITH_OPENSSL */

정수
sshpkt_get_end(struct ssh *ssh)
{
	만약 (sshbuf_len(ssh->state->incoming_packet) > 0)
		반환 SSH_ERR_UNEXPECTED_TRAILING_DATA;
	반환 0;
}

const u_char *
sshpkt_ptr(struct ssh *ssh, size_t *lenp)
{
	만약 (lenp != NULL)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	반환 sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

정수
sshpkt_start(struct ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, sizeof(buf));
	buf[sizeof(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	반환 sshbuf_put(ssh->state->outgoing_packet, buf, sizeof(buf));
}

static 정수
ssh_packet_send_mux(struct ssh *ssh)
{
	struct session_state *state = ssh->state;
	u_char type, *cp;
	size_t len;
	정수 r;

	만약 (ssh->kex)
		반환 SSH_ERR_INTERNAL_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	만약 (len < 6)
		반환 SSH_ERR_INTERNAL_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	만약 (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	만약 (type >= SSH2_MSG_CONNECTION_MIN &&
	    type <= SSH2_MSG_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		만약 ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			반환 r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	반환 0;
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
정수
sshpkt_msg_ignore(struct ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	정수 r;
	u_int i;

	만약 ((r = sshpkt_start(ssh, SSH2_MSG_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		반환 r;
	위해 (i = 0; i < nbytes; i++) {
		만약 (i % 4 == 0)
			rnd = arc4random();
		만약 ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			반환 r;
		rnd >>= 8;
	}
	반환 0;
}

/* send it */

정수
sshpkt_send(struct ssh *ssh)
{
	만약 (ssh->state && ssh->state->mux)
		반환 ssh_packet_send_mux(ssh);
	반환 ssh_packet_send2(ssh);
}

정수
sshpkt_disconnect(struct ssh *ssh, const char *fmt,...)
{
	char buf[1024];
	va_list args;
	정수 r;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	만약 ((r = sshpkt_start(ssh, SSH2_MSG_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		반환 r;
	반환 0;
}

/* roundup current message to pad bytes */
정수
sshpkt_add_padding(struct ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	반환 0;
}

static char *
format_traffic_stats(struct packet_state *ps)
{
	char *stats = NULL, bytes[FMT_SCALED_STRSIZE];

	만약 (ps->bytes > LLONG_MAX || fmt_scaled(ps->bytes, bytes) != 0)
		strlcpy(bytes, "OVERFLOW", sizeof(bytes));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (unsigned long)ps->packets, (unsigned long long)ps->blocks, bytes);
	반환 stats;
}

static char *
dedupe_alg_names(const char *in, const char *out)
{
	char *names = NULL;

	만약 (in == NULL)
		in = "<implicit>";
	만약 (out == NULL)
		out = "<implicit>";

	만약 (strcmp(in, out) == 0) {
		names = xstrdup(in);
	} 아니면 {
		xasprintf(&names, "%s in, %s out", in, out);
	}
	반환 names;
}

static char *
comp_status_message(struct ssh *ssh)
{
#ifdef WITH_ZLIB
	char *ret = NULL;
	struct session_state *state = ssh->state;
	unsigned long long iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	char iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	char icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	만약 (state->compression_buffer) {
		만약 (state->compression_in_started) {
			iraw = state->compression_in_stream.total_out;
			icmp = state->compression_in_stream.total_in;
			만약 (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", sizeof(iraw_f));
			만약 (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", sizeof(icmp_f));
		}
		만약 (state->compression_out_started) {
			oraw = state->compression_out_stream.total_in;
			ocmp = state->compression_out_stream.total_out;
			만약 (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", sizeof(oraw_f));
			만약 (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", sizeof(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (double)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (double)ocmp / oraw);
		반환 ret;
	}
#endif	/* WITH_ZLIB */
	반환 xstrdup("");
}

char *
connection_info_message(struct ssh *ssh)
{
	char *ret = NULL, *cipher = NULL, *mac = NULL, *comp = NULL;
	char *rekey_volume = NULL, *rekey_time = NULL, *comp_info = NULL;
	char thishost[NI_MAXHOST] = "unknown", *tcp_info = NULL;
	struct kex *kex;
	struct session_state *state;
	struct newkeys *nk_in, *nk_out;
	char *stats_in = NULL, *stats_out = NULL;
	uint64_t epoch = (uint64_t)time(NULL) - monotime();

	만약 (ssh == NULL)
		반환 NULL;
	state = ssh->state;
	kex = ssh->kex;

	(void)gethostname(thishost, sizeof(thishost));

	만약 (ssh_local_port(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	} 아니면 {
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
	만약 (state->rekey_limit == 0) {
		xasprintf(&rekey_volume, "limit none");
	} 아니면 {
		char *volumes = NULL, in[32], out[32];

		snprintf(in, sizeof(in), "%llu",
		   (unsigned long long)state->max_blocks_in);
		snprintf(out, sizeof(out), "%llu",
		   (unsigned long long)state->max_blocks_out);
		volumes = dedupe_alg_names(in, out);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		free(volumes);
	}

	/* Time based rekeying. */
	만약 (state->rekey_interval == 0) {
		rekey_time = xstrdup("interval none");
	} 아니면 {
		char rekey_next[64];

		format_absolute_time(epoch + state->rekey_time +
		    state->rekey_interval, rekey_next, sizeof(rekey_next));
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
	free(tcp_info);
	free(cipher);
	free(mac);
	free(comp);
	free(stats_in);
	free(stats_out);
	free(rekey_volume);
	free(rekey_time);
	free(comp_info);
	반환 ret;
}

