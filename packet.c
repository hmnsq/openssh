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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/queue.h>
#ضمن <sys/socket.h>
#ضمن <sys/time.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ضمن <errno.h>
#ضمن <netdb.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <limits.h>
#ضمن <poll.h>
#ضمن <signal.h>
#ضمن <time.h>
#ضمن <util.h>

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
#ضمن <zlib.h>
#endif

#ضمن "xmalloc.h"
#ضمن "compat.h"
#ضمن "ssh2.h"
#ضمن "cipher.h"
#ضمن "kex.h"
#ضمن "digest.h"
#ضمن "mac.h"
#ضمن "log.h"
#ضمن "canohost.h"
#ضمن "misc.h"
#ضمن "packet.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "version.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#אחרת
#define DBG(x)
#endif

#define PACKET_MAX_SIZE (256 * 1024)

بنية packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t blocks;
	uint64_t bytes;
};

بنية packet {
	TAILQ_ENTRY(packet) next;
	u_char type;
	بنية sshbuf *payload;
};

بنية session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	صحيح connection_in;
	صحيح connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	بنية sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	بنية sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	بنية sshbuf *input;

	/* Buffer for raw output data going to the socket. */
	بنية sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	بنية sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	بنية sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	بنية sshbuf *compression_buffer;

#ifdef WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_stream compression_in_stream;
	z_stream compression_out_stream;
#endif
	صحيح compression_in_started;
	صحيح compression_out_started;
	صحيح compression_in_failures;
	صحيح compression_out_failures;

	/* default maximum packet size */
	u_int max_packet_size;

	/* Flag indicating whether this module has been initialized. */
	صحيح initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t start_time;

	/* Set to true if the connection is interactive. */
	صحيح interactive_mode;

	/* Set to true if we are the server side. */
	صحيح server_side;

	/* Set to true if we are authenticated. */
	صحيح after_authentication;

	صحيح keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	صحيح packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	بنية newkeys *newkeys[MODE_MAX];
	بنية packet_state p_read, p_send;

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
	بنية sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	صحيح rekeying;

	/* Used in ssh_packet_send_mux() */
	صحيح mux;

	/* QoS handling */
	صحيح qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	صحيح set_maxsize_called;

	/* One-off warning about weak ciphers */
	صحيح cipher_warning_done;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	صحيح disconnecting;

	/* Nagle disabled on socket */
	صحيح nodelay_set;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_in;
	فراغ *hook_in_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

بنية ssh *
ssh_alloc_session_state(فراغ)
{
	بنية ssh *ssh = عدم;
	بنية session_state *state = عدم;

	אם ((ssh = calloc(1, حجم(*ssh))) == عدم ||
	    (state = calloc(1, حجم(*state))) == عدم ||
	    (ssh->kex = kex_new()) == عدم ||
	    (state->input = sshbuf_new()) == عدم ||
	    (state->output = sshbuf_new()) == عدم ||
	    (state->outgoing_packet = sshbuf_new()) == عدم ||
	    (state->incoming_packet = sshbuf_new()) == عدم)
		اذهب fail;
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
	החזר ssh;
 fail:
	אם (ssh) {
		kex_free(ssh->kex);
		حرر(ssh);
	}
	אם (state) {
		sshbuf_free(state->input);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		حرر(state);
	}
	החזר عدم;
}

فراغ
ssh_packet_set_input_hook(بنية ssh *ssh, ssh_packet_hook_fn *hook, فراغ *ctx)
{
	ssh->state->hook_in = hook;
	ssh->state->hook_in_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
صحيح
ssh_packet_is_rekeying(بنية ssh *ssh)
{
	החזר ssh->state->rekeying ||
	    (ssh->kex != عدم && ssh->kex->done == 0);
}

/*
 * Sets the descriptors used for communication.
 */
بنية ssh *
ssh_packet_set_connection(بنية ssh *ssh, صحيح fd_in, صحيح fd_out)
{
	بنية session_state *state;
	ثابت بنية sshcipher *none = cipher_by_name("none");
	صحيح r, wasnull = ssh == عدم;

	אם (none == عدم) {
		error_f("cannot load cipher 'none'");
		החזר عدم;
	}
	אם (ssh == عدم)
		ssh = ssh_alloc_session_state();
	אם (ssh == عدم) {
		error_f("could not allocate state");
		החזר عدم;
	}
	state = ssh->state;
	state->start_time = monotime();
	state->connection_in = fd_in;
	state->connection_out = fd_out;
	אם ((r = cipher_init(&state->send_context, none,
	    (ثابت u_char *)"", 0, عدم, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (ثابت u_char *)"", 0, عدم, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		אם (wasnull)
			حرر(ssh); /* XXX need ssh_free_session_state? */
		החזר عدم;
	}
	state->newkeys[MODE_IN] = state->newkeys[MODE_OUT] = عدم;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(فراغ)ssh_remote_ipaddr(ssh);
	החזר ssh;
}

فراغ
ssh_packet_set_timeout(بنية ssh *ssh, صحيح timeout, صحيح count)
{
	بنية session_state *state = ssh->state;

	אם (timeout <= 0 || count <= 0) {
		state->packet_timeout_ms = -1;
		החזר;
	}
	אם ((INT_MAX / 1000) / count < timeout)
		state->packet_timeout_ms = INT_MAX;
	אחרת
		state->packet_timeout_ms = timeout * count * 1000;
}

فراغ
ssh_packet_set_mux(بنية ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = عدم;
}

صحيح
ssh_packet_get_mux(بنية ssh *ssh)
{
	החזר ssh->state->mux;
}

صحيح
ssh_packet_set_log_preamble(بنية ssh *ssh, ثابت حرف *fmt, ...)
{
	va_list args;
	صحيح r;

	حرر(ssh->log_preamble);
	אם (fmt == عدم)
		ssh->log_preamble = عدم;
	אחרת {
		va_start(args, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, args);
		va_end(args);
		אם (r < 0 || ssh->log_preamble == عدم)
			החזר SSH_ERR_ALLOC_FAIL;
	}
	החזר 0;
}

صحيح
ssh_packet_stop_discard(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	صحيح r;

	אם (state->packet_discard_mac) {
		حرف buf[1024];
		size_t dlen = PACKET_MAX_SIZE;

		אם (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', حجم(buf));
		כלעוד (sshbuf_len(state->incoming_packet) < dlen)
			אם ((r = sshbuf_put(state->incoming_packet, buf,
			    حجم(buf))) != 0)
				החזר r;
		(فراغ) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    عدم, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	החזר SSH_ERR_MAC_INVALID;
}

ساكن صحيح
ssh_packet_start_discard(بنية ssh *ssh, بنية sshenc *enc,
    بنية sshmac *mac, size_t mac_already, u_int discard)
{
	بنية session_state *state = ssh->state;
	صحيح r;

	אם (enc == عدم || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		אם ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			החזר r;
		החזר SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	אם (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	אם (sshbuf_len(state->input) >= discard)
		החזר ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->input);
	החזר 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

صحيح
ssh_packet_connection_is_on_socket(بنية ssh *ssh)
{
	بنية session_state *state;
	بنية sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	אם (ssh == عدم || ssh->state == عدم)
		החזר 0;

	state = ssh->state;
	אם (state->connection_in == -1 || state->connection_out == -1)
		החזר 0;
	fromlen = حجم(from);
	memset(&from, 0, حجم(from));
	אם (getpeername(state->connection_in, (بنية sockaddr *)&from,
	    &fromlen) == -1)
		החזר 0;
	אם (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		החזר 0;
	/* filedescriptors in and out are the same, so it's a socket */
	אם (state->connection_in == state->connection_out)
		החזר 1;
	tolen = حجم(to);
	memset(&to, 0, حجم(to));
	אם (getpeername(state->connection_out, (بنية sockaddr *)&to,
	    &tolen) == -1)
		החזר 0;
	אם (fromlen != tolen || memcmp(&from, &to, fromlen) != 0)
		החזר 0;
	החזר 1;
}

فراغ
ssh_packet_get_bytes(بنية ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	אם (ibytes)
		*ibytes = ssh->state->p_read.bytes;
	אם (obytes)
		*obytes = ssh->state->p_send.bytes;
}

صحيح
ssh_packet_connection_af(بنية ssh *ssh)
{
	החזר get_sock_af(ssh->state->connection_out);
}

/* Sets the connection into non-blocking mode. */

فراغ
ssh_packet_set_nonblocking(بنية ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(ssh->state->connection_in);

	אם (ssh->state->connection_out != ssh->state->connection_in)
		set_nonblock(ssh->state->connection_out);
}

/* Returns the socket used for reading. */

صحيح
ssh_packet_get_connection_in(بنية ssh *ssh)
{
	החזר ssh->state->connection_in;
}

/* Returns the descriptor used for writing. */

صحيح
ssh_packet_get_connection_out(بنية ssh *ssh)
{
	החזר ssh->state->connection_out;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

ثابت حرف *
ssh_remote_ipaddr(بنية ssh *ssh)
{
	صحيح sock;

	/* Check whether we have cached the ipaddr. */
	אם (ssh->remote_ipaddr == عدم) {
		אם (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_in;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_port = get_peer_port(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_port = get_local_port(sock);
		} אחרת {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_port = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_port = 65535;
		}
	}
	החזר ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

حرف *
ssh_remote_hostname(بنية ssh *ssh)
{
	بنية sockaddr_storage from;
	socklen_t fromlen;
	بنية addrinfo hints, *ai, *aitop;
	حرف name[NI_MAXHOST], ntop2[NI_MAXHOST];
	ثابت حرف *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = حجم(from);
	memset(&from, 0, حجم(from));
	אם (getpeername(ssh_packet_get_connection_in(ssh),
	    (بنية sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		החזר xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	אם (from.ss_family == AF_INET6)
		fromlen = حجم(بنية sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	אם (getnameinfo((بنية sockaddr *)&from, fromlen, name, حجم(name),
	    عدم, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		החזר xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, حجم(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	אם (getaddrinfo(name, عدم, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		החזר xstrdup(ntop);
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
	memset(&hints, 0, حجم(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	אם (getaddrinfo(name, عدم, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		החזר xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	עבור (ai = aitop; ai; ai = ai->ai_next) {
		אם (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    حجم(ntop2), عدم, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				اكسر;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	אם (ai == عدم) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		החזר xstrdup(ntop);
	}
	החזר xstrdup(name);
}

/* Returns the port number of the remote host. */

صحيح
ssh_remote_port(بنية ssh *ssh)
{
	(فراغ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	החזר ssh->remote_port;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

ثابت حرف *
ssh_local_ipaddr(بنية ssh *ssh)
{
	(فراغ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	החזר ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

صحيح
ssh_local_port(بنية ssh *ssh)
{
	(فراغ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	החזר ssh->local_port;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
ثابت حرف *
ssh_packet_rdomain_in(بنية ssh *ssh)
{
	אם (ssh->rdomain_in != عدم)
		החזר ssh->rdomain_in;
	אם (!ssh_packet_connection_is_on_socket(ssh))
		החזר عدم;
	ssh->rdomain_in = get_rdomain(ssh->state->connection_in);
	החזר ssh->rdomain_in;
}

/* Closes the connection and clears and frees internal data structures. */

ساكن فراغ
ssh_packet_close_internal(بنية ssh *ssh, صحيح do_close)
{
	بنية session_state *state = ssh->state;
	u_int mode;
	بنية packet *p;

	אם (!state->initialized)
		החזר;
	state->initialized = 0;
	אם (do_close) {
		אם (state->connection_in == state->connection_out) {
			close(state->connection_out);
		} אחרת {
			close(state->connection_in);
			close(state->connection_out);
		}
	}
	sshbuf_free(state->input);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	כלעוד ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, next);
		حرر(p);
	}
	עבור (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(state->newkeys[mode]);	/* current keys */
		state->newkeys[mode] = عدم;
		ssh_clear_newkeys(ssh, mode);		/* next keys */
	}
#ifdef WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	אם (do_close && state->compression_buffer) {
		sshbuf_free(state->compression_buffer);
		אם (state->compression_out_started) {
			z_streamp stream = &state->compression_out_stream;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(unsigned long long)stream->total_in,
				(unsigned long long)stream->total_out,
				stream->total_in == 0 ? 0.0 :
				(مزدوج) stream->total_out / stream->total_in);
			אם (state->compression_out_failures == 0)
				deflateEnd(stream);
		}
		אם (state->compression_in_started) {
			z_streamp stream = &state->compression_in_stream;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (unsigned long long)stream->total_out,
			    (unsigned long long)stream->total_in,
			    stream->total_out == 0 ? 0.0 :
			    (مزدوج) stream->total_in / stream->total_out);
			אם (state->compression_in_failures == 0)
				inflateEnd(stream);
		}
	}
#endif	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = عدم;
	אם (do_close) {
		حرر(ssh->local_ipaddr);
		ssh->local_ipaddr = عدم;
		حرر(ssh->remote_ipaddr);
		ssh->remote_ipaddr = عدم;
		حرر(ssh->state);
		ssh->state = عدم;
		kex_free(ssh->kex);
		ssh->kex = عدم;
	}
}

فراغ
ssh_packet_free(بنية ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
	freezero(ssh, حجم(*ssh));
}

فراغ
ssh_packet_close(بنية ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
}

فراغ
ssh_packet_clear_keys(بنية ssh *ssh)
{
	ssh_packet_close_internal(ssh, 0);
}

/* Sets remote side protocol flags. */

فراغ
ssh_packet_set_protocol_flags(بنية ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(بنية ssh *ssh)
{
	החזר ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

ساكن صحيح
ssh_packet_init_compression(بنية ssh *ssh)
{
	אם (!ssh->state->compression_buffer &&
	    ((ssh->state->compression_buffer = sshbuf_new()) == عدم))
		החזר SSH_ERR_ALLOC_FAIL;
	החזר 0;
}

#ifdef WITH_ZLIB
ساكن صحيح
start_compression_out(بنية ssh *ssh)
{
	debug("Enabling compression.");
	אם (ssh->state->compression_out_started == 1)
		deflateEnd(&ssh->state->compression_out_stream);
	بدل (deflateInit2(&ssh->state->compression_out_stream,
	    Z_BEST_SPEED, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	حالة Z_OK:
		ssh->state->compression_out_started = 1;
		اكسر;
	حالة Z_MEM_ERROR:
		החזר SSH_ERR_ALLOC_FAIL;
	افتراضي:
		החזר SSH_ERR_INTERNAL_ERROR;
	}
	החזר 0;
}

ساكن صحيح
start_compression_in(بنية ssh *ssh)
{
	אם (ssh->state->compression_in_started == 1)
		inflateEnd(&ssh->state->compression_in_stream);
	بدل (inflateInit(&ssh->state->compression_in_stream)) {
	حالة Z_OK:
		ssh->state->compression_in_started = 1;
		اكسر;
	حالة Z_MEM_ERROR:
		החזר SSH_ERR_ALLOC_FAIL;
	افتراضي:
		החזר SSH_ERR_INTERNAL_ERROR;
	}
	החזר 0;
}

/* XXX remove need for separate compression buffer */
ساكن صحيح
compress_buffer(بنية ssh *ssh, بنية sshbuf *in, بنية sshbuf *out)
{
	u_char buf[4096];
	صحيح r, status;

	אם (ssh->state->compression_out_started != 1)
		החזר SSH_ERR_INTERNAL_ERROR;

	/* This case is not handled below. */
	אם (sshbuf_len(in) == 0)
		החזר 0;

	/* Input is the contents of the input buffer. */
	אם ((ssh->state->compression_out_stream.next_in =
	    sshbuf_mutable_ptr(in)) == عدم)
		החזר SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_out_stream.avail_in = sshbuf_len(in);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	עשה {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_out_stream.next_out = buf;
		ssh->state->compression_out_stream.avail_out = حجم(buf);

		/* Compress as much data into the buffer as possible. */
		status = deflate(&ssh->state->compression_out_stream,
		    Z_PARTIAL_FLUSH);
		بدل (status) {
		حالة Z_MEM_ERROR:
			החזר SSH_ERR_ALLOC_FAIL;
		حالة Z_OK:
			/* Append compressed data to output_buffer. */
			אם ((r = sshbuf_put(out, buf, حجم(buf) -
			    ssh->state->compression_out_stream.avail_out)) != 0)
				החזר r;
			اكسر;
		حالة Z_STREAM_ERROR:
		افتراضي:
			ssh->state->compression_out_failures++;
			החזר SSH_ERR_INVALID_FORMAT;
		}
	} כלעוד (ssh->state->compression_out_stream.avail_out == 0);
	החזר 0;
}

ساكن صحيح
uncompress_buffer(بنية ssh *ssh, بنية sshbuf *in, بنية sshbuf *out)
{
	u_char buf[4096];
	صحيح r, status;

	אם (ssh->state->compression_in_started != 1)
		החזר SSH_ERR_INTERNAL_ERROR;

	אם ((ssh->state->compression_in_stream.next_in =
	    sshbuf_mutable_ptr(in)) == عدم)
		החזר SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_in_stream.avail_in = sshbuf_len(in);

	עבור (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_in_stream.next_out = buf;
		ssh->state->compression_in_stream.avail_out = حجم(buf);

		status = inflate(&ssh->state->compression_in_stream,
		    Z_SYNC_FLUSH);
		بدل (status) {
		حالة Z_OK:
			אם ((r = sshbuf_put(out, buf, حجم(buf) -
			    ssh->state->compression_in_stream.avail_out)) != 0)
				החזר r;
			אם (sshbuf_len(out) >= PACKET_MAX_SIZE)
				החזר SSH_ERR_INVALID_FORMAT;
			اكسر;
		حالة Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			החזר 0;
		حالة Z_DATA_ERROR:
			החזר SSH_ERR_INVALID_FORMAT;
		حالة Z_MEM_ERROR:
			החזר SSH_ERR_ALLOC_FAIL;
		حالة Z_STREAM_ERROR:
		افتراضي:
			ssh->state->compression_in_failures++;
			החזר SSH_ERR_INTERNAL_ERROR;
		}
	}
	/* NOTREACHED */
}

#אחרת	/* WITH_ZLIB */

ساكن صحيح
start_compression_out(بنية ssh *ssh)
{
	החזר SSH_ERR_INTERNAL_ERROR;
}

ساكن صحيح
start_compression_in(بنية ssh *ssh)
{
	החזר SSH_ERR_INTERNAL_ERROR;
}

ساكن صحيح
compress_buffer(بنية ssh *ssh, بنية sshbuf *in, بنية sshbuf *out)
{
	החזר SSH_ERR_INTERNAL_ERROR;
}

ساكن صحيح
uncompress_buffer(بنية ssh *ssh, بنية sshbuf *in, بنية sshbuf *out)
{
	החזר SSH_ERR_INTERNAL_ERROR;
}
#endif	/* WITH_ZLIB */

فراغ
ssh_clear_newkeys(بنية ssh *ssh, صحيح mode)
{
	אם (ssh->kex && ssh->kex->newkeys[mode]) {
		kex_free_newkeys(ssh->kex->newkeys[mode]);
		ssh->kex->newkeys[mode] = عدم;
	}
}

صحيح
ssh_set_newkeys(بنية ssh *ssh, صحيح mode)
{
	بنية session_state *state = ssh->state;
	بنية sshenc *enc;
	بنية sshmac *mac;
	بنية sshcomp *comp;
	بنية sshcipher_ctx **ccp;
	بنية packet_state *ps;
	uint64_t *max_blocks, *hard_max_blocks;
	ثابت حرف *wmsg;
	صحيح r, crypt_type;
	ثابت حرف *dir = mode == MODE_OUT ? "out" : "in";

	debug2_f("mode %d", mode);

	אם (mode == MODE_OUT) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_blocks = &state->hard_max_blocks_out;
		max_blocks = &state->max_blocks_out;
	} אחרת {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_blocks = &state->hard_max_blocks_in;
		max_blocks = &state->max_blocks_in;
	}
	אם (state->newkeys[mode] != عدم) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (unsigned long long)state->p_read.bytes,
		    (unsigned long long)state->p_read.blocks,
		    (unsigned long long)state->p_send.bytes,
		    (unsigned long long)state->p_send.blocks);
		kex_free_newkeys(state->newkeys[mode]);
		state->newkeys[mode] = عدم;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->blocks = 0;
	/* move newkeys from kex to state */
	אם ((state->newkeys[mode] = ssh->kex->newkeys[mode]) == عدم)
		החזר SSH_ERR_INTERNAL_ERROR;
	ssh->kex->newkeys[mode] = عدم;
	enc  = &state->newkeys[mode]->enc;
	mac  = &state->newkeys[mode]->mac;
	comp = &state->newkeys[mode]->comp;
	אם (cipher_authlen(enc->cipher) == 0) {
		אם ((r = mac_init(mac)) != 0)
			החזר r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = عدم;
	אם ((r = cipher_init(ccp, enc->cipher, enc->key, enc->key_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		החזר r;
	אם (!state->cipher_warning_done &&
	    (wmsg = cipher_warning_message(*ccp)) != عدم) {
		error("Warning: %s", wmsg);
		state->cipher_warning_done = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	אם (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		אם ((r = ssh_packet_init_compression(ssh)) < 0)
			החזר r;
		אם (mode == MODE_OUT) {
			אם ((r = start_compression_out(ssh)) != 0)
				החזר r;
		} אחרת {
			אם ((r = start_compression_in(ssh)) != 0)
				החזר r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	אם (enc->block_size >= 16)
		*hard_max_blocks = (uint64_t)1 << (enc->block_size*2);
	אחרת
		*hard_max_blocks = ((uint64_t)1 << 30) / enc->block_size;
	*max_blocks = *hard_max_blocks;
	אם (state->rekey_limit) {
		*max_blocks = MINIMUM(*max_blocks,
		    state->rekey_limit / enc->block_size);
	}
	debug("rekey %s after %llu blocks", dir,
	    (unsigned long long)*max_blocks);
	החזר 0;
}

#define MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
ساكن مضمن صحيح
ssh_packet_check_rekey_blocklimit(بنية ssh *ssh, u_int packet_len, صحيح hard)
{
	بنية session_state *state = ssh->state;
	uint32_t out_blocks;
	ثابت uint64_t max_blocks_in = hard ?
	    state->hard_max_blocks_in : state->max_blocks_in;
	ثابت uint64_t max_blocks_out = hard ?
	    state->hard_max_blocks_out : state->max_blocks_out;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	אם (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		החזר 1;

	אם (state->newkeys[MODE_OUT] == عدم)
		החזר 0;

	/* Rekey after (cipher-specific) maximum blocks */
	out_blocks = ROUNDUP(packet_len,
	    state->newkeys[MODE_OUT]->enc.block_size);
	החזר (max_blocks_out &&
	    (state->p_send.blocks + out_blocks > max_blocks_out)) ||
	    (max_blocks_in &&
	    (state->p_read.blocks > max_blocks_in));
}

ساكن صحيح
ssh_packet_need_rekeying(بنية ssh *ssh, u_int outbound_packet_len)
{
	بنية session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	אם (!state->after_authentication)
		החזר 0;

	/* Haven't keyed yet or KEX in progress. */
	אם (ssh_packet_is_rekeying(ssh))
		החזר 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	אם (state->p_send.packets == 0 && state->p_read.packets == 0)
		החזר 0;

	/* Time-based rekeying */
	אם (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_time + state->rekey_interval <= monotime())
		החזר 1;

	החזר ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
ساكن صحيح
ssh_packet_check_rekey_preauth(بنية ssh *ssh, u_int outgoing_packet_len)
{
	אם (ssh->state->after_authentication)
		החזר 0;

	אם (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		החזר SSH_ERR_NEED_REKEY;
	}
	החזר 0;
}

صحيح
ssh_packet_check_rekey(بنية ssh *ssh)
{
	صحيح r;

	אם ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		החזר r;
	אם (!ssh_packet_need_rekeying(ssh, 0))
		החזר 0;
	debug3_f("rekex triggered");
	החזר kex_start_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
ساكن صحيح
ssh_packet_enable_delayed_compress(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	بنية sshcomp *comp = عدم;
	صحيح r, mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	עבור (mode = 0; mode < MODE_MAX; mode++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		אם (state->newkeys[mode] == عدم)
			استمر;
		comp = &state->newkeys[mode]->comp;
		אם (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			אם ((r = ssh_packet_init_compression(ssh)) != 0)
				החזר r;
			אם (mode == MODE_OUT) {
				אם ((r = start_compression_out(ssh)) != 0)
					החזר r;
			} אחרת {
				אם ((r = start_compression_in(ssh)) != 0)
					החזר r;
			}
			comp->enabled = 1;
		}
	}
	החזר 0;
}

/* Used to mute debug logging for noisy packet types */
صحيح
ssh_packet_log_type(u_char type)
{
	بدل (type) {
	حالة SSH2_MSG_PING:
	حالة SSH2_MSG_PONG:
	حالة SSH2_MSG_CHANNEL_DATA:
	حالة SSH2_MSG_CHANNEL_EXTENDED_DATA:
	حالة SSH2_MSG_CHANNEL_WINDOW_ADJUST:
		החזר 0;
	افتراضي:
		החזר 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
صحيح
ssh_packet_send2_wrapped(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_LENGTH];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	بنية sshenc *enc   = عدم;
	بنية sshmac *mac   = عدم;
	بنية sshcomp *comp = عدم;
	صحيح r, block_size;

	אם (state->newkeys[MODE_OUT] != عدم) {
		enc  = &state->newkeys[MODE_OUT]->enc;
		mac  = &state->newkeys[MODE_OUT]->mac;
		comp = &state->newkeys[MODE_OUT]->comp;
		/* disable mac for authenticated encryption */
		אם ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = عدم;
	}
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	אם (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#endif

	אם (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		אם ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			اذهب out;
		sshbuf_reset(state->compression_buffer);
		אם ((r = compress_buffer(ssh, state->outgoing_packet,
		    state->compression_buffer)) != 0)
			اذهب out;
		sshbuf_reset(state->outgoing_packet);
		אם ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_buffer)) != 0)
			اذهب out;
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
	אם (padlen < 4)
		padlen += block_size;
	אם (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, block_size);
		/* check if roundup overflowed */
		אם (state->extra_pad < tmp)
			החזר SSH_ERR_INVALID_ARGUMENT;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		אם (tmp > state->extra_pad)
			החזר SSH_ERR_INVALID_ARGUMENT;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		אם (padlen < tmp)
			החזר SSH_ERR_INVALID_ARGUMENT; /* overflow */
		state->extra_pad = 0;
	}
	אם ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		اذهب out;
	אם (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} אחרת {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	אם (cp == عدم) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	אם (mac && mac->enabled && !mac->etm) {
		אם ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, حجم(macbuf))) != 0)
			اذهب out;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	אם ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		اذهب out;
	אם ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		اذهب out;
	/* append unencrypted MAC */
	אם (mac && mac->enabled) {
		אם (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			אם ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, حجم(macbuf))) != 0)
				اذهب out;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		אם ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			اذهب out;
	}
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#endif
	/* increment sequence number for outgoing packets */
	אם (++state->p_send.seqnr == 0) {
		אם ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	אם (++state->p_send.packets == 0)
		החזר SSH_ERR_NEED_REKEY;
	state->p_send.blocks += len / block_size;
	state->p_send.bytes += len;
	sshbuf_reset(state->outgoing_packet);

	אם (type == SSH2_MSG_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	אם (type == SSH2_MSG_NEWKEYS)
		r = ssh_set_newkeys(ssh, MODE_OUT);
	אחרת אם (type == SSH2_MSG_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	אחרת
		r = 0;
 out:
	החזר r;
}

/* returns non-zero if the specified packet type is usec by KEX */
ساكن صحيح
ssh_packet_type_is_kex(u_char type)
{
	החזר
	    type >= SSH2_MSG_TRANSPORT_MIN &&
	    type <= SSH2_MSG_TRANSPORT_MAX &&
	    type != SSH2_MSG_SERVICE_REQUEST &&
	    type != SSH2_MSG_SERVICE_ACCEPT &&
	    type != SSH2_MSG_EXT_INFO;
}

صحيح
ssh_packet_send2(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	بنية packet *p;
	u_char type;
	صحيح r, need_rekey;

	אם (sshbuf_len(state->outgoing_packet) < 6)
		החזר SSH_ERR_INTERNAL_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	אם (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		החזר r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	אם ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		אם (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = calloc(1, حجم(*p));
		אם (p == عدم)
			החזר SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, next);
		state->outgoing_packet = sshbuf_new();
		אם (state->outgoing_packet == عدم)
			החזר SSH_ERR_ALLOC_FAIL;
		אם (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			החזר kex_start_rekex(ssh);
		}
		החזר 0;
	}

	/* rekeying starts with sending KEXINIT */
	אם (type == SSH2_MSG_KEXINIT)
		state->rekeying = 1;

	אם ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		החזר r;

	/* after a NEWKEYS message we can send the complete queue */
	אם (type == SSH2_MSG_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_time = monotime();
		כלעוד ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			אם (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				החזר kex_start_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, next);
			memset(p, 0, حجم(*p));
			حرر(p);
			אם ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				החזר r;
		}
	}
	החזר 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

صحيح
ssh_packet_read_seqnr(بنية ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	بنية session_state *state = ssh->state;
	صحيح len, r, ms_remain = 0;
	بنية pollfd pfd;
	حرف buf[8192];
	بنية timeval start;
	بنية timespec timespec, *timespecp = عدم;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	אם ((r = ssh_packet_write_wait(ssh)) != 0)
		اذهب out;

	/* Stay in the loop until we have received a complete packet. */
	עבור (;;) {
		/* Try to read a packet from the buffer. */
		אם ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			اكسر;
		/* If we got a packet, return it. */
		אם (*typep != SSH_MSG_NONE)
			اكسر;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_in;
		pfd.events = POLLIN;

		אם (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		עבור (;;) {
			אם (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			אם ((r = ppoll(&pfd, 1, timespecp, عدم)) >= 0)
				اكسر;
			אם (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب out;
			}
			אם (state->packet_timeout_ms <= 0)
				استمر;
			ms_subtract_diff(&start, &ms_remain);
			אם (ms_remain <= 0) {
				r = 0;
				اكسر;
			}
		}
		אם (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			اذهب out;
		}
		/* Read data from the socket. */
		len = اقرأ(state->connection_in, buf, حجم(buf));
		אם (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			اذهب out;
		}
		אם (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب out;
		}

		/* Append it to the buffer. */
		אם ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			اذهب out;
	}
 out:
	החזר r;
}

صحيح
ssh_packet_read(بنية ssh *ssh)
{
	u_char type;
	صحيح r;

	אם ((r = ssh_packet_read_seqnr(ssh, &type, عدم)) != 0)
		sshpkt_fatal(ssh, r, "read");
	החזר type;
}

ساكن صحيح
ssh_packet_read_poll2_mux(بنية ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	بنية session_state *state = ssh->state;
	ثابت u_char *cp;
	size_t need;
	صحيح r;

	אם (ssh->kex)
		החזר SSH_ERR_INTERNAL_ERROR;
	*typep = SSH_MSG_NONE;
	cp = sshbuf_ptr(state->input);
	אם (state->packlen == 0) {
		אם (sshbuf_len(state->input) < 4 + 1)
			החזר 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		אם (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_SIZE)
			החזר SSH_ERR_MESSAGE_INCOMPLETE;
	}
	need = state->packlen + 4;
	אם (sshbuf_len(state->input) < need)
		החזר 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	אם ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->input, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, عدم)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		החזר r;
	אם (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	החזר r;
}

صحيح
ssh_packet_read_poll2(بنية ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	بنية session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, block_size;
	بنية sshenc *enc   = عدم;
	بنية sshmac *mac   = عدم;
	بنية sshcomp *comp = عدم;
	صحيح r;

	אם (state->mux)
		החזר ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_MSG_NONE;

	אם (state->packet_discard)
		החזר 0;

	אם (state->newkeys[MODE_IN] != عدم) {
		enc  = &state->newkeys[MODE_IN]->enc;
		mac  = &state->newkeys[MODE_IN]->mac;
		comp = &state->newkeys[MODE_IN]->comp;
		/* disable mac for authenticated encryption */
		אם ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = عدم;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	אם (aadlen && state->packlen == 0) {
		אם (cipher_get_length(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->input), sshbuf_len(state->input)) != 0)
			החזר 0;
		אם (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			sshbuf_dump(state->input, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			אם ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				החזר r;
			החזר SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} אחרת אם (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		אם (sshbuf_len(state->input) < block_size)
			החזר 0;
		sshbuf_reset(state->incoming_packet);
		אם ((r = sshbuf_reserve(state->incoming_packet, block_size,
		    &cp)) != 0)
			اذهب out;
		אם ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->input),
		    block_size, 0, 0)) != 0)
			اذهب out;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		אם (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->input, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			החזר ssh_packet_start_discard(ssh, enc, mac, 0,
			    PACKET_MAX_SIZE);
		}
		אם ((r = sshbuf_consume(state->input, block_size)) != 0)
			اذهب out;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	אם (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} אחרת {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - block_size;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", block_size, need, maclen, authlen, aadlen));
	אם (need % block_size != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
		החזר ssh_packet_start_discard(ssh, enc, mac, 0,
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
	אם (sshbuf_len(state->input) < aadlen + need + authlen + maclen)
		החזר 0; /* packet is incomplete */
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->input, stderr);
#endif
	/* EtM: check mac over encrypted input */
	אם (mac && mac->enabled && mac->etm) {
		אם ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->input), aadlen + need,
		    sshbuf_ptr(state->input) + aadlen + need + authlen,
		    maclen)) != 0) {
			אם (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			اذهب out;
		}
	}
	אם ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		اذهب out;
	אם ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->input), need, aadlen, authlen)) != 0)
		اذهب out;
	אם ((r = sshbuf_consume(state->input, aadlen + need + authlen)) != 0)
		اذهب out;
	אם (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		אם (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->input), maclen)) != 0) {
			אם (r != SSH_ERR_MAC_INVALID)
				اذهب out;
			logit("Corrupted MAC on input.");
			אם (need + block_size > PACKET_MAX_SIZE)
				החזר SSH_ERR_INTERNAL_ERROR;
			החזר ssh_packet_start_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_SIZE - need - block_size);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		אם ((r = sshbuf_consume(state->input, mac->mac_len)) != 0)
			اذهب out;
	}

	אם (seqnr_p != عدم)
		*seqnr_p = state->p_read.seqnr;
	אם (++state->p_read.seqnr == 0) {
		אם ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	אם (++state->p_read.packets == 0)
		החזר SSH_ERR_NEED_REKEY;
	state->p_read.blocks += (state->packlen + 4) / block_size;
	state->p_read.bytes += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	אם (padlen < 4)	{
		אם ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			החזר r;
		החזר SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	אם ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_end(state->incoming_packet, padlen)) != 0))
		اذهب out;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	אם (comp && comp->enabled) {
		sshbuf_reset(state->compression_buffer);
		אם ((r = uncompress_buffer(ssh, state->incoming_packet,
		    state->compression_buffer)) != 0)
			اذهب out;
		sshbuf_reset(state->incoming_packet);
		אם ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_buffer)) != 0)
			اذهب out;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	אם ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		اذهب out;
	אם (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	אם (*typep < SSH2_MSG_MIN) {
		אם ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			החזר r;
		החזר SSH_ERR_PROTOCOL_ERROR;
	}
	אם (state->hook_in != عدم &&
	    (r = state->hook_in(ssh, state->incoming_packet, typep,
	    state->hook_in_ctx)) != 0)
		החזר r;
	אם (*typep == SSH2_MSG_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	אחרת
		r = 0;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#endif
	/* reset for next packet */
	state->packlen = 0;
	אם (*typep == SSH2_MSG_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	אם ((r = ssh_packet_check_rekey(ssh)) != 0)
		החזר r;
 out:
	החזר r;
}

صحيح
ssh_packet_read_poll_seqnr(بنية ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	بنية session_state *state = ssh->state;
	u_int reason, seqnr;
	صحيح r;
	u_char *msg;
	ثابت u_char *d;
	size_t len;

	עבור (;;) {
		msg = عدم;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		אם (r != 0)
			החזר r;
		אם (*typep == 0) {
			/* no message ready */
			החזר 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		אם (*typep == SSH2_MSG_DISCONNECT) {
			אם ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &msg, عدم)) != 0)
				החזר r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh), reason, msg);
			حرر(msg);
			החזר SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		אם (ssh->kex != عدم &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			החזר 0;
		/* Implicitly handle transport-level messages */
		بدل (*typep) {
		حالة SSH2_MSG_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			اكسر;
		حالة SSH2_MSG_DEBUG:
			אם ((r = sshpkt_get_u8(ssh, عدم)) != 0 ||
			    (r = sshpkt_get_string(ssh, &msg, عدم)) != 0 ||
			    (r = sshpkt_get_string(ssh, عدم, عدم)) != 0) {
				حرر(msg);
				החזר r;
			}
			debug("Remote: %.900s", msg);
			حرر(msg);
			اكسر;
		حالة SSH2_MSG_UNIMPLEMENTED:
			אם ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				החזר r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			اكسر;
		حالة SSH2_MSG_PING:
			אם ((r = sshpkt_get_string_direct(ssh, &d, &len)) != 0)
				החזר r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			אם (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				اكسر;
			}
			אם (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				اكسر;
			}
			אם ((r = sshpkt_start(ssh, SSH2_MSG_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				החזר r;
			اكسر;
		حالة SSH2_MSG_PONG:
			אם ((r = sshpkt_get_string_direct(ssh,
			    عدم, &len)) != 0)
				החזר r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			اكسر;
		افتراضي:
			אם (ssh->kex != عدم &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				החזר SSH_ERR_PROTOCOL_ERROR;
			}
			החזר 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
صحيح
ssh_packet_process_incoming(بنية ssh *ssh, ثابت حرف *buf, u_int len)
{
	بنية session_state *state = ssh->state;
	صحيح r;

	אם (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		אם (len >= state->packet_discard) {
			אם ((r = ssh_packet_stop_discard(ssh)) != 0)
				החזר r;
		}
		state->packet_discard -= len;
		החזר 0;
	}
	אם ((r = sshbuf_put(state->input, buf, len)) != 0)
		החזר r;

	החזר 0;
}

/* Reads and buffers data from the specified fd */
صحيح
ssh_packet_process_read(بنية ssh *ssh, صحيح fd)
{
	بنية session_state *state = ssh->state;
	صحيح r;
	size_t rlen;

	אם ((r = sshbuf_read(fd, state->input, PACKET_MAX_SIZE, &rlen)) != 0)
		החזר r;

	אם (state->packet_discard) {
		אם ((r = sshbuf_consume_end(state->input, rlen)) != 0)
			החזר r;
		state->keep_alive_timeouts = 0; /* ?? */
		אם (rlen >= state->packet_discard) {
			אם ((r = ssh_packet_stop_discard(ssh)) != 0)
				החזר r;
		}
		state->packet_discard -= rlen;
		החזר 0;
	}
	החזר 0;
}

صحيح
ssh_packet_remaining(بنية ssh *ssh)
{
	החזר sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
فراغ
ssh_packet_send_debug(بنية ssh *ssh, ثابت حرف *fmt,...)
{
	حرف buf[1024];
	va_list args;
	صحيح r;

	אם ((ssh->compat & SSH_BUG_DEBUG))
		החזר;

	va_start(args, fmt);
	vsnprintf(buf, حجم(buf), fmt, args);
	va_end(args);

	debug3("sending debug message: %s", buf);

	אם ((r = sshpkt_start(ssh, SSH2_MSG_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

فراغ
sshpkt_fmt_connection_id(بنية ssh *ssh, حرف *s, size_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
ساكن فراغ
sshpkt_vfatal(بنية ssh *ssh, صحيح r, ثابت حرف *fmt, va_list ap)
{
	حرف *tag = عدم, remote_id[512];
	صحيح oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));

	بدل (r) {
	حالة SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_keys(ssh);
		logdie("Connection closed by %s", remote_id);
	حالة SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_keys(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	حالة SSH_ERR_DISCONNECTED:
		ssh_packet_clear_keys(ssh);
		logdie("Disconnected from %s", remote_id);
	حالة SSH_ERR_SYSTEM_ERROR:
		אם (errno == ECONNRESET) {
			ssh_packet_clear_keys(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	حالة SSH_ERR_NO_CIPHER_ALG_MATCH:
	حالة SSH_ERR_NO_MAC_ALG_MATCH:
	حالة SSH_ERR_NO_COMPRESS_ALG_MATCH:
	حالة SSH_ERR_NO_KEX_ALG_MATCH:
	حالة SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		אם (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_keys(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	افتراضي:
		אם (vasprintf(&tag, fmt, ap) == -1) {
			ssh_packet_clear_keys(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_keys(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    tag != عدم ? tag : "", tag != عدم ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

فراغ
sshpkt_fatal(بنية ssh *ssh, صحيح r, ثابت حرف *fmt, ...)
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
فراغ
ssh_packet_disconnect(بنية ssh *ssh, ثابت حرف *fmt,...)
{
	حرف buf[1024], remote_id[512];
	va_list args;
	صحيح r;

	/* Guard against recursive invocations. */
	אם (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));
	va_start(args, fmt);
	vsnprintf(buf, حجم(buf), fmt, args);
	va_end(args);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	אם ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	אם ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
صحيح
ssh_packet_write_poll(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	صحيح len = sshbuf_len(state->output);
	صحيح r;

	אם (len > 0) {
		len = اكتب(state->connection_out,
		    sshbuf_ptr(state->output), len);
		אם (len == -1) {
			אם (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				החזר 0;
			החזר SSH_ERR_SYSTEM_ERROR;
		}
		אם (len == 0)
			החזר SSH_ERR_CONN_CLOSED;
		אם ((r = sshbuf_consume(state->output, len)) != 0)
			החזר r;
	}
	החזר 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
صحيح
ssh_packet_write_wait(بنية ssh *ssh)
{
	صحيح ret, r, ms_remain = 0;
	بنية timeval start;
	بنية timespec timespec, *timespecp = عدم;
	بنية session_state *state = ssh->state;
	بنية pollfd pfd;

	אם ((r = ssh_packet_write_poll(ssh)) != 0)
		החזר r;
	כלעוד (ssh_packet_have_data_to_write(ssh)) {
		pfd.fd = state->connection_out;
		pfd.events = POLLOUT;

		אם (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		עבור (;;) {
			אם (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			אם ((ret = ppoll(&pfd, 1, timespecp, عدم)) >= 0)
				اكسر;
			אם (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				اكسر;
			אם (state->packet_timeout_ms <= 0)
				استمر;
			ms_subtract_diff(&start, &ms_remain);
			אם (ms_remain <= 0) {
				ret = 0;
				اكسر;
			}
		}
		אם (ret == 0)
			החזר SSH_ERR_CONN_TIMEOUT;
		אם ((r = ssh_packet_write_poll(ssh)) != 0)
			החזר r;
	}
	החזר 0;
}

/* Returns true if there is buffered data to write to the connection. */

صحيح
ssh_packet_have_data_to_write(بنية ssh *ssh)
{
	החזר sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

صحيح
ssh_packet_not_very_much_data_to_write(بنية ssh *ssh)
{
	אם (ssh->state->interactive_mode)
		החזר sshbuf_len(ssh->state->output) < 16384;
	אחרת
		החזר sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

صحيح
ssh_packet_interactive_data_to_write(بنية ssh *ssh)
{
	החזר ssh->state->interactive_mode &&
	    sshbuf_len(ssh->state->output) < 256;
}

ساكن فراغ
apply_qos(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	صحيح qos = state->interactive_mode ?
	    state->qos_interactive : state->qos_other;

	אם (!ssh_packet_connection_is_on_socket(ssh))
		החזר;
	אם (!state->nodelay_set) {
		set_nodelay(state->connection_in);
		state->nodelay_set = 1;
	}
	set_sock_tos(ssh->state->connection_in, qos);
}

/* Informs that the current session is interactive. */
فراغ
ssh_packet_set_interactive(بنية ssh *ssh, صحيح interactive)
{
	بنية session_state *state = ssh->state;

	state->interactive_mode = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
فراغ
ssh_packet_set_qos(بنية ssh *ssh, صحيح qos_interactive, صحيح qos_other)
{
	بنية session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

صحيح
ssh_packet_set_maxsize(بنية ssh *ssh, u_int s)
{
	بنية session_state *state = ssh->state;

	אם (state->set_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_size, s);
		החזר -1;
	}
	אם (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		החזר -1;
	}
	state->set_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_size = s;
	החזר s;
}

صحيح
ssh_packet_inc_alive_timeouts(بنية ssh *ssh)
{
	החזר ++ssh->state->keep_alive_timeouts;
}

فراغ
ssh_packet_set_alive_timeouts(بنية ssh *ssh, صحيح ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(بنية ssh *ssh)
{
	החזר ssh->state->max_packet_size;
}

فراغ
ssh_packet_set_rekey_limits(بنية ssh *ssh, uint64_t bytes, uint32_t seconds)
{
	אם (bytes == 0 && seconds == 0)
		החזר;

	debug3("rekey after %llu bytes, %u seconds", (unsigned long long)bytes,
	    (unsigned صحيح)seconds);
	ssh->state->rekey_limit = bytes;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(بنية ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_time + ssh->state->rekey_interval -
	    monotime();
	החזר (seconds <= 0 ? 1 : seconds);
}

فراغ
ssh_packet_set_server(بنية ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

فراغ
ssh_packet_set_authenticated(بنية ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

فراغ *
ssh_packet_get_input(بنية ssh *ssh)
{
	החזר (فراغ *)ssh->state->input;
}

فراغ *
ssh_packet_get_output(بنية ssh *ssh)
{
	החזר (فراغ *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
ساكن صحيح
ssh_packet_set_postauth(بنية ssh *ssh)
{
	صحيح r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	אם ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		החזר r;
	החזר 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
ساكن صحيح
kex_to_blob(بنية sshbuf *m, بنية kex *kex)
{
	صحيح r;

	אם ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
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
		החזר r;
	החזר 0;
}

/* turn key exchange results into a blob for packet state serialization */
ساكن صحيح
newkeys_to_blob(بنية sshbuf *m, بنية ssh *ssh, صحيح mode)
{
	بنية sshbuf *b;
	بنية sshcipher_ctx *cc;
	بنية sshcomp *comp;
	بنية sshenc *enc;
	بنية sshmac *mac;
	بنية newkeys *newkey;
	صحيح r;

	אם ((newkey = ssh->state->newkeys[mode]) == عدم)
		החזר SSH_ERR_INTERNAL_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (mode == MODE_OUT) ? ssh->state->send_context :
	    ssh->state->receive_context;
	אם ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		החזר r;
	אם ((b = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->block_size)) != 0 ||
	    (r = sshbuf_put_string(b, enc->key, enc->key_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		اذهب out;
	אם (cipher_authlen(enc->cipher) == 0) {
		אם ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->key, mac->key_len)) != 0)
			اذهب out;
	}
	אם ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		اذهب out;
	r = sshbuf_put_stringb(m, b);
 out:
	sshbuf_free(b);
	החזר r;
}

/* serialize packet state into a blob */
صحيح
ssh_packet_get_state(بنية ssh *ssh, بنية sshbuf *m)
{
	بنية session_state *state = ssh->state;
	صحيح r;

#define ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	אם ((r = kex_to_blob(m, ssh->kex)) != 0 ||
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
		החזר r;
#undef ENCODE_INT
	החזר 0;
}

/* restore key exchange results from blob for packet state de-serialization */
ساكن صحيح
newkeys_from_blob(بنية sshbuf *m, بنية ssh *ssh, صحيح mode)
{
	بنية sshbuf *b = عدم;
	بنية sshcomp *comp;
	بنية sshenc *enc;
	بنية sshmac *mac;
	بنية newkeys *newkey = عدم;
	size_t keylen, ivlen, maclen;
	صحيح r;

	אם ((newkey = calloc(1, حجم(*newkey))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = sshbuf_froms(m, &b)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	אם ((r = sshbuf_get_cstring(b, &enc->name, عدم)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->block_size)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->key, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		اذهب out;
	אם ((enc->cipher = cipher_by_name(enc->name)) == عدم ||
	    enc->block_size != cipher_blocksize(enc->cipher) ||
	    cipher_is_internal(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (cipher_authlen(enc->cipher) == 0) {
		אם ((r = sshbuf_get_cstring(b, &mac->name, عدم)) != 0)
			اذهب out;
		אם ((r = mac_setup(mac, mac->name)) != 0)
			اذهب out;
		אם ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->key, &maclen)) != 0)
			اذهب out;
		אם (maclen != mac->key_len) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		mac->key_len = maclen;
	}
	אם ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, عدم)) != 0)
		اذهب out;
	אם (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	enc->key_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[mode] = newkey;
	newkey = عدم;
	r = 0;
 out:
	حرر(newkey);
	sshbuf_free(b);
	החזר r;
}

/* restore kex from blob for packet state de-serialization */
ساكن صحيح
kex_from_blob(بنية sshbuf *m, بنية kex **kexp)
{
	بنية kex *kex;
	صحيح r;

	אם ((kex = kex_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, عدم)) != 0 ||
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
		اذهب out;
	אם (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	kex->server = 1;
	kex->done = 1;
	r = 0;
 out:
	אם (r != 0 || kexp == عدم) {
		kex_free(kex);
		אם (kexp != عدم)
			*kexp = عدم;
	} אחרת {
		kex_free(*kexp);
		*kexp = kex;
	}
	החזר r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
صحيح
ssh_packet_set_state(بنية ssh *ssh, بنية sshbuf *m)
{
	بنية session_state *state = ssh->state;
	ثابت u_char *input, *output;
	size_t ilen, olen;
	صحيح r;
	u_int interactive, qos_interactive, qos_other;

	אם ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
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
		החזר r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_time = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	אם ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0 ||
	    (r = ssh_set_newkeys(ssh, MODE_OUT)) != 0)
		החזר r;

	אם ((r = ssh_packet_set_postauth(ssh)) != 0)
		החזר r;

	sshbuf_reset(state->input);
	sshbuf_reset(state->output);
	אם ((r = sshbuf_get_string_direct(m, &input, &ilen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->input, input, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		החזר r;

	אם ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		החזר r;
#define DECODE_INT(v) ((v) > INT_MAX ? -1 : (صحيح)(v))
	state->interactive_mode = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#undef DECODE_INT

	אם (sshbuf_len(m))
		החזר SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	החזר 0;
}

/* NEW API */

/* put data to the outgoing packet */

صحيح
sshpkt_put(بنية ssh *ssh, ثابت فراغ *v, size_t len)
{
	החזר sshbuf_put(ssh->state->outgoing_packet, v, len);
}

صحيح
sshpkt_putb(بنية ssh *ssh, ثابت بنية sshbuf *b)
{
	החזר sshbuf_putb(ssh->state->outgoing_packet, b);
}

صحيح
sshpkt_put_u8(بنية ssh *ssh, u_char val)
{
	החזר sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

صحيح
sshpkt_put_u32(بنية ssh *ssh, uint32_t val)
{
	החזר sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

صحيح
sshpkt_put_u64(بنية ssh *ssh, uint64_t val)
{
	החזר sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

صحيح
sshpkt_put_string(بنية ssh *ssh, ثابت فراغ *v, size_t len)
{
	החזר sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

صحيح
sshpkt_put_cstring(بنية ssh *ssh, ثابت فراغ *v)
{
	החזר sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

صحيح
sshpkt_put_stringb(بنية ssh *ssh, ثابت بنية sshbuf *v)
{
	החזר sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#ifdef WITH_OPENSSL
صحيح
sshpkt_put_ec(بنية ssh *ssh, ثابت EC_POINT *v, ثابت EC_GROUP *g)
{
	החזר sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

صحيح
sshpkt_put_ec_pkey(بنية ssh *ssh, EVP_PKEY *pkey)
{
	החזר sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

صحيح
sshpkt_put_bignum2(بنية ssh *ssh, ثابت BIGNUM *v)
{
	החזר sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#endif /* WITH_OPENSSL */

/* fetch data from the incoming packet */

صحيح
sshpkt_get(بنية ssh *ssh, فراغ *valp, size_t len)
{
	החזר sshbuf_get(ssh->state->incoming_packet, valp, len);
}

صحيح
sshpkt_get_u8(بنية ssh *ssh, u_char *valp)
{
	החזר sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

صحيح
sshpkt_get_u32(بنية ssh *ssh, uint32_t *valp)
{
	החזר sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

صحيح
sshpkt_get_u64(بنية ssh *ssh, uint64_t *valp)
{
	החזר sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

صحيح
sshpkt_get_string(بنية ssh *ssh, u_char **valp, size_t *lenp)
{
	החזר sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

صحيح
sshpkt_get_string_direct(بنية ssh *ssh, ثابت u_char **valp, size_t *lenp)
{
	החזר sshbuf_get_string_direct(ssh->state->incoming_packet, valp, lenp);
}

صحيح
sshpkt_peek_string_direct(بنية ssh *ssh, ثابت u_char **valp, size_t *lenp)
{
	החזר sshbuf_peek_string_direct(ssh->state->incoming_packet, valp, lenp);
}

صحيح
sshpkt_get_cstring(بنية ssh *ssh, حرف **valp, size_t *lenp)
{
	החזר sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

صحيح
sshpkt_getb_froms(بنية ssh *ssh, بنية sshbuf **valp)
{
	החזר sshbuf_froms(ssh->state->incoming_packet, valp);
}

#ifdef WITH_OPENSSL
صحيح
sshpkt_get_ec(بنية ssh *ssh, EC_POINT *v, ثابت EC_GROUP *g)
{
	החזר sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

صحيح
sshpkt_get_bignum2(بنية ssh *ssh, BIGNUM **valp)
{
	החזר sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#endif /* WITH_OPENSSL */

صحيح
sshpkt_get_end(بنية ssh *ssh)
{
	אם (sshbuf_len(ssh->state->incoming_packet) > 0)
		החזר SSH_ERR_UNEXPECTED_TRAILING_DATA;
	החזר 0;
}

ثابت u_char *
sshpkt_ptr(بنية ssh *ssh, size_t *lenp)
{
	אם (lenp != عدم)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	החזר sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

صحيح
sshpkt_start(بنية ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, حجم(buf));
	buf[حجم(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	החזר sshbuf_put(ssh->state->outgoing_packet, buf, حجم(buf));
}

ساكن صحيح
ssh_packet_send_mux(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	u_char type, *cp;
	size_t len;
	صحيح r;

	אם (ssh->kex)
		החזר SSH_ERR_INTERNAL_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	אם (len < 6)
		החזר SSH_ERR_INTERNAL_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	אם (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	אם (type >= SSH2_MSG_CONNECTION_MIN &&
	    type <= SSH2_MSG_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		אם ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			החזר r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	החזר 0;
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
صحيح
sshpkt_msg_ignore(بنية ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	صحيح r;
	u_int i;

	אם ((r = sshpkt_start(ssh, SSH2_MSG_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		החזר r;
	עבור (i = 0; i < nbytes; i++) {
		אם (i % 4 == 0)
			rnd = arc4random();
		אם ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			החזר r;
		rnd >>= 8;
	}
	החזר 0;
}

/* send it */

صحيح
sshpkt_send(بنية ssh *ssh)
{
	אם (ssh->state && ssh->state->mux)
		החזר ssh_packet_send_mux(ssh);
	החזר ssh_packet_send2(ssh);
}

صحيح
sshpkt_disconnect(بنية ssh *ssh, ثابت حرف *fmt,...)
{
	حرف buf[1024];
	va_list args;
	صحيح r;

	va_start(args, fmt);
	vsnprintf(buf, حجم(buf), fmt, args);
	va_end(args);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	אם ((r = sshpkt_start(ssh, SSH2_MSG_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		החזר r;
	החזר 0;
}

/* roundup current message to pad bytes */
صحيح
sshpkt_add_padding(بنية ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	החזר 0;
}

ساكن حرف *
format_traffic_stats(بنية packet_state *ps)
{
	حرف *stats = عدم, bytes[FMT_SCALED_STRSIZE];

	אם (ps->bytes > LLONG_MAX || fmt_scaled(ps->bytes, bytes) != 0)
		strlcpy(bytes, "OVERFLOW", حجم(bytes));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (unsigned long)ps->packets, (unsigned long long)ps->blocks, bytes);
	החזר stats;
}

ساكن حرف *
dedupe_alg_names(ثابت حرف *in, ثابت حرف *out)
{
	حرف *names = عدم;

	אם (in == عدم)
		in = "<implicit>";
	אם (out == عدم)
		out = "<implicit>";

	אם (strcmp(in, out) == 0) {
		names = xstrdup(in);
	} אחרת {
		xasprintf(&names, "%s in, %s out", in, out);
	}
	החזר names;
}

ساكن حرف *
comp_status_message(بنية ssh *ssh)
{
#ifdef WITH_ZLIB
	حرف *ret = عدم;
	بنية session_state *state = ssh->state;
	unsigned long long iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	حرف iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	حرف icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	אם (state->compression_buffer) {
		אם (state->compression_in_started) {
			iraw = state->compression_in_stream.total_out;
			icmp = state->compression_in_stream.total_in;
			אם (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", حجم(iraw_f));
			אם (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", حجم(icmp_f));
		}
		אם (state->compression_out_started) {
			oraw = state->compression_out_stream.total_in;
			ocmp = state->compression_out_stream.total_out;
			אם (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", حجم(oraw_f));
			אם (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", حجم(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (مزدوج)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (مزدوج)ocmp / oraw);
		החזר ret;
	}
#endif	/* WITH_ZLIB */
	החזר xstrdup("");
}

حرف *
connection_info_message(بنية ssh *ssh)
{
	حرف *ret = عدم, *cipher = عدم, *mac = عدم, *comp = عدم;
	حرف *rekey_volume = عدم, *rekey_time = عدم, *comp_info = عدم;
	حرف thishost[NI_MAXHOST] = "unknown", *tcp_info = عدم;
	بنية kex *kex;
	بنية session_state *state;
	بنية newkeys *nk_in, *nk_out;
	حرف *stats_in = عدم, *stats_out = عدم;
	uint64_t epoch = (uint64_t)time(عدم) - monotime();

	אם (ssh == عدم)
		החזר عدم;
	state = ssh->state;
	kex = ssh->kex;

	(فراغ)gethostname(thishost, حجم(thishost));

	אם (ssh_local_port(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	} אחרת {
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
	אם (state->rekey_limit == 0) {
		xasprintf(&rekey_volume, "limit none");
	} אחרת {
		حرف *volumes = عدم, in[32], out[32];

		snprintf(in, حجم(in), "%llu",
		   (unsigned long long)state->max_blocks_in);
		snprintf(out, حجم(out), "%llu",
		   (unsigned long long)state->max_blocks_out);
		volumes = dedupe_alg_names(in, out);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		حرر(volumes);
	}

	/* Time based rekeying. */
	אם (state->rekey_interval == 0) {
		rekey_time = xstrdup("interval none");
	} אחרת {
		حرف rekey_next[64];

		format_absolute_time(epoch + state->rekey_time +
		    state->rekey_interval, rekey_next, حجم(rekey_next));
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
	حرر(tcp_info);
	حرر(cipher);
	حرر(mac);
	حرر(comp);
	حرر(stats_in);
	حرر(stats_out);
	حرر(rekey_volume);
	حرر(rekey_time);
	حرر(comp_info);
	החזר ret;
}

