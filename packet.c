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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/queue.h>
#شامل <sys/socket.h>
#شامل <sys/time.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <errno.h>
#شامل <netdb.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <limits.h>
#شامل <poll.h>
#شامل <signal.h>
#شامل <time.h>
#شامل <util.h>

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
#شامل <zlib.h>
#endif

#شامل "xmalloc.h"
#شامل "compat.h"
#شامل "ssh2.h"
#شامل "cipher.h"
#شامل "kex.h"
#شامل "digest.h"
#شامل "mac.h"
#شامل "log.h"
#شامل "canohost.h"
#شامل "misc.h"
#شامل "packet.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "version.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#وگرنه
#define DBG(x)
#endif

#define PACKET_MAX_SIZE (256 * 1024)

ساختار packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t blocks;
	uint64_t bytes;
};

ساختار packet {
	TAILQ_ENTRY(packet) next;
	u_char type;
	ساختار sshbuf *payload;
};

ساختار session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	صحیح connection_in;
	صحیح connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	ساختار sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	ساختار sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	ساختار sshbuf *درون_داد;

	/* Buffer for raw output data going to the socket. */
	ساختار sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	ساختار sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	ساختار sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	ساختار sshbuf *compression_buffer;

#ifdef WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_stream compression_in_stream;
	z_stream compression_out_stream;
#endif
	صحیح compression_in_started;
	صحیح compression_out_started;
	صحیح compression_in_failures;
	صحیح compression_out_failures;

	/* default maximum packet size */
	u_int max_packet_size;

	/* Flag indicating whether this module has been initialized. */
	صحیح initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t start_time;

	/* Set to true if the connection is interactive. */
	صحیح interactive_mode;

	/* Set to true if we are the server side. */
	صحیح server_side;

	/* Set to true if we are authenticated. */
	صحیح after_authentication;

	صحیح keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	صحیح packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	ساختار newkeys *newkeys[MODE_MAX];
	ساختار packet_state p_read, p_send;

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
	ساختار sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	صحیح rekeying;

	/* Used in ssh_packet_send_mux() */
	صحیح mux;

	/* QoS handling */
	صحیح qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	صحیح set_maxsize_called;

	/* One-off warning about weak ciphers */
	صحیح cipher_warning_done;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	صحیح disconnecting;

	/* Nagle disabled on socket */
	صحیح nodelay_set;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_in;
	تهی *hook_in_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

ساختار ssh *
ssh_alloc_session_state(تهی)
{
	ساختار ssh *ssh = پوچ;
	ساختار session_state *state = پوچ;

	اگر ((ssh = calloc(1, اندازه(*ssh))) == پوچ ||
	    (state = calloc(1, اندازه(*state))) == پوچ ||
	    (ssh->kex = kex_new()) == پوچ ||
	    (state->درون_داد = sshbuf_new()) == پوچ ||
	    (state->output = sshbuf_new()) == پوچ ||
	    (state->outgoing_packet = sshbuf_new()) == پوچ ||
	    (state->incoming_packet = sshbuf_new()) == پوچ)
		برو fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->private_کلیدها);
	TAILQ_INIT(&ssh->public_کلیدها);
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
	بازگشت ssh;
 fail:
	اگر (ssh) {
		kex_free(ssh->kex);
		آزاد(ssh);
	}
	اگر (state) {
		sshbuf_free(state->درون_داد);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		آزاد(state);
	}
	بازگشت پوچ;
}

تهی
ssh_packet_set_درون_داد_hook(ساختار ssh *ssh, ssh_packet_hook_fn *hook, تهی *ctx)
{
	ssh->state->hook_in = hook;
	ssh->state->hook_in_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
صحیح
ssh_packet_is_rekeying(ساختار ssh *ssh)
{
	بازگشت ssh->state->rekeying ||
	    (ssh->kex != پوچ && ssh->kex->done == 0);
}

/*
 * Sets the descriptors used for communication.
 */
ساختار ssh *
ssh_packet_set_connection(ساختار ssh *ssh, صحیح fd_in, صحیح fd_out)
{
	ساختار session_state *state;
	ثابت ساختار sshcipher *none = cipher_by_name("none");
	صحیح r, wasnull = ssh == پوچ;

	اگر (none == پوچ) {
		error_f("cannot load cipher 'none'");
		بازگشت پوچ;
	}
	اگر (ssh == پوچ)
		ssh = ssh_alloc_session_state();
	اگر (ssh == پوچ) {
		error_f("could not allocate state");
		بازگشت پوچ;
	}
	state = ssh->state;
	state->start_time = monotime();
	state->connection_in = fd_in;
	state->connection_out = fd_out;
	اگر ((r = cipher_init(&state->send_context, none,
	    (ثابت u_char *)"", 0, پوچ, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (ثابت u_char *)"", 0, پوچ, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		اگر (wasnull)
			آزاد(ssh); /* XXX need ssh_free_session_state? */
		بازگشت پوچ;
	}
	state->newkeys[MODE_IN] = state->newkeys[MODE_OUT] = پوچ;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(تهی)ssh_remote_ipaddr(ssh);
	بازگشت ssh;
}

تهی
ssh_packet_set_timeout(ساختار ssh *ssh, صحیح timeout, صحیح شمار)
{
	ساختار session_state *state = ssh->state;

	اگر (timeout <= 0 || شمار <= 0) {
		state->packet_timeout_ms = -1;
		بازگشت;
	}
	اگر ((INT_MAX / 1000) / شمار < timeout)
		state->packet_timeout_ms = INT_MAX;
	وگرنه
		state->packet_timeout_ms = timeout * شمار * 1000;
}

تهی
ssh_packet_set_mux(ساختار ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = پوچ;
}

صحیح
ssh_packet_get_mux(ساختار ssh *ssh)
{
	بازگشت ssh->state->mux;
}

صحیح
ssh_packet_set_log_preamble(ساختار ssh *ssh, ثابت نویسه *fmt, ...)
{
	va_list args;
	صحیح r;

	آزاد(ssh->log_preamble);
	اگر (fmt == پوچ)
		ssh->log_preamble = پوچ;
	وگرنه {
		va_start(args, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, args);
		va_end(args);
		اگر (r < 0 || ssh->log_preamble == پوچ)
			بازگشت SSH_ERR_ALLOC_FAIL;
	}
	بازگشت 0;
}

صحیح
ssh_packet_stop_discard(ساختار ssh *ssh)
{
	ساختار session_state *state = ssh->state;
	صحیح r;

	اگر (state->packet_discard_mac) {
		نویسه buf[1024];
		size_t dlen = PACKET_MAX_SIZE;

		اگر (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', اندازه(buf));
		وقتی (sshbuf_len(state->incoming_packet) < dlen)
			اگر ((r = sshbuf_put(state->incoming_packet, buf,
			    اندازه(buf))) != 0)
				بازگشت r;
		(تهی) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    پوچ, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	بازگشت SSH_ERR_MAC_INVALID;
}

ایستا صحیح
ssh_packet_start_discard(ساختار ssh *ssh, ساختار sshenc *enc,
    ساختار sshmac *mac, size_t mac_already, u_int discard)
{
	ساختار session_state *state = ssh->state;
	صحیح r;

	اگر (enc == پوچ || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		اگر ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			بازگشت r;
		بازگشت SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	اگر (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	اگر (sshbuf_len(state->درون_داد) >= discard)
		بازگشت ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->درون_داد);
	بازگشت 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

صحیح
ssh_packet_connection_is_on_socket(ساختار ssh *ssh)
{
	ساختار session_state *state;
	ساختار sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	اگر (ssh == پوچ || ssh->state == پوچ)
		بازگشت 0;

	state = ssh->state;
	اگر (state->connection_in == -1 || state->connection_out == -1)
		بازگشت 0;
	fromlen = اندازه(from);
	memset(&from, 0, اندازه(from));
	اگر (getpeername(state->connection_in, (ساختار sockaddr *)&from,
	    &fromlen) == -1)
		بازگشت 0;
	اگر (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		بازگشت 0;
	/* filedescriptors in and out are the same, so it's a socket */
	اگر (state->connection_in == state->connection_out)
		بازگشت 1;
	tolen = اندازه(to);
	memset(&to, 0, اندازه(to));
	اگر (getpeername(state->connection_out, (ساختار sockaddr *)&to,
	    &tolen) == -1)
		بازگشت 0;
	اگر (fromlen != tolen || memcmp(&from, &to, fromlen) != 0)
		بازگشت 0;
	بازگشت 1;
}

تهی
ssh_packet_get_bytes(ساختار ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	اگر (ibytes)
		*ibytes = ssh->state->p_read.bytes;
	اگر (obytes)
		*obytes = ssh->state->p_send.bytes;
}

صحیح
ssh_packet_connection_af(ساختار ssh *ssh)
{
	بازگشت get_sock_af(ssh->state->connection_out);
}

/* Sets the connection into non-blocking mode. */

تهی
ssh_packet_set_nonblocking(ساختار ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(ssh->state->connection_in);

	اگر (ssh->state->connection_out != ssh->state->connection_in)
		set_nonblock(ssh->state->connection_out);
}

/* Returns the socket used for reading. */

صحیح
ssh_packet_get_connection_in(ساختار ssh *ssh)
{
	بازگشت ssh->state->connection_in;
}

/* Returns the descriptor used for writing. */

صحیح
ssh_packet_get_connection_out(ساختار ssh *ssh)
{
	بازگشت ssh->state->connection_out;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

ثابت نویسه *
ssh_remote_ipaddr(ساختار ssh *ssh)
{
	صحیح sock;

	/* Check whether we have cached the ipaddr. */
	اگر (ssh->remote_ipaddr == پوچ) {
		اگر (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_in;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_port = get_peer_port(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_port = get_local_port(sock);
		} وگرنه {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_port = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_port = 65535;
		}
	}
	بازگشت ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

نویسه *
ssh_remote_hostname(ساختار ssh *ssh)
{
	ساختار sockaddr_storage from;
	socklen_t fromlen;
	ساختار addrinfo hints, *ai, *aitop;
	نویسه name[NI_MAXHOST], ntop2[NI_MAXHOST];
	ثابت نویسه *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = اندازه(from);
	memset(&from, 0, اندازه(from));
	اگر (getpeername(ssh_packet_get_connection_in(ssh),
	    (ساختار sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		بازگشت xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	اگر (from.ss_family == AF_INET6)
		fromlen = اندازه(ساختار sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	اگر (getnameinfo((ساختار sockaddr *)&from, fromlen, name, اندازه(name),
	    پوچ, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		بازگشت xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, اندازه(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	اگر (getaddrinfo(name, پوچ, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		بازگشت xstrdup(ntop);
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
	memset(&hints, 0, اندازه(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	اگر (getaddrinfo(name, پوچ, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		بازگشت xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	برای (ai = aitop; ai; ai = ai->ai_next) {
		اگر (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    اندازه(ntop2), پوچ, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				بشکن;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	اگر (ai == پوچ) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		بازگشت xstrdup(ntop);
	}
	بازگشت xstrdup(name);
}

/* Returns the port number of the remote host. */

صحیح
ssh_remote_port(ساختار ssh *ssh)
{
	(تهی)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	بازگشت ssh->remote_port;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

ثابت نویسه *
ssh_local_ipaddr(ساختار ssh *ssh)
{
	(تهی)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	بازگشت ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

صحیح
ssh_local_port(ساختار ssh *ssh)
{
	(تهی)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	بازگشت ssh->local_port;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
ثابت نویسه *
ssh_packet_rdomain_in(ساختار ssh *ssh)
{
	اگر (ssh->rdomain_in != پوچ)
		بازگشت ssh->rdomain_in;
	اگر (!ssh_packet_connection_is_on_socket(ssh))
		بازگشت پوچ;
	ssh->rdomain_in = get_rdomain(ssh->state->connection_in);
	بازگشت ssh->rdomain_in;
}

/* Closes the connection and clears and frees internal data structures. */

ایستا تهی
ssh_packet_close_internal(ساختار ssh *ssh, صحیح do_close)
{
	ساختار session_state *state = ssh->state;
	u_int mode;
	ساختار packet *p;

	اگر (!state->initialized)
		بازگشت;
	state->initialized = 0;
	اگر (do_close) {
		اگر (state->connection_in == state->connection_out) {
			close(state->connection_out);
		} وگرنه {
			close(state->connection_in);
			close(state->connection_out);
		}
	}
	sshbuf_free(state->درون_داد);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	وقتی ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, next);
		آزاد(p);
	}
	برای (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(state->newkeys[mode]);	/* current keys */
		state->newkeys[mode] = پوچ;
		ssh_clear_newkeys(ssh, mode);		/* next keys */
	}
#ifdef WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	اگر (do_close && state->compression_buffer) {
		sshbuf_free(state->compression_buffer);
		اگر (state->compression_out_started) {
			z_streamp stream = &state->compression_out_stream;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(unsigned long long)stream->total_in,
				(unsigned long long)stream->total_out,
				stream->total_in == 0 ? 0.0 :
				(دوگانه) stream->total_out / stream->total_in);
			اگر (state->compression_out_failures == 0)
				deflateEnd(stream);
		}
		اگر (state->compression_in_started) {
			z_streamp stream = &state->compression_in_stream;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (unsigned long long)stream->total_out,
			    (unsigned long long)stream->total_in,
			    stream->total_out == 0 ? 0.0 :
			    (دوگانه) stream->total_in / stream->total_out);
			اگر (state->compression_in_failures == 0)
				inflateEnd(stream);
		}
	}
#endif	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = پوچ;
	اگر (do_close) {
		آزاد(ssh->local_ipaddr);
		ssh->local_ipaddr = پوچ;
		آزاد(ssh->remote_ipaddr);
		ssh->remote_ipaddr = پوچ;
		آزاد(ssh->state);
		ssh->state = پوچ;
		kex_free(ssh->kex);
		ssh->kex = پوچ;
	}
}

تهی
ssh_packet_free(ساختار ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
	freezero(ssh, اندازه(*ssh));
}

تهی
ssh_packet_close(ساختار ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
}

تهی
ssh_packet_clear_کلیدها(ساختار ssh *ssh)
{
	ssh_packet_close_internal(ssh, 0);
}

/* Sets remote side protocol flags. */

تهی
ssh_packet_set_protocol_flags(ساختار ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(ساختار ssh *ssh)
{
	بازگشت ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

ایستا صحیح
ssh_packet_init_compression(ساختار ssh *ssh)
{
	اگر (!ssh->state->compression_buffer &&
	    ((ssh->state->compression_buffer = sshbuf_new()) == پوچ))
		بازگشت SSH_ERR_ALLOC_FAIL;
	بازگشت 0;
}

#ifdef WITH_ZLIB
ایستا صحیح
start_compression_out(ساختار ssh *ssh)
{
	debug("Enabling compression.");
	اگر (ssh->state->compression_out_started == 1)
		deflateEnd(&ssh->state->compression_out_stream);
	انتخاب (deflateInit2(&ssh->state->compression_out_stream,
	    Z_BEST_SPEED, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	حالت Z_OK:
		ssh->state->compression_out_started = 1;
		بشکن;
	حالت Z_MEM_ERROR:
		بازگشت SSH_ERR_ALLOC_FAIL;
	پیشفرض:
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	بازگشت 0;
}

ایستا صحیح
start_compression_in(ساختار ssh *ssh)
{
	اگر (ssh->state->compression_in_started == 1)
		inflateEnd(&ssh->state->compression_in_stream);
	انتخاب (inflateInit(&ssh->state->compression_in_stream)) {
	حالت Z_OK:
		ssh->state->compression_in_started = 1;
		بشکن;
	حالت Z_MEM_ERROR:
		بازگشت SSH_ERR_ALLOC_FAIL;
	پیشفرض:
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	بازگشت 0;
}

/* XXX remove need for separate compression buffer */
ایستا صحیح
compress_buffer(ساختار ssh *ssh, ساختار sshbuf *in, ساختار sshbuf *out)
{
	u_char buf[4096];
	صحیح r, status;

	اگر (ssh->state->compression_out_started != 1)
		بازگشت SSH_ERR_INTERNAL_ERROR;

	/* This case is not handled below. */
	اگر (sshbuf_len(in) == 0)
		بازگشت 0;

	/* Input is the contents of the input buffer. */
	اگر ((ssh->state->compression_out_stream.next_in =
	    sshbuf_mutable_ptr(in)) == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_out_stream.avail_in = sshbuf_len(in);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	انجامبده {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_out_stream.next_out = buf;
		ssh->state->compression_out_stream.avail_out = اندازه(buf);

		/* Compress as much data into the buffer as possible. */
		status = deflate(&ssh->state->compression_out_stream,
		    Z_PARTIAL_FLUSH);
		انتخاب (status) {
		حالت Z_MEM_ERROR:
			بازگشت SSH_ERR_ALLOC_FAIL;
		حالت Z_OK:
			/* Append compressed data to output_buffer. */
			اگر ((r = sshbuf_put(out, buf, اندازه(buf) -
			    ssh->state->compression_out_stream.avail_out)) != 0)
				بازگشت r;
			بشکن;
		حالت Z_STREAM_ERROR:
		پیشفرض:
			ssh->state->compression_out_failures++;
			بازگشت SSH_ERR_INVALID_FORMAT;
		}
	} وقتی (ssh->state->compression_out_stream.avail_out == 0);
	بازگشت 0;
}

ایستا صحیح
uncompress_buffer(ساختار ssh *ssh, ساختار sshbuf *in, ساختار sshbuf *out)
{
	u_char buf[4096];
	صحیح r, status;

	اگر (ssh->state->compression_in_started != 1)
		بازگشت SSH_ERR_INTERNAL_ERROR;

	اگر ((ssh->state->compression_in_stream.next_in =
	    sshbuf_mutable_ptr(in)) == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_in_stream.avail_in = sshbuf_len(in);

	برای (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_in_stream.next_out = buf;
		ssh->state->compression_in_stream.avail_out = اندازه(buf);

		status = inflate(&ssh->state->compression_in_stream,
		    Z_SYNC_FLUSH);
		انتخاب (status) {
		حالت Z_OK:
			اگر ((r = sshbuf_put(out, buf, اندازه(buf) -
			    ssh->state->compression_in_stream.avail_out)) != 0)
				بازگشت r;
			اگر (sshbuf_len(out) >= PACKET_MAX_SIZE)
				بازگشت SSH_ERR_INVALID_FORMAT;
			بشکن;
		حالت Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			بازگشت 0;
		حالت Z_DATA_ERROR:
			بازگشت SSH_ERR_INVALID_FORMAT;
		حالت Z_MEM_ERROR:
			بازگشت SSH_ERR_ALLOC_FAIL;
		حالت Z_STREAM_ERROR:
		پیشفرض:
			ssh->state->compression_in_failures++;
			بازگشت SSH_ERR_INTERNAL_ERROR;
		}
	}
	/* NOTREACHED */
}

#وگرنه	/* WITH_ZLIB */

ایستا صحیح
start_compression_out(ساختار ssh *ssh)
{
	بازگشت SSH_ERR_INTERNAL_ERROR;
}

ایستا صحیح
start_compression_in(ساختار ssh *ssh)
{
	بازگشت SSH_ERR_INTERNAL_ERROR;
}

ایستا صحیح
compress_buffer(ساختار ssh *ssh, ساختار sshbuf *in, ساختار sshbuf *out)
{
	بازگشت SSH_ERR_INTERNAL_ERROR;
}

ایستا صحیح
uncompress_buffer(ساختار ssh *ssh, ساختار sshbuf *in, ساختار sshbuf *out)
{
	بازگشت SSH_ERR_INTERNAL_ERROR;
}
#endif	/* WITH_ZLIB */

تهی
ssh_clear_newkeys(ساختار ssh *ssh, صحیح mode)
{
	اگر (ssh->kex && ssh->kex->newkeys[mode]) {
		kex_free_newkeys(ssh->kex->newkeys[mode]);
		ssh->kex->newkeys[mode] = پوچ;
	}
}

صحیح
ssh_set_newkeys(ساختار ssh *ssh, صحیح mode)
{
	ساختار session_state *state = ssh->state;
	ساختار sshenc *enc;
	ساختار sshmac *mac;
	ساختار sshcomp *comp;
	ساختار sshcipher_ctx **ccp;
	ساختار packet_state *ps;
	uint64_t *max_blocks, *hard_max_blocks;
	ثابت نویسه *wmsg;
	صحیح r, crypt_type;
	ثابت نویسه *dir = mode == MODE_OUT ? "out" : "in";

	debug2_f("mode %d", mode);

	اگر (mode == MODE_OUT) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_blocks = &state->hard_max_blocks_out;
		max_blocks = &state->max_blocks_out;
	} وگرنه {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_blocks = &state->hard_max_blocks_in;
		max_blocks = &state->max_blocks_in;
	}
	اگر (state->newkeys[mode] != پوچ) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (unsigned long long)state->p_read.bytes,
		    (unsigned long long)state->p_read.blocks,
		    (unsigned long long)state->p_send.bytes,
		    (unsigned long long)state->p_send.blocks);
		kex_free_newkeys(state->newkeys[mode]);
		state->newkeys[mode] = پوچ;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->blocks = 0;
	/* move newkeys from kex to state */
	اگر ((state->newkeys[mode] = ssh->kex->newkeys[mode]) == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	ssh->kex->newkeys[mode] = پوچ;
	enc  = &state->newkeys[mode]->enc;
	mac  = &state->newkeys[mode]->mac;
	comp = &state->newkeys[mode]->comp;
	اگر (cipher_authlen(enc->cipher) == 0) {
		اگر ((r = mac_init(mac)) != 0)
			بازگشت r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = پوچ;
	اگر ((r = cipher_init(ccp, enc->cipher, enc->کلید, enc->کلید_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		بازگشت r;
	اگر (!state->cipher_warning_done &&
	    (wmsg = cipher_warning_message(*ccp)) != پوچ) {
		error("Warning: %s", wmsg);
		state->cipher_warning_done = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	اگر (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		اگر ((r = ssh_packet_init_compression(ssh)) < 0)
			بازگشت r;
		اگر (mode == MODE_OUT) {
			اگر ((r = start_compression_out(ssh)) != 0)
				بازگشت r;
		} وگرنه {
			اگر ((r = start_compression_in(ssh)) != 0)
				بازگشت r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	اگر (enc->block_size >= 16)
		*hard_max_blocks = (uint64_t)1 << (enc->block_size*2);
	وگرنه
		*hard_max_blocks = ((uint64_t)1 << 30) / enc->block_size;
	*max_blocks = *hard_max_blocks;
	اگر (state->rekey_limit) {
		*max_blocks = MINIMUM(*max_blocks,
		    state->rekey_limit / enc->block_size);
	}
	debug("rekey %s after %llu blocks", dir,
	    (unsigned long long)*max_blocks);
	بازگشت 0;
}

#define MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
ایستا درونخطی صحیح
ssh_packet_check_rekey_blocklimit(ساختار ssh *ssh, u_int packet_len, صحیح hard)
{
	ساختار session_state *state = ssh->state;
	uint32_t out_blocks;
	ثابت uint64_t max_blocks_in = hard ?
	    state->hard_max_blocks_in : state->max_blocks_in;
	ثابت uint64_t max_blocks_out = hard ?
	    state->hard_max_blocks_out : state->max_blocks_out;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	اگر (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		بازگشت 1;

	اگر (state->newkeys[MODE_OUT] == پوچ)
		بازگشت 0;

	/* Rekey after (cipher-specific) maximum blocks */
	out_blocks = ROUNDUP(packet_len,
	    state->newkeys[MODE_OUT]->enc.block_size);
	بازگشت (max_blocks_out &&
	    (state->p_send.blocks + out_blocks > max_blocks_out)) ||
	    (max_blocks_in &&
	    (state->p_read.blocks > max_blocks_in));
}

ایستا صحیح
ssh_packet_need_rekeying(ساختار ssh *ssh, u_int outbound_packet_len)
{
	ساختار session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	اگر (!state->after_authentication)
		بازگشت 0;

	/* Haven't keyed yet or KEX in progress. */
	اگر (ssh_packet_is_rekeying(ssh))
		بازگشت 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	اگر (state->p_send.packets == 0 && state->p_read.packets == 0)
		بازگشت 0;

	/* Time-based rekeying */
	اگر (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_time + state->rekey_interval <= monotime())
		بازگشت 1;

	بازگشت ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
ایستا صحیح
ssh_packet_check_rekey_preauth(ساختار ssh *ssh, u_int outgoing_packet_len)
{
	اگر (ssh->state->after_authentication)
		بازگشت 0;

	اگر (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		بازگشت SSH_ERR_NEED_REKEY;
	}
	بازگشت 0;
}

صحیح
ssh_packet_check_rekey(ساختار ssh *ssh)
{
	صحیح r;

	اگر ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		بازگشت r;
	اگر (!ssh_packet_need_rekeying(ssh, 0))
		بازگشت 0;
	debug3_f("rekex triggered");
	بازگشت kex_start_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
ایستا صحیح
ssh_packet_enable_delayed_compress(ساختار ssh *ssh)
{
	ساختار session_state *state = ssh->state;
	ساختار sshcomp *comp = پوچ;
	صحیح r, mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	برای (mode = 0; mode < MODE_MAX; mode++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		اگر (state->newkeys[mode] == پوچ)
			ادامه;
		comp = &state->newkeys[mode]->comp;
		اگر (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			اگر ((r = ssh_packet_init_compression(ssh)) != 0)
				بازگشت r;
			اگر (mode == MODE_OUT) {
				اگر ((r = start_compression_out(ssh)) != 0)
					بازگشت r;
			} وگرنه {
				اگر ((r = start_compression_in(ssh)) != 0)
					بازگشت r;
			}
			comp->enabled = 1;
		}
	}
	بازگشت 0;
}

/* Used to mute debug logging for noisy packet types */
صحیح
ssh_packet_log_type(u_char type)
{
	انتخاب (type) {
	حالت SSH2_پیام_PING:
	حالت SSH2_پیام_PONG:
	حالت SSH2_پیام_CHANNEL_DATA:
	حالت SSH2_پیام_CHANNEL_EXTENDED_DATA:
	حالت SSH2_پیام_CHANNEL_WINDOW_ADJUST:
		بازگشت 0;
	پیشفرض:
		بازگشت 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
صحیح
ssh_packet_send2_wrapped(ساختار ssh *ssh)
{
	ساختار session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_LENGTH];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	ساختار sshenc *enc   = پوچ;
	ساختار sshmac *mac   = پوچ;
	ساختار sshcomp *comp = پوچ;
	صحیح r, block_size;

	اگر (state->newkeys[MODE_OUT] != پوچ) {
		enc  = &state->newkeys[MODE_OUT]->enc;
		mac  = &state->newkeys[MODE_OUT]->mac;
		comp = &state->newkeys[MODE_OUT]->comp;
		/* disable mac for authenticated encryption */
		اگر ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = پوچ;
	}
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	اگر (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#endif

	اگر (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		اگر ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			برو out;
		sshbuf_reset(state->compression_buffer);
		اگر ((r = compress_buffer(ssh, state->outgoing_packet,
		    state->compression_buffer)) != 0)
			برو out;
		sshbuf_reset(state->outgoing_packet);
		اگر ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_buffer)) != 0)
			برو out;
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
	اگر (padlen < 4)
		padlen += block_size;
	اگر (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, block_size);
		/* check if roundup overflowed */
		اگر (state->extra_pad < tmp)
			بازگشت SSH_ERR_INVALID_ARGUMENT;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		اگر (tmp > state->extra_pad)
			بازگشت SSH_ERR_INVALID_ARGUMENT;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		اگر (padlen < tmp)
			بازگشت SSH_ERR_INVALID_ARGUMENT; /* overflow */
		state->extra_pad = 0;
	}
	اگر ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		برو out;
	اگر (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} وگرنه {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	اگر (cp == پوچ) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	اگر (mac && mac->enabled && !mac->etm) {
		اگر ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, اندازه(macbuf))) != 0)
			برو out;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	اگر ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		برو out;
	اگر ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		برو out;
	/* append unencrypted MAC */
	اگر (mac && mac->enabled) {
		اگر (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			اگر ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, اندازه(macbuf))) != 0)
				برو out;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		اگر ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			برو out;
	}
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#endif
	/* increment sequence number for outgoing packets */
	اگر (++state->p_send.seqnr == 0) {
		اگر ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	اگر (++state->p_send.packets == 0)
		بازگشت SSH_ERR_NEED_REKEY;
	state->p_send.blocks += len / block_size;
	state->p_send.bytes += len;
	sshbuf_reset(state->outgoing_packet);

	اگر (type == SSH2_پیام_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	اگر (type == SSH2_پیام_NEWKEYS)
		r = ssh_set_newkeys(ssh, MODE_OUT);
	وگرنه اگر (type == SSH2_پیام_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	وگرنه
		r = 0;
 out:
	بازگشت r;
}

/* returns non-zero if the specified packet type is usec by KEX */
ایستا صحیح
ssh_packet_type_is_kex(u_char type)
{
	بازگشت
	    type >= SSH2_پیام_TRANSPORT_MIN &&
	    type <= SSH2_پیام_TRANSPORT_MAX &&
	    type != SSH2_پیام_SERVICE_REQUEST &&
	    type != SSH2_پیام_SERVICE_ACCEPT &&
	    type != SSH2_پیام_EXT_INFO;
}

صحیح
ssh_packet_send2(ساختار ssh *ssh)
{
	ساختار session_state *state = ssh->state;
	ساختار packet *p;
	u_char type;
	صحیح r, need_rekey;

	اگر (sshbuf_len(state->outgoing_packet) < 6)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	اگر (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		بازگشت r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	اگر ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		اگر (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = calloc(1, اندازه(*p));
		اگر (p == پوچ)
			بازگشت SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, next);
		state->outgoing_packet = sshbuf_new();
		اگر (state->outgoing_packet == پوچ)
			بازگشت SSH_ERR_ALLOC_FAIL;
		اگر (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			بازگشت kex_start_rekex(ssh);
		}
		بازگشت 0;
	}

	/* rekeying starts with sending KEXINIT */
	اگر (type == SSH2_پیام_KEXINIT)
		state->rekeying = 1;

	اگر ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		بازگشت r;

	/* after a NEWKEYS message we can send the complete queue */
	اگر (type == SSH2_پیام_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_time = monotime();
		وقتی ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			اگر (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				بازگشت kex_start_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, next);
			memset(p, 0, اندازه(*p));
			آزاد(p);
			اگر ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				بازگشت r;
		}
	}
	بازگشت 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

صحیح
ssh_packet_read_seqnr(ساختار ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ساختار session_state *state = ssh->state;
	صحیح len, r, ms_remain = 0;
	ساختار pollfd pfd;
	نویسه buf[8192];
	ساختار timeval start;
	ساختار timespec timespec, *timespecp = پوچ;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	اگر ((r = ssh_packet_write_wait(ssh)) != 0)
		برو out;

	/* Stay in the loop until we have received a complete packet. */
	برای (;;) {
		/* Try to read a packet from the buffer. */
		اگر ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			بشکن;
		/* If we got a packet, return it. */
		اگر (*typep != SSH_پیام_NONE)
			بشکن;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_in;
		pfd.events = POLLIN;

		اگر (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		برای (;;) {
			اگر (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			اگر ((r = ppoll(&pfd, 1, timespecp, پوچ)) >= 0)
				بشکن;
			اگر (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				برو out;
			}
			اگر (state->packet_timeout_ms <= 0)
				ادامه;
			ms_subtract_diff(&start, &ms_remain);
			اگر (ms_remain <= 0) {
				r = 0;
				بشکن;
			}
		}
		اگر (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			برو out;
		}
		/* Read data from the socket. */
		len = اقرأ(state->connection_in, buf, اندازه(buf));
		اگر (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			برو out;
		}
		اگر (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			برو out;
		}

		/* Append it to the buffer. */
		اگر ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			برو out;
	}
 out:
	بازگشت r;
}

صحیح
ssh_packet_read(ساختار ssh *ssh)
{
	u_char type;
	صحیح r;

	اگر ((r = ssh_packet_read_seqnr(ssh, &type, پوچ)) != 0)
		sshpkt_fatal(ssh, r, "read");
	بازگشت type;
}

ایستا صحیح
ssh_packet_read_poll2_mux(ساختار ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ساختار session_state *state = ssh->state;
	ثابت u_char *cp;
	size_t need;
	صحیح r;

	اگر (ssh->kex)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	*typep = SSH_پیام_NONE;
	cp = sshbuf_ptr(state->درون_داد);
	اگر (state->packlen == 0) {
		اگر (sshbuf_len(state->درون_داد) < 4 + 1)
			بازگشت 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		اگر (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_SIZE)
			بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	}
	need = state->packlen + 4;
	اگر (sshbuf_len(state->درون_داد) < need)
		بازگشت 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	اگر ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->درون_داد, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, پوچ)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		بازگشت r;
	اگر (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	بازگشت r;
}

صحیح
ssh_packet_read_poll2(ساختار ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ساختار session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, block_size;
	ساختار sshenc *enc   = پوچ;
	ساختار sshmac *mac   = پوچ;
	ساختار sshcomp *comp = پوچ;
	صحیح r;

	اگر (state->mux)
		بازگشت ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_پیام_NONE;

	اگر (state->packet_discard)
		بازگشت 0;

	اگر (state->newkeys[MODE_IN] != پوچ) {
		enc  = &state->newkeys[MODE_IN]->enc;
		mac  = &state->newkeys[MODE_IN]->mac;
		comp = &state->newkeys[MODE_IN]->comp;
		/* disable mac for authenticated encryption */
		اگر ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = پوچ;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	اگر (aadlen && state->packlen == 0) {
		اگر (cipher_get_length(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->درون_داد), sshbuf_len(state->درون_داد)) != 0)
			بازگشت 0;
		اگر (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			sshbuf_dump(state->درون_داد, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			اگر ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				بازگشت r;
			بازگشت SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} وگرنه اگر (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		اگر (sshbuf_len(state->درون_داد) < block_size)
			بازگشت 0;
		sshbuf_reset(state->incoming_packet);
		اگر ((r = sshbuf_reserve(state->incoming_packet, block_size,
		    &cp)) != 0)
			برو out;
		اگر ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->درون_داد),
		    block_size, 0, 0)) != 0)
			برو out;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		اگر (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->درون_داد, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			بازگشت ssh_packet_start_discard(ssh, enc, mac, 0,
			    PACKET_MAX_SIZE);
		}
		اگر ((r = sshbuf_consume(state->درون_داد, block_size)) != 0)
			برو out;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	اگر (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} وگرنه {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - block_size;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", block_size, need, maclen, authlen, aadlen));
	اگر (need % block_size != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
		بازگشت ssh_packet_start_discard(ssh, enc, mac, 0,
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
	اگر (sshbuf_len(state->درون_داد) < aadlen + need + authlen + maclen)
		بازگشت 0; /* packet is incomplete */
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->درون_داد, stderr);
#endif
	/* EtM: check mac over encrypted input */
	اگر (mac && mac->enabled && mac->etm) {
		اگر ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->درون_داد), aadlen + need,
		    sshbuf_ptr(state->درون_داد) + aadlen + need + authlen,
		    maclen)) != 0) {
			اگر (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			برو out;
		}
	}
	اگر ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		برو out;
	اگر ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->درون_داد), need, aadlen, authlen)) != 0)
		برو out;
	اگر ((r = sshbuf_consume(state->درون_داد, aadlen + need + authlen)) != 0)
		برو out;
	اگر (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		اگر (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->درون_داد), maclen)) != 0) {
			اگر (r != SSH_ERR_MAC_INVALID)
				برو out;
			logit("Corrupted MAC on input.");
			اگر (need + block_size > PACKET_MAX_SIZE)
				بازگشت SSH_ERR_INTERNAL_ERROR;
			بازگشت ssh_packet_start_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_SIZE - need - block_size);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		اگر ((r = sshbuf_consume(state->درون_داد, mac->mac_len)) != 0)
			برو out;
	}

	اگر (seqnr_p != پوچ)
		*seqnr_p = state->p_read.seqnr;
	اگر (++state->p_read.seqnr == 0) {
		اگر ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	اگر (++state->p_read.packets == 0)
		بازگشت SSH_ERR_NEED_REKEY;
	state->p_read.blocks += (state->packlen + 4) / block_size;
	state->p_read.bytes += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	اگر (padlen < 4)	{
		اگر ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			بازگشت r;
		بازگشت SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	اگر ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_end(state->incoming_packet, padlen)) != 0))
		برو out;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	اگر (comp && comp->enabled) {
		sshbuf_reset(state->compression_buffer);
		اگر ((r = uncompress_buffer(ssh, state->incoming_packet,
		    state->compression_buffer)) != 0)
			برو out;
		sshbuf_reset(state->incoming_packet);
		اگر ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_buffer)) != 0)
			برو out;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	اگر ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		برو out;
	اگر (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	اگر (*typep < SSH2_پیام_MIN) {
		اگر ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			بازگشت r;
		بازگشت SSH_ERR_PROTOCOL_ERROR;
	}
	اگر (state->hook_in != پوچ &&
	    (r = state->hook_in(ssh, state->incoming_packet, typep,
	    state->hook_in_ctx)) != 0)
		بازگشت r;
	اگر (*typep == SSH2_پیام_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	وگرنه
		r = 0;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#endif
	/* reset for next packet */
	state->packlen = 0;
	اگر (*typep == SSH2_پیام_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	اگر ((r = ssh_packet_check_rekey(ssh)) != 0)
		بازگشت r;
 out:
	بازگشت r;
}

صحیح
ssh_packet_read_poll_seqnr(ساختار ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ساختار session_state *state = ssh->state;
	u_int reason, seqnr;
	صحیح r;
	u_char *پیام;
	ثابت u_char *d;
	size_t len;

	برای (;;) {
		پیام = پوچ;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		اگر (r != 0)
			بازگشت r;
		اگر (*typep == 0) {
			/* no message ready */
			بازگشت 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		اگر (*typep == SSH2_پیام_DISCONNECT) {
			اگر ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &پیام, پوچ)) != 0)
				بازگشت r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh), reason, پیام);
			آزاد(پیام);
			بازگشت SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		اگر (ssh->kex != پوچ &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			بازگشت 0;
		/* Implicitly handle transport-level messages */
		انتخاب (*typep) {
		حالت SSH2_پیام_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			بشکن;
		حالت SSH2_پیام_DEBUG:
			اگر ((r = sshpkt_get_u8(ssh, پوچ)) != 0 ||
			    (r = sshpkt_get_string(ssh, &پیام, پوچ)) != 0 ||
			    (r = sshpkt_get_string(ssh, پوچ, پوچ)) != 0) {
				آزاد(پیام);
				بازگشت r;
			}
			debug("Remote: %.900s", پیام);
			آزاد(پیام);
			بشکن;
		حالت SSH2_پیام_UNIMPLEMENTED:
			اگر ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				بازگشت r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			بشکن;
		حالت SSH2_پیام_PING:
			اگر ((r = sshpkt_get_string_direct(ssh, &d, &len)) != 0)
				بازگشت r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			اگر (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				بشکن;
			}
			اگر (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				بشکن;
			}
			اگر ((r = sshpkt_start(ssh, SSH2_پیام_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				بازگشت r;
			بشکن;
		حالت SSH2_پیام_PONG:
			اگر ((r = sshpkt_get_string_direct(ssh,
			    پوچ, &len)) != 0)
				بازگشت r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			بشکن;
		پیشفرض:
			اگر (ssh->kex != پوچ &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				بازگشت SSH_ERR_PROTOCOL_ERROR;
			}
			بازگشت 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
صحیح
ssh_packet_process_incoming(ساختار ssh *ssh, ثابت نویسه *buf, u_int len)
{
	ساختار session_state *state = ssh->state;
	صحیح r;

	اگر (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		اگر (len >= state->packet_discard) {
			اگر ((r = ssh_packet_stop_discard(ssh)) != 0)
				بازگشت r;
		}
		state->packet_discard -= len;
		بازگشت 0;
	}
	اگر ((r = sshbuf_put(state->درون_داد, buf, len)) != 0)
		بازگشت r;

	بازگشت 0;
}

/* Reads and buffers data from the specified fd */
صحیح
ssh_packet_process_read(ساختار ssh *ssh, صحیح fd)
{
	ساختار session_state *state = ssh->state;
	صحیح r;
	size_t rlen;

	اگر ((r = sshbuf_read(fd, state->درون_داد, PACKET_MAX_SIZE, &rlen)) != 0)
		بازگشت r;

	اگر (state->packet_discard) {
		اگر ((r = sshbuf_consume_end(state->درون_داد, rlen)) != 0)
			بازگشت r;
		state->keep_alive_timeouts = 0; /* ?? */
		اگر (rlen >= state->packet_discard) {
			اگر ((r = ssh_packet_stop_discard(ssh)) != 0)
				بازگشت r;
		}
		state->packet_discard -= rlen;
		بازگشت 0;
	}
	بازگشت 0;
}

صحیح
ssh_packet_remaining(ساختار ssh *ssh)
{
	بازگشت sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
تهی
ssh_packet_send_debug(ساختار ssh *ssh, ثابت نویسه *fmt,...)
{
	نویسه buf[1024];
	va_list args;
	صحیح r;

	اگر ((ssh->compat & SSH_BUG_DEBUG))
		بازگشت;

	va_start(args, fmt);
	vsnprintf(buf, اندازه(buf), fmt, args);
	va_end(args);

	debug3("sending debug message: %s", buf);

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

تهی
sshpkt_fmt_connection_id(ساختار ssh *ssh, نویسه *s, size_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
ایستا تهی
sshpkt_vfatal(ساختار ssh *ssh, صحیح r, ثابت نویسه *fmt, va_list ap)
{
	نویسه *tag = پوچ, remote_id[512];
	صحیح oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, اندازه(remote_id));

	انتخاب (r) {
	حالت SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_کلیدها(ssh);
		logdie("Connection closed by %s", remote_id);
	حالت SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_کلیدها(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	حالت SSH_ERR_DISCONNECTED:
		ssh_packet_clear_کلیدها(ssh);
		logdie("Disconnected from %s", remote_id);
	حالت SSH_ERR_SYSTEM_ERROR:
		اگر (errno == ECONNRESET) {
			ssh_packet_clear_کلیدها(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	حالت SSH_ERR_NO_CIPHER_ALG_MATCH:
	حالت SSH_ERR_NO_MAC_ALG_MATCH:
	حالت SSH_ERR_NO_COMPRESS_ALG_MATCH:
	حالت SSH_ERR_NO_KEX_ALG_MATCH:
	حالت SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		اگر (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_کلیدها(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	پیشفرض:
		اگر (vasprintf(&tag, fmt, ap) == -1) {
			ssh_packet_clear_کلیدها(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_کلیدها(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    tag != پوچ ? tag : "", tag != پوچ ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

تهی
sshpkt_fatal(ساختار ssh *ssh, صحیح r, ثابت نویسه *fmt, ...)
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
تهی
ssh_packet_disconnect(ساختار ssh *ssh, ثابت نویسه *fmt,...)
{
	نویسه buf[1024], remote_id[512];
	va_list args;
	صحیح r;

	/* Guard against recursive invocations. */
	اگر (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, اندازه(remote_id));
	va_start(args, fmt);
	vsnprintf(buf, اندازه(buf), fmt, args);
	va_end(args);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	اگر ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	اگر ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
صحیح
ssh_packet_write_poll(ساختار ssh *ssh)
{
	ساختار session_state *state = ssh->state;
	صحیح len = sshbuf_len(state->output);
	صحیح r;

	اگر (len > 0) {
		len = اكتب(state->connection_out,
		    sshbuf_ptr(state->output), len);
		اگر (len == -1) {
			اگر (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				بازگشت 0;
			بازگشت SSH_ERR_SYSTEM_ERROR;
		}
		اگر (len == 0)
			بازگشت SSH_ERR_CONN_CLOSED;
		اگر ((r = sshbuf_consume(state->output, len)) != 0)
			بازگشت r;
	}
	بازگشت 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
صحیح
ssh_packet_write_wait(ساختار ssh *ssh)
{
	صحیح ret, r, ms_remain = 0;
	ساختار timeval start;
	ساختار timespec timespec, *timespecp = پوچ;
	ساختار session_state *state = ssh->state;
	ساختار pollfd pfd;

	اگر ((r = ssh_packet_write_poll(ssh)) != 0)
		بازگشت r;
	وقتی (ssh_packet_have_data_to_write(ssh)) {
		pfd.fd = state->connection_out;
		pfd.events = POLLOUT;

		اگر (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		برای (;;) {
			اگر (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			اگر ((ret = ppoll(&pfd, 1, timespecp, پوچ)) >= 0)
				بشکن;
			اگر (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				بشکن;
			اگر (state->packet_timeout_ms <= 0)
				ادامه;
			ms_subtract_diff(&start, &ms_remain);
			اگر (ms_remain <= 0) {
				ret = 0;
				بشکن;
			}
		}
		اگر (ret == 0)
			بازگشت SSH_ERR_CONN_TIMEOUT;
		اگر ((r = ssh_packet_write_poll(ssh)) != 0)
			بازگشت r;
	}
	بازگشت 0;
}

/* Returns true if there is buffered data to write to the connection. */

صحیح
ssh_packet_have_data_to_write(ساختار ssh *ssh)
{
	بازگشت sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

صحیح
ssh_packet_not_very_much_data_to_write(ساختار ssh *ssh)
{
	اگر (ssh->state->interactive_mode)
		بازگشت sshbuf_len(ssh->state->output) < 16384;
	وگرنه
		بازگشت sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

صحیح
ssh_packet_interactive_data_to_write(ساختار ssh *ssh)
{
	بازگشت ssh->state->interactive_mode &&
	    sshbuf_len(ssh->state->output) < 256;
}

ایستا تهی
apply_qos(ساختار ssh *ssh)
{
	ساختار session_state *state = ssh->state;
	صحیح qos = state->interactive_mode ?
	    state->qos_interactive : state->qos_other;

	اگر (!ssh_packet_connection_is_on_socket(ssh))
		بازگشت;
	اگر (!state->nodelay_set) {
		set_nodelay(state->connection_in);
		state->nodelay_set = 1;
	}
	set_sock_tos(ssh->state->connection_in, qos);
}

/* Informs that the current session is interactive. */
تهی
ssh_packet_set_interactive(ساختار ssh *ssh, صحیح interactive)
{
	ساختار session_state *state = ssh->state;

	state->interactive_mode = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
تهی
ssh_packet_set_qos(ساختار ssh *ssh, صحیح qos_interactive, صحیح qos_other)
{
	ساختار session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

صحیح
ssh_packet_set_maxsize(ساختار ssh *ssh, u_int s)
{
	ساختار session_state *state = ssh->state;

	اگر (state->set_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_size, s);
		بازگشت -1;
	}
	اگر (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		بازگشت -1;
	}
	state->set_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_size = s;
	بازگشت s;
}

صحیح
ssh_packet_inc_alive_timeouts(ساختار ssh *ssh)
{
	بازگشت ++ssh->state->keep_alive_timeouts;
}

تهی
ssh_packet_set_alive_timeouts(ساختار ssh *ssh, صحیح ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(ساختار ssh *ssh)
{
	بازگشت ssh->state->max_packet_size;
}

تهی
ssh_packet_set_rekey_limits(ساختار ssh *ssh, uint64_t bytes, uint32_t seconds)
{
	اگر (bytes == 0 && seconds == 0)
		بازگشت;

	debug3("rekey after %llu bytes, %u seconds", (unsigned long long)bytes,
	    (unsigned صحیح)seconds);
	ssh->state->rekey_limit = bytes;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(ساختار ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_time + ssh->state->rekey_interval -
	    monotime();
	بازگشت (seconds <= 0 ? 1 : seconds);
}

تهی
ssh_packet_set_server(ساختار ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

تهی
ssh_packet_set_authenticated(ساختار ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

تهی *
ssh_packet_get_درون_داد(ساختار ssh *ssh)
{
	بازگشت (تهی *)ssh->state->درون_داد;
}

تهی *
ssh_packet_get_output(ساختار ssh *ssh)
{
	بازگشت (تهی *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
ایستا صحیح
ssh_packet_set_postauth(ساختار ssh *ssh)
{
	صحیح r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	اگر ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		بازگشت r;
	بازگشت 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
ایستا صحیح
kex_to_blob(ساختار sshbuf *m, ساختار kex *kex)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
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
		بازگشت r;
	بازگشت 0;
}

/* turn key exchange results into a blob for packet state serialization */
ایستا صحیح
newkeys_to_blob(ساختار sshbuf *m, ساختار ssh *ssh, صحیح mode)
{
	ساختار sshbuf *b;
	ساختار sshcipher_ctx *cc;
	ساختار sshcomp *comp;
	ساختار sshenc *enc;
	ساختار sshmac *mac;
	ساختار newkeys *newkey;
	صحیح r;

	اگر ((newkey = ssh->state->newkeys[mode]) == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (mode == MODE_OUT) ? ssh->state->send_context :
	    ssh->state->receive_context;
	اگر ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		بازگشت r;
	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->block_size)) != 0 ||
	    (r = sshbuf_put_string(b, enc->کلید, enc->کلید_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		برو out;
	اگر (cipher_authlen(enc->cipher) == 0) {
		اگر ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->کلید, mac->کلید_len)) != 0)
			برو out;
	}
	اگر ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		برو out;
	r = sshbuf_put_stringb(m, b);
 out:
	sshbuf_free(b);
	بازگشت r;
}

/* serialize packet state into a blob */
صحیح
ssh_packet_get_state(ساختار ssh *ssh, ساختار sshbuf *m)
{
	ساختار session_state *state = ssh->state;
	صحیح r;

#define ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	اگر ((r = kex_to_blob(m, ssh->kex)) != 0 ||
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
	    (r = sshbuf_put_stringb(m, state->درون_داد)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_mode))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		بازگشت r;
#undef ENCODE_INT
	بازگشت 0;
}

/* restore key exchange results from blob for packet state de-serialization */
ایستا صحیح
newkeys_from_blob(ساختار sshbuf *m, ساختار ssh *ssh, صحیح mode)
{
	ساختار sshbuf *b = پوچ;
	ساختار sshcomp *comp;
	ساختار sshenc *enc;
	ساختار sshmac *mac;
	ساختار newkeys *newkey = پوچ;
	size_t keylen, ivlen, maclen;
	صحیح r;

	اگر ((newkey = calloc(1, اندازه(*newkey))) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_froms(m, &b)) != 0)
		برو out;
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	اگر ((r = sshbuf_get_cstring(b, &enc->name, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->block_size)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->کلید, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		برو out;
	اگر ((enc->cipher = cipher_by_name(enc->name)) == پوچ ||
	    enc->block_size != cipher_blocksize(enc->cipher) ||
	    cipher_is_internal(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (cipher_authlen(enc->cipher) == 0) {
		اگر ((r = sshbuf_get_cstring(b, &mac->name, پوچ)) != 0)
			برو out;
		اگر ((r = mac_setup(mac, mac->name)) != 0)
			برو out;
		اگر ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->کلید, &maclen)) != 0)
			برو out;
		اگر (maclen != mac->کلید_len) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		mac->کلید_len = maclen;
	}
	اگر ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, پوچ)) != 0)
		برو out;
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	enc->کلید_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[mode] = newkey;
	newkey = پوچ;
	r = 0;
 out:
	آزاد(newkey);
	sshbuf_free(b);
	بازگشت r;
}

/* restore kex from blob for packet state de-serialization */
ایستا صحیح
kex_from_blob(ساختار sshbuf *m, ساختار kex **kexp)
{
	ساختار kex *kex;
	صحیح r;

	اگر ((kex = kex_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, پوچ)) != 0 ||
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
		برو out;
	اگر (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	kex->server = 1;
	kex->done = 1;
	r = 0;
 out:
	اگر (r != 0 || kexp == پوچ) {
		kex_free(kex);
		اگر (kexp != پوچ)
			*kexp = پوچ;
	} وگرنه {
		kex_free(*kexp);
		*kexp = kex;
	}
	بازگشت r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
صحیح
ssh_packet_set_state(ساختار ssh *ssh, ساختار sshbuf *m)
{
	ساختار session_state *state = ssh->state;
	ثابت u_char *درون_داد, *output;
	size_t ilen, olen;
	صحیح r;
	u_int interactive, qos_interactive, qos_other;

	اگر ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
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
		بازگشت r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_time = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	اگر ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0 ||
	    (r = ssh_set_newkeys(ssh, MODE_OUT)) != 0)
		بازگشت r;

	اگر ((r = ssh_packet_set_postauth(ssh)) != 0)
		بازگشت r;

	sshbuf_reset(state->درون_داد);
	sshbuf_reset(state->output);
	اگر ((r = sshbuf_get_string_direct(m, &درون_داد, &ilen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->درون_داد, درون_داد, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		بازگشت r;

	اگر ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		بازگشت r;
#define DECODE_INT(v) ((v) > INT_MAX ? -1 : (صحیح)(v))
	state->interactive_mode = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#undef DECODE_INT

	اگر (sshbuf_len(m))
		بازگشت SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	بازگشت 0;
}

/* NEW API */

/* put data to the outgoing packet */

صحیح
sshpkt_put(ساختار ssh *ssh, ثابت تهی *v, size_t len)
{
	بازگشت sshbuf_put(ssh->state->outgoing_packet, v, len);
}

صحیح
sshpkt_putb(ساختار ssh *ssh, ثابت ساختار sshbuf *b)
{
	بازگشت sshbuf_putb(ssh->state->outgoing_packet, b);
}

صحیح
sshpkt_put_u8(ساختار ssh *ssh, u_char val)
{
	بازگشت sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

صحیح
sshpkt_put_u32(ساختار ssh *ssh, uint32_t val)
{
	بازگشت sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

صحیح
sshpkt_put_u64(ساختار ssh *ssh, uint64_t val)
{
	بازگشت sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

صحیح
sshpkt_put_string(ساختار ssh *ssh, ثابت تهی *v, size_t len)
{
	بازگشت sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

صحیح
sshpkt_put_cstring(ساختار ssh *ssh, ثابت تهی *v)
{
	بازگشت sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

صحیح
sshpkt_put_stringb(ساختار ssh *ssh, ثابت ساختار sshbuf *v)
{
	بازگشت sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#ifdef WITH_OPENSSL
صحیح
sshpkt_put_ec(ساختار ssh *ssh, ثابت EC_POINT *v, ثابت EC_GROUP *g)
{
	بازگشت sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

صحیح
sshpkt_put_ec_pkey(ساختار ssh *ssh, EVP_PKEY *pkey)
{
	بازگشت sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

صحیح
sshpkt_put_bignum2(ساختار ssh *ssh, ثابت BIGNUM *v)
{
	بازگشت sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#endif /* WITH_OPENSSL */

/* fetch data from the incoming packet */

صحیح
sshpkt_get(ساختار ssh *ssh, تهی *valp, size_t len)
{
	بازگشت sshbuf_get(ssh->state->incoming_packet, valp, len);
}

صحیح
sshpkt_get_u8(ساختار ssh *ssh, u_char *valp)
{
	بازگشت sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

صحیح
sshpkt_get_u32(ساختار ssh *ssh, uint32_t *valp)
{
	بازگشت sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

صحیح
sshpkt_get_u64(ساختار ssh *ssh, uint64_t *valp)
{
	بازگشت sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

صحیح
sshpkt_get_string(ساختار ssh *ssh, u_char **valp, size_t *lenp)
{
	بازگشت sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

صحیح
sshpkt_get_string_direct(ساختار ssh *ssh, ثابت u_char **valp, size_t *lenp)
{
	بازگشت sshbuf_get_string_direct(ssh->state->incoming_packet, valp, lenp);
}

صحیح
sshpkt_peek_string_direct(ساختار ssh *ssh, ثابت u_char **valp, size_t *lenp)
{
	بازگشت sshbuf_peek_string_direct(ssh->state->incoming_packet, valp, lenp);
}

صحیح
sshpkt_get_cstring(ساختار ssh *ssh, نویسه **valp, size_t *lenp)
{
	بازگشت sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

صحیح
sshpkt_getb_froms(ساختار ssh *ssh, ساختار sshbuf **valp)
{
	بازگشت sshbuf_froms(ssh->state->incoming_packet, valp);
}

#ifdef WITH_OPENSSL
صحیح
sshpkt_get_ec(ساختار ssh *ssh, EC_POINT *v, ثابت EC_GROUP *g)
{
	بازگشت sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

صحیح
sshpkt_get_bignum2(ساختار ssh *ssh, BIGNUM **valp)
{
	بازگشت sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#endif /* WITH_OPENSSL */

صحیح
sshpkt_get_end(ساختار ssh *ssh)
{
	اگر (sshbuf_len(ssh->state->incoming_packet) > 0)
		بازگشت SSH_ERR_UNEXPECTED_TRAILING_DATA;
	بازگشت 0;
}

ثابت u_char *
sshpkt_ptr(ساختار ssh *ssh, size_t *lenp)
{
	اگر (lenp != پوچ)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	بازگشت sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

صحیح
sshpkt_start(ساختار ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, اندازه(buf));
	buf[اندازه(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	بازگشت sshbuf_put(ssh->state->outgoing_packet, buf, اندازه(buf));
}

ایستا صحیح
ssh_packet_send_mux(ساختار ssh *ssh)
{
	ساختار session_state *state = ssh->state;
	u_char type, *cp;
	size_t len;
	صحیح r;

	اگر (ssh->kex)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	اگر (len < 6)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	اگر (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	اگر (type >= SSH2_پیام_CONNECTION_MIN &&
	    type <= SSH2_پیام_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		اگر ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			بازگشت r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	بازگشت 0;
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
صحیح
sshpkt_پیام_ignore(ساختار ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	صحیح r;
	u_int i;

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		بازگشت r;
	برای (i = 0; i < nbytes; i++) {
		اگر (i % 4 == 0)
			rnd = arc4random();
		اگر ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			بازگشت r;
		rnd >>= 8;
	}
	بازگشت 0;
}

/* send it */

صحیح
sshpkt_send(ساختار ssh *ssh)
{
	اگر (ssh->state && ssh->state->mux)
		بازگشت ssh_packet_send_mux(ssh);
	بازگشت ssh_packet_send2(ssh);
}

صحیح
sshpkt_disconnect(ساختار ssh *ssh, ثابت نویسه *fmt,...)
{
	نویسه buf[1024];
	va_list args;
	صحیح r;

	va_start(args, fmt);
	vsnprintf(buf, اندازه(buf), fmt, args);
	va_end(args);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		بازگشت r;
	بازگشت 0;
}

/* roundup current message to pad bytes */
صحیح
sshpkt_add_padding(ساختار ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	بازگشت 0;
}

ایستا نویسه *
format_traffic_stats(ساختار packet_state *ps)
{
	نویسه *stats = پوچ, bytes[FMT_SCALED_STRSIZE];

	اگر (ps->bytes > LLONG_MAX || fmt_scaled(ps->bytes, bytes) != 0)
		strlcpy(bytes, "OVERFLOW", اندازه(bytes));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (unsigned long)ps->packets, (unsigned long long)ps->blocks, bytes);
	بازگشت stats;
}

ایستا نویسه *
dedupe_alg_names(ثابت نویسه *in, ثابت نویسه *out)
{
	نویسه *names = پوچ;

	اگر (in == پوچ)
		in = "<implicit>";
	اگر (out == پوچ)
		out = "<implicit>";

	اگر (strcmp(in, out) == 0) {
		names = xstrdup(in);
	} وگرنه {
		xasprintf(&names, "%s in, %s out", in, out);
	}
	بازگشت names;
}

ایستا نویسه *
comp_status_message(ساختار ssh *ssh)
{
#ifdef WITH_ZLIB
	نویسه *ret = پوچ;
	ساختار session_state *state = ssh->state;
	unsigned long long iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	نویسه iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	نویسه icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	اگر (state->compression_buffer) {
		اگر (state->compression_in_started) {
			iraw = state->compression_in_stream.total_out;
			icmp = state->compression_in_stream.total_in;
			اگر (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", اندازه(iraw_f));
			اگر (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", اندازه(icmp_f));
		}
		اگر (state->compression_out_started) {
			oraw = state->compression_out_stream.total_in;
			ocmp = state->compression_out_stream.total_out;
			اگر (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", اندازه(oraw_f));
			اگر (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", اندازه(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (دوگانه)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (دوگانه)ocmp / oraw);
		بازگشت ret;
	}
#endif	/* WITH_ZLIB */
	بازگشت xstrdup("");
}

نویسه *
connection_info_message(ساختار ssh *ssh)
{
	نویسه *ret = پوچ, *cipher = پوچ, *mac = پوچ, *comp = پوچ;
	نویسه *rekey_volume = پوچ, *rekey_time = پوچ, *comp_info = پوچ;
	نویسه thishost[NI_MAXHOST] = "unknown", *tcp_info = پوچ;
	ساختار kex *kex;
	ساختار session_state *state;
	ساختار newkeys *nk_in, *nk_out;
	نویسه *stats_in = پوچ, *stats_out = پوچ;
	uint64_t epoch = (uint64_t)time(پوچ) - monotime();

	اگر (ssh == پوچ)
		بازگشت پوچ;
	state = ssh->state;
	kex = ssh->kex;

	(تهی)gethostname(thishost, اندازه(thishost));

	اگر (ssh_local_port(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	} وگرنه {
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
	اگر (state->rekey_limit == 0) {
		xasprintf(&rekey_volume, "limit none");
	} وگرنه {
		نویسه *volumes = پوچ, in[32], out[32];

		snprintf(in, اندازه(in), "%llu",
		   (unsigned long long)state->max_blocks_in);
		snprintf(out, اندازه(out), "%llu",
		   (unsigned long long)state->max_blocks_out);
		volumes = dedupe_alg_names(in, out);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		آزاد(volumes);
	}

	/* Time based rekeying. */
	اگر (state->rekey_interval == 0) {
		rekey_time = xstrdup("interval none");
	} وگرنه {
		نویسه rekey_next[64];

		format_absolute_time(epoch + state->rekey_time +
		    state->rekey_interval, rekey_next, اندازه(rekey_next));
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
	آزاد(tcp_info);
	آزاد(cipher);
	آزاد(mac);
	آزاد(comp);
	آزاد(stats_in);
	آزاد(stats_out);
	آزاد(rekey_volume);
	آزاد(rekey_time);
	آزاد(comp_info);
	بازگشت ret;
}

