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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/queue.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/time.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <util.h>

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
#অন্তর্ভাব <zlib.h>
#endif

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "mac.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "version.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#অন্যথা
#define DBG(x)
#endif

#define PACKET_MAX_আকার (256 * 1024)

কাঠামো packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t blocks;
	uint64_t bytes;
};

কাঠামো packet {
	TAILQ_ENTRY(packet) পরবর্তী;
	u_char type;
	কাঠামো sshbuf *payload;
};

কাঠামো session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	পূর্ণসংখ্যা connection_in;
	পূর্ণসংখ্যা connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	কাঠামো sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	কাঠামো sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	কাঠামো sshbuf *প্রবেশ;

	/* Buffer for raw output data going to the socket. */
	কাঠামো sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	কাঠামো sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	কাঠামো sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	কাঠামো sshbuf *compression_বাফার;

#ifdef WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_stream compression_in_stream;
	z_stream compression_out_stream;
#endif
	পূর্ণসংখ্যা compression_in_started;
	পূর্ণসংখ্যা compression_out_started;
	পূর্ণসংখ্যা compression_in_failures;
	পূর্ণসংখ্যা compression_out_failures;

	/* default maximum packet size */
	u_int max_packet_আকার;

	/* Flag indicating whether this module has been initialized. */
	পূর্ণসংখ্যা initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t start_time;

	/* Set to true if the connection is interactive. */
	পূর্ণসংখ্যা interactive_mode;

	/* Set to true if we are the server side. */
	পূর্ণসংখ্যা server_side;

	/* Set to true if we are authenticated. */
	পূর্ণসংখ্যা after_authentication;

	পূর্ণসংখ্যা keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	পূর্ণসংখ্যা packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	কাঠামো newkeys *newkeys[MODE_MAX];
	কাঠামো packet_state p_read, p_send;

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
	আকার_t packet_discard_mac_already;
	কাঠামো sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	পূর্ণসংখ্যা rekeying;

	/* Used in ssh_packet_send_mux() */
	পূর্ণসংখ্যা mux;

	/* QoS handling */
	পূর্ণসংখ্যা qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	পূর্ণসংখ্যা set_maxsize_called;

	/* One-off warning about weak ciphers */
	পূর্ণসংখ্যা cipher_warning_done;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	পূর্ণসংখ্যা disconnecting;

	/* Nagle disabled on socket */
	পূর্ণসংখ্যা nodelay_set;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_in;
	শূন্য *hook_in_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

কাঠামো ssh *
ssh_alloc_session_state(শূন্য)
{
	কাঠামো ssh *ssh = ফাঁকা;
	কাঠামো session_state *state = ফাঁকা;

	যদি ((ssh = calloc(1, আকার(*ssh))) == ফাঁকা ||
	    (state = calloc(1, আকার(*state))) == ফাঁকা ||
	    (ssh->kex = kex_new()) == ফাঁকা ||
	    (state->প্রবেশ = sshbuf_new()) == ফাঁকা ||
	    (state->output = sshbuf_new()) == ফাঁকা ||
	    (state->outgoing_packet = sshbuf_new()) == ফাঁকা ||
	    (state->incoming_packet = sshbuf_new()) == ফাঁকা)
		যাও fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->private_চাবিগুলি);
	TAILQ_INIT(&ssh->public_চাবিগুলি);
	state->connection_in = -1;
	state->connection_out = -1;
	state->max_packet_আকার = 32768;
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
	ফেরত ssh;
 fail:
	যদি (ssh) {
		kex_free(ssh->kex);
		মুক্ত(ssh);
	}
	যদি (state) {
		sshbuf_free(state->প্রবেশ);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		মুক্ত(state);
	}
	ফেরত ফাঁকা;
}

শূন্য
ssh_packet_set_প্রবেশ_hook(কাঠামো ssh *ssh, ssh_packet_hook_fn *hook, শূন্য *ctx)
{
	ssh->state->hook_in = hook;
	ssh->state->hook_in_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
পূর্ণসংখ্যা
ssh_packet_is_rekeying(কাঠামো ssh *ssh)
{
	ফেরত ssh->state->rekeying ||
	    (ssh->kex != ফাঁকা && ssh->kex->done == 0);
}

/*
 * Sets the descriptors used for communication.
 */
কাঠামো ssh *
ssh_packet_set_connection(কাঠামো ssh *ssh, পূর্ণসংখ্যা fd_in, পূর্ণসংখ্যা fd_out)
{
	কাঠামো session_state *state;
	ধ্রুবক কাঠামো sshcipher *none = cipher_by_name("none");
	পূর্ণসংখ্যা r, wasnull = ssh == ফাঁকা;

	যদি (none == ফাঁকা) {
		error_f("cannot load cipher 'none'");
		ফেরত ফাঁকা;
	}
	যদি (ssh == ফাঁকা)
		ssh = ssh_alloc_session_state();
	যদি (ssh == ফাঁকা) {
		error_f("could not allocate state");
		ফেরত ফাঁকা;
	}
	state = ssh->state;
	state->start_time = monotime();
	state->connection_in = fd_in;
	state->connection_out = fd_out;
	যদি ((r = cipher_init(&state->send_context, none,
	    (ধ্রুবক u_char *)"", 0, ফাঁকা, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (ধ্রুবক u_char *)"", 0, ফাঁকা, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		যদি (wasnull)
			মুক্ত(ssh); /* XXX need ssh_free_session_state? */
		ফেরত ফাঁকা;
	}
	state->newkeys[MODE_IN] = state->newkeys[MODE_OUT] = ফাঁকা;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(শূন্য)ssh_remote_ipaddr(ssh);
	ফেরত ssh;
}

শূন্য
ssh_packet_set_timeout(কাঠামো ssh *ssh, পূর্ণসংখ্যা timeout, পূর্ণসংখ্যা গুনতি)
{
	কাঠামো session_state *state = ssh->state;

	যদি (timeout <= 0 || গুনতি <= 0) {
		state->packet_timeout_ms = -1;
		ফেরত;
	}
	যদি ((INT_MAX / 1000) / গুনতি < timeout)
		state->packet_timeout_ms = INT_MAX;
	অন্যথা
		state->packet_timeout_ms = timeout * গুনতি * 1000;
}

শূন্য
ssh_packet_set_mux(কাঠামো ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = ফাঁকা;
}

পূর্ণসংখ্যা
ssh_packet_get_mux(কাঠামো ssh *ssh)
{
	ফেরত ssh->state->mux;
}

পূর্ণসংখ্যা
ssh_packet_set_log_preamble(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list args;
	পূর্ণসংখ্যা r;

	মুক্ত(ssh->log_preamble);
	যদি (fmt == ফাঁকা)
		ssh->log_preamble = ফাঁকা;
	অন্যথা {
		va_start(args, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, args);
		va_end(args);
		যদি (r < 0 || ssh->log_preamble == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_packet_stop_discard(কাঠামো ssh *ssh)
{
	কাঠামো session_state *state = ssh->state;
	পূর্ণসংখ্যা r;

	যদি (state->packet_discard_mac) {
		অক্ষর buf[1024];
		আকার_t dlen = PACKET_MAX_আকার;

		যদি (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', আকার(buf));
		যখন (sshbuf_len(state->incoming_packet) < dlen)
			যদি ((r = sshbuf_put(state->incoming_packet, buf,
			    আকার(buf))) != 0)
				ফেরত r;
		(শূন্য) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    ফাঁকা, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	ফেরত SSH_ERR_MAC_INVALID;
}

স্থির পূর্ণসংখ্যা
ssh_packet_start_discard(কাঠামো ssh *ssh, কাঠামো sshenc *enc,
    কাঠামো sshmac *mac, আকার_t mac_already, u_int discard)
{
	কাঠামো session_state *state = ssh->state;
	পূর্ণসংখ্যা r;

	যদি (enc == ফাঁকা || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		যদি ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			ফেরত r;
		ফেরত SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	যদি (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	যদি (sshbuf_len(state->প্রবেশ) >= discard)
		ফেরত ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->প্রবেশ);
	ফেরত 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

পূর্ণসংখ্যা
ssh_packet_connection_is_on_socket(কাঠামো ssh *ssh)
{
	কাঠামো session_state *state;
	কাঠামো sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	যদি (ssh == ফাঁকা || ssh->state == ফাঁকা)
		ফেরত 0;

	state = ssh->state;
	যদি (state->connection_in == -1 || state->connection_out == -1)
		ফেরত 0;
	fromlen = আকার(from);
	memset(&from, 0, আকার(from));
	যদি (getpeername(state->connection_in, (কাঠামো sockaddr *)&from,
	    &fromlen) == -1)
		ফেরত 0;
	যদি (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ফেরত 0;
	/* filedescriptors in and out are the same, so it's a socket */
	যদি (state->connection_in == state->connection_out)
		ফেরত 1;
	tolen = আকার(to);
	memset(&to, 0, আকার(to));
	যদি (getpeername(state->connection_out, (কাঠামো sockaddr *)&to,
	    &tolen) == -1)
		ফেরত 0;
	যদি (fromlen != tolen || memcmp(&from, &to, fromlen) != 0)
		ফেরত 0;
	ফেরত 1;
}

শূন্য
ssh_packet_get_bytes(কাঠামো ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	যদি (ibytes)
		*ibytes = ssh->state->p_read.bytes;
	যদি (obytes)
		*obytes = ssh->state->p_send.bytes;
}

পূর্ণসংখ্যা
ssh_packet_connection_af(কাঠামো ssh *ssh)
{
	ফেরত get_sock_af(ssh->state->connection_out);
}

/* Sets the connection into non-blocking mode. */

শূন্য
ssh_packet_set_nonblocking(কাঠামো ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(ssh->state->connection_in);

	যদি (ssh->state->connection_out != ssh->state->connection_in)
		set_nonblock(ssh->state->connection_out);
}

/* Returns the socket used for reading. */

পূর্ণসংখ্যা
ssh_packet_get_connection_in(কাঠামো ssh *ssh)
{
	ফেরত ssh->state->connection_in;
}

/* Returns the descriptor used for writing. */

পূর্ণসংখ্যা
ssh_packet_get_connection_out(কাঠামো ssh *ssh)
{
	ফেরত ssh->state->connection_out;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

ধ্রুবক অক্ষর *
ssh_remote_ipaddr(কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা sock;

	/* Check whether we have cached the ipaddr. */
	যদি (ssh->remote_ipaddr == ফাঁকা) {
		যদি (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_in;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_port = get_peer_port(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_port = get_local_port(sock);
		} অন্যথা {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_port = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_port = 65535;
		}
	}
	ফেরত ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

অক্ষর *
ssh_remote_hostname(কাঠামো ssh *ssh)
{
	কাঠামো sockaddr_storage from;
	socklen_t fromlen;
	কাঠামো addrinfo hints, *ai, *aitop;
	অক্ষর name[NI_MAXHOST], ntop2[NI_MAXHOST];
	ধ্রুবক অক্ষর *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = আকার(from);
	memset(&from, 0, আকার(from));
	যদি (getpeername(ssh_packet_get_connection_in(ssh),
	    (কাঠামো sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		ফেরত xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	যদি (from.ss_family == AF_INET6)
		fromlen = আকার(কাঠামো sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	যদি (getnameinfo((কাঠামো sockaddr *)&from, fromlen, name, আকার(name),
	    ফাঁকা, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		ফেরত xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, আকার(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	যদি (getaddrinfo(name, ফাঁকা, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		ফেরত xstrdup(ntop);
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
	memset(&hints, 0, আকার(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	যদি (getaddrinfo(name, ফাঁকা, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		ফেরত xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	জন্য (ai = aitop; ai; ai = ai->ai_next) {
		যদি (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    আকার(ntop2), ফাঁকা, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				বিরতি;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	যদি (ai == ফাঁকা) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		ফেরত xstrdup(ntop);
	}
	ফেরত xstrdup(name);
}

/* Returns the port number of the remote host. */

পূর্ণসংখ্যা
ssh_remote_port(কাঠামো ssh *ssh)
{
	(শূন্য)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ফেরত ssh->remote_port;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

ধ্রুবক অক্ষর *
ssh_local_ipaddr(কাঠামো ssh *ssh)
{
	(শূন্য)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ফেরত ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

পূর্ণসংখ্যা
ssh_local_port(কাঠামো ssh *ssh)
{
	(শূন্য)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	ফেরত ssh->local_port;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
ধ্রুবক অক্ষর *
ssh_packet_rdomain_in(কাঠামো ssh *ssh)
{
	যদি (ssh->rdomain_in != ফাঁকা)
		ফেরত ssh->rdomain_in;
	যদি (!ssh_packet_connection_is_on_socket(ssh))
		ফেরত ফাঁকা;
	ssh->rdomain_in = get_rdomain(ssh->state->connection_in);
	ফেরত ssh->rdomain_in;
}

/* Closes the connection and clears and frees internal data structures. */

স্থির শূন্য
ssh_packet_close_internal(কাঠামো ssh *ssh, পূর্ণসংখ্যা do_close)
{
	কাঠামো session_state *state = ssh->state;
	u_int mode;
	কাঠামো packet *p;

	যদি (!state->initialized)
		ফেরত;
	state->initialized = 0;
	যদি (do_close) {
		যদি (state->connection_in == state->connection_out) {
			close(state->connection_out);
		} অন্যথা {
			close(state->connection_in);
			close(state->connection_out);
		}
	}
	sshbuf_free(state->প্রবেশ);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	যখন ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, পরবর্তী);
		মুক্ত(p);
	}
	জন্য (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(state->newkeys[mode]);	/* current keys */
		state->newkeys[mode] = ফাঁকা;
		ssh_clear_newkeys(ssh, mode);		/* next keys */
	}
#ifdef WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	যদি (do_close && state->compression_বাফার) {
		sshbuf_free(state->compression_বাফার);
		যদি (state->compression_out_started) {
			z_streamp stream = &state->compression_out_stream;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(unsigned long long)stream->যোগ_in,
				(unsigned long long)stream->যোগ_out,
				stream->যোগ_in == 0 ? 0.0 :
				(দ্বিগুণ) stream->যোগ_out / stream->যোগ_in);
			যদি (state->compression_out_failures == 0)
				deflateEnd(stream);
		}
		যদি (state->compression_in_started) {
			z_streamp stream = &state->compression_in_stream;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (unsigned long long)stream->যোগ_out,
			    (unsigned long long)stream->যোগ_in,
			    stream->যোগ_out == 0 ? 0.0 :
			    (দ্বিগুণ) stream->যোগ_in / stream->যোগ_out);
			যদি (state->compression_in_failures == 0)
				inflateEnd(stream);
		}
	}
#endif	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = ফাঁকা;
	যদি (do_close) {
		মুক্ত(ssh->local_ipaddr);
		ssh->local_ipaddr = ফাঁকা;
		মুক্ত(ssh->remote_ipaddr);
		ssh->remote_ipaddr = ফাঁকা;
		মুক্ত(ssh->state);
		ssh->state = ফাঁকা;
		kex_free(ssh->kex);
		ssh->kex = ফাঁকা;
	}
}

শূন্য
ssh_packet_free(কাঠামো ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
	freezero(ssh, আকার(*ssh));
}

শূন্য
ssh_packet_close(কাঠামো ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
}

শূন্য
ssh_packet_clear_চাবিগুলি(কাঠামো ssh *ssh)
{
	ssh_packet_close_internal(ssh, 0);
}

/* Sets remote side protocol flags. */

শূন্য
ssh_packet_set_protocol_flags(কাঠামো ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(কাঠামো ssh *ssh)
{
	ফেরত ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

স্থির পূর্ণসংখ্যা
ssh_packet_init_compression(কাঠামো ssh *ssh)
{
	যদি (!ssh->state->compression_বাফার &&
	    ((ssh->state->compression_বাফার = sshbuf_new()) == ফাঁকা))
		ফেরত SSH_ERR_ALLOC_FAIL;
	ফেরত 0;
}

#ifdef WITH_ZLIB
স্থির পূর্ণসংখ্যা
start_compression_out(কাঠামো ssh *ssh)
{
	debug("Enabling compression.");
	যদি (ssh->state->compression_out_started == 1)
		deflateEnd(&ssh->state->compression_out_stream);
	নির্বাচন (deflateInit2(&ssh->state->compression_out_stream,
	    Z_BEST_SPEED, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	ক্ষেত্র Z_OK:
		ssh->state->compression_out_started = 1;
		বিরতি;
	ক্ষেত্র Z_MEM_ERROR:
		ফেরত SSH_ERR_ALLOC_FAIL;
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
start_compression_in(কাঠামো ssh *ssh)
{
	যদি (ssh->state->compression_in_started == 1)
		inflateEnd(&ssh->state->compression_in_stream);
	নির্বাচন (inflateInit(&ssh->state->compression_in_stream)) {
	ক্ষেত্র Z_OK:
		ssh->state->compression_in_started = 1;
		বিরতি;
	ক্ষেত্র Z_MEM_ERROR:
		ফেরত SSH_ERR_ALLOC_FAIL;
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	ফেরত 0;
}

/* XXX remove need for separate compression buffer */
স্থির পূর্ণসংখ্যা
compress_বাফার(কাঠামো ssh *ssh, কাঠামো sshbuf *in, কাঠামো sshbuf *out)
{
	u_char buf[4096];
	পূর্ণসংখ্যা r, status;

	যদি (ssh->state->compression_out_started != 1)
		ফেরত SSH_ERR_INTERNAL_ERROR;

	/* This case is not handled below. */
	যদি (sshbuf_len(in) == 0)
		ফেরত 0;

	/* Input is the contents of the input buffer. */
	যদি ((ssh->state->compression_out_stream.পরবর্তী_in =
	    sshbuf_mutable_ptr(in)) == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_out_stream.avail_in = sshbuf_len(in);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	করো {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_out_stream.পরবর্তী_out = buf;
		ssh->state->compression_out_stream.avail_out = আকার(buf);

		/* Compress as much data into the buffer as possible. */
		status = deflate(&ssh->state->compression_out_stream,
		    Z_PARTIAL_FLUSH);
		নির্বাচন (status) {
		ক্ষেত্র Z_MEM_ERROR:
			ফেরত SSH_ERR_ALLOC_FAIL;
		ক্ষেত্র Z_OK:
			/* Append compressed data to output_buffer. */
			যদি ((r = sshbuf_put(out, buf, আকার(buf) -
			    ssh->state->compression_out_stream.avail_out)) != 0)
				ফেরত r;
			বিরতি;
		ক্ষেত্র Z_STREAM_ERROR:
		পূর্বনির্ধারিত:
			ssh->state->compression_out_failures++;
			ফেরত SSH_ERR_INVALID_FORMAT;
		}
	} যখন (ssh->state->compression_out_stream.avail_out == 0);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
uncompress_বাফার(কাঠামো ssh *ssh, কাঠামো sshbuf *in, কাঠামো sshbuf *out)
{
	u_char buf[4096];
	পূর্ণসংখ্যা r, status;

	যদি (ssh->state->compression_in_started != 1)
		ফেরত SSH_ERR_INTERNAL_ERROR;

	যদি ((ssh->state->compression_in_stream.পরবর্তী_in =
	    sshbuf_mutable_ptr(in)) == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_in_stream.avail_in = sshbuf_len(in);

	জন্য (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_in_stream.পরবর্তী_out = buf;
		ssh->state->compression_in_stream.avail_out = আকার(buf);

		status = inflate(&ssh->state->compression_in_stream,
		    Z_SYNC_FLUSH);
		নির্বাচন (status) {
		ক্ষেত্র Z_OK:
			যদি ((r = sshbuf_put(out, buf, আকার(buf) -
			    ssh->state->compression_in_stream.avail_out)) != 0)
				ফেরত r;
			যদি (sshbuf_len(out) >= PACKET_MAX_আকার)
				ফেরত SSH_ERR_INVALID_FORMAT;
			বিরতি;
		ক্ষেত্র Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			ফেরত 0;
		ক্ষেত্র Z_তথ্য_ERROR:
			ফেরত SSH_ERR_INVALID_FORMAT;
		ক্ষেত্র Z_MEM_ERROR:
			ফেরত SSH_ERR_ALLOC_FAIL;
		ক্ষেত্র Z_STREAM_ERROR:
		পূর্বনির্ধারিত:
			ssh->state->compression_in_failures++;
			ফেরত SSH_ERR_INTERNAL_ERROR;
		}
	}
	/* NOTREACHED */
}

#অন্যথা	/* WITH_ZLIB */

স্থির পূর্ণসংখ্যা
start_compression_out(কাঠামো ssh *ssh)
{
	ফেরত SSH_ERR_INTERNAL_ERROR;
}

স্থির পূর্ণসংখ্যা
start_compression_in(কাঠামো ssh *ssh)
{
	ফেরত SSH_ERR_INTERNAL_ERROR;
}

স্থির পূর্ণসংখ্যা
compress_বাফার(কাঠামো ssh *ssh, কাঠামো sshbuf *in, কাঠামো sshbuf *out)
{
	ফেরত SSH_ERR_INTERNAL_ERROR;
}

স্থির পূর্ণসংখ্যা
uncompress_বাফার(কাঠামো ssh *ssh, কাঠামো sshbuf *in, কাঠামো sshbuf *out)
{
	ফেরত SSH_ERR_INTERNAL_ERROR;
}
#endif	/* WITH_ZLIB */

শূন্য
ssh_clear_newkeys(কাঠামো ssh *ssh, পূর্ণসংখ্যা mode)
{
	যদি (ssh->kex && ssh->kex->newkeys[mode]) {
		kex_free_newkeys(ssh->kex->newkeys[mode]);
		ssh->kex->newkeys[mode] = ফাঁকা;
	}
}

পূর্ণসংখ্যা
ssh_set_newkeys(কাঠামো ssh *ssh, পূর্ণসংখ্যা mode)
{
	কাঠামো session_state *state = ssh->state;
	কাঠামো sshenc *enc;
	কাঠামো sshmac *mac;
	কাঠামো sshcomp *comp;
	কাঠামো sshcipher_ctx **ccp;
	কাঠামো packet_state *ps;
	uint64_t *max_blocks, *hard_max_blocks;
	ধ্রুবক অক্ষর *wmsg;
	পূর্ণসংখ্যা r, crypt_type;
	ধ্রুবক অক্ষর *dir = mode == MODE_OUT ? "out" : "in";

	debug2_f("mode %d", mode);

	যদি (mode == MODE_OUT) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_blocks = &state->hard_max_blocks_out;
		max_blocks = &state->max_blocks_out;
	} অন্যথা {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_blocks = &state->hard_max_blocks_in;
		max_blocks = &state->max_blocks_in;
	}
	যদি (state->newkeys[mode] != ফাঁকা) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (unsigned long long)state->p_read.bytes,
		    (unsigned long long)state->p_read.blocks,
		    (unsigned long long)state->p_send.bytes,
		    (unsigned long long)state->p_send.blocks);
		kex_free_newkeys(state->newkeys[mode]);
		state->newkeys[mode] = ফাঁকা;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->blocks = 0;
	/* move newkeys from kex to state */
	যদি ((state->newkeys[mode] = ssh->kex->newkeys[mode]) == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	ssh->kex->newkeys[mode] = ফাঁকা;
	enc  = &state->newkeys[mode]->enc;
	mac  = &state->newkeys[mode]->mac;
	comp = &state->newkeys[mode]->comp;
	যদি (cipher_authlen(enc->cipher) == 0) {
		যদি ((r = mac_init(mac)) != 0)
			ফেরত r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = ফাঁকা;
	যদি ((r = cipher_init(ccp, enc->cipher, enc->চাবি, enc->চাবি_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		ফেরত r;
	যদি (!state->cipher_warning_done &&
	    (wmsg = cipher_warning_message(*ccp)) != ফাঁকা) {
		error("Warning: %s", wmsg);
		state->cipher_warning_done = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	যদি (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		যদি ((r = ssh_packet_init_compression(ssh)) < 0)
			ফেরত r;
		যদি (mode == MODE_OUT) {
			যদি ((r = start_compression_out(ssh)) != 0)
				ফেরত r;
		} অন্যথা {
			যদি ((r = start_compression_in(ssh)) != 0)
				ফেরত r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	যদি (enc->block_আকার >= 16)
		*hard_max_blocks = (uint64_t)1 << (enc->block_আকার*2);
	অন্যথা
		*hard_max_blocks = ((uint64_t)1 << 30) / enc->block_আকার;
	*max_blocks = *hard_max_blocks;
	যদি (state->rekey_limit) {
		*max_blocks = MINIMUM(*max_blocks,
		    state->rekey_limit / enc->block_আকার);
	}
	debug("rekey %s after %llu blocks", dir,
	    (unsigned long long)*max_blocks);
	ফেরত 0;
}

#define MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
স্থির অন্তঃরেখ পূর্ণসংখ্যা
ssh_packet_check_rekey_blocklimit(কাঠামো ssh *ssh, u_int packet_len, পূর্ণসংখ্যা hard)
{
	কাঠামো session_state *state = ssh->state;
	uint32_t out_blocks;
	ধ্রুবক uint64_t max_blocks_in = hard ?
	    state->hard_max_blocks_in : state->max_blocks_in;
	ধ্রুবক uint64_t max_blocks_out = hard ?
	    state->hard_max_blocks_out : state->max_blocks_out;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	যদি (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		ফেরত 1;

	যদি (state->newkeys[MODE_OUT] == ফাঁকা)
		ফেরত 0;

	/* Rekey after (cipher-specific) maximum blocks */
	out_blocks = ROUNDUP(packet_len,
	    state->newkeys[MODE_OUT]->enc.block_আকার);
	ফেরত (max_blocks_out &&
	    (state->p_send.blocks + out_blocks > max_blocks_out)) ||
	    (max_blocks_in &&
	    (state->p_read.blocks > max_blocks_in));
}

স্থির পূর্ণসংখ্যা
ssh_packet_need_rekeying(কাঠামো ssh *ssh, u_int outbound_packet_len)
{
	কাঠামো session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	যদি (!state->after_authentication)
		ফেরত 0;

	/* Haven't keyed yet or KEX in progress. */
	যদি (ssh_packet_is_rekeying(ssh))
		ফেরত 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	যদি (state->p_send.packets == 0 && state->p_read.packets == 0)
		ফেরত 0;

	/* Time-based rekeying */
	যদি (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_time + state->rekey_interval <= monotime())
		ফেরত 1;

	ফেরত ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
স্থির পূর্ণসংখ্যা
ssh_packet_check_rekey_preauth(কাঠামো ssh *ssh, u_int outgoing_packet_len)
{
	যদি (ssh->state->after_authentication)
		ফেরত 0;

	যদি (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		ফেরত SSH_ERR_NEED_REKEY;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_packet_check_rekey(কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;

	যদি ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		ফেরত r;
	যদি (!ssh_packet_need_rekeying(ssh, 0))
		ফেরত 0;
	debug3_f("rekex triggered");
	ফেরত kex_start_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
স্থির পূর্ণসংখ্যা
ssh_packet_enable_delayed_compress(কাঠামো ssh *ssh)
{
	কাঠামো session_state *state = ssh->state;
	কাঠামো sshcomp *comp = ফাঁকা;
	পূর্ণসংখ্যা r, mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	জন্য (mode = 0; mode < MODE_MAX; mode++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		যদি (state->newkeys[mode] == ফাঁকা)
			চালু;
		comp = &state->newkeys[mode]->comp;
		যদি (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			যদি ((r = ssh_packet_init_compression(ssh)) != 0)
				ফেরত r;
			যদি (mode == MODE_OUT) {
				যদি ((r = start_compression_out(ssh)) != 0)
					ফেরত r;
			} অন্যথা {
				যদি ((r = start_compression_in(ssh)) != 0)
					ফেরত r;
			}
			comp->enabled = 1;
		}
	}
	ফেরত 0;
}

/* Used to mute debug logging for noisy packet types */
পূর্ণসংখ্যা
ssh_packet_log_type(u_char type)
{
	নির্বাচন (type) {
	ক্ষেত্র SSH2_বার্তা_PING:
	ক্ষেত্র SSH2_বার্তা_PONG:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_তথ্য:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_EXTENDED_তথ্য:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_WINDOW_ADJUST:
		ফেরত 0;
	পূর্বনির্ধারিত:
		ফেরত 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
পূর্ণসংখ্যা
ssh_packet_send2_wrapped(কাঠামো ssh *ssh)
{
	কাঠামো session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_দৈর্ঘ্য];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	কাঠামো sshenc *enc   = ফাঁকা;
	কাঠামো sshmac *mac   = ফাঁকা;
	কাঠামো sshcomp *comp = ফাঁকা;
	পূর্ণসংখ্যা r, block_আকার;

	যদি (state->newkeys[MODE_OUT] != ফাঁকা) {
		enc  = &state->newkeys[MODE_OUT]->enc;
		mac  = &state->newkeys[MODE_OUT]->mac;
		comp = &state->newkeys[MODE_OUT]->comp;
		/* disable mac for authenticated encryption */
		যদি ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ফাঁকা;
	}
	block_আকার = enc ? enc->block_আকার : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	যদি (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#endif

	যদি (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		যদি ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			যাও out;
		sshbuf_reset(state->compression_বাফার);
		যদি ((r = compress_বাফার(ssh, state->outgoing_packet,
		    state->compression_বাফার)) != 0)
			যাও out;
		sshbuf_reset(state->outgoing_packet);
		যদি ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_বাফার)) != 0)
			যাও out;
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
	padlen = block_আকার - (len % block_আকার);
	যদি (padlen < 4)
		padlen += block_আকার;
	যদি (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, block_আকার);
		/* check if roundup overflowed */
		যদি (state->extra_pad < tmp)
			ফেরত SSH_ERR_INVALID_ARGUMENT;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		যদি (tmp > state->extra_pad)
			ফেরত SSH_ERR_INVALID_ARGUMENT;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		যদি (padlen < tmp)
			ফেরত SSH_ERR_INVALID_ARGUMENT; /* overflow */
		state->extra_pad = 0;
	}
	যদি ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		যাও out;
	যদি (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} অন্যথা {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	যদি (cp == ফাঁকা) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	যদি (mac && mac->enabled && !mac->etm) {
		যদি ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, আকার(macbuf))) != 0)
			যাও out;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	যদি ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		যাও out;
	যদি ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		যাও out;
	/* append unencrypted MAC */
	যদি (mac && mac->enabled) {
		যদি (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			যদি ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, আকার(macbuf))) != 0)
				যাও out;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		যদি ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			যাও out;
	}
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#endif
	/* increment sequence number for outgoing packets */
	যদি (++state->p_send.seqnr == 0) {
		যদি ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	যদি (++state->p_send.packets == 0)
		ফেরত SSH_ERR_NEED_REKEY;
	state->p_send.blocks += len / block_আকার;
	state->p_send.bytes += len;
	sshbuf_reset(state->outgoing_packet);

	যদি (type == SSH2_বার্তা_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	যদি (type == SSH2_বার্তা_NEWKEYS)
		r = ssh_set_newkeys(ssh, MODE_OUT);
	অন্যথা যদি (type == SSH2_বার্তা_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	অন্যথা
		r = 0;
 out:
	ফেরত r;
}

/* returns non-zero if the specified packet type is usec by KEX */
স্থির পূর্ণসংখ্যা
ssh_packet_type_is_kex(u_char type)
{
	ফেরত
	    type >= SSH2_বার্তা_TRANSPORT_MIN &&
	    type <= SSH2_বার্তা_TRANSPORT_MAX &&
	    type != SSH2_বার্তা_SERVICE_REQUEST &&
	    type != SSH2_বার্তা_SERVICE_ACCEPT &&
	    type != SSH2_বার্তা_EXT_INFO;
}

পূর্ণসংখ্যা
ssh_packet_send2(কাঠামো ssh *ssh)
{
	কাঠামো session_state *state = ssh->state;
	কাঠামো packet *p;
	u_char type;
	পূর্ণসংখ্যা r, need_rekey;

	যদি (sshbuf_len(state->outgoing_packet) < 6)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	যদি (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		ফেরত r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	যদি ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		যদি (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = calloc(1, আকার(*p));
		যদি (p == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, পরবর্তী);
		state->outgoing_packet = sshbuf_new();
		যদি (state->outgoing_packet == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
		যদি (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			ফেরত kex_start_rekex(ssh);
		}
		ফেরত 0;
	}

	/* rekeying starts with sending KEXINIT */
	যদি (type == SSH2_বার্তা_KEXINIT)
		state->rekeying = 1;

	যদি ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		ফেরত r;

	/* after a NEWKEYS message we can send the complete queue */
	যদি (type == SSH2_বার্তা_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_time = monotime();
		যখন ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			যদি (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				ফেরত kex_start_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, পরবর্তী);
			memset(p, 0, আকার(*p));
			মুক্ত(p);
			যদি ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				ফেরত r;
		}
	}
	ফেরত 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

পূর্ণসংখ্যা
ssh_packet_read_seqnr(কাঠামো ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	কাঠামো session_state *state = ssh->state;
	পূর্ণসংখ্যা len, r, ms_remain = 0;
	কাঠামো pollfd pfd;
	অক্ষর buf[8192];
	কাঠামো timeval start;
	কাঠামো timespec timespec, *timespecp = ফাঁকা;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	যদি ((r = ssh_packet_write_wait(ssh)) != 0)
		যাও out;

	/* Stay in the loop until we have received a complete packet. */
	জন্য (;;) {
		/* Try to read a packet from the buffer. */
		যদি ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			বিরতি;
		/* If we got a packet, return it. */
		যদি (*typep != SSH_বার্তা_NONE)
			বিরতি;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_in;
		pfd.events = POLLIN;

		যদি (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		জন্য (;;) {
			যদি (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			যদি ((r = ppoll(&pfd, 1, timespecp, ফাঁকা)) >= 0)
				বিরতি;
			যদি (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				যাও out;
			}
			যদি (state->packet_timeout_ms <= 0)
				চালু;
			ms_subtract_diff(&start, &ms_remain);
			যদি (ms_remain <= 0) {
				r = 0;
				বিরতি;
			}
		}
		যদি (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			যাও out;
		}
		/* Read data from the socket. */
		len = পঠ(state->connection_in, buf, আকার(buf));
		যদি (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			যাও out;
		}
		যদি (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			যাও out;
		}

		/* Append it to the buffer. */
		যদি ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			যাও out;
	}
 out:
	ফেরত r;
}

পূর্ণসংখ্যা
ssh_packet_read(কাঠামো ssh *ssh)
{
	u_char type;
	পূর্ণসংখ্যা r;

	যদি ((r = ssh_packet_read_seqnr(ssh, &type, ফাঁকা)) != 0)
		sshpkt_fatal(ssh, r, "read");
	ফেরত type;
}

স্থির পূর্ণসংখ্যা
ssh_packet_read_poll2_mux(কাঠামো ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	কাঠামো session_state *state = ssh->state;
	ধ্রুবক u_char *cp;
	আকার_t need;
	পূর্ণসংখ্যা r;

	যদি (ssh->kex)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	*typep = SSH_বার্তা_NONE;
	cp = sshbuf_ptr(state->প্রবেশ);
	যদি (state->packlen == 0) {
		যদি (sshbuf_len(state->প্রবেশ) < 4 + 1)
			ফেরত 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		যদি (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_আকার)
			ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
	}
	need = state->packlen + 4;
	যদি (sshbuf_len(state->প্রবেশ) < need)
		ফেরত 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	যদি ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->প্রবেশ, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		ফেরত r;
	যদি (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	ফেরত r;
}

পূর্ণসংখ্যা
ssh_packet_read_poll2(কাঠামো ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	কাঠামো session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, block_আকার;
	কাঠামো sshenc *enc   = ফাঁকা;
	কাঠামো sshmac *mac   = ফাঁকা;
	কাঠামো sshcomp *comp = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (state->mux)
		ফেরত ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_বার্তা_NONE;

	যদি (state->packet_discard)
		ফেরত 0;

	যদি (state->newkeys[MODE_IN] != ফাঁকা) {
		enc  = &state->newkeys[MODE_IN]->enc;
		mac  = &state->newkeys[MODE_IN]->mac;
		comp = &state->newkeys[MODE_IN]->comp;
		/* disable mac for authenticated encryption */
		যদি ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ফাঁকা;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_আকার = enc ? enc->block_আকার : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	যদি (aadlen && state->packlen == 0) {
		যদি (cipher_get_দৈর্ঘ্য(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->প্রবেশ), sshbuf_len(state->প্রবেশ)) != 0)
			ফেরত 0;
		যদি (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_আকার) {
#ifdef PACKET_DEBUG
			sshbuf_dump(state->প্রবেশ, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			যদি ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				ফেরত r;
			ফেরত SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} অন্যথা যদি (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		যদি (sshbuf_len(state->প্রবেশ) < block_আকার)
			ফেরত 0;
		sshbuf_reset(state->incoming_packet);
		যদি ((r = sshbuf_reserve(state->incoming_packet, block_আকার,
		    &cp)) != 0)
			যাও out;
		যদি ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->প্রবেশ),
		    block_আকার, 0, 0)) != 0)
			যাও out;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		যদি (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_আকার) {
#ifdef PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->প্রবেশ, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			ফেরত ssh_packet_start_discard(ssh, enc, mac, 0,
			    PACKET_MAX_আকার);
		}
		যদি ((r = sshbuf_consume(state->প্রবেশ, block_আকার)) != 0)
			যাও out;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	যদি (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} অন্যথা {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - block_আকার;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", block_আকার, need, maclen, authlen, aadlen));
	যদি (need % block_আকার != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_আকার, need % block_আকার);
		ফেরত ssh_packet_start_discard(ssh, enc, mac, 0,
		    PACKET_MAX_আকার - block_আকার);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet:
	 * 'aadlen' bytes are unencrypted, but authenticated.
	 * 'need' bytes are encrypted, followed by either
	 * 'authlen' bytes of authentication tag or
	 * 'maclen' bytes of message authentication code.
	 */
	যদি (sshbuf_len(state->প্রবেশ) < aadlen + need + authlen + maclen)
		ফেরত 0; /* packet is incomplete */
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->প্রবেশ, stderr);
#endif
	/* EtM: check mac over encrypted input */
	যদি (mac && mac->enabled && mac->etm) {
		যদি ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->প্রবেশ), aadlen + need,
		    sshbuf_ptr(state->প্রবেশ) + aadlen + need + authlen,
		    maclen)) != 0) {
			যদি (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			যাও out;
		}
	}
	যদি ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		যাও out;
	যদি ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->প্রবেশ), need, aadlen, authlen)) != 0)
		যাও out;
	যদি ((r = sshbuf_consume(state->প্রবেশ, aadlen + need + authlen)) != 0)
		যাও out;
	যদি (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		যদি (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->প্রবেশ), maclen)) != 0) {
			যদি (r != SSH_ERR_MAC_INVALID)
				যাও out;
			logit("Corrupted MAC on input.");
			যদি (need + block_আকার > PACKET_MAX_আকার)
				ফেরত SSH_ERR_INTERNAL_ERROR;
			ফেরত ssh_packet_start_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_আকার - need - block_আকার);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		যদি ((r = sshbuf_consume(state->প্রবেশ, mac->mac_len)) != 0)
			যাও out;
	}

	যদি (seqnr_p != ফাঁকা)
		*seqnr_p = state->p_read.seqnr;
	যদি (++state->p_read.seqnr == 0) {
		যদি ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	যদি (++state->p_read.packets == 0)
		ফেরত SSH_ERR_NEED_REKEY;
	state->p_read.blocks += (state->packlen + 4) / block_আকার;
	state->p_read.bytes += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	যদি (padlen < 4)	{
		যদি ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ফেরত r;
		ফেরত SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	যদি ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_end(state->incoming_packet, padlen)) != 0))
		যাও out;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	যদি (comp && comp->enabled) {
		sshbuf_reset(state->compression_বাফার);
		যদি ((r = uncompress_বাফার(ssh, state->incoming_packet,
		    state->compression_বাফার)) != 0)
			যাও out;
		sshbuf_reset(state->incoming_packet);
		যদি ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_বাফার)) != 0)
			যাও out;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	যদি ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		যাও out;
	যদি (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	যদি (*typep < SSH2_বার্তা_MIN) {
		যদি ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ফেরত r;
		ফেরত SSH_ERR_PROTOCOL_ERROR;
	}
	যদি (state->hook_in != ফাঁকা &&
	    (r = state->hook_in(ssh, state->incoming_packet, typep,
	    state->hook_in_ctx)) != 0)
		ফেরত r;
	যদি (*typep == SSH2_বার্তা_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	অন্যথা
		r = 0;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#endif
	/* reset for next packet */
	state->packlen = 0;
	যদি (*typep == SSH2_বার্তা_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	যদি ((r = ssh_packet_check_rekey(ssh)) != 0)
		ফেরত r;
 out:
	ফেরত r;
}

পূর্ণসংখ্যা
ssh_packet_read_poll_seqnr(কাঠামো ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	কাঠামো session_state *state = ssh->state;
	u_int reason, seqnr;
	পূর্ণসংখ্যা r;
	u_char *বার্তা;
	ধ্রুবক u_char *d;
	আকার_t len;

	জন্য (;;) {
		বার্তা = ফাঁকা;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		যদি (r != 0)
			ফেরত r;
		যদি (*typep == 0) {
			/* no message ready */
			ফেরত 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		যদি (*typep == SSH2_বার্তা_DISCONNECT) {
			যদি ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &বার্তা, ফাঁকা)) != 0)
				ফেরত r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh), reason, বার্তা);
			মুক্ত(বার্তা);
			ফেরত SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		যদি (ssh->kex != ফাঁকা &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			ফেরত 0;
		/* Implicitly handle transport-level messages */
		নির্বাচন (*typep) {
		ক্ষেত্র SSH2_বার্তা_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			বিরতি;
		ক্ষেত্র SSH2_বার্তা_DEBUG:
			যদি ((r = sshpkt_get_u8(ssh, ফাঁকা)) != 0 ||
			    (r = sshpkt_get_string(ssh, &বার্তা, ফাঁকা)) != 0 ||
			    (r = sshpkt_get_string(ssh, ফাঁকা, ফাঁকা)) != 0) {
				মুক্ত(বার্তা);
				ফেরত r;
			}
			debug("Remote: %.900s", বার্তা);
			মুক্ত(বার্তা);
			বিরতি;
		ক্ষেত্র SSH2_বার্তা_UNIMPLEMENTED:
			যদি ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				ফেরত r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			বিরতি;
		ক্ষেত্র SSH2_বার্তা_PING:
			যদি ((r = sshpkt_get_string_direct(ssh, &d, &len)) != 0)
				ফেরত r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			যদি (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				বিরতি;
			}
			যদি (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				বিরতি;
			}
			যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				ফেরত r;
			বিরতি;
		ক্ষেত্র SSH2_বার্তা_PONG:
			যদি ((r = sshpkt_get_string_direct(ssh,
			    ফাঁকা, &len)) != 0)
				ফেরত r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			বিরতি;
		পূর্বনির্ধারিত:
			যদি (ssh->kex != ফাঁকা &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				ফেরত SSH_ERR_PROTOCOL_ERROR;
			}
			ফেরত 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
পূর্ণসংখ্যা
ssh_packet_process_incoming(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *buf, u_int len)
{
	কাঠামো session_state *state = ssh->state;
	পূর্ণসংখ্যা r;

	যদি (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		যদি (len >= state->packet_discard) {
			যদি ((r = ssh_packet_stop_discard(ssh)) != 0)
				ফেরত r;
		}
		state->packet_discard -= len;
		ফেরত 0;
	}
	যদি ((r = sshbuf_put(state->প্রবেশ, buf, len)) != 0)
		ফেরত r;

	ফেরত 0;
}

/* Reads and buffers data from the specified fd */
পূর্ণসংখ্যা
ssh_packet_process_read(কাঠামো ssh *ssh, পূর্ণসংখ্যা fd)
{
	কাঠামো session_state *state = ssh->state;
	পূর্ণসংখ্যা r;
	আকার_t rlen;

	যদি ((r = sshbuf_read(fd, state->প্রবেশ, PACKET_MAX_আকার, &rlen)) != 0)
		ফেরত r;

	যদি (state->packet_discard) {
		যদি ((r = sshbuf_consume_end(state->প্রবেশ, rlen)) != 0)
			ফেরত r;
		state->keep_alive_timeouts = 0; /* ?? */
		যদি (rlen >= state->packet_discard) {
			যদি ((r = ssh_packet_stop_discard(ssh)) != 0)
				ফেরত r;
		}
		state->packet_discard -= rlen;
		ফেরত 0;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_packet_remaining(কাঠামো ssh *ssh)
{
	ফেরত sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
শূন্য
ssh_packet_send_debug(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *fmt,...)
{
	অক্ষর buf[1024];
	va_list args;
	পূর্ণসংখ্যা r;

	যদি ((ssh->compat & SSH_BUG_DEBUG))
		ফেরত;

	va_start(args, fmt);
	vsnprintf(buf, আকার(buf), fmt, args);
	va_end(args);

	debug3("sending debug message: %s", buf);

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

শূন্য
sshpkt_fmt_connection_id(কাঠামো ssh *ssh, অক্ষর *s, আকার_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
স্থির শূন্য
sshpkt_vfatal(কাঠামো ssh *ssh, পূর্ণসংখ্যা r, ধ্রুবক অক্ষর *fmt, va_list ap)
{
	অক্ষর *tag = ফাঁকা, remote_id[512];
	পূর্ণসংখ্যা oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, আকার(remote_id));

	নির্বাচন (r) {
	ক্ষেত্র SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_চাবিগুলি(ssh);
		logdie("Connection closed by %s", remote_id);
	ক্ষেত্র SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_চাবিগুলি(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	ক্ষেত্র SSH_ERR_DISCONNECTED:
		ssh_packet_clear_চাবিগুলি(ssh);
		logdie("Disconnected from %s", remote_id);
	ক্ষেত্র SSH_ERR_SYSTEM_ERROR:
		যদি (errno == ECONNRESET) {
			ssh_packet_clear_চাবিগুলি(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	ক্ষেত্র SSH_ERR_NO_CIPHER_ALG_MATCH:
	ক্ষেত্র SSH_ERR_NO_MAC_ALG_MATCH:
	ক্ষেত্র SSH_ERR_NO_COMPRESS_ALG_MATCH:
	ক্ষেত্র SSH_ERR_NO_KEX_ALG_MATCH:
	ক্ষেত্র SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		যদি (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_চাবিগুলি(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	পূর্বনির্ধারিত:
		যদি (vasprintf(&tag, fmt, ap) == -1) {
			ssh_packet_clear_চাবিগুলি(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_চাবিগুলি(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    tag != ফাঁকা ? tag : "", tag != ফাঁকা ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

শূন্য
sshpkt_fatal(কাঠামো ssh *ssh, পূর্ণসংখ্যা r, ধ্রুবক অক্ষর *fmt, ...)
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
শূন্য
ssh_packet_disconnect(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *fmt,...)
{
	অক্ষর buf[1024], remote_id[512];
	va_list args;
	পূর্ণসংখ্যা r;

	/* Guard against recursive invocations. */
	যদি (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, আকার(remote_id));
	va_start(args, fmt);
	vsnprintf(buf, আকার(buf), fmt, args);
	va_end(args);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	যদি ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	যদি ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
পূর্ণসংখ্যা
ssh_packet_write_poll(কাঠামো ssh *ssh)
{
	কাঠামো session_state *state = ssh->state;
	পূর্ণসংখ্যা len = sshbuf_len(state->output);
	পূর্ণসংখ্যা r;

	যদি (len > 0) {
		len = লিখ(state->connection_out,
		    sshbuf_ptr(state->output), len);
		যদি (len == -1) {
			যদি (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				ফেরত 0;
			ফেরত SSH_ERR_SYSTEM_ERROR;
		}
		যদি (len == 0)
			ফেরত SSH_ERR_CONN_CLOSED;
		যদি ((r = sshbuf_consume(state->output, len)) != 0)
			ফেরত r;
	}
	ফেরত 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
পূর্ণসংখ্যা
ssh_packet_write_wait(কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা ret, r, ms_remain = 0;
	কাঠামো timeval start;
	কাঠামো timespec timespec, *timespecp = ফাঁকা;
	কাঠামো session_state *state = ssh->state;
	কাঠামো pollfd pfd;

	যদি ((r = ssh_packet_write_poll(ssh)) != 0)
		ফেরত r;
	যখন (ssh_packet_have_তথ্য_to_write(ssh)) {
		pfd.fd = state->connection_out;
		pfd.events = POLLOUT;

		যদি (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		জন্য (;;) {
			যদি (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			যদি ((ret = ppoll(&pfd, 1, timespecp, ফাঁকা)) >= 0)
				বিরতি;
			যদি (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				বিরতি;
			যদি (state->packet_timeout_ms <= 0)
				চালু;
			ms_subtract_diff(&start, &ms_remain);
			যদি (ms_remain <= 0) {
				ret = 0;
				বিরতি;
			}
		}
		যদি (ret == 0)
			ফেরত SSH_ERR_CONN_TIMEOUT;
		যদি ((r = ssh_packet_write_poll(ssh)) != 0)
			ফেরত r;
	}
	ফেরত 0;
}

/* Returns true if there is buffered data to write to the connection. */

পূর্ণসংখ্যা
ssh_packet_have_তথ্য_to_write(কাঠামো ssh *ssh)
{
	ফেরত sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

পূর্ণসংখ্যা
ssh_packet_not_very_much_তথ্য_to_write(কাঠামো ssh *ssh)
{
	যদি (ssh->state->interactive_mode)
		ফেরত sshbuf_len(ssh->state->output) < 16384;
	অন্যথা
		ফেরত sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

পূর্ণসংখ্যা
ssh_packet_interactive_তথ্য_to_write(কাঠামো ssh *ssh)
{
	ফেরত ssh->state->interactive_mode &&
	    sshbuf_len(ssh->state->output) < 256;
}

স্থির শূন্য
apply_qos(কাঠামো ssh *ssh)
{
	কাঠামো session_state *state = ssh->state;
	পূর্ণসংখ্যা qos = state->interactive_mode ?
	    state->qos_interactive : state->qos_other;

	যদি (!ssh_packet_connection_is_on_socket(ssh))
		ফেরত;
	যদি (!state->nodelay_set) {
		set_nodelay(state->connection_in);
		state->nodelay_set = 1;
	}
	set_sock_tos(ssh->state->connection_in, qos);
}

/* Informs that the current session is interactive. */
শূন্য
ssh_packet_set_interactive(কাঠামো ssh *ssh, পূর্ণসংখ্যা interactive)
{
	কাঠামো session_state *state = ssh->state;

	state->interactive_mode = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
শূন্য
ssh_packet_set_qos(কাঠামো ssh *ssh, পূর্ণসংখ্যা qos_interactive, পূর্ণসংখ্যা qos_other)
{
	কাঠামো session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

পূর্ণসংখ্যা
ssh_packet_set_maxsize(কাঠামো ssh *ssh, u_int s)
{
	কাঠামো session_state *state = ssh->state;

	যদি (state->set_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_আকার, s);
		ফেরত -1;
	}
	যদি (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		ফেরত -1;
	}
	state->set_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_আকার = s;
	ফেরত s;
}

পূর্ণসংখ্যা
ssh_packet_inc_alive_timeouts(কাঠামো ssh *ssh)
{
	ফেরত ++ssh->state->keep_alive_timeouts;
}

শূন্য
ssh_packet_set_alive_timeouts(কাঠামো ssh *ssh, পূর্ণসংখ্যা ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(কাঠামো ssh *ssh)
{
	ফেরত ssh->state->max_packet_আকার;
}

শূন্য
ssh_packet_set_rekey_limits(কাঠামো ssh *ssh, uint64_t bytes, uint32_t seconds)
{
	যদি (bytes == 0 && seconds == 0)
		ফেরত;

	debug3("rekey after %llu bytes, %u seconds", (unsigned long long)bytes,
	    (unsigned পূর্ণসংখ্যা)seconds);
	ssh->state->rekey_limit = bytes;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(কাঠামো ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_time + ssh->state->rekey_interval -
	    monotime();
	ফেরত (seconds <= 0 ? 1 : seconds);
}

শূন্য
ssh_packet_set_server(কাঠামো ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

শূন্য
ssh_packet_set_authenticated(কাঠামো ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

শূন্য *
ssh_packet_get_প্রবেশ(কাঠামো ssh *ssh)
{
	ফেরত (শূন্য *)ssh->state->প্রবেশ;
}

শূন্য *
ssh_packet_get_output(কাঠামো ssh *ssh)
{
	ফেরত (শূন্য *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
স্থির পূর্ণসংখ্যা
ssh_packet_set_postauth(কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	যদি ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		ফেরত r;
	ফেরত 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
স্থির পূর্ণসংখ্যা
kex_to_blob(কাঠামো sshbuf *m, কাঠামো kex *kex)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
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
		ফেরত r;
	ফেরত 0;
}

/* turn key exchange results into a blob for packet state serialization */
স্থির পূর্ণসংখ্যা
newkeys_to_blob(কাঠামো sshbuf *m, কাঠামো ssh *ssh, পূর্ণসংখ্যা mode)
{
	কাঠামো sshbuf *b;
	কাঠামো sshcipher_ctx *cc;
	কাঠামো sshcomp *comp;
	কাঠামো sshenc *enc;
	কাঠামো sshmac *mac;
	কাঠামো newkeys *newkey;
	পূর্ণসংখ্যা r;

	যদি ((newkey = ssh->state->newkeys[mode]) == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (mode == MODE_OUT) ? ssh->state->send_context :
	    ssh->state->receive_context;
	যদি ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		ফেরত r;
	যদি ((b = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->block_আকার)) != 0 ||
	    (r = sshbuf_put_string(b, enc->চাবি, enc->চাবি_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		যাও out;
	যদি (cipher_authlen(enc->cipher) == 0) {
		যদি ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->চাবি, mac->চাবি_len)) != 0)
			যাও out;
	}
	যদি ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		যাও out;
	r = sshbuf_put_stringb(m, b);
 out:
	sshbuf_free(b);
	ফেরত r;
}

/* serialize packet state into a blob */
পূর্ণসংখ্যা
ssh_packet_get_state(কাঠামো ssh *ssh, কাঠামো sshbuf *m)
{
	কাঠামো session_state *state = ssh->state;
	পূর্ণসংখ্যা r;

#define ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	যদি ((r = kex_to_blob(m, ssh->kex)) != 0 ||
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
	    (r = sshbuf_put_stringb(m, state->প্রবেশ)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_mode))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		ফেরত r;
#undef ENCODE_INT
	ফেরত 0;
}

/* restore key exchange results from blob for packet state de-serialization */
স্থির পূর্ণসংখ্যা
newkeys_from_blob(কাঠামো sshbuf *m, কাঠামো ssh *ssh, পূর্ণসংখ্যা mode)
{
	কাঠামো sshbuf *b = ফাঁকা;
	কাঠামো sshcomp *comp;
	কাঠামো sshenc *enc;
	কাঠামো sshmac *mac;
	কাঠামো newkeys *newkey = ফাঁকা;
	আকার_t keylen, ivlen, maclen;
	পূর্ণসংখ্যা r;

	যদি ((newkey = calloc(1, আকার(*newkey))) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_froms(m, &b)) != 0)
		যাও out;
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	যদি ((r = sshbuf_get_cstring(b, &enc->name, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->block_আকার)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->চাবি, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		যাও out;
	যদি ((enc->cipher = cipher_by_name(enc->name)) == ফাঁকা ||
	    enc->block_আকার != cipher_blocksize(enc->cipher) ||
	    cipher_is_internal(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (cipher_authlen(enc->cipher) == 0) {
		যদি ((r = sshbuf_get_cstring(b, &mac->name, ফাঁকা)) != 0)
			যাও out;
		যদি ((r = mac_setup(mac, mac->name)) != 0)
			যাও out;
		যদি ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->চাবি, &maclen)) != 0)
			যাও out;
		যদি (maclen != mac->চাবি_len) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		mac->চাবি_len = maclen;
	}
	যদি ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, ফাঁকা)) != 0)
		যাও out;
	যদি (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	enc->চাবি_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[mode] = newkey;
	newkey = ফাঁকা;
	r = 0;
 out:
	মুক্ত(newkey);
	sshbuf_free(b);
	ফেরত r;
}

/* restore kex from blob for packet state de-serialization */
স্থির পূর্ণসংখ্যা
kex_from_blob(কাঠামো sshbuf *m, কাঠামো kex **kexp)
{
	কাঠামো kex *kex;
	পূর্ণসংখ্যা r;

	যদি ((kex = kex_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, ফাঁকা)) != 0 ||
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
		যাও out;
	যদি (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	kex->server = 1;
	kex->done = 1;
	r = 0;
 out:
	যদি (r != 0 || kexp == ফাঁকা) {
		kex_free(kex);
		যদি (kexp != ফাঁকা)
			*kexp = ফাঁকা;
	} অন্যথা {
		kex_free(*kexp);
		*kexp = kex;
	}
	ফেরত r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
পূর্ণসংখ্যা
ssh_packet_set_state(কাঠামো ssh *ssh, কাঠামো sshbuf *m)
{
	কাঠামো session_state *state = ssh->state;
	ধ্রুবক u_char *প্রবেশ, *output;
	আকার_t ilen, olen;
	পূর্ণসংখ্যা r;
	u_int interactive, qos_interactive, qos_other;

	যদি ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
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
		ফেরত r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_time = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	যদি ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0 ||
	    (r = ssh_set_newkeys(ssh, MODE_OUT)) != 0)
		ফেরত r;

	যদি ((r = ssh_packet_set_postauth(ssh)) != 0)
		ফেরত r;

	sshbuf_reset(state->প্রবেশ);
	sshbuf_reset(state->output);
	যদি ((r = sshbuf_get_string_direct(m, &প্রবেশ, &ilen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->প্রবেশ, প্রবেশ, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		ফেরত r;

	যদি ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		ফেরত r;
#define DECODE_INT(v) ((v) > INT_MAX ? -1 : (পূর্ণসংখ্যা)(v))
	state->interactive_mode = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#undef DECODE_INT

	যদি (sshbuf_len(m))
		ফেরত SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	ফেরত 0;
}

/* NEW API */

/* put data to the outgoing packet */

পূর্ণসংখ্যা
sshpkt_put(কাঠামো ssh *ssh, ধ্রুবক শূন্য *v, আকার_t len)
{
	ফেরত sshbuf_put(ssh->state->outgoing_packet, v, len);
}

পূর্ণসংখ্যা
sshpkt_putb(কাঠামো ssh *ssh, ধ্রুবক কাঠামো sshbuf *b)
{
	ফেরত sshbuf_putb(ssh->state->outgoing_packet, b);
}

পূর্ণসংখ্যা
sshpkt_put_u8(কাঠামো ssh *ssh, u_char val)
{
	ফেরত sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

পূর্ণসংখ্যা
sshpkt_put_u32(কাঠামো ssh *ssh, uint32_t val)
{
	ফেরত sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

পূর্ণসংখ্যা
sshpkt_put_u64(কাঠামো ssh *ssh, uint64_t val)
{
	ফেরত sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

পূর্ণসংখ্যা
sshpkt_put_string(কাঠামো ssh *ssh, ধ্রুবক শূন্য *v, আকার_t len)
{
	ফেরত sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

পূর্ণসংখ্যা
sshpkt_put_cstring(কাঠামো ssh *ssh, ধ্রুবক শূন্য *v)
{
	ফেরত sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

পূর্ণসংখ্যা
sshpkt_put_stringb(কাঠামো ssh *ssh, ধ্রুবক কাঠামো sshbuf *v)
{
	ফেরত sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#ifdef WITH_OPENSSL
পূর্ণসংখ্যা
sshpkt_put_ec(কাঠামো ssh *ssh, ধ্রুবক EC_POINT *v, ধ্রুবক EC_GROUP *g)
{
	ফেরত sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

পূর্ণসংখ্যা
sshpkt_put_ec_pkey(কাঠামো ssh *ssh, EVP_PKEY *pkey)
{
	ফেরত sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

পূর্ণসংখ্যা
sshpkt_put_bignum2(কাঠামো ssh *ssh, ধ্রুবক BIGNUM *v)
{
	ফেরত sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#endif /* WITH_OPENSSL */

/* fetch data from the incoming packet */

পূর্ণসংখ্যা
sshpkt_get(কাঠামো ssh *ssh, শূন্য *valp, আকার_t len)
{
	ফেরত sshbuf_get(ssh->state->incoming_packet, valp, len);
}

পূর্ণসংখ্যা
sshpkt_get_u8(কাঠামো ssh *ssh, u_char *valp)
{
	ফেরত sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

পূর্ণসংখ্যা
sshpkt_get_u32(কাঠামো ssh *ssh, uint32_t *valp)
{
	ফেরত sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

পূর্ণসংখ্যা
sshpkt_get_u64(কাঠামো ssh *ssh, uint64_t *valp)
{
	ফেরত sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

পূর্ণসংখ্যা
sshpkt_get_string(কাঠামো ssh *ssh, u_char **valp, আকার_t *lenp)
{
	ফেরত sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

পূর্ণসংখ্যা
sshpkt_get_string_direct(কাঠামো ssh *ssh, ধ্রুবক u_char **valp, আকার_t *lenp)
{
	ফেরত sshbuf_get_string_direct(ssh->state->incoming_packet, valp, lenp);
}

পূর্ণসংখ্যা
sshpkt_peek_string_direct(কাঠামো ssh *ssh, ধ্রুবক u_char **valp, আকার_t *lenp)
{
	ফেরত sshbuf_peek_string_direct(ssh->state->incoming_packet, valp, lenp);
}

পূর্ণসংখ্যা
sshpkt_get_cstring(কাঠামো ssh *ssh, অক্ষর **valp, আকার_t *lenp)
{
	ফেরত sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

পূর্ণসংখ্যা
sshpkt_getb_froms(কাঠামো ssh *ssh, কাঠামো sshbuf **valp)
{
	ফেরত sshbuf_froms(ssh->state->incoming_packet, valp);
}

#ifdef WITH_OPENSSL
পূর্ণসংখ্যা
sshpkt_get_ec(কাঠামো ssh *ssh, EC_POINT *v, ধ্রুবক EC_GROUP *g)
{
	ফেরত sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

পূর্ণসংখ্যা
sshpkt_get_bignum2(কাঠামো ssh *ssh, BIGNUM **valp)
{
	ফেরত sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#endif /* WITH_OPENSSL */

পূর্ণসংখ্যা
sshpkt_get_end(কাঠামো ssh *ssh)
{
	যদি (sshbuf_len(ssh->state->incoming_packet) > 0)
		ফেরত SSH_ERR_UNEXPECTED_TRAILING_তথ্য;
	ফেরত 0;
}

ধ্রুবক u_char *
sshpkt_ptr(কাঠামো ssh *ssh, আকার_t *lenp)
{
	যদি (lenp != ফাঁকা)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	ফেরত sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

পূর্ণসংখ্যা
sshpkt_start(কাঠামো ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, আকার(buf));
	buf[আকার(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	ফেরত sshbuf_put(ssh->state->outgoing_packet, buf, আকার(buf));
}

স্থির পূর্ণসংখ্যা
ssh_packet_send_mux(কাঠামো ssh *ssh)
{
	কাঠামো session_state *state = ssh->state;
	u_char type, *cp;
	আকার_t len;
	পূর্ণসংখ্যা r;

	যদি (ssh->kex)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	যদি (len < 6)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	যদি (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	যদি (type >= SSH2_বার্তা_CONNECTION_MIN &&
	    type <= SSH2_বার্তা_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		যদি ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			ফেরত r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	ফেরত 0;
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
পূর্ণসংখ্যা
sshpkt_বার্তা_ignore(কাঠামো ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	পূর্ণসংখ্যা r;
	u_int i;

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		ফেরত r;
	জন্য (i = 0; i < nbytes; i++) {
		যদি (i % 4 == 0)
			rnd = arc4random();
		যদি ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			ফেরত r;
		rnd >>= 8;
	}
	ফেরত 0;
}

/* send it */

পূর্ণসংখ্যা
sshpkt_send(কাঠামো ssh *ssh)
{
	যদি (ssh->state && ssh->state->mux)
		ফেরত ssh_packet_send_mux(ssh);
	ফেরত ssh_packet_send2(ssh);
}

পূর্ণসংখ্যা
sshpkt_disconnect(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *fmt,...)
{
	অক্ষর buf[1024];
	va_list args;
	পূর্ণসংখ্যা r;

	va_start(args, fmt);
	vsnprintf(buf, আকার(buf), fmt, args);
	va_end(args);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ফেরত r;
	ফেরত 0;
}

/* roundup current message to pad bytes */
পূর্ণসংখ্যা
sshpkt_add_padding(কাঠামো ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	ফেরত 0;
}

স্থির অক্ষর *
format_traffic_stats(কাঠামো packet_state *ps)
{
	অক্ষর *stats = ফাঁকা, bytes[FMT_SCALED_STRSIZE];

	যদি (ps->bytes > LLONG_MAX || fmt_scaled(ps->bytes, bytes) != 0)
		strlcpy(bytes, "OVERFLOW", আকার(bytes));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (unsigned long)ps->packets, (unsigned long long)ps->blocks, bytes);
	ফেরত stats;
}

স্থির অক্ষর *
dedupe_alg_names(ধ্রুবক অক্ষর *in, ধ্রুবক অক্ষর *out)
{
	অক্ষর *names = ফাঁকা;

	যদি (in == ফাঁকা)
		in = "<implicit>";
	যদি (out == ফাঁকা)
		out = "<implicit>";

	যদি (strcmp(in, out) == 0) {
		names = xstrdup(in);
	} অন্যথা {
		xasprintf(&names, "%s in, %s out", in, out);
	}
	ফেরত names;
}

স্থির অক্ষর *
comp_status_message(কাঠামো ssh *ssh)
{
#ifdef WITH_ZLIB
	অক্ষর *ret = ফাঁকা;
	কাঠামো session_state *state = ssh->state;
	unsigned long long iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	অক্ষর iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	অক্ষর icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	যদি (state->compression_বাফার) {
		যদি (state->compression_in_started) {
			iraw = state->compression_in_stream.যোগ_out;
			icmp = state->compression_in_stream.যোগ_in;
			যদি (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", আকার(iraw_f));
			যদি (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", আকার(icmp_f));
		}
		যদি (state->compression_out_started) {
			oraw = state->compression_out_stream.যোগ_in;
			ocmp = state->compression_out_stream.যোগ_out;
			যদি (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", আকার(oraw_f));
			যদি (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", আকার(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (দ্বিগুণ)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (দ্বিগুণ)ocmp / oraw);
		ফেরত ret;
	}
#endif	/* WITH_ZLIB */
	ফেরত xstrdup("");
}

অক্ষর *
connection_info_message(কাঠামো ssh *ssh)
{
	অক্ষর *ret = ফাঁকা, *cipher = ফাঁকা, *mac = ফাঁকা, *comp = ফাঁকা;
	অক্ষর *rekey_volume = ফাঁকা, *rekey_time = ফাঁকা, *comp_info = ফাঁকা;
	অক্ষর thishost[NI_MAXHOST] = "unknown", *tcp_info = ফাঁকা;
	কাঠামো kex *kex;
	কাঠামো session_state *state;
	কাঠামো newkeys *nk_in, *nk_out;
	অক্ষর *stats_in = ফাঁকা, *stats_out = ফাঁকা;
	uint64_t epoch = (uint64_t)time(ফাঁকা) - monotime();

	যদি (ssh == ফাঁকা)
		ফেরত ফাঁকা;
	state = ssh->state;
	kex = ssh->kex;

	(শূন্য)gethostname(thishost, আকার(thishost));

	যদি (ssh_local_port(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	} অন্যথা {
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
	যদি (state->rekey_limit == 0) {
		xasprintf(&rekey_volume, "limit none");
	} অন্যথা {
		অক্ষর *volumes = ফাঁকা, in[32], out[32];

		snprintf(in, আকার(in), "%llu",
		   (unsigned long long)state->max_blocks_in);
		snprintf(out, আকার(out), "%llu",
		   (unsigned long long)state->max_blocks_out);
		volumes = dedupe_alg_names(in, out);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		মুক্ত(volumes);
	}

	/* Time based rekeying. */
	যদি (state->rekey_interval == 0) {
		rekey_time = xstrdup("interval none");
	} অন্যথা {
		অক্ষর rekey_পরবর্তী[64];

		format_absolute_time(epoch + state->rekey_time +
		    state->rekey_interval, rekey_পরবর্তী, আকার(rekey_পরবর্তী));
		xasprintf(&rekey_time, "interval %s, next %s",
		    fmt_timeframe(state->rekey_interval), rekey_পরবর্তী);
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
	মুক্ত(tcp_info);
	মুক্ত(cipher);
	মুক্ত(mac);
	মুক্ত(comp);
	মুক্ত(stats_in);
	মুক্ত(stats_out);
	মুক্ত(rekey_volume);
	মুক্ত(rekey_time);
	মুক্ত(comp_info);
	ফেরত ret;
}

