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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/time.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <util.h>

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
#અન્તર્ભાવ <zlib.h>
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "mac.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "version.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#નહીંતર
#define DBG(x)
#endif

#define PACKET_MAX_SIZE (256 * 1024)

સંરચના packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t blocks;
	uint64_t bytes;
};

સંરચના packet {
	TAILQ_ENTRY(packet) next;
	u_char type;
	સંરચના sshbuf *payload;
};

સંરચના session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	પૂર્ણાંક connection_in;
	પૂર્ણાંક connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	સંરચના sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	સંરચના sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	સંરચના sshbuf *આગત;

	/* Buffer for raw output data going to the socket. */
	સંરચના sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	સંરચના sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	સંરચના sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	સંરચના sshbuf *compression_buffer;

#ifdef WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_stream compression_in_stream;
	z_stream compression_out_stream;
#endif
	પૂર્ણાંક compression_in_started;
	પૂર્ણાંક compression_out_started;
	પૂર્ણાંક compression_in_failures;
	પૂર્ણાંક compression_out_failures;

	/* default maximum packet size */
	u_int max_packet_size;

	/* Flag indicating whether this module has been initialized. */
	પૂર્ણાંક initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t start_time;

	/* Set to true if the connection is interactive. */
	પૂર્ણાંક interactive_mode;

	/* Set to true if we are the server side. */
	પૂર્ણાંક server_side;

	/* Set to true if we are authenticated. */
	પૂર્ણાંક after_authentication;

	પૂર્ણાંક keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	પૂર્ણાંક packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	સંરચના newkeys *newkeys[MODE_MAX];
	સંરચના packet_state p_read, p_send;

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
	સંરચના sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	પૂર્ણાંક rekeying;

	/* Used in ssh_packet_send_mux() */
	પૂર્ણાંક mux;

	/* QoS handling */
	પૂર્ણાંક qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	પૂર્ણાંક set_maxsize_called;

	/* One-off warning about weak ciphers */
	પૂર્ણાંક cipher_warning_done;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	પૂર્ણાંક disconnecting;

	/* Nagle disabled on socket */
	પૂર્ણાંક nodelay_set;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_in;
	શૂન્ય *hook_in_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

સંરચના ssh *
ssh_alloc_session_state(શૂન્ય)
{
	સંરચના ssh *ssh = ખાલી;
	સંરચના session_state *state = ખાલી;

	જો ((ssh = calloc(1, કદ(*ssh))) == ખાલી ||
	    (state = calloc(1, કદ(*state))) == ખાલી ||
	    (ssh->kex = kex_new()) == ખાલી ||
	    (state->આગત = sshbuf_new()) == ખાલી ||
	    (state->output = sshbuf_new()) == ખાલી ||
	    (state->outgoing_packet = sshbuf_new()) == ખાલી ||
	    (state->incoming_packet = sshbuf_new()) == ખાલી)
		જાઓ fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->private_ચાવીઓ);
	TAILQ_INIT(&ssh->public_ચાવીઓ);
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
	પાછા ssh;
 fail:
	જો (ssh) {
		kex_free(ssh->kex);
		મુક્ત(ssh);
	}
	જો (state) {
		sshbuf_free(state->આગત);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		મુક્ત(state);
	}
	પાછા ખાલી;
}

શૂન્ય
ssh_packet_set_આગત_hook(સંરચના ssh *ssh, ssh_packet_hook_fn *hook, શૂન્ય *ctx)
{
	ssh->state->hook_in = hook;
	ssh->state->hook_in_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
પૂર્ણાંક
ssh_packet_is_rekeying(સંરચના ssh *ssh)
{
	પાછા ssh->state->rekeying ||
	    (ssh->kex != ખાલી && ssh->kex->done == 0);
}

/*
 * Sets the descriptors used for communication.
 */
સંરચના ssh *
ssh_packet_set_connection(સંરચના ssh *ssh, પૂર્ણાંક fd_in, પૂર્ણાંક fd_out)
{
	સંરચના session_state *state;
	અચલ સંરચના sshcipher *none = cipher_by_name("none");
	પૂર્ણાંક r, wasnull = ssh == ખાલી;

	જો (none == ખાલી) {
		error_f("cannot load cipher 'none'");
		પાછા ખાલી;
	}
	જો (ssh == ખાલી)
		ssh = ssh_alloc_session_state();
	જો (ssh == ખાલી) {
		error_f("could not allocate state");
		પાછા ખાલી;
	}
	state = ssh->state;
	state->start_time = monotime();
	state->connection_in = fd_in;
	state->connection_out = fd_out;
	જો ((r = cipher_init(&state->send_context, none,
	    (અચલ u_char *)"", 0, ખાલી, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (અચલ u_char *)"", 0, ખાલી, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		જો (wasnull)
			મુક્ત(ssh); /* XXX need ssh_free_session_state? */
		પાછા ખાલી;
	}
	state->newkeys[MODE_IN] = state->newkeys[MODE_OUT] = ખાલી;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(શૂન્ય)ssh_remote_ipaddr(ssh);
	પાછા ssh;
}

શૂન્ય
ssh_packet_set_timeout(સંરચના ssh *ssh, પૂર્ણાંક timeout, પૂર્ણાંક ગણતરી)
{
	સંરચના session_state *state = ssh->state;

	જો (timeout <= 0 || ગણતરી <= 0) {
		state->packet_timeout_ms = -1;
		પાછા;
	}
	જો ((INT_MAX / 1000) / ગણતરી < timeout)
		state->packet_timeout_ms = INT_MAX;
	નહીંતર
		state->packet_timeout_ms = timeout * ગણતરી * 1000;
}

શૂન્ય
ssh_packet_set_mux(સંરચના ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = ખાલી;
}

પૂર્ણાંક
ssh_packet_get_mux(સંરચના ssh *ssh)
{
	પાછા ssh->state->mux;
}

પૂર્ણાંક
ssh_packet_set_log_preamble(સંરચના ssh *ssh, અચલ અક્ષર *fmt, ...)
{
	va_list args;
	પૂર્ણાંક r;

	મુક્ત(ssh->log_preamble);
	જો (fmt == ખાલી)
		ssh->log_preamble = ખાલી;
	નહીંતર {
		va_start(args, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, args);
		va_end(args);
		જો (r < 0 || ssh->log_preamble == ખાલી)
			પાછા SSH_ERR_ALLOC_FAIL;
	}
	પાછા 0;
}

પૂર્ણાંક
ssh_packet_stop_discard(સંરચના ssh *ssh)
{
	સંરચના session_state *state = ssh->state;
	પૂર્ણાંક r;

	જો (state->packet_discard_mac) {
		અક્ષર buf[1024];
		size_t dlen = PACKET_MAX_SIZE;

		જો (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', કદ(buf));
		જ્યારે (sshbuf_len(state->incoming_packet) < dlen)
			જો ((r = sshbuf_put(state->incoming_packet, buf,
			    કદ(buf))) != 0)
				પાછા r;
		(શૂન્ય) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    ખાલી, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	પાછા SSH_ERR_MAC_INVALID;
}

સ્થિર પૂર્ણાંક
ssh_packet_start_discard(સંરચના ssh *ssh, સંરચના sshenc *enc,
    સંરચના sshmac *mac, size_t mac_already, u_int discard)
{
	સંરચના session_state *state = ssh->state;
	પૂર્ણાંક r;

	જો (enc == ખાલી || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		જો ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			પાછા r;
		પાછા SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	જો (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	જો (sshbuf_len(state->આગત) >= discard)
		પાછા ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->આગત);
	પાછા 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

પૂર્ણાંક
ssh_packet_connection_is_on_socket(સંરચના ssh *ssh)
{
	સંરચના session_state *state;
	સંરચના sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	જો (ssh == ખાલી || ssh->state == ખાલી)
		પાછા 0;

	state = ssh->state;
	જો (state->connection_in == -1 || state->connection_out == -1)
		પાછા 0;
	fromlen = કદ(from);
	memset(&from, 0, કદ(from));
	જો (getpeername(state->connection_in, (સંરચના sockaddr *)&from,
	    &fromlen) == -1)
		પાછા 0;
	જો (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		પાછા 0;
	/* filedescriptors in and out are the same, so it's a socket */
	જો (state->connection_in == state->connection_out)
		પાછા 1;
	tolen = કદ(to);
	memset(&to, 0, કદ(to));
	જો (getpeername(state->connection_out, (સંરચના sockaddr *)&to,
	    &tolen) == -1)
		પાછા 0;
	જો (fromlen != tolen || memcmp(&from, &to, fromlen) != 0)
		પાછા 0;
	પાછા 1;
}

શૂન્ય
ssh_packet_get_bytes(સંરચના ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	જો (ibytes)
		*ibytes = ssh->state->p_read.bytes;
	જો (obytes)
		*obytes = ssh->state->p_send.bytes;
}

પૂર્ણાંક
ssh_packet_connection_af(સંરચના ssh *ssh)
{
	પાછા get_sock_af(ssh->state->connection_out);
}

/* Sets the connection into non-blocking mode. */

શૂન્ય
ssh_packet_set_nonblocking(સંરચના ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(ssh->state->connection_in);

	જો (ssh->state->connection_out != ssh->state->connection_in)
		set_nonblock(ssh->state->connection_out);
}

/* Returns the socket used for reading. */

પૂર્ણાંક
ssh_packet_get_connection_in(સંરચના ssh *ssh)
{
	પાછા ssh->state->connection_in;
}

/* Returns the descriptor used for writing. */

પૂર્ણાંક
ssh_packet_get_connection_out(સંરચના ssh *ssh)
{
	પાછા ssh->state->connection_out;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

અચલ અક્ષર *
ssh_remote_ipaddr(સંરચના ssh *ssh)
{
	પૂર્ણાંક sock;

	/* Check whether we have cached the ipaddr. */
	જો (ssh->remote_ipaddr == ખાલી) {
		જો (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_in;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_port = get_peer_port(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_port = get_local_port(sock);
		} નહીંતર {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_port = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_port = 65535;
		}
	}
	પાછા ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

અક્ષર *
ssh_remote_hostname(સંરચના ssh *ssh)
{
	સંરચના sockaddr_storage from;
	socklen_t fromlen;
	સંરચના addrinfo hints, *ai, *aitop;
	અક્ષર name[NI_MAXHOST], ntop2[NI_MAXHOST];
	અચલ અક્ષર *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = કદ(from);
	memset(&from, 0, કદ(from));
	જો (getpeername(ssh_packet_get_connection_in(ssh),
	    (સંરચના sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		પાછા xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	જો (from.ss_family == AF_INET6)
		fromlen = કદ(સંરચના sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	જો (getnameinfo((સંરચના sockaddr *)&from, fromlen, name, કદ(name),
	    ખાલી, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		પાછા xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, કદ(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	જો (getaddrinfo(name, ખાલી, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		પાછા xstrdup(ntop);
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
	memset(&hints, 0, કદ(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	જો (getaddrinfo(name, ખાલી, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		પાછા xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	માટે (ai = aitop; ai; ai = ai->ai_next) {
		જો (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    કદ(ntop2), ખાલી, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				તોડો;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	જો (ai == ખાલી) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		પાછા xstrdup(ntop);
	}
	પાછા xstrdup(name);
}

/* Returns the port number of the remote host. */

પૂર્ણાંક
ssh_remote_port(સંરચના ssh *ssh)
{
	(શૂન્ય)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	પાછા ssh->remote_port;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

અચલ અક્ષર *
ssh_local_ipaddr(સંરચના ssh *ssh)
{
	(શૂન્ય)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	પાછા ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

પૂર્ણાંક
ssh_local_port(સંરચના ssh *ssh)
{
	(શૂન્ય)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	પાછા ssh->local_port;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
અચલ અક્ષર *
ssh_packet_rdomain_in(સંરચના ssh *ssh)
{
	જો (ssh->rdomain_in != ખાલી)
		પાછા ssh->rdomain_in;
	જો (!ssh_packet_connection_is_on_socket(ssh))
		પાછા ખાલી;
	ssh->rdomain_in = get_rdomain(ssh->state->connection_in);
	પાછા ssh->rdomain_in;
}

/* Closes the connection and clears and frees internal data structures. */

સ્થિર શૂન્ય
ssh_packet_close_internal(સંરચના ssh *ssh, પૂર્ણાંક do_close)
{
	સંરચના session_state *state = ssh->state;
	u_int mode;
	સંરચના packet *p;

	જો (!state->initialized)
		પાછા;
	state->initialized = 0;
	જો (do_close) {
		જો (state->connection_in == state->connection_out) {
			close(state->connection_out);
		} નહીંતર {
			close(state->connection_in);
			close(state->connection_out);
		}
	}
	sshbuf_free(state->આગત);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	જ્યારે ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, next);
		મુક્ત(p);
	}
	માટે (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(state->newkeys[mode]);	/* current keys */
		state->newkeys[mode] = ખાલી;
		ssh_clear_newkeys(ssh, mode);		/* next keys */
	}
#ifdef WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	જો (do_close && state->compression_buffer) {
		sshbuf_free(state->compression_buffer);
		જો (state->compression_out_started) {
			z_streamp stream = &state->compression_out_stream;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(unsigned long long)stream->total_in,
				(unsigned long long)stream->total_out,
				stream->total_in == 0 ? 0.0 :
				(દ્વિગુણ) stream->total_out / stream->total_in);
			જો (state->compression_out_failures == 0)
				deflateEnd(stream);
		}
		જો (state->compression_in_started) {
			z_streamp stream = &state->compression_in_stream;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (unsigned long long)stream->total_out,
			    (unsigned long long)stream->total_in,
			    stream->total_out == 0 ? 0.0 :
			    (દ્વિગુણ) stream->total_in / stream->total_out);
			જો (state->compression_in_failures == 0)
				inflateEnd(stream);
		}
	}
#endif	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = ખાલી;
	જો (do_close) {
		મુક્ત(ssh->local_ipaddr);
		ssh->local_ipaddr = ખાલી;
		મુક્ત(ssh->remote_ipaddr);
		ssh->remote_ipaddr = ખાલી;
		મુક્ત(ssh->state);
		ssh->state = ખાલી;
		kex_free(ssh->kex);
		ssh->kex = ખાલી;
	}
}

શૂન્ય
ssh_packet_free(સંરચના ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
	freezero(ssh, કદ(*ssh));
}

શૂન્ય
ssh_packet_close(સંરચના ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
}

શૂન્ય
ssh_packet_clear_ચાવીઓ(સંરચના ssh *ssh)
{
	ssh_packet_close_internal(ssh, 0);
}

/* Sets remote side protocol flags. */

શૂન્ય
ssh_packet_set_protocol_flags(સંરચના ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(સંરચના ssh *ssh)
{
	પાછા ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

સ્થિર પૂર્ણાંક
ssh_packet_init_compression(સંરચના ssh *ssh)
{
	જો (!ssh->state->compression_buffer &&
	    ((ssh->state->compression_buffer = sshbuf_new()) == ખાલી))
		પાછા SSH_ERR_ALLOC_FAIL;
	પાછા 0;
}

#ifdef WITH_ZLIB
સ્થિર પૂર્ણાંક
start_compression_out(સંરચના ssh *ssh)
{
	debug("Enabling compression.");
	જો (ssh->state->compression_out_started == 1)
		deflateEnd(&ssh->state->compression_out_stream);
	પસંદગી (deflateInit2(&ssh->state->compression_out_stream,
	    Z_BEST_SPEED, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	સ્થિતિ Z_OK:
		ssh->state->compression_out_started = 1;
		તોડો;
	સ્થિતિ Z_MEM_ERROR:
		પાછા SSH_ERR_ALLOC_FAIL;
	મૂળભૂત:
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
start_compression_in(સંરચના ssh *ssh)
{
	જો (ssh->state->compression_in_started == 1)
		inflateEnd(&ssh->state->compression_in_stream);
	પસંદગી (inflateInit(&ssh->state->compression_in_stream)) {
	સ્થિતિ Z_OK:
		ssh->state->compression_in_started = 1;
		તોડો;
	સ્થિતિ Z_MEM_ERROR:
		પાછા SSH_ERR_ALLOC_FAIL;
	મૂળભૂત:
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	પાછા 0;
}

/* XXX remove need for separate compression buffer */
સ્થિર પૂર્ણાંક
compress_buffer(સંરચના ssh *ssh, સંરચના sshbuf *in, સંરચના sshbuf *out)
{
	u_char buf[4096];
	પૂર્ણાંક r, status;

	જો (ssh->state->compression_out_started != 1)
		પાછા SSH_ERR_INTERNAL_ERROR;

	/* This case is not handled below. */
	જો (sshbuf_len(in) == 0)
		પાછા 0;

	/* Input is the contents of the input buffer. */
	જો ((ssh->state->compression_out_stream.next_in =
	    sshbuf_mutable_ptr(in)) == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_out_stream.avail_in = sshbuf_len(in);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	કરો {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_out_stream.next_out = buf;
		ssh->state->compression_out_stream.avail_out = કદ(buf);

		/* Compress as much data into the buffer as possible. */
		status = deflate(&ssh->state->compression_out_stream,
		    Z_PARTIAL_FLUSH);
		પસંદગી (status) {
		સ્થિતિ Z_MEM_ERROR:
			પાછા SSH_ERR_ALLOC_FAIL;
		સ્થિતિ Z_OK:
			/* Append compressed data to output_buffer. */
			જો ((r = sshbuf_put(out, buf, કદ(buf) -
			    ssh->state->compression_out_stream.avail_out)) != 0)
				પાછા r;
			તોડો;
		સ્થિતિ Z_STREAM_ERROR:
		મૂળભૂત:
			ssh->state->compression_out_failures++;
			પાછા SSH_ERR_INVALID_FORMAT;
		}
	} જ્યારે (ssh->state->compression_out_stream.avail_out == 0);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
uncompress_buffer(સંરચના ssh *ssh, સંરચના sshbuf *in, સંરચના sshbuf *out)
{
	u_char buf[4096];
	પૂર્ણાંક r, status;

	જો (ssh->state->compression_in_started != 1)
		પાછા SSH_ERR_INTERNAL_ERROR;

	જો ((ssh->state->compression_in_stream.next_in =
	    sshbuf_mutable_ptr(in)) == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_in_stream.avail_in = sshbuf_len(in);

	માટે (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_in_stream.next_out = buf;
		ssh->state->compression_in_stream.avail_out = કદ(buf);

		status = inflate(&ssh->state->compression_in_stream,
		    Z_SYNC_FLUSH);
		પસંદગી (status) {
		સ્થિતિ Z_OK:
			જો ((r = sshbuf_put(out, buf, કદ(buf) -
			    ssh->state->compression_in_stream.avail_out)) != 0)
				પાછા r;
			જો (sshbuf_len(out) >= PACKET_MAX_SIZE)
				પાછા SSH_ERR_INVALID_FORMAT;
			તોડો;
		સ્થિતિ Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			પાછા 0;
		સ્થિતિ Z_DATA_ERROR:
			પાછા SSH_ERR_INVALID_FORMAT;
		સ્થિતિ Z_MEM_ERROR:
			પાછા SSH_ERR_ALLOC_FAIL;
		સ્થિતિ Z_STREAM_ERROR:
		મૂળભૂત:
			ssh->state->compression_in_failures++;
			પાછા SSH_ERR_INTERNAL_ERROR;
		}
	}
	/* NOTREACHED */
}

#નહીંતર	/* WITH_ZLIB */

સ્થિર પૂર્ણાંક
start_compression_out(સંરચના ssh *ssh)
{
	પાછા SSH_ERR_INTERNAL_ERROR;
}

સ્થિર પૂર્ણાંક
start_compression_in(સંરચના ssh *ssh)
{
	પાછા SSH_ERR_INTERNAL_ERROR;
}

સ્થિર પૂર્ણાંક
compress_buffer(સંરચના ssh *ssh, સંરચના sshbuf *in, સંરચના sshbuf *out)
{
	પાછા SSH_ERR_INTERNAL_ERROR;
}

સ્થિર પૂર્ણાંક
uncompress_buffer(સંરચના ssh *ssh, સંરચના sshbuf *in, સંરચના sshbuf *out)
{
	પાછા SSH_ERR_INTERNAL_ERROR;
}
#endif	/* WITH_ZLIB */

શૂન્ય
ssh_clear_newkeys(સંરચના ssh *ssh, પૂર્ણાંક mode)
{
	જો (ssh->kex && ssh->kex->newkeys[mode]) {
		kex_free_newkeys(ssh->kex->newkeys[mode]);
		ssh->kex->newkeys[mode] = ખાલી;
	}
}

પૂર્ણાંક
ssh_set_newkeys(સંરચના ssh *ssh, પૂર્ણાંક mode)
{
	સંરચના session_state *state = ssh->state;
	સંરચના sshenc *enc;
	સંરચના sshmac *mac;
	સંરચના sshcomp *comp;
	સંરચના sshcipher_ctx **ccp;
	સંરચના packet_state *ps;
	uint64_t *max_blocks, *hard_max_blocks;
	અચલ અક્ષર *wmsg;
	પૂર્ણાંક r, crypt_type;
	અચલ અક્ષર *dir = mode == MODE_OUT ? "out" : "in";

	debug2_f("mode %d", mode);

	જો (mode == MODE_OUT) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_blocks = &state->hard_max_blocks_out;
		max_blocks = &state->max_blocks_out;
	} નહીંતર {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_blocks = &state->hard_max_blocks_in;
		max_blocks = &state->max_blocks_in;
	}
	જો (state->newkeys[mode] != ખાલી) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (unsigned long long)state->p_read.bytes,
		    (unsigned long long)state->p_read.blocks,
		    (unsigned long long)state->p_send.bytes,
		    (unsigned long long)state->p_send.blocks);
		kex_free_newkeys(state->newkeys[mode]);
		state->newkeys[mode] = ખાલી;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->blocks = 0;
	/* move newkeys from kex to state */
	જો ((state->newkeys[mode] = ssh->kex->newkeys[mode]) == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;
	ssh->kex->newkeys[mode] = ખાલી;
	enc  = &state->newkeys[mode]->enc;
	mac  = &state->newkeys[mode]->mac;
	comp = &state->newkeys[mode]->comp;
	જો (cipher_authlen(enc->cipher) == 0) {
		જો ((r = mac_init(mac)) != 0)
			પાછા r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = ખાલી;
	જો ((r = cipher_init(ccp, enc->cipher, enc->ચાવી, enc->ચાવી_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		પાછા r;
	જો (!state->cipher_warning_done &&
	    (wmsg = cipher_warning_message(*ccp)) != ખાલી) {
		error("Warning: %s", wmsg);
		state->cipher_warning_done = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	જો (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		જો ((r = ssh_packet_init_compression(ssh)) < 0)
			પાછા r;
		જો (mode == MODE_OUT) {
			જો ((r = start_compression_out(ssh)) != 0)
				પાછા r;
		} નહીંતર {
			જો ((r = start_compression_in(ssh)) != 0)
				પાછા r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	જો (enc->block_size >= 16)
		*hard_max_blocks = (uint64_t)1 << (enc->block_size*2);
	નહીંતર
		*hard_max_blocks = ((uint64_t)1 << 30) / enc->block_size;
	*max_blocks = *hard_max_blocks;
	જો (state->rekey_limit) {
		*max_blocks = MINIMUM(*max_blocks,
		    state->rekey_limit / enc->block_size);
	}
	debug("rekey %s after %llu blocks", dir,
	    (unsigned long long)*max_blocks);
	પાછા 0;
}

#define MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
સ્થિર અંતઃરેખ પૂર્ણાંક
ssh_packet_check_rekey_blocklimit(સંરચના ssh *ssh, u_int packet_len, પૂર્ણાંક hard)
{
	સંરચના session_state *state = ssh->state;
	uint32_t out_blocks;
	અચલ uint64_t max_blocks_in = hard ?
	    state->hard_max_blocks_in : state->max_blocks_in;
	અચલ uint64_t max_blocks_out = hard ?
	    state->hard_max_blocks_out : state->max_blocks_out;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	જો (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		પાછા 1;

	જો (state->newkeys[MODE_OUT] == ખાલી)
		પાછા 0;

	/* Rekey after (cipher-specific) maximum blocks */
	out_blocks = ROUNDUP(packet_len,
	    state->newkeys[MODE_OUT]->enc.block_size);
	પાછા (max_blocks_out &&
	    (state->p_send.blocks + out_blocks > max_blocks_out)) ||
	    (max_blocks_in &&
	    (state->p_read.blocks > max_blocks_in));
}

સ્થિર પૂર્ણાંક
ssh_packet_need_rekeying(સંરચના ssh *ssh, u_int outbound_packet_len)
{
	સંરચના session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	જો (!state->after_authentication)
		પાછા 0;

	/* Haven't keyed yet or KEX in progress. */
	જો (ssh_packet_is_rekeying(ssh))
		પાછા 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	જો (state->p_send.packets == 0 && state->p_read.packets == 0)
		પાછા 0;

	/* Time-based rekeying */
	જો (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_time + state->rekey_interval <= monotime())
		પાછા 1;

	પાછા ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
સ્થિર પૂર્ણાંક
ssh_packet_check_rekey_preauth(સંરચના ssh *ssh, u_int outgoing_packet_len)
{
	જો (ssh->state->after_authentication)
		પાછા 0;

	જો (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		પાછા SSH_ERR_NEED_REKEY;
	}
	પાછા 0;
}

પૂર્ણાંક
ssh_packet_check_rekey(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	જો ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		પાછા r;
	જો (!ssh_packet_need_rekeying(ssh, 0))
		પાછા 0;
	debug3_f("rekex triggered");
	પાછા kex_start_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
સ્થિર પૂર્ણાંક
ssh_packet_enable_delayed_compress(સંરચના ssh *ssh)
{
	સંરચના session_state *state = ssh->state;
	સંરચના sshcomp *comp = ખાલી;
	પૂર્ણાંક r, mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	માટે (mode = 0; mode < MODE_MAX; mode++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		જો (state->newkeys[mode] == ખાલી)
			ચાલુ;
		comp = &state->newkeys[mode]->comp;
		જો (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			જો ((r = ssh_packet_init_compression(ssh)) != 0)
				પાછા r;
			જો (mode == MODE_OUT) {
				જો ((r = start_compression_out(ssh)) != 0)
					પાછા r;
			} નહીંતર {
				જો ((r = start_compression_in(ssh)) != 0)
					પાછા r;
			}
			comp->enabled = 1;
		}
	}
	પાછા 0;
}

/* Used to mute debug logging for noisy packet types */
પૂર્ણાંક
ssh_packet_log_type(u_char type)
{
	પસંદગી (type) {
	સ્થિતિ SSH2_સંદેશ_PING:
	સ્થિતિ SSH2_સંદેશ_PONG:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_DATA:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_EXTENDED_DATA:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_WINDOW_ADJUST:
		પાછા 0;
	મૂળભૂત:
		પાછા 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
પૂર્ણાંક
ssh_packet_send2_wrapped(સંરચના ssh *ssh)
{
	સંરચના session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_LENGTH];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	સંરચના sshenc *enc   = ખાલી;
	સંરચના sshmac *mac   = ખાલી;
	સંરચના sshcomp *comp = ખાલી;
	પૂર્ણાંક r, block_size;

	જો (state->newkeys[MODE_OUT] != ખાલી) {
		enc  = &state->newkeys[MODE_OUT]->enc;
		mac  = &state->newkeys[MODE_OUT]->mac;
		comp = &state->newkeys[MODE_OUT]->comp;
		/* disable mac for authenticated encryption */
		જો ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ખાલી;
	}
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	જો (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#endif

	જો (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		જો ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			જાઓ out;
		sshbuf_reset(state->compression_buffer);
		જો ((r = compress_buffer(ssh, state->outgoing_packet,
		    state->compression_buffer)) != 0)
			જાઓ out;
		sshbuf_reset(state->outgoing_packet);
		જો ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_buffer)) != 0)
			જાઓ out;
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
	જો (padlen < 4)
		padlen += block_size;
	જો (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, block_size);
		/* check if roundup overflowed */
		જો (state->extra_pad < tmp)
			પાછા SSH_ERR_INVALID_ARGUMENT;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		જો (tmp > state->extra_pad)
			પાછા SSH_ERR_INVALID_ARGUMENT;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		જો (padlen < tmp)
			પાછા SSH_ERR_INVALID_ARGUMENT; /* overflow */
		state->extra_pad = 0;
	}
	જો ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		જાઓ out;
	જો (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} નહીંતર {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	જો (cp == ખાલી) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	જો (mac && mac->enabled && !mac->etm) {
		જો ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, કદ(macbuf))) != 0)
			જાઓ out;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	જો ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		જાઓ out;
	જો ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		જાઓ out;
	/* append unencrypted MAC */
	જો (mac && mac->enabled) {
		જો (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			જો ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, કદ(macbuf))) != 0)
				જાઓ out;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		જો ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			જાઓ out;
	}
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#endif
	/* increment sequence number for outgoing packets */
	જો (++state->p_send.seqnr == 0) {
		જો ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	જો (++state->p_send.packets == 0)
		પાછા SSH_ERR_NEED_REKEY;
	state->p_send.blocks += len / block_size;
	state->p_send.bytes += len;
	sshbuf_reset(state->outgoing_packet);

	જો (type == SSH2_સંદેશ_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	જો (type == SSH2_સંદેશ_NEWKEYS)
		r = ssh_set_newkeys(ssh, MODE_OUT);
	નહીંતર જો (type == SSH2_સંદેશ_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	નહીંતર
		r = 0;
 out:
	પાછા r;
}

/* returns non-zero if the specified packet type is usec by KEX */
સ્થિર પૂર્ણાંક
ssh_packet_type_is_kex(u_char type)
{
	પાછા
	    type >= SSH2_સંદેશ_TRANSPORT_MIN &&
	    type <= SSH2_સંદેશ_TRANSPORT_MAX &&
	    type != SSH2_સંદેશ_SERVICE_REQUEST &&
	    type != SSH2_સંદેશ_SERVICE_ACCEPT &&
	    type != SSH2_સંદેશ_EXT_INFO;
}

પૂર્ણાંક
ssh_packet_send2(સંરચના ssh *ssh)
{
	સંરચના session_state *state = ssh->state;
	સંરચના packet *p;
	u_char type;
	પૂર્ણાંક r, need_rekey;

	જો (sshbuf_len(state->outgoing_packet) < 6)
		પાછા SSH_ERR_INTERNAL_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	જો (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		પાછા r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	જો ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		જો (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = calloc(1, કદ(*p));
		જો (p == ખાલી)
			પાછા SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, next);
		state->outgoing_packet = sshbuf_new();
		જો (state->outgoing_packet == ખાલી)
			પાછા SSH_ERR_ALLOC_FAIL;
		જો (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			પાછા kex_start_rekex(ssh);
		}
		પાછા 0;
	}

	/* rekeying starts with sending KEXINIT */
	જો (type == SSH2_સંદેશ_KEXINIT)
		state->rekeying = 1;

	જો ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		પાછા r;

	/* after a NEWKEYS message we can send the complete queue */
	જો (type == SSH2_સંદેશ_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_time = monotime();
		જ્યારે ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			જો (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				પાછા kex_start_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, next);
			memset(p, 0, કદ(*p));
			મુક્ત(p);
			જો ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				પાછા r;
		}
	}
	પાછા 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

પૂર્ણાંક
ssh_packet_read_seqnr(સંરચના ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	સંરચના session_state *state = ssh->state;
	પૂર્ણાંક len, r, ms_remain = 0;
	સંરચના pollfd pfd;
	અક્ષર buf[8192];
	સંરચના timeval start;
	સંરચના timespec timespec, *timespecp = ખાલી;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	જો ((r = ssh_packet_write_wait(ssh)) != 0)
		જાઓ out;

	/* Stay in the loop until we have received a complete packet. */
	માટે (;;) {
		/* Try to read a packet from the buffer. */
		જો ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			તોડો;
		/* If we got a packet, return it. */
		જો (*typep != SSH_સંદેશ_NONE)
			તોડો;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_in;
		pfd.events = POLLIN;

		જો (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		માટે (;;) {
			જો (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			જો ((r = ppoll(&pfd, 1, timespecp, ખાલી)) >= 0)
				તોડો;
			જો (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				જાઓ out;
			}
			જો (state->packet_timeout_ms <= 0)
				ચાલુ;
			ms_subtract_diff(&start, &ms_remain);
			જો (ms_remain <= 0) {
				r = 0;
				તોડો;
			}
		}
		જો (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			જાઓ out;
		}
		/* Read data from the socket. */
		len = પઠ(state->connection_in, buf, કદ(buf));
		જો (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			જાઓ out;
		}
		જો (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			જાઓ out;
		}

		/* Append it to the buffer. */
		જો ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			જાઓ out;
	}
 out:
	પાછા r;
}

પૂર્ણાંક
ssh_packet_read(સંરચના ssh *ssh)
{
	u_char type;
	પૂર્ણાંક r;

	જો ((r = ssh_packet_read_seqnr(ssh, &type, ખાલી)) != 0)
		sshpkt_fatal(ssh, r, "read");
	પાછા type;
}

સ્થિર પૂર્ણાંક
ssh_packet_read_poll2_mux(સંરચના ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	સંરચના session_state *state = ssh->state;
	અચલ u_char *cp;
	size_t need;
	પૂર્ણાંક r;

	જો (ssh->kex)
		પાછા SSH_ERR_INTERNAL_ERROR;
	*typep = SSH_સંદેશ_NONE;
	cp = sshbuf_ptr(state->આગત);
	જો (state->packlen == 0) {
		જો (sshbuf_len(state->આગત) < 4 + 1)
			પાછા 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		જો (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_SIZE)
			પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	}
	need = state->packlen + 4;
	જો (sshbuf_len(state->આગત) < need)
		પાછા 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	જો ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->આગત, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, ખાલી)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		પાછા r;
	જો (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	પાછા r;
}

પૂર્ણાંક
ssh_packet_read_poll2(સંરચના ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	સંરચના session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, block_size;
	સંરચના sshenc *enc   = ખાલી;
	સંરચના sshmac *mac   = ખાલી;
	સંરચના sshcomp *comp = ખાલી;
	પૂર્ણાંક r;

	જો (state->mux)
		પાછા ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_સંદેશ_NONE;

	જો (state->packet_discard)
		પાછા 0;

	જો (state->newkeys[MODE_IN] != ખાલી) {
		enc  = &state->newkeys[MODE_IN]->enc;
		mac  = &state->newkeys[MODE_IN]->mac;
		comp = &state->newkeys[MODE_IN]->comp;
		/* disable mac for authenticated encryption */
		જો ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ખાલી;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_size = enc ? enc->block_size : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	જો (aadlen && state->packlen == 0) {
		જો (cipher_get_length(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->આગત), sshbuf_len(state->આગત)) != 0)
			પાછા 0;
		જો (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			sshbuf_dump(state->આગત, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			જો ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				પાછા r;
			પાછા SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} નહીંતર જો (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		જો (sshbuf_len(state->આગત) < block_size)
			પાછા 0;
		sshbuf_reset(state->incoming_packet);
		જો ((r = sshbuf_reserve(state->incoming_packet, block_size,
		    &cp)) != 0)
			જાઓ out;
		જો ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->આગત),
		    block_size, 0, 0)) != 0)
			જાઓ out;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		જો (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->આગત, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#endif
			logit("Bad packet length %u.", state->packlen);
			પાછા ssh_packet_start_discard(ssh, enc, mac, 0,
			    PACKET_MAX_SIZE);
		}
		જો ((r = sshbuf_consume(state->આગત, block_size)) != 0)
			જાઓ out;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	જો (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} નહીંતર {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - block_size;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", block_size, need, maclen, authlen, aadlen));
	જો (need % block_size != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
		પાછા ssh_packet_start_discard(ssh, enc, mac, 0,
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
	જો (sshbuf_len(state->આગત) < aadlen + need + authlen + maclen)
		પાછા 0; /* packet is incomplete */
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->આગત, stderr);
#endif
	/* EtM: check mac over encrypted input */
	જો (mac && mac->enabled && mac->etm) {
		જો ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->આગત), aadlen + need,
		    sshbuf_ptr(state->આગત) + aadlen + need + authlen,
		    maclen)) != 0) {
			જો (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			જાઓ out;
		}
	}
	જો ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		જાઓ out;
	જો ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->આગત), need, aadlen, authlen)) != 0)
		જાઓ out;
	જો ((r = sshbuf_consume(state->આગત, aadlen + need + authlen)) != 0)
		જાઓ out;
	જો (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		જો (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->આગત), maclen)) != 0) {
			જો (r != SSH_ERR_MAC_INVALID)
				જાઓ out;
			logit("Corrupted MAC on input.");
			જો (need + block_size > PACKET_MAX_SIZE)
				પાછા SSH_ERR_INTERNAL_ERROR;
			પાછા ssh_packet_start_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_SIZE - need - block_size);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		જો ((r = sshbuf_consume(state->આગત, mac->mac_len)) != 0)
			જાઓ out;
	}

	જો (seqnr_p != ખાલી)
		*seqnr_p = state->p_read.seqnr;
	જો (++state->p_read.seqnr == 0) {
		જો ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	જો (++state->p_read.packets == 0)
		પાછા SSH_ERR_NEED_REKEY;
	state->p_read.blocks += (state->packlen + 4) / block_size;
	state->p_read.bytes += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	જો (padlen < 4)	{
		જો ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			પાછા r;
		પાછા SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	જો ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_end(state->incoming_packet, padlen)) != 0))
		જાઓ out;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	જો (comp && comp->enabled) {
		sshbuf_reset(state->compression_buffer);
		જો ((r = uncompress_buffer(ssh, state->incoming_packet,
		    state->compression_buffer)) != 0)
			જાઓ out;
		sshbuf_reset(state->incoming_packet);
		જો ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_buffer)) != 0)
			જાઓ out;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	જો ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		જાઓ out;
	જો (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	જો (*typep < SSH2_સંદેશ_MIN) {
		જો ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			પાછા r;
		પાછા SSH_ERR_PROTOCOL_ERROR;
	}
	જો (state->hook_in != ખાલી &&
	    (r = state->hook_in(ssh, state->incoming_packet, typep,
	    state->hook_in_ctx)) != 0)
		પાછા r;
	જો (*typep == SSH2_સંદેશ_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	નહીંતર
		r = 0;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#endif
	/* reset for next packet */
	state->packlen = 0;
	જો (*typep == SSH2_સંદેશ_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	જો ((r = ssh_packet_check_rekey(ssh)) != 0)
		પાછા r;
 out:
	પાછા r;
}

પૂર્ણાંક
ssh_packet_read_poll_seqnr(સંરચના ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	સંરચના session_state *state = ssh->state;
	u_int reason, seqnr;
	પૂર્ણાંક r;
	u_char *સંદેશ;
	અચલ u_char *d;
	size_t len;

	માટે (;;) {
		સંદેશ = ખાલી;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		જો (r != 0)
			પાછા r;
		જો (*typep == 0) {
			/* no message ready */
			પાછા 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		જો (*typep == SSH2_સંદેશ_DISCONNECT) {
			જો ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &સંદેશ, ખાલી)) != 0)
				પાછા r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh), reason, સંદેશ);
			મુક્ત(સંદેશ);
			પાછા SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		જો (ssh->kex != ખાલી &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			પાછા 0;
		/* Implicitly handle transport-level messages */
		પસંદગી (*typep) {
		સ્થિતિ SSH2_સંદેશ_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			તોડો;
		સ્થિતિ SSH2_સંદેશ_DEBUG:
			જો ((r = sshpkt_get_u8(ssh, ખાલી)) != 0 ||
			    (r = sshpkt_get_string(ssh, &સંદેશ, ખાલી)) != 0 ||
			    (r = sshpkt_get_string(ssh, ખાલી, ખાલી)) != 0) {
				મુક્ત(સંદેશ);
				પાછા r;
			}
			debug("Remote: %.900s", સંદેશ);
			મુક્ત(સંદેશ);
			તોડો;
		સ્થિતિ SSH2_સંદેશ_UNIMPLEMENTED:
			જો ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				પાછા r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			તોડો;
		સ્થિતિ SSH2_સંદેશ_PING:
			જો ((r = sshpkt_get_string_direct(ssh, &d, &len)) != 0)
				પાછા r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			જો (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				તોડો;
			}
			જો (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				તોડો;
			}
			જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				પાછા r;
			તોડો;
		સ્થિતિ SSH2_સંદેશ_PONG:
			જો ((r = sshpkt_get_string_direct(ssh,
			    ખાલી, &len)) != 0)
				પાછા r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			તોડો;
		મૂળભૂત:
			જો (ssh->kex != ખાલી &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				પાછા SSH_ERR_PROTOCOL_ERROR;
			}
			પાછા 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
પૂર્ણાંક
ssh_packet_process_incoming(સંરચના ssh *ssh, અચલ અક્ષર *buf, u_int len)
{
	સંરચના session_state *state = ssh->state;
	પૂર્ણાંક r;

	જો (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		જો (len >= state->packet_discard) {
			જો ((r = ssh_packet_stop_discard(ssh)) != 0)
				પાછા r;
		}
		state->packet_discard -= len;
		પાછા 0;
	}
	જો ((r = sshbuf_put(state->આગત, buf, len)) != 0)
		પાછા r;

	પાછા 0;
}

/* Reads and buffers data from the specified fd */
પૂર્ણાંક
ssh_packet_process_read(સંરચના ssh *ssh, પૂર્ણાંક fd)
{
	સંરચના session_state *state = ssh->state;
	પૂર્ણાંક r;
	size_t rlen;

	જો ((r = sshbuf_read(fd, state->આગત, PACKET_MAX_SIZE, &rlen)) != 0)
		પાછા r;

	જો (state->packet_discard) {
		જો ((r = sshbuf_consume_end(state->આગત, rlen)) != 0)
			પાછા r;
		state->keep_alive_timeouts = 0; /* ?? */
		જો (rlen >= state->packet_discard) {
			જો ((r = ssh_packet_stop_discard(ssh)) != 0)
				પાછા r;
		}
		state->packet_discard -= rlen;
		પાછા 0;
	}
	પાછા 0;
}

પૂર્ણાંક
ssh_packet_remaining(સંરચના ssh *ssh)
{
	પાછા sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
શૂન્ય
ssh_packet_send_debug(સંરચના ssh *ssh, અચલ અક્ષર *fmt,...)
{
	અક્ષર buf[1024];
	va_list args;
	પૂર્ણાંક r;

	જો ((ssh->compat & SSH_BUG_DEBUG))
		પાછા;

	va_start(args, fmt);
	vsnprintf(buf, કદ(buf), fmt, args);
	va_end(args);

	debug3("sending debug message: %s", buf);

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

શૂન્ય
sshpkt_fmt_connection_id(સંરચના ssh *ssh, અક્ષર *s, size_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
સ્થિર શૂન્ય
sshpkt_vfatal(સંરચના ssh *ssh, પૂર્ણાંક r, અચલ અક્ષર *fmt, va_list ap)
{
	અક્ષર *tag = ખાલી, remote_id[512];
	પૂર્ણાંક oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, કદ(remote_id));

	પસંદગી (r) {
	સ્થિતિ SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_ચાવીઓ(ssh);
		logdie("Connection closed by %s", remote_id);
	સ્થિતિ SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_ચાવીઓ(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	સ્થિતિ SSH_ERR_DISCONNECTED:
		ssh_packet_clear_ચાવીઓ(ssh);
		logdie("Disconnected from %s", remote_id);
	સ્થિતિ SSH_ERR_SYSTEM_ERROR:
		જો (errno == ECONNRESET) {
			ssh_packet_clear_ચાવીઓ(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	સ્થિતિ SSH_ERR_NO_CIPHER_ALG_MATCH:
	સ્થિતિ SSH_ERR_NO_MAC_ALG_MATCH:
	સ્થિતિ SSH_ERR_NO_COMPRESS_ALG_MATCH:
	સ્થિતિ SSH_ERR_NO_KEX_ALG_MATCH:
	સ્થિતિ SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		જો (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_ચાવીઓ(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	મૂળભૂત:
		જો (vasprintf(&tag, fmt, ap) == -1) {
			ssh_packet_clear_ચાવીઓ(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_ચાવીઓ(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    tag != ખાલી ? tag : "", tag != ખાલી ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

શૂન્ય
sshpkt_fatal(સંરચના ssh *ssh, પૂર્ણાંક r, અચલ અક્ષર *fmt, ...)
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
શૂન્ય
ssh_packet_disconnect(સંરચના ssh *ssh, અચલ અક્ષર *fmt,...)
{
	અક્ષર buf[1024], remote_id[512];
	va_list args;
	પૂર્ણાંક r;

	/* Guard against recursive invocations. */
	જો (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, કદ(remote_id));
	va_start(args, fmt);
	vsnprintf(buf, કદ(buf), fmt, args);
	va_end(args);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	જો ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	જો ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
પૂર્ણાંક
ssh_packet_write_poll(સંરચના ssh *ssh)
{
	સંરચના session_state *state = ssh->state;
	પૂર્ણાંક len = sshbuf_len(state->output);
	પૂર્ણાંક r;

	જો (len > 0) {
		len = લિખ(state->connection_out,
		    sshbuf_ptr(state->output), len);
		જો (len == -1) {
			જો (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				પાછા 0;
			પાછા SSH_ERR_SYSTEM_ERROR;
		}
		જો (len == 0)
			પાછા SSH_ERR_CONN_CLOSED;
		જો ((r = sshbuf_consume(state->output, len)) != 0)
			પાછા r;
	}
	પાછા 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
પૂર્ણાંક
ssh_packet_write_wait(સંરચના ssh *ssh)
{
	પૂર્ણાંક ret, r, ms_remain = 0;
	સંરચના timeval start;
	સંરચના timespec timespec, *timespecp = ખાલી;
	સંરચના session_state *state = ssh->state;
	સંરચના pollfd pfd;

	જો ((r = ssh_packet_write_poll(ssh)) != 0)
		પાછા r;
	જ્યારે (ssh_packet_have_data_to_write(ssh)) {
		pfd.fd = state->connection_out;
		pfd.events = POLLOUT;

		જો (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		માટે (;;) {
			જો (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			જો ((ret = ppoll(&pfd, 1, timespecp, ખાલી)) >= 0)
				તોડો;
			જો (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				તોડો;
			જો (state->packet_timeout_ms <= 0)
				ચાલુ;
			ms_subtract_diff(&start, &ms_remain);
			જો (ms_remain <= 0) {
				ret = 0;
				તોડો;
			}
		}
		જો (ret == 0)
			પાછા SSH_ERR_CONN_TIMEOUT;
		જો ((r = ssh_packet_write_poll(ssh)) != 0)
			પાછા r;
	}
	પાછા 0;
}

/* Returns true if there is buffered data to write to the connection. */

પૂર્ણાંક
ssh_packet_have_data_to_write(સંરચના ssh *ssh)
{
	પાછા sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

પૂર્ણાંક
ssh_packet_not_very_much_data_to_write(સંરચના ssh *ssh)
{
	જો (ssh->state->interactive_mode)
		પાછા sshbuf_len(ssh->state->output) < 16384;
	નહીંતર
		પાછા sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

પૂર્ણાંક
ssh_packet_interactive_data_to_write(સંરચના ssh *ssh)
{
	પાછા ssh->state->interactive_mode &&
	    sshbuf_len(ssh->state->output) < 256;
}

સ્થિર શૂન્ય
apply_qos(સંરચના ssh *ssh)
{
	સંરચના session_state *state = ssh->state;
	પૂર્ણાંક qos = state->interactive_mode ?
	    state->qos_interactive : state->qos_other;

	જો (!ssh_packet_connection_is_on_socket(ssh))
		પાછા;
	જો (!state->nodelay_set) {
		set_nodelay(state->connection_in);
		state->nodelay_set = 1;
	}
	set_sock_tos(ssh->state->connection_in, qos);
}

/* Informs that the current session is interactive. */
શૂન્ય
ssh_packet_set_interactive(સંરચના ssh *ssh, પૂર્ણાંક interactive)
{
	સંરચના session_state *state = ssh->state;

	state->interactive_mode = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
શૂન્ય
ssh_packet_set_qos(સંરચના ssh *ssh, પૂર્ણાંક qos_interactive, પૂર્ણાંક qos_other)
{
	સંરચના session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

પૂર્ણાંક
ssh_packet_set_maxsize(સંરચના ssh *ssh, u_int s)
{
	સંરચના session_state *state = ssh->state;

	જો (state->set_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_size, s);
		પાછા -1;
	}
	જો (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		પાછા -1;
	}
	state->set_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_size = s;
	પાછા s;
}

પૂર્ણાંક
ssh_packet_inc_alive_timeouts(સંરચના ssh *ssh)
{
	પાછા ++ssh->state->keep_alive_timeouts;
}

શૂન્ય
ssh_packet_set_alive_timeouts(સંરચના ssh *ssh, પૂર્ણાંક ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(સંરચના ssh *ssh)
{
	પાછા ssh->state->max_packet_size;
}

શૂન્ય
ssh_packet_set_rekey_limits(સંરચના ssh *ssh, uint64_t bytes, uint32_t seconds)
{
	જો (bytes == 0 && seconds == 0)
		પાછા;

	debug3("rekey after %llu bytes, %u seconds", (unsigned long long)bytes,
	    (unsigned પૂર્ણાંક)seconds);
	ssh->state->rekey_limit = bytes;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(સંરચના ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_time + ssh->state->rekey_interval -
	    monotime();
	પાછા (seconds <= 0 ? 1 : seconds);
}

શૂન્ય
ssh_packet_set_server(સંરચના ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

શૂન્ય
ssh_packet_set_authenticated(સંરચના ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

શૂન્ય *
ssh_packet_get_આગત(સંરચના ssh *ssh)
{
	પાછા (શૂન્ય *)ssh->state->આગત;
}

શૂન્ય *
ssh_packet_get_output(સંરચના ssh *ssh)
{
	પાછા (શૂન્ય *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
સ્થિર પૂર્ણાંક
ssh_packet_set_postauth(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	જો ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		પાછા r;
	પાછા 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
સ્થિર પૂર્ણાંક
kex_to_blob(સંરચના sshbuf *m, સંરચના kex *kex)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
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
		પાછા r;
	પાછા 0;
}

/* turn key exchange results into a blob for packet state serialization */
સ્થિર પૂર્ણાંક
newkeys_to_blob(સંરચના sshbuf *m, સંરચના ssh *ssh, પૂર્ણાંક mode)
{
	સંરચના sshbuf *b;
	સંરચના sshcipher_ctx *cc;
	સંરચના sshcomp *comp;
	સંરચના sshenc *enc;
	સંરચના sshmac *mac;
	સંરચના newkeys *newkey;
	પૂર્ણાંક r;

	જો ((newkey = ssh->state->newkeys[mode]) == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (mode == MODE_OUT) ? ssh->state->send_context :
	    ssh->state->receive_context;
	જો ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		પાછા r;
	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->block_size)) != 0 ||
	    (r = sshbuf_put_string(b, enc->ચાવી, enc->ચાવી_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		જાઓ out;
	જો (cipher_authlen(enc->cipher) == 0) {
		જો ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->ચાવી, mac->ચાવી_len)) != 0)
			જાઓ out;
	}
	જો ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		જાઓ out;
	r = sshbuf_put_stringb(m, b);
 out:
	sshbuf_free(b);
	પાછા r;
}

/* serialize packet state into a blob */
પૂર્ણાંક
ssh_packet_get_state(સંરચના ssh *ssh, સંરચના sshbuf *m)
{
	સંરચના session_state *state = ssh->state;
	પૂર્ણાંક r;

#define ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	જો ((r = kex_to_blob(m, ssh->kex)) != 0 ||
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
	    (r = sshbuf_put_stringb(m, state->આગત)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_mode))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		પાછા r;
#undef ENCODE_INT
	પાછા 0;
}

/* restore key exchange results from blob for packet state de-serialization */
સ્થિર પૂર્ણાંક
newkeys_from_blob(સંરચના sshbuf *m, સંરચના ssh *ssh, પૂર્ણાંક mode)
{
	સંરચના sshbuf *b = ખાલી;
	સંરચના sshcomp *comp;
	સંરચના sshenc *enc;
	સંરચના sshmac *mac;
	સંરચના newkeys *newkey = ખાલી;
	size_t keylen, ivlen, maclen;
	પૂર્ણાંક r;

	જો ((newkey = calloc(1, કદ(*newkey))) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_froms(m, &b)) != 0)
		જાઓ out;
#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	જો ((r = sshbuf_get_cstring(b, &enc->name, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->block_size)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->ચાવી, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		જાઓ out;
	જો ((enc->cipher = cipher_by_name(enc->name)) == ખાલી ||
	    enc->block_size != cipher_blocksize(enc->cipher) ||
	    cipher_is_internal(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (cipher_authlen(enc->cipher) == 0) {
		જો ((r = sshbuf_get_cstring(b, &mac->name, ખાલી)) != 0)
			જાઓ out;
		જો ((r = mac_setup(mac, mac->name)) != 0)
			જાઓ out;
		જો ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->ચાવી, &maclen)) != 0)
			જાઓ out;
		જો (maclen != mac->ચાવી_len) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		mac->ચાવી_len = maclen;
	}
	જો ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, ખાલી)) != 0)
		જાઓ out;
	જો (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	enc->ચાવી_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[mode] = newkey;
	newkey = ખાલી;
	r = 0;
 out:
	મુક્ત(newkey);
	sshbuf_free(b);
	પાછા r;
}

/* restore kex from blob for packet state de-serialization */
સ્થિર પૂર્ણાંક
kex_from_blob(સંરચના sshbuf *m, સંરચના kex **kexp)
{
	સંરચના kex *kex;
	પૂર્ણાંક r;

	જો ((kex = kex_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, ખાલી)) != 0 ||
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
		જાઓ out;
	જો (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	kex->server = 1;
	kex->done = 1;
	r = 0;
 out:
	જો (r != 0 || kexp == ખાલી) {
		kex_free(kex);
		જો (kexp != ખાલી)
			*kexp = ખાલી;
	} નહીંતર {
		kex_free(*kexp);
		*kexp = kex;
	}
	પાછા r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
પૂર્ણાંક
ssh_packet_set_state(સંરચના ssh *ssh, સંરચના sshbuf *m)
{
	સંરચના session_state *state = ssh->state;
	અચલ u_char *આગત, *output;
	size_t ilen, olen;
	પૂર્ણાંક r;
	u_int interactive, qos_interactive, qos_other;

	જો ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
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
		પાછા r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_time = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	જો ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0 ||
	    (r = ssh_set_newkeys(ssh, MODE_OUT)) != 0)
		પાછા r;

	જો ((r = ssh_packet_set_postauth(ssh)) != 0)
		પાછા r;

	sshbuf_reset(state->આગત);
	sshbuf_reset(state->output);
	જો ((r = sshbuf_get_string_direct(m, &આગત, &ilen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->આગત, આગત, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		પાછા r;

	જો ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		પાછા r;
#define DECODE_INT(v) ((v) > INT_MAX ? -1 : (પૂર્ણાંક)(v))
	state->interactive_mode = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#undef DECODE_INT

	જો (sshbuf_len(m))
		પાછા SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	પાછા 0;
}

/* NEW API */

/* put data to the outgoing packet */

પૂર્ણાંક
sshpkt_put(સંરચના ssh *ssh, અચલ શૂન્ય *v, size_t len)
{
	પાછા sshbuf_put(ssh->state->outgoing_packet, v, len);
}

પૂર્ણાંક
sshpkt_putb(સંરચના ssh *ssh, અચલ સંરચના sshbuf *b)
{
	પાછા sshbuf_putb(ssh->state->outgoing_packet, b);
}

પૂર્ણાંક
sshpkt_put_u8(સંરચના ssh *ssh, u_char val)
{
	પાછા sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

પૂર્ણાંક
sshpkt_put_u32(સંરચના ssh *ssh, uint32_t val)
{
	પાછા sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

પૂર્ણાંક
sshpkt_put_u64(સંરચના ssh *ssh, uint64_t val)
{
	પાછા sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

પૂર્ણાંક
sshpkt_put_string(સંરચના ssh *ssh, અચલ શૂન્ય *v, size_t len)
{
	પાછા sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

પૂર્ણાંક
sshpkt_put_cstring(સંરચના ssh *ssh, અચલ શૂન્ય *v)
{
	પાછા sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

પૂર્ણાંક
sshpkt_put_stringb(સંરચના ssh *ssh, અચલ સંરચના sshbuf *v)
{
	પાછા sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#ifdef WITH_OPENSSL
પૂર્ણાંક
sshpkt_put_ec(સંરચના ssh *ssh, અચલ EC_POINT *v, અચલ EC_GROUP *g)
{
	પાછા sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

પૂર્ણાંક
sshpkt_put_ec_pkey(સંરચના ssh *ssh, EVP_PKEY *pkey)
{
	પાછા sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

પૂર્ણાંક
sshpkt_put_bignum2(સંરચના ssh *ssh, અચલ BIGNUM *v)
{
	પાછા sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#endif /* WITH_OPENSSL */

/* fetch data from the incoming packet */

પૂર્ણાંક
sshpkt_get(સંરચના ssh *ssh, શૂન્ય *valp, size_t len)
{
	પાછા sshbuf_get(ssh->state->incoming_packet, valp, len);
}

પૂર્ણાંક
sshpkt_get_u8(સંરચના ssh *ssh, u_char *valp)
{
	પાછા sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

પૂર્ણાંક
sshpkt_get_u32(સંરચના ssh *ssh, uint32_t *valp)
{
	પાછા sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

પૂર્ણાંક
sshpkt_get_u64(સંરચના ssh *ssh, uint64_t *valp)
{
	પાછા sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

પૂર્ણાંક
sshpkt_get_string(સંરચના ssh *ssh, u_char **valp, size_t *lenp)
{
	પાછા sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

પૂર્ણાંક
sshpkt_get_string_direct(સંરચના ssh *ssh, અચલ u_char **valp, size_t *lenp)
{
	પાછા sshbuf_get_string_direct(ssh->state->incoming_packet, valp, lenp);
}

પૂર્ણાંક
sshpkt_peek_string_direct(સંરચના ssh *ssh, અચલ u_char **valp, size_t *lenp)
{
	પાછા sshbuf_peek_string_direct(ssh->state->incoming_packet, valp, lenp);
}

પૂર્ણાંક
sshpkt_get_cstring(સંરચના ssh *ssh, અક્ષર **valp, size_t *lenp)
{
	પાછા sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

પૂર્ણાંક
sshpkt_getb_froms(સંરચના ssh *ssh, સંરચના sshbuf **valp)
{
	પાછા sshbuf_froms(ssh->state->incoming_packet, valp);
}

#ifdef WITH_OPENSSL
પૂર્ણાંક
sshpkt_get_ec(સંરચના ssh *ssh, EC_POINT *v, અચલ EC_GROUP *g)
{
	પાછા sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

પૂર્ણાંક
sshpkt_get_bignum2(સંરચના ssh *ssh, BIGNUM **valp)
{
	પાછા sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#endif /* WITH_OPENSSL */

પૂર્ણાંક
sshpkt_get_end(સંરચના ssh *ssh)
{
	જો (sshbuf_len(ssh->state->incoming_packet) > 0)
		પાછા SSH_ERR_UNEXPECTED_TRAILING_DATA;
	પાછા 0;
}

અચલ u_char *
sshpkt_ptr(સંરચના ssh *ssh, size_t *lenp)
{
	જો (lenp != ખાલી)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	પાછા sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

પૂર્ણાંક
sshpkt_start(સંરચના ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, કદ(buf));
	buf[કદ(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	પાછા sshbuf_put(ssh->state->outgoing_packet, buf, કદ(buf));
}

સ્થિર પૂર્ણાંક
ssh_packet_send_mux(સંરચના ssh *ssh)
{
	સંરચના session_state *state = ssh->state;
	u_char type, *cp;
	size_t len;
	પૂર્ણાંક r;

	જો (ssh->kex)
		પાછા SSH_ERR_INTERNAL_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	જો (len < 6)
		પાછા SSH_ERR_INTERNAL_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	જો (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	જો (type >= SSH2_સંદેશ_CONNECTION_MIN &&
	    type <= SSH2_સંદેશ_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		જો ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			પાછા r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	પાછા 0;
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
પૂર્ણાંક
sshpkt_સંદેશ_ignore(સંરચના ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	પૂર્ણાંક r;
	u_int i;

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		પાછા r;
	માટે (i = 0; i < nbytes; i++) {
		જો (i % 4 == 0)
			rnd = arc4random();
		જો ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			પાછા r;
		rnd >>= 8;
	}
	પાછા 0;
}

/* send it */

પૂર્ણાંક
sshpkt_send(સંરચના ssh *ssh)
{
	જો (ssh->state && ssh->state->mux)
		પાછા ssh_packet_send_mux(ssh);
	પાછા ssh_packet_send2(ssh);
}

પૂર્ણાંક
sshpkt_disconnect(સંરચના ssh *ssh, અચલ અક્ષર *fmt,...)
{
	અક્ષર buf[1024];
	va_list args;
	પૂર્ણાંક r;

	va_start(args, fmt);
	vsnprintf(buf, કદ(buf), fmt, args);
	va_end(args);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		પાછા r;
	પાછા 0;
}

/* roundup current message to pad bytes */
પૂર્ણાંક
sshpkt_add_padding(સંરચના ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	પાછા 0;
}

સ્થિર અક્ષર *
format_traffic_stats(સંરચના packet_state *ps)
{
	અક્ષર *stats = ખાલી, bytes[FMT_SCALED_STRSIZE];

	જો (ps->bytes > LLONG_MAX || fmt_scaled(ps->bytes, bytes) != 0)
		strlcpy(bytes, "OVERFLOW", કદ(bytes));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (unsigned long)ps->packets, (unsigned long long)ps->blocks, bytes);
	પાછા stats;
}

સ્થિર અક્ષર *
dedupe_alg_names(અચલ અક્ષર *in, અચલ અક્ષર *out)
{
	અક્ષર *names = ખાલી;

	જો (in == ખાલી)
		in = "<implicit>";
	જો (out == ખાલી)
		out = "<implicit>";

	જો (strcmp(in, out) == 0) {
		names = xstrdup(in);
	} નહીંતર {
		xasprintf(&names, "%s in, %s out", in, out);
	}
	પાછા names;
}

સ્થિર અક્ષર *
comp_status_message(સંરચના ssh *ssh)
{
#ifdef WITH_ZLIB
	અક્ષર *ret = ખાલી;
	સંરચના session_state *state = ssh->state;
	unsigned long long iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	અક્ષર iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	અક્ષર icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	જો (state->compression_buffer) {
		જો (state->compression_in_started) {
			iraw = state->compression_in_stream.total_out;
			icmp = state->compression_in_stream.total_in;
			જો (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", કદ(iraw_f));
			જો (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", કદ(icmp_f));
		}
		જો (state->compression_out_started) {
			oraw = state->compression_out_stream.total_in;
			ocmp = state->compression_out_stream.total_out;
			જો (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", કદ(oraw_f));
			જો (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", કદ(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (દ્વિગુણ)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (દ્વિગુણ)ocmp / oraw);
		પાછા ret;
	}
#endif	/* WITH_ZLIB */
	પાછા xstrdup("");
}

અક્ષર *
connection_info_message(સંરચના ssh *ssh)
{
	અક્ષર *ret = ખાલી, *cipher = ખાલી, *mac = ખાલી, *comp = ખાલી;
	અક્ષર *rekey_volume = ખાલી, *rekey_time = ખાલી, *comp_info = ખાલી;
	અક્ષર thishost[NI_MAXHOST] = "unknown", *tcp_info = ખાલી;
	સંરચના kex *kex;
	સંરચના session_state *state;
	સંરચના newkeys *nk_in, *nk_out;
	અક્ષર *stats_in = ખાલી, *stats_out = ખાલી;
	uint64_t epoch = (uint64_t)time(ખાલી) - monotime();

	જો (ssh == ખાલી)
		પાછા ખાલી;
	state = ssh->state;
	kex = ssh->kex;

	(શૂન્ય)gethostname(thishost, કદ(thishost));

	જો (ssh_local_port(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	} નહીંતર {
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
	જો (state->rekey_limit == 0) {
		xasprintf(&rekey_volume, "limit none");
	} નહીંતર {
		અક્ષર *volumes = ખાલી, in[32], out[32];

		snprintf(in, કદ(in), "%llu",
		   (unsigned long long)state->max_blocks_in);
		snprintf(out, કદ(out), "%llu",
		   (unsigned long long)state->max_blocks_out);
		volumes = dedupe_alg_names(in, out);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		મુક્ત(volumes);
	}

	/* Time based rekeying. */
	જો (state->rekey_interval == 0) {
		rekey_time = xstrdup("interval none");
	} નહીંતર {
		અક્ષર rekey_next[64];

		format_absolute_time(epoch + state->rekey_time +
		    state->rekey_interval, rekey_next, કદ(rekey_next));
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
	મુક્ત(tcp_info);
	મુક્ત(cipher);
	મુક્ત(mac);
	મુક્ત(comp);
	મુક્ત(stats_in);
	મુક્ત(stats_out);
	મુક્ત(rekey_volume);
	મુક્ત(rekey_time);
	મુક્ત(comp_info);
	પાછા ret;
}

