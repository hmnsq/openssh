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
#اگر_تعریف_شده WITH_OPENSSL
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/ec.h>
#پایان_اگر

#اگر_تعریف_شده WITH_ZLIB
#ضمن <zlib.h>
#پایان_اگر

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

#اگر_تعریف_شده PACKET_DEBUG
#تعریف_کن DBG(x) x
#وإلا
#تعریف_کن DBG(x)
#پایان_اگر

#تعریف_کن PACKET_MAX_اندازه (256 * 1024)

بنية packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t بلوکها;
	uint64_t بایتها;
};

بنية packet {
	TAILQ_ENTRY(packet) بعدی;
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
	صحيح connection_درون;
	صحيح connection_بیرون;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	بنية sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	بنية sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	بنية sshbuf *درون_داد;

	/* Buffer for raw output data going to the socket. */
	بنية sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	بنية sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	بنية sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	بنية sshbuf *compression_میانگیر;

#اگر_تعریف_شده WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_جریان compression_درون_جریان;
	z_جریان compression_بیرون_جریان;
#پایان_اگر
	صحيح compression_درون_started;
	صحيح compression_بیرون_started;
	صحيح compression_درون_failures;
	صحيح compression_بیرون_failures;

	/* default maximum packet size */
	u_int max_packet_اندازه;

	/* Flag indicating whether this module has been initialized. */
	صحيح initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t شروع_زمان;

	/* Set to true if the connection is interactive. */
	صحيح interactive_نما;

	/* Set to true if we are the server side. */
	صحيح server_side;

	/* Set to true if we are authenticated. */
	صحيح after_authentication;

	صحيح keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	صحيح packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	بنية newkeys *newkeys[نما_MAX];
	بنية packet_state p_read, p_send;

	/* Volume-based rekeying */
	uint64_t hard_max_بلوکها_درون, hard_max_بلوکها_بیرون;
	uint64_t max_بلوکها_درون, max_بلوکها_بیرون, rekey_حد;

	/* Time-based rekeying */
	uint32_t rekey_interval;	/* how often in seconds */
	time_t rekey_زمان;	/* time of last rekeying */

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	اندازه_t packet_discard_mac_already;
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
	صحيح مجموعه_maxsize_called;

	/* One-off warning about weak ciphers */
	صحيح cipher_warning_انجامشده;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	صحيح disconnecting;

	/* Nagle disabled on socket */
	صحيح nodelay_مجموعه;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_درون;
	فراغ *hook_درون_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

بنية ssh *
ssh_alloc_session_state(فراغ)
{
	بنية ssh *ssh = عدم;
	بنية session_state *state = عدم;

	إذا ((ssh = حافظه_صفر_بده(1, حجم(*ssh))) == عدم ||
	    (state = حافظه_صفر_بده(1, حجم(*state))) == عدم ||
	    (ssh->kex = kex_new()) == عدم ||
	    (state->درون_داد = sshbuf_new()) == عدم ||
	    (state->output = sshbuf_new()) == عدم ||
	    (state->outgoing_packet = sshbuf_new()) == عدم ||
	    (state->incoming_packet = sshbuf_new()) == عدم)
		اذهب fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->خصوصی_کلیدها);
	TAILQ_INIT(&ssh->عمومی_کلیدها);
	state->connection_درون = -1;
	state->connection_بیرون = -1;
	state->max_packet_اندازه = 32768;
	state->packet_timeout_ms = -1;
	state->interactive_نما = 1;
	state->qos_interactive = state->qos_other = -1;
	state->p_send.packets = state->p_read.packets = 0;
	state->initialized = 1;
	/*
	 * ssh_packet_send2() needs to queue packets until
	 * we've done the initial key exchange.
	 */
	state->rekeying = 1;
	ssh->state = state;
	أرجع ssh;
 fail:
	إذا (ssh) {
		kex_free(ssh->kex);
		حرر(ssh);
	}
	إذا (state) {
		sshbuf_free(state->درون_داد);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		حرر(state);
	}
	أرجع عدم;
}

فراغ
ssh_packet_مجموعه_درون_داد_hook(بنية ssh *ssh, ssh_packet_hook_fn *hook, فراغ *ctx)
{
	ssh->state->hook_درون = hook;
	ssh->state->hook_درون_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
صحيح
ssh_packet_is_rekeying(بنية ssh *ssh)
{
	أرجع ssh->state->rekeying ||
	    (ssh->kex != عدم && ssh->kex->انجامشده == 0);
}

/*
 * Sets the descriptors used for communication.
 */
بنية ssh *
ssh_packet_مجموعه_connection(بنية ssh *ssh, صحيح fd_درون, صحيح fd_بیرون)
{
	بنية session_state *state;
	ثابت بنية sshcipher *none = cipher_by_name("none");
	صحيح r, wasnull = ssh == عدم;

	إذا (none == عدم) {
		error_f("cannot load cipher 'none'");
		أرجع عدم;
	}
	إذا (ssh == عدم)
		ssh = ssh_alloc_session_state();
	إذا (ssh == عدم) {
		error_f("could not allocate state");
		أرجع عدم;
	}
	state = ssh->state;
	state->شروع_زمان = monotime();
	state->connection_درون = fd_درون;
	state->connection_بیرون = fd_بیرون;
	إذا ((r = cipher_init(&state->send_context, none,
	    (ثابت u_char *)"", 0, عدم, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (ثابت u_char *)"", 0, عدم, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		إذا (wasnull)
			حرر(ssh); /* XXX need ssh_free_session_state? */
		أرجع عدم;
	}
	state->newkeys[نما_درون] = state->newkeys[نما_بیرون] = عدم;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(فراغ)ssh_remote_ipaddr(ssh);
	أرجع ssh;
}

فراغ
ssh_packet_مجموعه_timeout(بنية ssh *ssh, صحيح timeout, صحيح شمار)
{
	بنية session_state *state = ssh->state;

	إذا (timeout <= 0 || شمار <= 0) {
		state->packet_timeout_ms = -1;
		أرجع;
	}
	إذا ((بیشترین_صحیح / 1000) / شمار < timeout)
		state->packet_timeout_ms = بیشترین_صحیح;
	وإلا
		state->packet_timeout_ms = timeout * شمار * 1000;
}

فراغ
ssh_packet_مجموعه_mux(بنية ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = عدم;
}

صحيح
ssh_packet_get_mux(بنية ssh *ssh)
{
	أرجع ssh->state->mux;
}

صحيح
ssh_packet_مجموعه_log_preamble(بنية ssh *ssh, ثابت حرف *fmt, ...)
{
	va_list آرگومانها;
	صحيح r;

	حرر(ssh->log_preamble);
	إذا (fmt == عدم)
		ssh->log_preamble = عدم;
	وإلا {
		va_start(آرگومانها, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, آرگومانها);
		va_end(آرگومانها);
		إذا (r < 0 || ssh->log_preamble == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
	}
	أرجع 0;
}

صحيح
ssh_packet_stop_discard(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	صحيح r;

	إذا (state->packet_discard_mac) {
		حرف buf[1024];
		اندازه_t dlen = PACKET_MAX_اندازه;

		إذا (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', حجم(buf));
		طالما (sshbuf_len(state->incoming_packet) < dlen)
			إذا ((r = sshbuf_put(state->incoming_packet, buf,
			    حجم(buf))) != 0)
				أرجع r;
		(فراغ) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    عدم, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh));
	أرجع SSH_ERR_MAC_INVALID;
}

ساكن صحيح
ssh_packet_شروع_discard(بنية ssh *ssh, بنية sshenc *enc,
    بنية sshmac *mac, اندازه_t mac_already, u_int discard)
{
	بنية session_state *state = ssh->state;
	صحيح r;

	إذا (enc == عدم || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		إذا ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			أرجع r;
		أرجع SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	إذا (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	إذا (sshbuf_len(state->درون_داد) >= discard)
		أرجع ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->درون_داد);
	أرجع 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

صحيح
ssh_packet_connection_is_on_socket(بنية ssh *ssh)
{
	بنية session_state *state;
	بنية sockaddr_storage from, مقصد;
	socklen_t fromlen, tolen;

	إذا (ssh == عدم || ssh->state == عدم)
		أرجع 0;

	state = ssh->state;
	إذا (state->connection_درون == -1 || state->connection_بیرون == -1)
		أرجع 0;
	fromlen = حجم(from);
	memset(&from, 0, حجم(from));
	إذا (getpeername(state->connection_درون, (بنية sockaddr *)&from,
	    &fromlen) == -1)
		أرجع 0;
	إذا (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		أرجع 0;
	/* filedescriptors in and out are the same, so it's a socket */
	إذا (state->connection_درون == state->connection_بیرون)
		أرجع 1;
	tolen = حجم(مقصد);
	memset(&مقصد, 0, حجم(مقصد));
	إذا (getpeername(state->connection_بیرون, (بنية sockaddr *)&مقصد,
	    &tolen) == -1)
		أرجع 0;
	إذا (fromlen != tolen || memcmp(&from, &مقصد, fromlen) != 0)
		أرجع 0;
	أرجع 1;
}

فراغ
ssh_packet_get_بایتها(بنية ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	إذا (ibytes)
		*ibytes = ssh->state->p_read.بایتها;
	إذا (obytes)
		*obytes = ssh->state->p_send.بایتها;
}

صحيح
ssh_packet_connection_af(بنية ssh *ssh)
{
	أرجع get_sock_af(ssh->state->connection_بیرون);
}

/* Sets the connection into non-blocking mode. */

فراغ
ssh_packet_مجموعه_nonblocking(بنية ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	مجموعه_nonblock(ssh->state->connection_درون);

	إذا (ssh->state->connection_بیرون != ssh->state->connection_درون)
		مجموعه_nonblock(ssh->state->connection_بیرون);
}

/* Returns the socket used for reading. */

صحيح
ssh_packet_get_connection_درون(بنية ssh *ssh)
{
	أرجع ssh->state->connection_درون;
}

/* Returns the descriptor used for writing. */

صحيح
ssh_packet_get_connection_بیرون(بنية ssh *ssh)
{
	أرجع ssh->state->connection_بیرون;
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
	إذا (ssh->remote_ipaddr == عدم) {
		إذا (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_درون;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_پورت = get_peer_پورت(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_پورت = get_local_پورت(sock);
		} وإلا {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_پورت = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_پورت = 65535;
		}
	}
	أرجع ssh->remote_ipaddr;
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
	إذا (getpeername(ssh_packet_get_connection_درون(ssh),
	    (بنية sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		أرجع xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	إذا (from.ss_family == AF_INET6)
		fromlen = حجم(بنية sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	إذا (getnameinfo((بنية sockaddr *)&from, fromlen, name, حجم(name),
	    عدم, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		أرجع xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, حجم(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	إذا (getaddrinfo(name, عدم, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		أرجع xstrdup(ntop);
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
	إذا (getaddrinfo(name, عدم, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		أرجع xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	لكل (ai = aitop; ai; ai = ai->ai_next) {
		إذا (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    حجم(ntop2), عدم, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				اكسر;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	إذا (ai == عدم) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		أرجع xstrdup(ntop);
	}
	أرجع xstrdup(name);
}

/* Returns the port number of the remote host. */

صحيح
ssh_remote_پورت(بنية ssh *ssh)
{
	(فراغ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	أرجع ssh->remote_پورت;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

ثابت حرف *
ssh_local_ipaddr(بنية ssh *ssh)
{
	(فراغ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	أرجع ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

صحيح
ssh_local_پورت(بنية ssh *ssh)
{
	(فراغ)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	أرجع ssh->local_پورت;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
ثابت حرف *
ssh_packet_rdomain_درون(بنية ssh *ssh)
{
	إذا (ssh->rdomain_درون != عدم)
		أرجع ssh->rdomain_درون;
	إذا (!ssh_packet_connection_is_on_socket(ssh))
		أرجع عدم;
	ssh->rdomain_درون = get_rdomain(ssh->state->connection_درون);
	أرجع ssh->rdomain_درون;
}

/* Closes the connection and clears and frees internal data structures. */

ساكن فراغ
ssh_packet_close_داخلی(بنية ssh *ssh, صحيح do_close)
{
	بنية session_state *state = ssh->state;
	u_int نما;
	بنية packet *p;

	إذا (!state->initialized)
		أرجع;
	state->initialized = 0;
	إذا (do_close) {
		إذا (state->connection_درون == state->connection_بیرون) {
			close(state->connection_بیرون);
		} وإلا {
			close(state->connection_درون);
			close(state->connection_بیرون);
		}
	}
	sshbuf_free(state->درون_داد);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	طالما ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, بعدی);
		حرر(p);
	}
	لكل (نما = 0; نما < نما_MAX; نما++) {
		kex_free_newkeys(state->newkeys[نما]);	/* current keys */
		state->newkeys[نما] = عدم;
		ssh_clear_newkeys(ssh, نما);		/* next keys */
	}
#اگر_تعریف_شده WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	إذا (do_close && state->compression_میانگیر) {
		sshbuf_free(state->compression_میانگیر);
		إذا (state->compression_بیرون_started) {
			z_streamp جریان = &state->compression_بیرون_جریان;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(بیعلامت دراز دراز)جریان->مجموع_درون,
				(بیعلامت دراز دراز)جریان->مجموع_بیرون,
				جریان->مجموع_درون == 0 ? 0.0 :
				(مزدوج) جریان->مجموع_بیرون / جریان->مجموع_درون);
			إذا (state->compression_بیرون_failures == 0)
				deflate_انتها(جریان);
		}
		إذا (state->compression_درون_started) {
			z_streamp جریان = &state->compression_درون_جریان;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (بیعلامت دراز دراز)جریان->مجموع_بیرون,
			    (بیعلامت دراز دراز)جریان->مجموع_درون,
			    جریان->مجموع_بیرون == 0 ? 0.0 :
			    (مزدوج) جریان->مجموع_درون / جریان->مجموع_بیرون);
			إذا (state->compression_درون_failures == 0)
				inflate_انتها(جریان);
		}
	}
#پایان_اگر	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = عدم;
	إذا (do_close) {
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
	ssh_packet_close_داخلی(ssh, 1);
	freezero(ssh, حجم(*ssh));
}

فراغ
ssh_packet_close(بنية ssh *ssh)
{
	ssh_packet_close_داخلی(ssh, 1);
}

فراغ
ssh_packet_clear_کلیدها(بنية ssh *ssh)
{
	ssh_packet_close_داخلی(ssh, 0);
}

/* Sets remote side protocol flags. */

فراغ
ssh_packet_مجموعه_protocol_flags(بنية ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(بنية ssh *ssh)
{
	أرجع ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

ساكن صحيح
ssh_packet_init_compression(بنية ssh *ssh)
{
	إذا (!ssh->state->compression_میانگیر &&
	    ((ssh->state->compression_میانگیر = sshbuf_new()) == عدم))
		أرجع SSH_ERR_ALLOC_FAIL;
	أرجع 0;
}

#اگر_تعریف_شده WITH_ZLIB
ساكن صحيح
شروع_compression_بیرون(بنية ssh *ssh)
{
	debug("Enabling compression.");
	إذا (ssh->state->compression_بیرون_started == 1)
		deflate_انتها(&ssh->state->compression_بیرون_جریان);
	بدل (deflateInit2(&ssh->state->compression_بیرون_جریان,
	    Z_بهترین_سرعت, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	حالة Z_OK:
		ssh->state->compression_بیرون_started = 1;
		اكسر;
	حالة Z_MEM_ERROR:
		أرجع SSH_ERR_ALLOC_FAIL;
	افتراضي:
		أرجع SSH_ERR_داخلی_ERROR;
	}
	أرجع 0;
}

ساكن صحيح
شروع_compression_درون(بنية ssh *ssh)
{
	إذا (ssh->state->compression_درون_started == 1)
		inflate_انتها(&ssh->state->compression_درون_جریان);
	بدل (inflateInit(&ssh->state->compression_درون_جریان)) {
	حالة Z_OK:
		ssh->state->compression_درون_started = 1;
		اكسر;
	حالة Z_MEM_ERROR:
		أرجع SSH_ERR_ALLOC_FAIL;
	افتراضي:
		أرجع SSH_ERR_داخلی_ERROR;
	}
	أرجع 0;
}

/* XXX remove need for separate compression buffer */
ساكن صحيح
compress_میانگیر(بنية ssh *ssh, بنية sshbuf *درون, بنية sshbuf *بیرون)
{
	u_char buf[4096];
	صحيح r, وضعیت;

	إذا (ssh->state->compression_بیرون_started != 1)
		أرجع SSH_ERR_داخلی_ERROR;

	/* This case is not handled below. */
	إذا (sshbuf_len(درون) == 0)
		أرجع 0;

	/* Input is the contents of the input buffer. */
	إذا ((ssh->state->compression_بیرون_جریان.بعدی_درون =
	    sshbuf_mutable_ptr(درون)) == عدم)
		أرجع SSH_ERR_داخلی_ERROR;
	ssh->state->compression_بیرون_جریان.avail_درون = sshbuf_len(درون);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	افعل {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_بیرون_جریان.بعدی_بیرون = buf;
		ssh->state->compression_بیرون_جریان.avail_بیرون = حجم(buf);

		/* Compress as much data into the buffer as possible. */
		وضعیت = deflate(&ssh->state->compression_بیرون_جریان,
		    Z_PARTIAL_FLUSH);
		بدل (وضعیت) {
		حالة Z_MEM_ERROR:
			أرجع SSH_ERR_ALLOC_FAIL;
		حالة Z_OK:
			/* Append compressed data to output_buffer. */
			إذا ((r = sshbuf_put(بیرون, buf, حجم(buf) -
			    ssh->state->compression_بیرون_جریان.avail_بیرون)) != 0)
				أرجع r;
			اكسر;
		حالة Z_جریان_ERROR:
		افتراضي:
			ssh->state->compression_بیرون_failures++;
			أرجع SSH_ERR_INVALID_FORMAT;
		}
	} طالما (ssh->state->compression_بیرون_جریان.avail_بیرون == 0);
	أرجع 0;
}

ساكن صحيح
uncompress_میانگیر(بنية ssh *ssh, بنية sshbuf *درون, بنية sshbuf *بیرون)
{
	u_char buf[4096];
	صحيح r, وضعیت;

	إذا (ssh->state->compression_درون_started != 1)
		أرجع SSH_ERR_داخلی_ERROR;

	إذا ((ssh->state->compression_درون_جریان.بعدی_درون =
	    sshbuf_mutable_ptr(درون)) == عدم)
		أرجع SSH_ERR_داخلی_ERROR;
	ssh->state->compression_درون_جریان.avail_درون = sshbuf_len(درون);

	لكل (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_درون_جریان.بعدی_بیرون = buf;
		ssh->state->compression_درون_جریان.avail_بیرون = حجم(buf);

		وضعیت = inflate(&ssh->state->compression_درون_جریان,
		    Z_SYNC_FLUSH);
		بدل (وضعیت) {
		حالة Z_OK:
			إذا ((r = sshbuf_put(بیرون, buf, حجم(buf) -
			    ssh->state->compression_درون_جریان.avail_بیرون)) != 0)
				أرجع r;
			إذا (sshbuf_len(بیرون) >= PACKET_MAX_اندازه)
				أرجع SSH_ERR_INVALID_FORMAT;
			اكسر;
		حالة Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			أرجع 0;
		حالة Z_داده_ERROR:
			أرجع SSH_ERR_INVALID_FORMAT;
		حالة Z_MEM_ERROR:
			أرجع SSH_ERR_ALLOC_FAIL;
		حالة Z_جریان_ERROR:
		افتراضي:
			ssh->state->compression_درون_failures++;
			أرجع SSH_ERR_داخلی_ERROR;
		}
	}
	/* NOTREACHED */
}

#وإلا	/* WITH_ZLIB */

ساكن صحيح
شروع_compression_بیرون(بنية ssh *ssh)
{
	أرجع SSH_ERR_داخلی_ERROR;
}

ساكن صحيح
شروع_compression_درون(بنية ssh *ssh)
{
	أرجع SSH_ERR_داخلی_ERROR;
}

ساكن صحيح
compress_میانگیر(بنية ssh *ssh, بنية sshbuf *درون, بنية sshbuf *بیرون)
{
	أرجع SSH_ERR_داخلی_ERROR;
}

ساكن صحيح
uncompress_میانگیر(بنية ssh *ssh, بنية sshbuf *درون, بنية sshbuf *بیرون)
{
	أرجع SSH_ERR_داخلی_ERROR;
}
#پایان_اگر	/* WITH_ZLIB */

فراغ
ssh_clear_newkeys(بنية ssh *ssh, صحيح نما)
{
	إذا (ssh->kex && ssh->kex->newkeys[نما]) {
		kex_free_newkeys(ssh->kex->newkeys[نما]);
		ssh->kex->newkeys[نما] = عدم;
	}
}

صحيح
ssh_مجموعه_newkeys(بنية ssh *ssh, صحيح نما)
{
	بنية session_state *state = ssh->state;
	بنية sshenc *enc;
	بنية sshmac *mac;
	بنية sshcomp *comp;
	بنية sshcipher_ctx **ccp;
	بنية packet_state *ps;
	uint64_t *max_بلوکها, *hard_max_بلوکها;
	ثابت حرف *wmsg;
	صحيح r, crypt_type;
	ثابت حرف *dir = نما == نما_بیرون ? "out" : "in";

	debug2_f("mode %d", نما);

	إذا (نما == نما_بیرون) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_بلوکها = &state->hard_max_بلوکها_بیرون;
		max_بلوکها = &state->max_بلوکها_بیرون;
	} وإلا {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_بلوکها = &state->hard_max_بلوکها_درون;
		max_بلوکها = &state->max_بلوکها_درون;
	}
	إذا (state->newkeys[نما] != عدم) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (بیعلامت دراز دراز)state->p_read.بایتها,
		    (بیعلامت دراز دراز)state->p_read.بلوکها,
		    (بیعلامت دراز دراز)state->p_send.بایتها,
		    (بیعلامت دراز دراز)state->p_send.بلوکها);
		kex_free_newkeys(state->newkeys[نما]);
		state->newkeys[نما] = عدم;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->بلوکها = 0;
	/* move newkeys from kex to state */
	إذا ((state->newkeys[نما] = ssh->kex->newkeys[نما]) == عدم)
		أرجع SSH_ERR_داخلی_ERROR;
	ssh->kex->newkeys[نما] = عدم;
	enc  = &state->newkeys[نما]->enc;
	mac  = &state->newkeys[نما]->mac;
	comp = &state->newkeys[نما]->comp;
	إذا (cipher_authlen(enc->cipher) == 0) {
		إذا ((r = mac_init(mac)) != 0)
			أرجع r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = عدم;
	إذا ((r = cipher_init(ccp, enc->cipher, enc->کلید, enc->کلید_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		أرجع r;
	إذا (!state->cipher_warning_انجامشده &&
	    (wmsg = cipher_warning_پیام(*ccp)) != عدم) {
		error("Warning: %s", wmsg);
		state->cipher_warning_انجامشده = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	إذا (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		إذا ((r = ssh_packet_init_compression(ssh)) < 0)
			أرجع r;
		إذا (نما == نما_بیرون) {
			إذا ((r = شروع_compression_بیرون(ssh)) != 0)
				أرجع r;
		} وإلا {
			إذا ((r = شروع_compression_درون(ssh)) != 0)
				أرجع r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	إذا (enc->بلوک_اندازه >= 16)
		*hard_max_بلوکها = (uint64_t)1 << (enc->بلوک_اندازه*2);
	وإلا
		*hard_max_بلوکها = ((uint64_t)1 << 30) / enc->بلوک_اندازه;
	*max_بلوکها = *hard_max_بلوکها;
	إذا (state->rekey_حد) {
		*max_بلوکها = MINIMUM(*max_بلوکها,
		    state->rekey_حد / enc->بلوک_اندازه);
	}
	debug("rekey %s after %llu blocks", dir,
	    (بیعلامت دراز دراز)*max_بلوکها);
	أرجع 0;
}

#تعریف_کن MAX_PACKETS	(1U<<31)
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
	uint32_t بیرون_بلوکها;
	ثابت uint64_t max_بلوکها_درون = hard ?
	    state->hard_max_بلوکها_درون : state->max_بلوکها_درون;
	ثابت uint64_t max_بلوکها_بیرون = hard ?
	    state->hard_max_بلوکها_بیرون : state->max_بلوکها_بیرون;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	إذا (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		أرجع 1;

	إذا (state->newkeys[نما_بیرون] == عدم)
		أرجع 0;

	/* Rekey after (cipher-specific) maximum blocks */
	بیرون_بلوکها = ROUNDUP(packet_len,
	    state->newkeys[نما_بیرون]->enc.بلوک_اندازه);
	أرجع (max_بلوکها_بیرون &&
	    (state->p_send.بلوکها + بیرون_بلوکها > max_بلوکها_بیرون)) ||
	    (max_بلوکها_درون &&
	    (state->p_read.بلوکها > max_بلوکها_درون));
}

ساكن صحيح
ssh_packet_need_rekeying(بنية ssh *ssh, u_int outbound_packet_len)
{
	بنية session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	إذا (!state->after_authentication)
		أرجع 0;

	/* Haven't keyed yet or KEX in progress. */
	إذا (ssh_packet_is_rekeying(ssh))
		أرجع 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	إذا (state->p_send.packets == 0 && state->p_read.packets == 0)
		أرجع 0;

	/* Time-based rekeying */
	إذا (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_زمان + state->rekey_interval <= monotime())
		أرجع 1;

	أرجع ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
ساكن صحيح
ssh_packet_check_rekey_preauth(بنية ssh *ssh, u_int outgoing_packet_len)
{
	إذا (ssh->state->after_authentication)
		أرجع 0;

	إذا (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		أرجع SSH_ERR_NEED_REKEY;
	}
	أرجع 0;
}

صحيح
ssh_packet_check_rekey(بنية ssh *ssh)
{
	صحيح r;

	إذا ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		أرجع r;
	إذا (!ssh_packet_need_rekeying(ssh, 0))
		أرجع 0;
	debug3_f("rekex triggered");
	أرجع kex_شروع_rekex(ssh);
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
	صحيح r, نما;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	لكل (نما = 0; نما < نما_MAX; نما++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		إذا (state->newkeys[نما] == عدم)
			استمر;
		comp = &state->newkeys[نما]->comp;
		إذا (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			إذا ((r = ssh_packet_init_compression(ssh)) != 0)
				أرجع r;
			إذا (نما == نما_بیرون) {
				إذا ((r = شروع_compression_بیرون(ssh)) != 0)
					أرجع r;
			} وإلا {
				إذا ((r = شروع_compression_درون(ssh)) != 0)
					أرجع r;
			}
			comp->enabled = 1;
		}
	}
	أرجع 0;
}

/* Used to mute debug logging for noisy packet types */
صحيح
ssh_packet_log_type(u_char type)
{
	بدل (type) {
	حالة SSH2_پیام_PING:
	حالة SSH2_پیام_PONG:
	حالة SSH2_پیام_CHANNEL_داده:
	حالة SSH2_پیام_CHANNEL_EXTENDED_داده:
	حالة SSH2_پیام_CHANNEL_پنجره_ADJUST:
		أرجع 0;
	افتراضي:
		أرجع 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
صحيح
ssh_packet_send2_wrapped(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_درازی];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	بنية sshenc *enc   = عدم;
	بنية sshmac *mac   = عدم;
	بنية sshcomp *comp = عدم;
	صحيح r, بلوک_اندازه;

	إذا (state->newkeys[نما_بیرون] != عدم) {
		enc  = &state->newkeys[نما_بیرون]->enc;
		mac  = &state->newkeys[نما_بیرون]->mac;
		comp = &state->newkeys[نما_بیرون]->comp;
		/* disable mac for authenticated encryption */
		إذا ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = عدم;
	}
	بلوک_اندازه = enc ? enc->بلوک_اندازه : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	إذا (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#اگر_تعریف_شده PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#پایان_اگر

	إذا (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		إذا ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			اذهب بیرون;
		sshbuf_reset(state->compression_میانگیر);
		إذا ((r = compress_میانگیر(ssh, state->outgoing_packet,
		    state->compression_میانگیر)) != 0)
			اذهب بیرون;
		sshbuf_reset(state->outgoing_packet);
		إذا ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_میانگیر)) != 0)
			اذهب بیرون;
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
	padlen = بلوک_اندازه - (len % بلوک_اندازه);
	إذا (padlen < 4)
		padlen += بلوک_اندازه;
	إذا (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, بلوک_اندازه);
		/* check if roundup overflowed */
		إذا (state->extra_pad < tmp)
			أرجع SSH_ERR_INVALID_آرگومان;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		إذا (tmp > state->extra_pad)
			أرجع SSH_ERR_INVALID_آرگومان;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		إذا (padlen < tmp)
			أرجع SSH_ERR_INVALID_آرگومان; /*سرریز*/
		state->extra_pad = 0;
	}
	إذا ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		اذهب بیرون;
	إذا (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} وإلا {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	إذا (cp == عدم) {
		r = SSH_ERR_داخلی_ERROR;
		اذهب بیرون;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	إذا (mac && mac->enabled && !mac->etm) {
		إذا ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, حجم(macbuf))) != 0)
			اذهب بیرون;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	إذا ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		اذهب بیرون;
	إذا ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		اذهب بیرون;
	/* append unencrypted MAC */
	إذا (mac && mac->enabled) {
		إذا (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			إذا ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, حجم(macbuf))) != 0)
				اذهب بیرون;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		إذا ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			اذهب بیرون;
	}
#اگر_تعریف_شده PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#پایان_اگر
	/* increment sequence number for outgoing packets */
	إذا (++state->p_send.seqnr == 0) {
		إذا ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	إذا (++state->p_send.packets == 0)
		أرجع SSH_ERR_NEED_REKEY;
	state->p_send.بلوکها += len / بلوک_اندازه;
	state->p_send.بایتها += len;
	sshbuf_reset(state->outgoing_packet);

	إذا (type == SSH2_پیام_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	إذا (type == SSH2_پیام_NEWKEYS)
		r = ssh_مجموعه_newkeys(ssh, نما_بیرون);
	وإلا إذا (type == SSH2_پیام_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	وإلا
		r = 0;
 بیرون:
	أرجع r;
}

/* returns non-zero if the specified packet type is usec by KEX */
ساكن صحيح
ssh_packet_type_is_kex(u_char type)
{
	أرجع
	    type >= SSH2_پیام_TRANSPORT_MIN &&
	    type <= SSH2_پیام_TRANSPORT_MAX &&
	    type != SSH2_پیام_SERVICE_REQUEST &&
	    type != SSH2_پیام_SERVICE_ACCEPT &&
	    type != SSH2_پیام_EXT_INFO;
}

صحيح
ssh_packet_send2(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	بنية packet *p;
	u_char type;
	صحيح r, need_rekey;

	إذا (sshbuf_len(state->outgoing_packet) < 6)
		أرجع SSH_ERR_داخلی_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	إذا (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		أرجع r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	إذا ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		إذا (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = حافظه_صفر_بده(1, حجم(*p));
		إذا (p == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, بعدی);
		state->outgoing_packet = sshbuf_new();
		إذا (state->outgoing_packet == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		إذا (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			أرجع kex_شروع_rekex(ssh);
		}
		أرجع 0;
	}

	/* rekeying starts with sending KEXINIT */
	إذا (type == SSH2_پیام_KEXINIT)
		state->rekeying = 1;

	إذا ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		أرجع r;

	/* after a NEWKEYS message we can send the complete queue */
	إذا (type == SSH2_پیام_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_زمان = monotime();
		طالما ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			إذا (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				أرجع kex_شروع_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, بعدی);
			memset(p, 0, حجم(*p));
			حرر(p);
			إذا ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				أرجع r;
		}
	}
	أرجع 0;
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
	بنية timeval شروع;
	بنية timespec timespec, *timespecp = عدم;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	إذا ((r = ssh_packet_write_wait(ssh)) != 0)
		اذهب بیرون;

	/* Stay in the loop until we have received a complete packet. */
	لكل (;;) {
		/* Try to read a packet from the buffer. */
		إذا ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			اكسر;
		/* If we got a packet, return it. */
		إذا (*typep != SSH_پیام_NONE)
			اكسر;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_درون;
		pfd.events = POLLIN;

		إذا (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		لكل (;;) {
			إذا (state->packet_timeout_ms > 0) {
				ms_مقصد_timespec(&timespec, ms_remain);
				monotime_tv(&شروع);
			}
			إذا ((r = ppoll(&pfd, 1, timespecp, عدم)) >= 0)
				اكسر;
			إذا (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب بیرون;
			}
			إذا (state->packet_timeout_ms <= 0)
				استمر;
			ms_تفریق_diff(&شروع, &ms_remain);
			إذا (ms_remain <= 0) {
				r = 0;
				اكسر;
			}
		}
		إذا (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			اذهب بیرون;
		}
		/* Read data from the socket. */
		len = اقرأ(state->connection_درون, buf, حجم(buf));
		إذا (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			اذهب بیرون;
		}
		إذا (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب بیرون;
		}

		/* Append it to the buffer. */
		إذا ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			اذهب بیرون;
	}
 بیرون:
	أرجع r;
}

صحيح
ssh_packet_read(بنية ssh *ssh)
{
	u_char type;
	صحيح r;

	إذا ((r = ssh_packet_read_seqnr(ssh, &type, عدم)) != 0)
		sshpkt_fatal(ssh, r, "read");
	أرجع type;
}

ساكن صحيح
ssh_packet_read_poll2_mux(بنية ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	بنية session_state *state = ssh->state;
	ثابت u_char *cp;
	اندازه_t need;
	صحيح r;

	إذا (ssh->kex)
		أرجع SSH_ERR_داخلی_ERROR;
	*typep = SSH_پیام_NONE;
	cp = sshbuf_ptr(state->درون_داد);
	إذا (state->packlen == 0) {
		إذا (sshbuf_len(state->درون_داد) < 4 + 1)
			أرجع 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		إذا (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_اندازه)
			أرجع SSH_ERR_پیام_INCOMPLETE;
	}
	need = state->packlen + 4;
	إذا (sshbuf_len(state->درون_داد) < need)
		أرجع 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	إذا ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->درون_داد, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, عدم)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		أرجع r;
	إذا (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	أرجع r;
}

صحيح
ssh_packet_read_poll2(بنية ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	بنية session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, بلوک_اندازه;
	بنية sshenc *enc   = عدم;
	بنية sshmac *mac   = عدم;
	بنية sshcomp *comp = عدم;
	صحيح r;

	إذا (state->mux)
		أرجع ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_پیام_NONE;

	إذا (state->packet_discard)
		أرجع 0;

	إذا (state->newkeys[نما_درون] != عدم) {
		enc  = &state->newkeys[نما_درون]->enc;
		mac  = &state->newkeys[نما_درون]->mac;
		comp = &state->newkeys[نما_درون]->comp;
		/* disable mac for authenticated encryption */
		إذا ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = عدم;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	بلوک_اندازه = enc ? enc->بلوک_اندازه : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	إذا (aadlen && state->packlen == 0) {
		إذا (cipher_get_درازی(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->درون_داد), sshbuf_len(state->درون_داد)) != 0)
			أرجع 0;
		إذا (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_اندازه) {
#اگر_تعریف_شده PACKET_DEBUG
			sshbuf_dump(state->درون_داد, stderr);
#پایان_اگر
			logit("Bad packet length %u.", state->packlen);
			إذا ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				أرجع r;
			أرجع SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} وإلا إذا (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		إذا (sshbuf_len(state->درون_داد) < بلوک_اندازه)
			أرجع 0;
		sshbuf_reset(state->incoming_packet);
		إذا ((r = sshbuf_reserve(state->incoming_packet, بلوک_اندازه,
		    &cp)) != 0)
			اذهب بیرون;
		إذا ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->درون_داد),
		    بلوک_اندازه, 0, 0)) != 0)
			اذهب بیرون;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		إذا (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_اندازه) {
#اگر_تعریف_شده PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->درون_داد, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#پایان_اگر
			logit("Bad packet length %u.", state->packlen);
			أرجع ssh_packet_شروع_discard(ssh, enc, mac, 0,
			    PACKET_MAX_اندازه);
		}
		إذا ((r = sshbuf_consume(state->درون_داد, بلوک_اندازه)) != 0)
			اذهب بیرون;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	إذا (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} وإلا {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - بلوک_اندازه;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", بلوک_اندازه, need, maclen, authlen, aadlen));
	إذا (need % بلوک_اندازه != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, بلوک_اندازه, need % بلوک_اندازه);
		أرجع ssh_packet_شروع_discard(ssh, enc, mac, 0,
		    PACKET_MAX_اندازه - بلوک_اندازه);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet:
	 * 'aadlen' bytes are unencrypted, but authenticated.
	 * 'need' bytes are encrypted, followed by either
	 * 'authlen' bytes of authentication tag or
	 * 'maclen' bytes of message authentication code.
	 */
	إذا (sshbuf_len(state->درون_داد) < aadlen + need + authlen + maclen)
		أرجع 0; /* packet is incomplete */
#اگر_تعریف_شده PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->درون_داد, stderr);
#پایان_اگر
	/* EtM: check mac over encrypted input */
	إذا (mac && mac->enabled && mac->etm) {
		إذا ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->درون_داد), aadlen + need,
		    sshbuf_ptr(state->درون_داد) + aadlen + need + authlen,
		    maclen)) != 0) {
			إذا (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			اذهب بیرون;
		}
	}
	إذا ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		اذهب بیرون;
	إذا ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->درون_داد), need, aadlen, authlen)) != 0)
		اذهب بیرون;
	إذا ((r = sshbuf_consume(state->درون_داد, aadlen + need + authlen)) != 0)
		اذهب بیرون;
	إذا (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		إذا (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->درون_داد), maclen)) != 0) {
			إذا (r != SSH_ERR_MAC_INVALID)
				اذهب بیرون;
			logit("Corrupted MAC on input.");
			إذا (need + بلوک_اندازه > PACKET_MAX_اندازه)
				أرجع SSH_ERR_داخلی_ERROR;
			أرجع ssh_packet_شروع_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_اندازه - need - بلوک_اندازه);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		إذا ((r = sshbuf_consume(state->درون_داد, mac->mac_len)) != 0)
			اذهب بیرون;
	}

	إذا (seqnr_p != عدم)
		*seqnr_p = state->p_read.seqnr;
	إذا (++state->p_read.seqnr == 0) {
		إذا ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	إذا (++state->p_read.packets == 0)
		أرجع SSH_ERR_NEED_REKEY;
	state->p_read.بلوکها += (state->packlen + 4) / بلوک_اندازه;
	state->p_read.بایتها += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	إذا (padlen < 4)	{
		إذا ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			أرجع r;
		أرجع SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	إذا ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_انتها(state->incoming_packet, padlen)) != 0))
		اذهب بیرون;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	إذا (comp && comp->enabled) {
		sshbuf_reset(state->compression_میانگیر);
		إذا ((r = uncompress_میانگیر(ssh, state->incoming_packet,
		    state->compression_میانگیر)) != 0)
			اذهب بیرون;
		sshbuf_reset(state->incoming_packet);
		إذا ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_میانگیر)) != 0)
			اذهب بیرون;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	إذا ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		اذهب بیرون;
	إذا (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	إذا (*typep < SSH2_پیام_MIN) {
		إذا ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			أرجع r;
		أرجع SSH_ERR_PROTOCOL_ERROR;
	}
	إذا (state->hook_درون != عدم &&
	    (r = state->hook_درون(ssh, state->incoming_packet, typep,
	    state->hook_درون_ctx)) != 0)
		أرجع r;
	إذا (*typep == SSH2_پیام_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	وإلا
		r = 0;
#اگر_تعریف_شده PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#پایان_اگر
	/* reset for next packet */
	state->packlen = 0;
	إذا (*typep == SSH2_پیام_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	إذا ((r = ssh_packet_check_rekey(ssh)) != 0)
		أرجع r;
 بیرون:
	أرجع r;
}

صحيح
ssh_packet_read_poll_seqnr(بنية ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	بنية session_state *state = ssh->state;
	u_int reason, seqnr;
	صحيح r;
	u_char *پیام;
	ثابت u_char *d;
	اندازه_t len;

	لكل (;;) {
		پیام = عدم;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		إذا (r != 0)
			أرجع r;
		إذا (*typep == 0) {
			/* no message ready */
			أرجع 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		إذا (*typep == SSH2_پیام_DISCONNECT) {
			إذا ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &پیام, عدم)) != 0)
				أرجع r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_پورت(ssh), reason, پیام);
			حرر(پیام);
			أرجع SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		إذا (ssh->kex != عدم &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			أرجع 0;
		/* Implicitly handle transport-level messages */
		بدل (*typep) {
		حالة SSH2_پیام_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			اكسر;
		حالة SSH2_پیام_DEBUG:
			إذا ((r = sshpkt_get_u8(ssh, عدم)) != 0 ||
			    (r = sshpkt_get_string(ssh, &پیام, عدم)) != 0 ||
			    (r = sshpkt_get_string(ssh, عدم, عدم)) != 0) {
				حرر(پیام);
				أرجع r;
			}
			debug("Remote: %.900s", پیام);
			حرر(پیام);
			اكسر;
		حالة SSH2_پیام_UNIMPLEMENTED:
			إذا ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				أرجع r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			اكسر;
		حالة SSH2_پیام_PING:
			إذا ((r = sshpkt_get_string_مستقیم(ssh, &d, &len)) != 0)
				أرجع r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			إذا (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				اكسر;
			}
			إذا (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				اكسر;
			}
			إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				أرجع r;
			اكسر;
		حالة SSH2_پیام_PONG:
			إذا ((r = sshpkt_get_string_مستقیم(ssh,
			    عدم, &len)) != 0)
				أرجع r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			اكسر;
		افتراضي:
			إذا (ssh->kex != عدم &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				أرجع SSH_ERR_PROTOCOL_ERROR;
			}
			أرجع 0;
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

	إذا (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		إذا (len >= state->packet_discard) {
			إذا ((r = ssh_packet_stop_discard(ssh)) != 0)
				أرجع r;
		}
		state->packet_discard -= len;
		أرجع 0;
	}
	إذا ((r = sshbuf_put(state->درون_داد, buf, len)) != 0)
		أرجع r;

	أرجع 0;
}

/* Reads and buffers data from the specified fd */
صحيح
ssh_packet_process_read(بنية ssh *ssh, صحيح fd)
{
	بنية session_state *state = ssh->state;
	صحيح r;
	اندازه_t rlen;

	إذا ((r = sshbuf_read(fd, state->درون_داد, PACKET_MAX_اندازه, &rlen)) != 0)
		أرجع r;

	إذا (state->packet_discard) {
		إذا ((r = sshbuf_consume_انتها(state->درون_داد, rlen)) != 0)
			أرجع r;
		state->keep_alive_timeouts = 0; /* ?? */
		إذا (rlen >= state->packet_discard) {
			إذا ((r = ssh_packet_stop_discard(ssh)) != 0)
				أرجع r;
		}
		state->packet_discard -= rlen;
		أرجع 0;
	}
	أرجع 0;
}

صحيح
ssh_packet_مانده(بنية ssh *ssh)
{
	أرجع sshbuf_len(ssh->state->incoming_packet);
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
	va_list آرگومانها;
	صحيح r;

	إذا ((ssh->compat & SSH_BUG_DEBUG))
		أرجع;

	va_start(آرگومانها, fmt);
	vsnprintf(buf, حجم(buf), fmt, آرگومانها);
	va_end(آرگومانها);

	debug3("sending debug message: %s", buf);

	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

فراغ
sshpkt_fmt_connection_id(بنية ssh *ssh, حرف *s, اندازه_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
ساكن فراغ
sshpkt_vfatal(بنية ssh *ssh, صحيح r, ثابت حرف *fmt, va_list ap)
{
	حرف *برچسب = عدم, remote_id[512];
	صحيح oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));

	بدل (r) {
	حالة SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_کلیدها(ssh);
		logdie("Connection closed by %s", remote_id);
	حالة SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_کلیدها(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	حالة SSH_ERR_DISCONNECTED:
		ssh_packet_clear_کلیدها(ssh);
		logdie("Disconnected from %s", remote_id);
	حالة SSH_ERR_SYSTEM_ERROR:
		إذا (errno == ECONNRESET) {
			ssh_packet_clear_کلیدها(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	حالة SSH_ERR_NO_CIPHER_ALG_تطابق:
	حالة SSH_ERR_NO_MAC_ALG_تطابق:
	حالة SSH_ERR_NO_COMPRESS_ALG_تطابق:
	حالة SSH_ERR_NO_KEX_ALG_تطابق:
	حالة SSH_ERR_NO_HOSTKEY_ALG_تطابق:
		إذا (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_کلیدها(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	افتراضي:
		إذا (vasprintf(&برچسب, fmt, ap) == -1) {
			ssh_packet_clear_کلیدها(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_کلیدها(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    برچسب != عدم ? برچسب : "", برچسب != عدم ? ": " : "",
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
	va_list آرگومانها;
	صحيح r;

	/* Guard against recursive invocations. */
	إذا (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));
	va_start(آرگومانها, fmt);
	vsnprintf(buf, حجم(buf), fmt, آرگومانها);
	va_end(آرگومانها);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	إذا ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	إذا ((r = ssh_packet_write_wait(ssh)) != 0)
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

	إذا (len > 0) {
		len = اكتب(state->connection_بیرون,
		    sshbuf_ptr(state->output), len);
		إذا (len == -1) {
			إذا (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				أرجع 0;
			أرجع SSH_ERR_SYSTEM_ERROR;
		}
		إذا (len == 0)
			أرجع SSH_ERR_CONN_CLOSED;
		إذا ((r = sshbuf_consume(state->output, len)) != 0)
			أرجع r;
	}
	أرجع 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
صحيح
ssh_packet_write_wait(بنية ssh *ssh)
{
	صحيح ret, r, ms_remain = 0;
	بنية timeval شروع;
	بنية timespec timespec, *timespecp = عدم;
	بنية session_state *state = ssh->state;
	بنية pollfd pfd;

	إذا ((r = ssh_packet_write_poll(ssh)) != 0)
		أرجع r;
	طالما (ssh_packet_have_داده_مقصد_write(ssh)) {
		pfd.fd = state->connection_بیرون;
		pfd.events = POLLOUT;

		إذا (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		لكل (;;) {
			إذا (state->packet_timeout_ms > 0) {
				ms_مقصد_timespec(&timespec, ms_remain);
				monotime_tv(&شروع);
			}
			إذا ((ret = ppoll(&pfd, 1, timespecp, عدم)) >= 0)
				اكسر;
			إذا (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				اكسر;
			إذا (state->packet_timeout_ms <= 0)
				استمر;
			ms_تفریق_diff(&شروع, &ms_remain);
			إذا (ms_remain <= 0) {
				ret = 0;
				اكسر;
			}
		}
		إذا (ret == 0)
			أرجع SSH_ERR_CONN_TIMEOUT;
		إذا ((r = ssh_packet_write_poll(ssh)) != 0)
			أرجع r;
	}
	أرجع 0;
}

/* Returns true if there is buffered data to write to the connection. */

صحيح
ssh_packet_have_داده_مقصد_write(بنية ssh *ssh)
{
	أرجع sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

صحيح
ssh_packet_not_very_much_داده_مقصد_write(بنية ssh *ssh)
{
	إذا (ssh->state->interactive_نما)
		أرجع sshbuf_len(ssh->state->output) < 16384;
	وإلا
		أرجع sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

صحيح
ssh_packet_interactive_داده_مقصد_write(بنية ssh *ssh)
{
	أرجع ssh->state->interactive_نما &&
	    sshbuf_len(ssh->state->output) < 256;
}

ساكن فراغ
apply_qos(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	صحيح qos = state->interactive_نما ?
	    state->qos_interactive : state->qos_other;

	إذا (!ssh_packet_connection_is_on_socket(ssh))
		أرجع;
	إذا (!state->nodelay_مجموعه) {
		مجموعه_nodelay(state->connection_درون);
		state->nodelay_مجموعه = 1;
	}
	مجموعه_sock_tos(ssh->state->connection_درون, qos);
}

/* Informs that the current session is interactive. */
فراغ
ssh_packet_مجموعه_interactive(بنية ssh *ssh, صحيح interactive)
{
	بنية session_state *state = ssh->state;

	state->interactive_نما = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
فراغ
ssh_packet_مجموعه_qos(بنية ssh *ssh, صحيح qos_interactive, صحيح qos_other)
{
	بنية session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

صحيح
ssh_packet_مجموعه_maxsize(بنية ssh *ssh, u_int s)
{
	بنية session_state *state = ssh->state;

	إذا (state->مجموعه_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_اندازه, s);
		أرجع -1;
	}
	إذا (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		أرجع -1;
	}
	state->مجموعه_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_اندازه = s;
	أرجع s;
}

صحيح
ssh_packet_inc_alive_timeouts(بنية ssh *ssh)
{
	أرجع ++ssh->state->keep_alive_timeouts;
}

فراغ
ssh_packet_مجموعه_alive_timeouts(بنية ssh *ssh, صحيح ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(بنية ssh *ssh)
{
	أرجع ssh->state->max_packet_اندازه;
}

فراغ
ssh_packet_مجموعه_rekey_limits(بنية ssh *ssh, uint64_t بایتها, uint32_t seconds)
{
	إذا (بایتها == 0 && seconds == 0)
		أرجع;

	debug3("rekey after %llu bytes, %u seconds", (بیعلامت دراز دراز)بایتها,
	    (بیعلامت صحيح)seconds);
	ssh->state->rekey_حد = بایتها;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(بنية ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_زمان + ssh->state->rekey_interval -
	    monotime();
	أرجع (seconds <= 0 ? 1 : seconds);
}

فراغ
ssh_packet_مجموعه_server(بنية ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

فراغ
ssh_packet_مجموعه_authenticated(بنية ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

فراغ *
ssh_packet_get_درون_داد(بنية ssh *ssh)
{
	أرجع (فراغ *)ssh->state->درون_داد;
}

فراغ *
ssh_packet_get_output(بنية ssh *ssh)
{
	أرجع (فراغ *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
ساكن صحيح
ssh_packet_مجموعه_postauth(بنية ssh *ssh)
{
	صحيح r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	إذا ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		أرجع r;
	أرجع 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
ساكن صحيح
kex_مقصد_blob(بنية sshbuf *m, بنية kex *kex)
{
	صحيح r;

	إذا ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
	    (r = sshbuf_put_cstring(m, kex->hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_strict)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->client_نسخه)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->server_نسخه)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->flags)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->non_pq_kex_warned)) != 0)
		أرجع r;
	أرجع 0;
}

/* turn key exchange results into a blob for packet state serialization */
ساكن صحيح
newkeys_مقصد_blob(بنية sshbuf *m, بنية ssh *ssh, صحيح نما)
{
	بنية sshbuf *b;
	بنية sshcipher_ctx *cc;
	بنية sshcomp *comp;
	بنية sshenc *enc;
	بنية sshmac *mac;
	بنية newkeys *newkey;
	صحيح r;

	إذا ((newkey = ssh->state->newkeys[نما]) == عدم)
		أرجع SSH_ERR_داخلی_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (نما == نما_بیرون) ? ssh->state->send_context :
	    ssh->state->receive_context;
	إذا ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		أرجع r;
	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->بلوک_اندازه)) != 0 ||
	    (r = sshbuf_put_string(b, enc->کلید, enc->کلید_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		اذهب بیرون;
	إذا (cipher_authlen(enc->cipher) == 0) {
		إذا ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->کلید, mac->کلید_len)) != 0)
			اذهب بیرون;
	}
	إذا ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		اذهب بیرون;
	r = sshbuf_put_stringb(m, b);
 بیرون:
	sshbuf_free(b);
	أرجع r;
}

/* serialize packet state into a blob */
صحيح
ssh_packet_get_state(بنية ssh *ssh, بنية sshbuf *m)
{
	بنية session_state *state = ssh->state;
	صحيح r;

#تعریف_کن ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	إذا ((r = kex_مقصد_blob(m, ssh->kex)) != 0 ||
	    (r = newkeys_مقصد_blob(m, ssh, نما_بیرون)) != 0 ||
	    (r = newkeys_مقصد_blob(m, ssh, نما_درون)) != 0 ||
	    (r = sshbuf_put_u64(m, state->rekey_حد)) != 0 ||
	    (r = sshbuf_put_u32(m, state->rekey_interval)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.بلوکها)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.بایتها)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.بلوکها)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.بایتها)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->درون_داد)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_نما))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		أرجع r;
#لغو_تعریف ENCODE_INT
	أرجع 0;
}

/* restore key exchange results from blob for packet state de-serialization */
ساكن صحيح
newkeys_from_blob(بنية sshbuf *m, بنية ssh *ssh, صحيح نما)
{
	بنية sshbuf *b = عدم;
	بنية sshcomp *comp;
	بنية sshenc *enc;
	بنية sshmac *mac;
	بنية newkeys *newkey = عدم;
	اندازه_t keylen, ivlen, maclen;
	صحيح r;

	إذا ((newkey = حافظه_صفر_بده(1, حجم(*newkey))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_froms(m, &b)) != 0)
		اذهب بیرون;
#اگر_تعریف_شده DEBUG_PK
	sshbuf_dump(b, stderr);
#پایان_اگر
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	إذا ((r = sshbuf_get_cstring(b, &enc->name, عدم)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->بلوک_اندازه)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->کلید, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		اذهب بیرون;
	إذا ((enc->cipher = cipher_by_name(enc->name)) == عدم ||
	    enc->بلوک_اندازه != cipher_blocksize(enc->cipher) ||
	    cipher_is_داخلی(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	إذا (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	إذا (cipher_authlen(enc->cipher) == 0) {
		إذا ((r = sshbuf_get_cstring(b, &mac->name, عدم)) != 0)
			اذهب بیرون;
		إذا ((r = mac_راهاندازی(mac, mac->name)) != 0)
			اذهب بیرون;
		إذا ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->کلید, &maclen)) != 0)
			اذهب بیرون;
		إذا (maclen != mac->کلید_len) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بیرون;
		}
		mac->کلید_len = maclen;
	}
	إذا ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, عدم)) != 0)
		اذهب بیرون;
	إذا (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	enc->کلید_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[نما] = newkey;
	newkey = عدم;
	r = 0;
 بیرون:
	حرر(newkey);
	sshbuf_free(b);
	أرجع r;
}

/* restore kex from blob for packet state de-serialization */
ساكن صحيح
kex_from_blob(بنية sshbuf *m, بنية kex **kexp)
{
	بنية kex *kex;
	صحيح r;

	إذا ((kex = kex_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, عدم)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_type)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_type)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_strict)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->client_نسخه)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->server_نسخه)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->flags)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->non_pq_kex_warned)) != 0)
		اذهب بیرون;
	إذا (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	kex->server = 1;
	kex->انجامشده = 1;
	r = 0;
 بیرون:
	إذا (r != 0 || kexp == عدم) {
		kex_free(kex);
		إذا (kexp != عدم)
			*kexp = عدم;
	} وإلا {
		kex_free(*kexp);
		*kexp = kex;
	}
	أرجع r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
صحيح
ssh_packet_مجموعه_state(بنية ssh *ssh, بنية sshbuf *m)
{
	بنية session_state *state = ssh->state;
	ثابت u_char *درون_داد, *output;
	اندازه_t ilen, olen;
	صحيح r;
	u_int interactive, qos_interactive, qos_other;

	إذا ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, نما_بیرون)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, نما_درون)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->rekey_حد)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->rekey_interval)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.بلوکها)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.بایتها)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.بلوکها)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.بایتها)) != 0)
		أرجع r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_زمان = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	إذا ((r = ssh_مجموعه_newkeys(ssh, نما_درون)) != 0 ||
	    (r = ssh_مجموعه_newkeys(ssh, نما_بیرون)) != 0)
		أرجع r;

	إذا ((r = ssh_packet_مجموعه_postauth(ssh)) != 0)
		أرجع r;

	sshbuf_reset(state->درون_داد);
	sshbuf_reset(state->output);
	إذا ((r = sshbuf_get_string_مستقیم(m, &درون_داد, &ilen)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->درون_داد, درون_داد, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		أرجع r;

	إذا ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		أرجع r;
#تعریف_کن DECODE_INT(v) ((v) > بیشترین_صحیح ? -1 : (صحيح)(v))
	state->interactive_نما = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#لغو_تعریف DECODE_INT

	إذا (sshbuf_len(m))
		أرجع SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	أرجع 0;
}

/* NEW API */

/* put data to the outgoing packet */

صحيح
sshpkt_put(بنية ssh *ssh, ثابت فراغ *v, اندازه_t len)
{
	أرجع sshbuf_put(ssh->state->outgoing_packet, v, len);
}

صحيح
sshpkt_putb(بنية ssh *ssh, ثابت بنية sshbuf *b)
{
	أرجع sshbuf_putb(ssh->state->outgoing_packet, b);
}

صحيح
sshpkt_put_u8(بنية ssh *ssh, u_char val)
{
	أرجع sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

صحيح
sshpkt_put_u32(بنية ssh *ssh, uint32_t val)
{
	أرجع sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

صحيح
sshpkt_put_u64(بنية ssh *ssh, uint64_t val)
{
	أرجع sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

صحيح
sshpkt_put_string(بنية ssh *ssh, ثابت فراغ *v, اندازه_t len)
{
	أرجع sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

صحيح
sshpkt_put_cstring(بنية ssh *ssh, ثابت فراغ *v)
{
	أرجع sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

صحيح
sshpkt_put_stringb(بنية ssh *ssh, ثابت بنية sshbuf *v)
{
	أرجع sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#اگر_تعریف_شده WITH_OPENSSL
صحيح
sshpkt_put_ec(بنية ssh *ssh, ثابت EC_نقطه *v, ثابت EC_گروه *g)
{
	أرجع sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

صحيح
sshpkt_put_ec_pkey(بنية ssh *ssh, EVP_PKEY *pkey)
{
	أرجع sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

صحيح
sshpkt_put_bignum2(بنية ssh *ssh, ثابت BIGNUM *v)
{
	أرجع sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#پایان_اگر /* WITH_OPENSSL */

/* fetch data from the incoming packet */

صحيح
sshpkt_get(بنية ssh *ssh, فراغ *valp, اندازه_t len)
{
	أرجع sshbuf_get(ssh->state->incoming_packet, valp, len);
}

صحيح
sshpkt_get_u8(بنية ssh *ssh, u_char *valp)
{
	أرجع sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

صحيح
sshpkt_get_u32(بنية ssh *ssh, uint32_t *valp)
{
	أرجع sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

صحيح
sshpkt_get_u64(بنية ssh *ssh, uint64_t *valp)
{
	أرجع sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

صحيح
sshpkt_get_string(بنية ssh *ssh, u_char **valp, اندازه_t *lenp)
{
	أرجع sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

صحيح
sshpkt_get_string_مستقیم(بنية ssh *ssh, ثابت u_char **valp, اندازه_t *lenp)
{
	أرجع sshbuf_get_string_مستقیم(ssh->state->incoming_packet, valp, lenp);
}

صحيح
sshpkt_peek_string_مستقیم(بنية ssh *ssh, ثابت u_char **valp, اندازه_t *lenp)
{
	أرجع sshbuf_peek_string_مستقیم(ssh->state->incoming_packet, valp, lenp);
}

صحيح
sshpkt_get_cstring(بنية ssh *ssh, حرف **valp, اندازه_t *lenp)
{
	أرجع sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

صحيح
sshpkt_getb_froms(بنية ssh *ssh, بنية sshbuf **valp)
{
	أرجع sshbuf_froms(ssh->state->incoming_packet, valp);
}

#اگر_تعریف_شده WITH_OPENSSL
صحيح
sshpkt_get_ec(بنية ssh *ssh, EC_نقطه *v, ثابت EC_گروه *g)
{
	أرجع sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

صحيح
sshpkt_get_bignum2(بنية ssh *ssh, BIGNUM **valp)
{
	أرجع sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#پایان_اگر /* WITH_OPENSSL */

صحيح
sshpkt_get_انتها(بنية ssh *ssh)
{
	إذا (sshbuf_len(ssh->state->incoming_packet) > 0)
		أرجع SSH_ERR_UNEXPECTED_TRAILING_داده;
	أرجع 0;
}

ثابت u_char *
sshpkt_ptr(بنية ssh *ssh, اندازه_t *lenp)
{
	إذا (lenp != عدم)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	أرجع sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

صحيح
sshpkt_شروع(بنية ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, حجم(buf));
	buf[حجم(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	أرجع sshbuf_put(ssh->state->outgoing_packet, buf, حجم(buf));
}

ساكن صحيح
ssh_packet_send_mux(بنية ssh *ssh)
{
	بنية session_state *state = ssh->state;
	u_char type, *cp;
	اندازه_t len;
	صحيح r;

	إذا (ssh->kex)
		أرجع SSH_ERR_داخلی_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	إذا (len < 6)
		أرجع SSH_ERR_داخلی_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	إذا (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	إذا (type >= SSH2_پیام_CONNECTION_MIN &&
	    type <= SSH2_پیام_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		إذا ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			أرجع r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	أرجع 0;
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
sshpkt_پیام_ignore(بنية ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	صحيح r;
	u_int i;

	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		أرجع r;
	لكل (i = 0; i < nbytes; i++) {
		إذا (i % 4 == 0)
			rnd = arc4random();
		إذا ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			أرجع r;
		rnd >>= 8;
	}
	أرجع 0;
}

/* send it */

صحيح
sshpkt_send(بنية ssh *ssh)
{
	إذا (ssh->state && ssh->state->mux)
		أرجع ssh_packet_send_mux(ssh);
	أرجع ssh_packet_send2(ssh);
}

صحيح
sshpkt_disconnect(بنية ssh *ssh, ثابت حرف *fmt,...)
{
	حرف buf[1024];
	va_list آرگومانها;
	صحيح r;

	va_start(آرگومانها, fmt);
	vsnprintf(buf, حجم(buf), fmt, آرگومانها);
	va_end(آرگومانها);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		أرجع r;
	أرجع 0;
}

/* roundup current message to pad bytes */
صحيح
sshpkt_جمع_کن_padding(بنية ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	أرجع 0;
}

ساكن حرف *
format_traffic_stats(بنية packet_state *ps)
{
	حرف *stats = عدم, بایتها[FMT_SCALED_STRSIZE];

	إذا (ps->بایتها > LLONG_MAX || fmt_scaled(ps->بایتها, بایتها) != 0)
		strlcpy(بایتها, "OVERFLOW", حجم(بایتها));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (بیعلامت دراز)ps->packets, (بیعلامت دراز دراز)ps->بلوکها, بایتها);
	أرجع stats;
}

ساكن حرف *
dedupe_alg_نامها(ثابت حرف *درون, ثابت حرف *بیرون)
{
	حرف *نامها = عدم;

	إذا (درون == عدم)
		درون = "<implicit>";
	إذا (بیرون == عدم)
		بیرون = "<implicit>";

	إذا (strcmp(درون, بیرون) == 0) {
		نامها = xstrdup(درون);
	} وإلا {
		xasprintf(&نامها, "%s in, %s out", درون, بیرون);
	}
	أرجع نامها;
}

ساكن حرف *
comp_وضعیت_پیام(بنية ssh *ssh)
{
#اگر_تعریف_شده WITH_ZLIB
	حرف *ret = عدم;
	بنية session_state *state = ssh->state;
	بیعلامت دراز دراز iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	حرف iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	حرف icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	إذا (state->compression_میانگیر) {
		إذا (state->compression_درون_started) {
			iraw = state->compression_درون_جریان.مجموع_بیرون;
			icmp = state->compression_درون_جریان.مجموع_درون;
			إذا (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", حجم(iraw_f));
			إذا (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", حجم(icmp_f));
		}
		إذا (state->compression_بیرون_started) {
			oraw = state->compression_بیرون_جریان.مجموع_درون;
			ocmp = state->compression_بیرون_جریان.مجموع_بیرون;
			إذا (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", حجم(oraw_f));
			إذا (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", حجم(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (مزدوج)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (مزدوج)ocmp / oraw);
		أرجع ret;
	}
#پایان_اگر	/* WITH_ZLIB */
	أرجع xstrdup("");
}

حرف *
connection_info_پیام(بنية ssh *ssh)
{
	حرف *ret = عدم, *cipher = عدم, *mac = عدم, *comp = عدم;
	حرف *rekey_volume = عدم, *rekey_زمان = عدم, *comp_info = عدم;
	حرف thishost[NI_MAXHOST] = "unknown", *tcp_info = عدم;
	بنية kex *kex;
	بنية session_state *state;
	بنية newkeys *nk_درون, *nk_بیرون;
	حرف *stats_درون = عدم, *stats_بیرون = عدم;
	uint64_t epoch = (uint64_t)time(عدم) - monotime();

	إذا (ssh == عدم)
		أرجع عدم;
	state = ssh->state;
	kex = ssh->kex;

	(فراغ)gethostname(thishost, حجم(thishost));

	إذا (ssh_local_پورت(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_پورت(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh));
	} وإلا {
		tcp_info = xstrdup("");
	}

	nk_درون = ssh->state->newkeys[نما_درون];
	nk_بیرون = ssh->state->newkeys[نما_بیرون];
	stats_درون = format_traffic_stats(&ssh->state->p_read);
	stats_بیرون = format_traffic_stats(&ssh->state->p_send);

	cipher = dedupe_alg_نامها(nk_درون->enc.name, nk_بیرون->enc.name);
	mac = dedupe_alg_نامها(nk_درون->mac.name, nk_بیرون->mac.name);
	comp = dedupe_alg_نامها(nk_درون->comp.name, nk_بیرون->comp.name);

	/* Volume based rekeying. */
	إذا (state->rekey_حد == 0) {
		xasprintf(&rekey_volume, "limit none");
	} وإلا {
		حرف *volumes = عدم, درون[32], بیرون[32];

		snprintf(درون, حجم(درون), "%llu",
		   (بیعلامت دراز دراز)state->max_بلوکها_درون);
		snprintf(بیرون, حجم(بیرون), "%llu",
		   (بیعلامت دراز دراز)state->max_بلوکها_بیرون);
		volumes = dedupe_alg_نامها(درون, بیرون);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		حرر(volumes);
	}

	/* Time based rekeying. */
	إذا (state->rekey_interval == 0) {
		rekey_زمان = xstrdup("interval none");
	} وإلا {
		حرف rekey_بعدی[64];

		format_absolute_زمان(epoch + state->rekey_زمان +
		    state->rekey_interval, rekey_بعدی, حجم(rekey_بعدی));
		xasprintf(&rekey_زمان, "interval %s, next %s",
		    fmt_timeframe(state->rekey_interval), rekey_بعدی);
	}
	comp_info = comp_وضعیت_پیام(ssh);

	xasprintf(&ret, "Connection information for %s pid %lld\r\n"
	    "  versions %s -> %s\r\n"
	    "%s"
	    "  duration %s\r\n"
	    "  kexalgorithm %s\r\n  hostkeyalgorithm %s\r\n"
	    "  cipher %s\r\n  mac %s\r\n  compression %s\r\n"
	    "  rekey %s %s\r\n"
	    "  traffic %s in, %s out\r\n"
	    "%s",
	    thishost, (دراز دراز)getpid(),
	    SSH_RELEASE, ssh->remote_نسخه,
	    tcp_info,
	    fmt_timeframe(monotime() - state->شروع_زمان),
	    kex->name, kex->hostkey_alg,
	    cipher, mac, comp,
	    rekey_volume, rekey_زمان,
	    stats_درون, stats_بیرون,
	    comp_info
	);
	حرر(tcp_info);
	حرر(cipher);
	حرر(mac);
	حرر(comp);
	حرر(stats_درون);
	حرر(stats_بیرون);
	حرر(rekey_volume);
	حرر(rekey_زمان);
	حرر(comp_info);
	أرجع ret;
}

