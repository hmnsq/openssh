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
#اگر_تعریف_شدہ WITH_OPENSSL
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/ec.h>
#اگر_ختم

#اگر_تعریف_شدہ WITH_ZLIB
#شامل <zlib.h>
#اگر_ختم

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

#اگر_تعریف_شدہ PACKET_DEBUG
#تعریف_کرو DBG(x) x
#ورنہ
#تعریف_کرو DBG(x)
#اگر_ختم

#تعریف_کرو PACKET_MAX_سائز (256 * 1024)

ساخت packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t بلاکیں;
	uint64_t بائٹیں;
};

ساخت packet {
	TAILQ_ENTRY(packet) اگلا;
	u_char type;
	ساخت sshbuf *payload;
};

ساخت session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	صحیح connection_اندر;
	صحیح connection_برآمد;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	ساخت sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	ساخت sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	ساخت sshbuf *داخلہ;

	/* Buffer for raw output data going to the socket. */
	ساخت sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	ساخت sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	ساخت sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	ساخت sshbuf *compression_بفر;

#اگر_تعریف_شدہ WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_دھارا compression_اندر_دھارا;
	z_دھارا compression_برآمد_دھارا;
#اگر_ختم
	صحیح compression_اندر_started;
	صحیح compression_برآمد_started;
	صحیح compression_اندر_failures;
	صحیح compression_برآمد_failures;

	/* default maximum packet size */
	u_int max_packet_سائز;

	/* Flag indicating whether this module has been initialized. */
	صحیح initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t آغاز_وقت;

	/* Set to true if the connection is interactive. */
	صحیح interactive_منوال;

	/* Set to true if we are the server side. */
	صحیح server_side;

	/* Set to true if we are authenticated. */
	صحیح after_authentication;

	صحیح keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	صحیح packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	ساخت newkeys *newkeys[منوال_MAX];
	ساخت packet_state p_read, p_send;

	/* Volume-based rekeying */
	uint64_t hard_max_بلاکیں_اندر, hard_max_بلاکیں_برآمد;
	uint64_t max_بلاکیں_اندر, max_بلاکیں_برآمد, rekey_حد_بندی;

	/* Time-based rekeying */
	uint32_t rekey_interval;	/* how often in seconds */
	time_t rekey_وقت;	/* time of last rekeying */

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	سائز_t packet_discard_mac_already;
	ساخت sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	صحیح rekeying;

	/* Used in ssh_packet_send_mux() */
	صحیح mux;

	/* QoS handling */
	صحیح qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	صحیح سیٹ_maxsize_called;

	/* One-off warning about weak ciphers */
	صحیح cipher_warning_مکمل;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	صحیح disconnecting;

	/* Nagle disabled on socket */
	صحیح nodelay_سیٹ;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_اندر;
	خالی *hook_اندر_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

ساخت ssh *
ssh_alloc_session_state(خالی)
{
	ساخت ssh *ssh = تہی;
	ساخت session_state *state = تہی;

	اگر ((ssh = صفر_حافظہ_دو(1, حجم(*ssh))) == تہی ||
	    (state = صفر_حافظہ_دو(1, حجم(*state))) == تہی ||
	    (ssh->kex = kex_new()) == تہی ||
	    (state->داخلہ = sshbuf_new()) == تہی ||
	    (state->output = sshbuf_new()) == تہی ||
	    (state->outgoing_packet = sshbuf_new()) == تہی ||
	    (state->incoming_packet = sshbuf_new()) == تہی)
		جاؤ fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->نجی_کلیدیں);
	TAILQ_INIT(&ssh->عوامی_کلیدیں);
	state->connection_اندر = -1;
	state->connection_برآمد = -1;
	state->max_packet_سائز = 32768;
	state->packet_timeout_ms = -1;
	state->interactive_منوال = 1;
	state->qos_interactive = state->qos_other = -1;
	state->p_send.packets = state->p_read.packets = 0;
	state->initialized = 1;
	/*
	 * ssh_packet_send2() needs to queue packets until
	 * we've done the initial key exchange.
	 */
	state->rekeying = 1;
	ssh->state = state;
	واپس ssh;
 fail:
	اگر (ssh) {
		kex_free(ssh->kex);
		آزاد(ssh);
	}
	اگر (state) {
		sshbuf_free(state->داخلہ);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		آزاد(state);
	}
	واپس تہی;
}

خالی
ssh_packet_سیٹ_داخلہ_hook(ساخت ssh *ssh, ssh_packet_hook_fn *hook, خالی *ctx)
{
	ssh->state->hook_اندر = hook;
	ssh->state->hook_اندر_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
صحیح
ssh_packet_is_rekeying(ساخت ssh *ssh)
{
	واپس ssh->state->rekeying ||
	    (ssh->kex != تہی && ssh->kex->مکمل == 0);
}

/*
 * Sets the descriptors used for communication.
 */
ساخت ssh *
ssh_packet_سیٹ_connection(ساخت ssh *ssh, صحیح fd_اندر, صحیح fd_برآمد)
{
	ساخت session_state *state;
	ثابت ساخت sshcipher *none = cipher_by_name("none");
	صحیح r, wasnull = ssh == تہی;

	اگر (none == تہی) {
		error_f("cannot load cipher 'none'");
		واپس تہی;
	}
	اگر (ssh == تہی)
		ssh = ssh_alloc_session_state();
	اگر (ssh == تہی) {
		error_f("could not allocate state");
		واپس تہی;
	}
	state = ssh->state;
	state->آغاز_وقت = monotime();
	state->connection_اندر = fd_اندر;
	state->connection_برآمد = fd_برآمد;
	اگر ((r = cipher_init(&state->send_context, none,
	    (ثابت u_char *)"", 0, تہی, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (ثابت u_char *)"", 0, تہی, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		اگر (wasnull)
			آزاد(ssh); /* XXX need ssh_free_session_state? */
		واپس تہی;
	}
	state->newkeys[منوال_اندر] = state->newkeys[منوال_برآمد] = تہی;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(خالی)ssh_remote_ipaddr(ssh);
	واپس ssh;
}

خالی
ssh_packet_سیٹ_timeout(ساخت ssh *ssh, صحیح timeout, صحیح گنتی)
{
	ساخت session_state *state = ssh->state;

	اگر (timeout <= 0 || گنتی <= 0) {
		state->packet_timeout_ms = -1;
		واپس;
	}
	اگر ((زیادہ_سے_زیادہ_عدد / 1000) / گنتی < timeout)
		state->packet_timeout_ms = زیادہ_سے_زیادہ_عدد;
	ورنہ
		state->packet_timeout_ms = timeout * گنتی * 1000;
}

خالی
ssh_packet_سیٹ_mux(ساخت ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = تہی;
}

صحیح
ssh_packet_get_mux(ساخت ssh *ssh)
{
	واپس ssh->state->mux;
}

صحیح
ssh_packet_سیٹ_log_preamble(ساخت ssh *ssh, ثابت حرف *fmt, ...)
{
	va_list دلائل;
	صحیح r;

	آزاد(ssh->log_preamble);
	اگر (fmt == تہی)
		ssh->log_preamble = تہی;
	ورنہ {
		va_start(دلائل, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, دلائل);
		va_end(دلائل);
		اگر (r < 0 || ssh->log_preamble == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
	}
	واپس 0;
}

صحیح
ssh_packet_stop_discard(ساخت ssh *ssh)
{
	ساخت session_state *state = ssh->state;
	صحیح r;

	اگر (state->packet_discard_mac) {
		حرف buf[1024];
		سائز_t dlen = PACKET_MAX_سائز;

		اگر (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', حجم(buf));
		جب (sshbuf_len(state->incoming_packet) < dlen)
			اگر ((r = sshbuf_put(state->incoming_packet, buf,
			    حجم(buf))) != 0)
				واپس r;
		(خالی) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    تہی, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
	واپس SSH_ERR_MAC_INVALID;
}

ساکن صحیح
ssh_packet_آغاز_discard(ساخت ssh *ssh, ساخت sshenc *enc,
    ساخت sshmac *mac, سائز_t mac_already, u_int discard)
{
	ساخت session_state *state = ssh->state;
	صحیح r;

	اگر (enc == تہی || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		اگر ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			واپس r;
		واپس SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	اگر (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	اگر (sshbuf_len(state->داخلہ) >= discard)
		واپس ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->داخلہ);
	واپس 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

صحیح
ssh_packet_connection_is_on_socket(ساخت ssh *ssh)
{
	ساخت session_state *state;
	ساخت sockaddr_storage from, مقصد;
	socklen_t fromlen, tolen;

	اگر (ssh == تہی || ssh->state == تہی)
		واپس 0;

	state = ssh->state;
	اگر (state->connection_اندر == -1 || state->connection_برآمد == -1)
		واپس 0;
	fromlen = حجم(from);
	memset(&from, 0, حجم(from));
	اگر (getpeername(state->connection_اندر, (ساخت sockaddr *)&from,
	    &fromlen) == -1)
		واپس 0;
	اگر (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		واپس 0;
	/* filedescriptors in and out are the same, so it's a socket */
	اگر (state->connection_اندر == state->connection_برآمد)
		واپس 1;
	tolen = حجم(مقصد);
	memset(&مقصد, 0, حجم(مقصد));
	اگر (getpeername(state->connection_برآمد, (ساخت sockaddr *)&مقصد,
	    &tolen) == -1)
		واپس 0;
	اگر (fromlen != tolen || memcmp(&from, &مقصد, fromlen) != 0)
		واپس 0;
	واپس 1;
}

خالی
ssh_packet_get_بائٹیں(ساخت ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	اگر (ibytes)
		*ibytes = ssh->state->p_read.بائٹیں;
	اگر (obytes)
		*obytes = ssh->state->p_send.بائٹیں;
}

صحیح
ssh_packet_connection_af(ساخت ssh *ssh)
{
	واپس get_sock_af(ssh->state->connection_برآمد);
}

/* Sets the connection into non-blocking mode. */

خالی
ssh_packet_سیٹ_nonblocking(ساخت ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	سیٹ_nonblock(ssh->state->connection_اندر);

	اگر (ssh->state->connection_برآمد != ssh->state->connection_اندر)
		سیٹ_nonblock(ssh->state->connection_برآمد);
}

/* Returns the socket used for reading. */

صحیح
ssh_packet_get_connection_اندر(ساخت ssh *ssh)
{
	واپس ssh->state->connection_اندر;
}

/* Returns the descriptor used for writing. */

صحیح
ssh_packet_get_connection_برآمد(ساخت ssh *ssh)
{
	واپس ssh->state->connection_برآمد;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

ثابت حرف *
ssh_remote_ipaddr(ساخت ssh *ssh)
{
	صحیح sock;

	/* Check whether we have cached the ipaddr. */
	اگر (ssh->remote_ipaddr == تہی) {
		اگر (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_اندر;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_پورٹ = get_peer_پورٹ(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_پورٹ = get_local_پورٹ(sock);
		} ورنہ {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_پورٹ = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_پورٹ = 65535;
		}
	}
	واپس ssh->remote_ipaddr;
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
ssh_remote_hostname(ساخت ssh *ssh)
{
	ساخت sockaddr_storage from;
	socklen_t fromlen;
	ساخت addrinfo hints, *ai, *aitop;
	حرف name[NI_MAXHOST], ntop2[NI_MAXHOST];
	ثابت حرف *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = حجم(from);
	memset(&from, 0, حجم(from));
	اگر (getpeername(ssh_packet_get_connection_اندر(ssh),
	    (ساخت sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		واپس xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	اگر (from.ss_family == AF_INET6)
		fromlen = حجم(ساخت sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	اگر (getnameinfo((ساخت sockaddr *)&from, fromlen, name, حجم(name),
	    تہی, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		واپس xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, حجم(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	اگر (getaddrinfo(name, تہی, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		واپس xstrdup(ntop);
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
	اگر (getaddrinfo(name, تہی, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		واپس xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	برائے (ai = aitop; ai; ai = ai->ai_next) {
		اگر (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    حجم(ntop2), تہی, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				توڑو;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	اگر (ai == تہی) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		واپس xstrdup(ntop);
	}
	واپس xstrdup(name);
}

/* Returns the port number of the remote host. */

صحیح
ssh_remote_پورٹ(ساخت ssh *ssh)
{
	(خالی)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	واپس ssh->remote_پورٹ;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

ثابت حرف *
ssh_local_ipaddr(ساخت ssh *ssh)
{
	(خالی)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	واپس ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

صحیح
ssh_local_پورٹ(ساخت ssh *ssh)
{
	(خالی)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	واپس ssh->local_پورٹ;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
ثابت حرف *
ssh_packet_rdomain_اندر(ساخت ssh *ssh)
{
	اگر (ssh->rdomain_اندر != تہی)
		واپس ssh->rdomain_اندر;
	اگر (!ssh_packet_connection_is_on_socket(ssh))
		واپس تہی;
	ssh->rdomain_اندر = get_rdomain(ssh->state->connection_اندر);
	واپس ssh->rdomain_اندر;
}

/* Closes the connection and clears and frees internal data structures. */

ساکن خالی
ssh_packet_close_اندرونی(ساخت ssh *ssh, صحیح do_close)
{
	ساخت session_state *state = ssh->state;
	u_int منوال;
	ساخت packet *p;

	اگر (!state->initialized)
		واپس;
	state->initialized = 0;
	اگر (do_close) {
		اگر (state->connection_اندر == state->connection_برآمد) {
			close(state->connection_برآمد);
		} ورنہ {
			close(state->connection_اندر);
			close(state->connection_برآمد);
		}
	}
	sshbuf_free(state->داخلہ);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	جب ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, اگلا);
		آزاد(p);
	}
	برائے (منوال = 0; منوال < منوال_MAX; منوال++) {
		kex_free_newkeys(state->newkeys[منوال]);	/* current keys */
		state->newkeys[منوال] = تہی;
		ssh_clear_newkeys(ssh, منوال);		/* next keys */
	}
#اگر_تعریف_شدہ WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	اگر (do_close && state->compression_بفر) {
		sshbuf_free(state->compression_بفر);
		اگر (state->compression_برآمد_started) {
			z_streamp دھارا = &state->compression_برآمد_دھارا;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(غیرعلامتی طویل طویل)دھارا->کل_اندر,
				(غیرعلامتی طویل طویل)دھارا->کل_برآمد,
				دھارا->کل_اندر == 0 ? 0.0 :
				(دوہرا) دھارا->کل_برآمد / دھارا->کل_اندر);
			اگر (state->compression_برآمد_failures == 0)
				deflate_انتہا(دھارا);
		}
		اگر (state->compression_اندر_started) {
			z_streamp دھارا = &state->compression_اندر_دھارا;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (غیرعلامتی طویل طویل)دھارا->کل_برآمد,
			    (غیرعلامتی طویل طویل)دھارا->کل_اندر,
			    دھارا->کل_برآمد == 0 ? 0.0 :
			    (دوہرا) دھارا->کل_اندر / دھارا->کل_برآمد);
			اگر (state->compression_اندر_failures == 0)
				inflate_انتہا(دھارا);
		}
	}
#اگر_ختم	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = تہی;
	اگر (do_close) {
		آزاد(ssh->local_ipaddr);
		ssh->local_ipaddr = تہی;
		آزاد(ssh->remote_ipaddr);
		ssh->remote_ipaddr = تہی;
		آزاد(ssh->state);
		ssh->state = تہی;
		kex_free(ssh->kex);
		ssh->kex = تہی;
	}
}

خالی
ssh_packet_free(ساخت ssh *ssh)
{
	ssh_packet_close_اندرونی(ssh, 1);
	freezero(ssh, حجم(*ssh));
}

خالی
ssh_packet_close(ساخت ssh *ssh)
{
	ssh_packet_close_اندرونی(ssh, 1);
}

خالی
ssh_packet_clear_کلیدیں(ساخت ssh *ssh)
{
	ssh_packet_close_اندرونی(ssh, 0);
}

/* Sets remote side protocol flags. */

خالی
ssh_packet_سیٹ_protocol_flags(ساخت ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(ساخت ssh *ssh)
{
	واپس ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

ساکن صحیح
ssh_packet_init_compression(ساخت ssh *ssh)
{
	اگر (!ssh->state->compression_بفر &&
	    ((ssh->state->compression_بفر = sshbuf_new()) == تہی))
		واپس SSH_ERR_ALLOC_FAIL;
	واپس 0;
}

#اگر_تعریف_شدہ WITH_ZLIB
ساکن صحیح
آغاز_compression_برآمد(ساخت ssh *ssh)
{
	debug("Enabling compression.");
	اگر (ssh->state->compression_برآمد_started == 1)
		deflate_انتہا(&ssh->state->compression_برآمد_دھارا);
	انتخاب (deflateInit2(&ssh->state->compression_برآمد_دھارا,
	    Z_بہترین_رفتار, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	حالت Z_OK:
		ssh->state->compression_برآمد_started = 1;
		توڑو;
	حالت Z_MEM_ERROR:
		واپس SSH_ERR_ALLOC_FAIL;
	طےشدہ:
		واپس SSH_ERR_اندرونی_ERROR;
	}
	واپس 0;
}

ساکن صحیح
آغاز_compression_اندر(ساخت ssh *ssh)
{
	اگر (ssh->state->compression_اندر_started == 1)
		inflate_انتہا(&ssh->state->compression_اندر_دھارا);
	انتخاب (inflateInit(&ssh->state->compression_اندر_دھارا)) {
	حالت Z_OK:
		ssh->state->compression_اندر_started = 1;
		توڑو;
	حالت Z_MEM_ERROR:
		واپس SSH_ERR_ALLOC_FAIL;
	طےشدہ:
		واپس SSH_ERR_اندرونی_ERROR;
	}
	واپس 0;
}

/* XXX remove need for separate compression buffer */
ساکن صحیح
compress_بفر(ساخت ssh *ssh, ساخت sshbuf *اندر, ساخت sshbuf *برآمد)
{
	u_char buf[4096];
	صحیح r, حالت_2;

	اگر (ssh->state->compression_برآمد_started != 1)
		واپس SSH_ERR_اندرونی_ERROR;

	/* This case is not handled below. */
	اگر (sshbuf_len(اندر) == 0)
		واپس 0;

	/* Input is the contents of the input buffer. */
	اگر ((ssh->state->compression_برآمد_دھارا.اگلا_اندر =
	    sshbuf_mutable_ptr(اندر)) == تہی)
		واپس SSH_ERR_اندرونی_ERROR;
	ssh->state->compression_برآمد_دھارا.avail_اندر = sshbuf_len(اندر);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	کرو {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_برآمد_دھارا.اگلا_برآمد = buf;
		ssh->state->compression_برآمد_دھارا.avail_برآمد = حجم(buf);

		/* Compress as much data into the buffer as possible. */
		حالت_2 = deflate(&ssh->state->compression_برآمد_دھارا,
		    Z_PARTIAL_FLUSH);
		انتخاب (حالت_2) {
		حالت Z_MEM_ERROR:
			واپس SSH_ERR_ALLOC_FAIL;
		حالت Z_OK:
			/* Append compressed data to output_buffer. */
			اگر ((r = sshbuf_put(برآمد, buf, حجم(buf) -
			    ssh->state->compression_برآمد_دھارا.avail_برآمد)) != 0)
				واپس r;
			توڑو;
		حالت Z_دھارا_ERROR:
		طےشدہ:
			ssh->state->compression_برآمد_failures++;
			واپس SSH_ERR_INVALID_FORMAT;
		}
	} جب (ssh->state->compression_برآمد_دھارا.avail_برآمد == 0);
	واپس 0;
}

ساکن صحیح
uncompress_بفر(ساخت ssh *ssh, ساخت sshbuf *اندر, ساخت sshbuf *برآمد)
{
	u_char buf[4096];
	صحیح r, حالت_2;

	اگر (ssh->state->compression_اندر_started != 1)
		واپس SSH_ERR_اندرونی_ERROR;

	اگر ((ssh->state->compression_اندر_دھارا.اگلا_اندر =
	    sshbuf_mutable_ptr(اندر)) == تہی)
		واپس SSH_ERR_اندرونی_ERROR;
	ssh->state->compression_اندر_دھارا.avail_اندر = sshbuf_len(اندر);

	برائے (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_اندر_دھارا.اگلا_برآمد = buf;
		ssh->state->compression_اندر_دھارا.avail_برآمد = حجم(buf);

		حالت_2 = inflate(&ssh->state->compression_اندر_دھارا,
		    Z_SYNC_FLUSH);
		انتخاب (حالت_2) {
		حالت Z_OK:
			اگر ((r = sshbuf_put(برآمد, buf, حجم(buf) -
			    ssh->state->compression_اندر_دھارا.avail_برآمد)) != 0)
				واپس r;
			اگر (sshbuf_len(برآمد) >= PACKET_MAX_سائز)
				واپس SSH_ERR_INVALID_FORMAT;
			توڑو;
		حالت Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			واپس 0;
		حالت Z_ڈیٹا_ERROR:
			واپس SSH_ERR_INVALID_FORMAT;
		حالت Z_MEM_ERROR:
			واپس SSH_ERR_ALLOC_FAIL;
		حالت Z_دھارا_ERROR:
		طےشدہ:
			ssh->state->compression_اندر_failures++;
			واپس SSH_ERR_اندرونی_ERROR;
		}
	}
	/* NOTREACHED */
}

#ورنہ	/* WITH_ZLIB */

ساکن صحیح
آغاز_compression_برآمد(ساخت ssh *ssh)
{
	واپس SSH_ERR_اندرونی_ERROR;
}

ساکن صحیح
آغاز_compression_اندر(ساخت ssh *ssh)
{
	واپس SSH_ERR_اندرونی_ERROR;
}

ساکن صحیح
compress_بفر(ساخت ssh *ssh, ساخت sshbuf *اندر, ساخت sshbuf *برآمد)
{
	واپس SSH_ERR_اندرونی_ERROR;
}

ساکن صحیح
uncompress_بفر(ساخت ssh *ssh, ساخت sshbuf *اندر, ساخت sshbuf *برآمد)
{
	واپس SSH_ERR_اندرونی_ERROR;
}
#اگر_ختم	/* WITH_ZLIB */

خالی
ssh_clear_newkeys(ساخت ssh *ssh, صحیح منوال)
{
	اگر (ssh->kex && ssh->kex->newkeys[منوال]) {
		kex_free_newkeys(ssh->kex->newkeys[منوال]);
		ssh->kex->newkeys[منوال] = تہی;
	}
}

صحیح
ssh_سیٹ_newkeys(ساخت ssh *ssh, صحیح منوال)
{
	ساخت session_state *state = ssh->state;
	ساخت sshenc *enc;
	ساخت sshmac *mac;
	ساخت sshcomp *comp;
	ساخت sshcipher_ctx **ccp;
	ساخت packet_state *ps;
	uint64_t *max_بلاکیں, *hard_max_بلاکیں;
	ثابت حرف *wmsg;
	صحیح r, crypt_type;
	ثابت حرف *dir = منوال == منوال_برآمد ? "out" : "in";

	debug2_f("mode %d", منوال);

	اگر (منوال == منوال_برآمد) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_بلاکیں = &state->hard_max_بلاکیں_برآمد;
		max_بلاکیں = &state->max_بلاکیں_برآمد;
	} ورنہ {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_بلاکیں = &state->hard_max_بلاکیں_اندر;
		max_بلاکیں = &state->max_بلاکیں_اندر;
	}
	اگر (state->newkeys[منوال] != تہی) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (غیرعلامتی طویل طویل)state->p_read.بائٹیں,
		    (غیرعلامتی طویل طویل)state->p_read.بلاکیں,
		    (غیرعلامتی طویل طویل)state->p_send.بائٹیں,
		    (غیرعلامتی طویل طویل)state->p_send.بلاکیں);
		kex_free_newkeys(state->newkeys[منوال]);
		state->newkeys[منوال] = تہی;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->بلاکیں = 0;
	/* move newkeys from kex to state */
	اگر ((state->newkeys[منوال] = ssh->kex->newkeys[منوال]) == تہی)
		واپس SSH_ERR_اندرونی_ERROR;
	ssh->kex->newkeys[منوال] = تہی;
	enc  = &state->newkeys[منوال]->enc;
	mac  = &state->newkeys[منوال]->mac;
	comp = &state->newkeys[منوال]->comp;
	اگر (cipher_authlen(enc->cipher) == 0) {
		اگر ((r = mac_init(mac)) != 0)
			واپس r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = تہی;
	اگر ((r = cipher_init(ccp, enc->cipher, enc->کلید, enc->کلید_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		واپس r;
	اگر (!state->cipher_warning_مکمل &&
	    (wmsg = cipher_warning_پیغام(*ccp)) != تہی) {
		error("Warning: %s", wmsg);
		state->cipher_warning_مکمل = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	اگر (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		اگر ((r = ssh_packet_init_compression(ssh)) < 0)
			واپس r;
		اگر (منوال == منوال_برآمد) {
			اگر ((r = آغاز_compression_برآمد(ssh)) != 0)
				واپس r;
		} ورنہ {
			اگر ((r = آغاز_compression_اندر(ssh)) != 0)
				واپس r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	اگر (enc->بلاک_سائز >= 16)
		*hard_max_بلاکیں = (uint64_t)1 << (enc->بلاک_سائز*2);
	ورنہ
		*hard_max_بلاکیں = ((uint64_t)1 << 30) / enc->بلاک_سائز;
	*max_بلاکیں = *hard_max_بلاکیں;
	اگر (state->rekey_حد_بندی) {
		*max_بلاکیں = MINIMUM(*max_بلاکیں,
		    state->rekey_حد_بندی / enc->بلاک_سائز);
	}
	debug("rekey %s after %llu blocks", dir,
	    (غیرعلامتی طویل طویل)*max_بلاکیں);
	واپس 0;
}

#تعریف_کرو MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
ساکن اندرونی صحیح
ssh_packet_check_rekey_blocklimit(ساخت ssh *ssh, u_int packet_len, صحیح hard)
{
	ساخت session_state *state = ssh->state;
	uint32_t برآمد_بلاکیں;
	ثابت uint64_t max_بلاکیں_اندر = hard ?
	    state->hard_max_بلاکیں_اندر : state->max_بلاکیں_اندر;
	ثابت uint64_t max_بلاکیں_برآمد = hard ?
	    state->hard_max_بلاکیں_برآمد : state->max_بلاکیں_برآمد;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	اگر (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		واپس 1;

	اگر (state->newkeys[منوال_برآمد] == تہی)
		واپس 0;

	/* Rekey after (cipher-specific) maximum blocks */
	برآمد_بلاکیں = ROUNDUP(packet_len,
	    state->newkeys[منوال_برآمد]->enc.بلاک_سائز);
	واپس (max_بلاکیں_برآمد &&
	    (state->p_send.بلاکیں + برآمد_بلاکیں > max_بلاکیں_برآمد)) ||
	    (max_بلاکیں_اندر &&
	    (state->p_read.بلاکیں > max_بلاکیں_اندر));
}

ساکن صحیح
ssh_packet_need_rekeying(ساخت ssh *ssh, u_int outbound_packet_len)
{
	ساخت session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	اگر (!state->after_authentication)
		واپس 0;

	/* Haven't keyed yet or KEX in progress. */
	اگر (ssh_packet_is_rekeying(ssh))
		واپس 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	اگر (state->p_send.packets == 0 && state->p_read.packets == 0)
		واپس 0;

	/* Time-based rekeying */
	اگر (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_وقت + state->rekey_interval <= monotime())
		واپس 1;

	واپس ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
ساکن صحیح
ssh_packet_check_rekey_preauth(ساخت ssh *ssh, u_int outgoing_packet_len)
{
	اگر (ssh->state->after_authentication)
		واپس 0;

	اگر (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		واپس SSH_ERR_NEED_REKEY;
	}
	واپس 0;
}

صحیح
ssh_packet_check_rekey(ساخت ssh *ssh)
{
	صحیح r;

	اگر ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		واپس r;
	اگر (!ssh_packet_need_rekeying(ssh, 0))
		واپس 0;
	debug3_f("rekex triggered");
	واپس kex_آغاز_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
ساکن صحیح
ssh_packet_enable_delayed_compress(ساخت ssh *ssh)
{
	ساخت session_state *state = ssh->state;
	ساخت sshcomp *comp = تہی;
	صحیح r, منوال;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	برائے (منوال = 0; منوال < منوال_MAX; منوال++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		اگر (state->newkeys[منوال] == تہی)
			جاری;
		comp = &state->newkeys[منوال]->comp;
		اگر (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			اگر ((r = ssh_packet_init_compression(ssh)) != 0)
				واپس r;
			اگر (منوال == منوال_برآمد) {
				اگر ((r = آغاز_compression_برآمد(ssh)) != 0)
					واپس r;
			} ورنہ {
				اگر ((r = آغاز_compression_اندر(ssh)) != 0)
					واپس r;
			}
			comp->enabled = 1;
		}
	}
	واپس 0;
}

/* Used to mute debug logging for noisy packet types */
صحیح
ssh_packet_log_type(u_char type)
{
	انتخاب (type) {
	حالت SSH2_پیغام_PING:
	حالت SSH2_پیغام_PONG:
	حالت SSH2_پیغام_CHANNEL_ڈیٹا:
	حالت SSH2_پیغام_CHANNEL_EXTENDED_ڈیٹا:
	حالت SSH2_پیغام_CHANNEL_کھڑکی_ADJUST:
		واپس 0;
	طےشدہ:
		واپس 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
صحیح
ssh_packet_send2_wrapped(ساخت ssh *ssh)
{
	ساخت session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_لمبائی];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	ساخت sshenc *enc   = تہی;
	ساخت sshmac *mac   = تہی;
	ساخت sshcomp *comp = تہی;
	صحیح r, بلاک_سائز;

	اگر (state->newkeys[منوال_برآمد] != تہی) {
		enc  = &state->newkeys[منوال_برآمد]->enc;
		mac  = &state->newkeys[منوال_برآمد]->mac;
		comp = &state->newkeys[منوال_برآمد]->comp;
		/* disable mac for authenticated encryption */
		اگر ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = تہی;
	}
	بلاک_سائز = enc ? enc->بلاک_سائز : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	اگر (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#اگر_تعریف_شدہ PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#اگر_ختم

	اگر (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		اگر ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			جاؤ برآمد;
		sshbuf_reset(state->compression_بفر);
		اگر ((r = compress_بفر(ssh, state->outgoing_packet,
		    state->compression_بفر)) != 0)
			جاؤ برآمد;
		sshbuf_reset(state->outgoing_packet);
		اگر ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_بفر)) != 0)
			جاؤ برآمد;
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
	padlen = بلاک_سائز - (len % بلاک_سائز);
	اگر (padlen < 4)
		padlen += بلاک_سائز;
	اگر (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, بلاک_سائز);
		/* check if roundup overflowed */
		اگر (state->extra_pad < tmp)
			واپس SSH_ERR_INVALID_دلیل;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		اگر (tmp > state->extra_pad)
			واپس SSH_ERR_INVALID_دلیل;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		اگر (padlen < tmp)
			واپس SSH_ERR_INVALID_دلیل; /*حد_سے_تجاوز*/
		state->extra_pad = 0;
	}
	اگر ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		جاؤ برآمد;
	اگر (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} ورنہ {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	اگر (cp == تہی) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
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
		    macbuf, حجم(macbuf))) != 0)
			جاؤ برآمد;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	اگر ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		جاؤ برآمد;
	اگر ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		جاؤ برآمد;
	/* append unencrypted MAC */
	اگر (mac && mac->enabled) {
		اگر (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			اگر ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, حجم(macbuf))) != 0)
				جاؤ برآمد;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		اگر ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			جاؤ برآمد;
	}
#اگر_تعریف_شدہ PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#اگر_ختم
	/* increment sequence number for outgoing packets */
	اگر (++state->p_send.seqnr == 0) {
		اگر ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	اگر (++state->p_send.packets == 0)
		واپس SSH_ERR_NEED_REKEY;
	state->p_send.بلاکیں += len / بلاک_سائز;
	state->p_send.بائٹیں += len;
	sshbuf_reset(state->outgoing_packet);

	اگر (type == SSH2_پیغام_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	اگر (type == SSH2_پیغام_NEWKEYS)
		r = ssh_سیٹ_newkeys(ssh, منوال_برآمد);
	ورنہ اگر (type == SSH2_پیغام_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	ورنہ
		r = 0;
 برآمد:
	واپس r;
}

/* returns non-zero if the specified packet type is usec by KEX */
ساکن صحیح
ssh_packet_type_is_kex(u_char type)
{
	واپس
	    type >= SSH2_پیغام_TRANSPORT_MIN &&
	    type <= SSH2_پیغام_TRANSPORT_MAX &&
	    type != SSH2_پیغام_SERVICE_REQUEST &&
	    type != SSH2_پیغام_SERVICE_ACCEPT &&
	    type != SSH2_پیغام_EXT_INFO;
}

صحیح
ssh_packet_send2(ساخت ssh *ssh)
{
	ساخت session_state *state = ssh->state;
	ساخت packet *p;
	u_char type;
	صحیح r, need_rekey;

	اگر (sshbuf_len(state->outgoing_packet) < 6)
		واپس SSH_ERR_اندرونی_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	اگر (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		واپس r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	اگر ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		اگر (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = صفر_حافظہ_دو(1, حجم(*p));
		اگر (p == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, اگلا);
		state->outgoing_packet = sshbuf_new();
		اگر (state->outgoing_packet == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
		اگر (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			واپس kex_آغاز_rekex(ssh);
		}
		واپس 0;
	}

	/* rekeying starts with sending KEXINIT */
	اگر (type == SSH2_پیغام_KEXINIT)
		state->rekeying = 1;

	اگر ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		واپس r;

	/* after a NEWKEYS message we can send the complete queue */
	اگر (type == SSH2_پیغام_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_وقت = monotime();
		جب ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			اگر (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				واپس kex_آغاز_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, اگلا);
			memset(p, 0, حجم(*p));
			آزاد(p);
			اگر ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				واپس r;
		}
	}
	واپس 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

صحیح
ssh_packet_read_seqnr(ساخت ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ساخت session_state *state = ssh->state;
	صحیح len, r, ms_remain = 0;
	ساخت pollfd pfd;
	حرف buf[8192];
	ساخت timeval آغاز;
	ساخت timespec timespec, *timespecp = تہی;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	اگر ((r = ssh_packet_write_wait(ssh)) != 0)
		جاؤ برآمد;

	/* Stay in the loop until we have received a complete packet. */
	برائے (;;) {
		/* Try to read a packet from the buffer. */
		اگر ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			توڑو;
		/* If we got a packet, return it. */
		اگر (*typep != SSH_پیغام_NONE)
			توڑو;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_اندر;
		pfd.events = POLLIN;

		اگر (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		برائے (;;) {
			اگر (state->packet_timeout_ms > 0) {
				ms_مقصد_timespec(&timespec, ms_remain);
				monotime_tv(&آغاز);
			}
			اگر ((r = ppoll(&pfd, 1, timespecp, تہی)) >= 0)
				توڑو;
			اگر (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				جاؤ برآمد;
			}
			اگر (state->packet_timeout_ms <= 0)
				جاری;
			ms_تفریق_diff(&آغاز, &ms_remain);
			اگر (ms_remain <= 0) {
				r = 0;
				توڑو;
			}
		}
		اگر (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			جاؤ برآمد;
		}
		/* Read data from the socket. */
		len = اقرأ(state->connection_اندر, buf, حجم(buf));
		اگر (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			جاؤ برآمد;
		}
		اگر (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			جاؤ برآمد;
		}

		/* Append it to the buffer. */
		اگر ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			جاؤ برآمد;
	}
 برآمد:
	واپس r;
}

صحیح
ssh_packet_read(ساخت ssh *ssh)
{
	u_char type;
	صحیح r;

	اگر ((r = ssh_packet_read_seqnr(ssh, &type, تہی)) != 0)
		sshpkt_fatal(ssh, r, "read");
	واپس type;
}

ساکن صحیح
ssh_packet_read_poll2_mux(ساخت ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ساخت session_state *state = ssh->state;
	ثابت u_char *cp;
	سائز_t need;
	صحیح r;

	اگر (ssh->kex)
		واپس SSH_ERR_اندرونی_ERROR;
	*typep = SSH_پیغام_NONE;
	cp = sshbuf_ptr(state->داخلہ);
	اگر (state->packlen == 0) {
		اگر (sshbuf_len(state->داخلہ) < 4 + 1)
			واپس 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		اگر (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_سائز)
			واپس SSH_ERR_پیغام_INCOMPLETE;
	}
	need = state->packlen + 4;
	اگر (sshbuf_len(state->داخلہ) < need)
		واپس 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	اگر ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->داخلہ, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, تہی)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		واپس r;
	اگر (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	واپس r;
}

صحیح
ssh_packet_read_poll2(ساخت ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ساخت session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, بلاک_سائز;
	ساخت sshenc *enc   = تہی;
	ساخت sshmac *mac   = تہی;
	ساخت sshcomp *comp = تہی;
	صحیح r;

	اگر (state->mux)
		واپس ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_پیغام_NONE;

	اگر (state->packet_discard)
		واپس 0;

	اگر (state->newkeys[منوال_اندر] != تہی) {
		enc  = &state->newkeys[منوال_اندر]->enc;
		mac  = &state->newkeys[منوال_اندر]->mac;
		comp = &state->newkeys[منوال_اندر]->comp;
		/* disable mac for authenticated encryption */
		اگر ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = تہی;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	بلاک_سائز = enc ? enc->بلاک_سائز : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	اگر (aadlen && state->packlen == 0) {
		اگر (cipher_get_لمبائی(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->داخلہ), sshbuf_len(state->داخلہ)) != 0)
			واپس 0;
		اگر (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_سائز) {
#اگر_تعریف_شدہ PACKET_DEBUG
			sshbuf_dump(state->داخلہ, stderr);
#اگر_ختم
			logit("Bad packet length %u.", state->packlen);
			اگر ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				واپس r;
			واپس SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} ورنہ اگر (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		اگر (sshbuf_len(state->داخلہ) < بلاک_سائز)
			واپس 0;
		sshbuf_reset(state->incoming_packet);
		اگر ((r = sshbuf_reserve(state->incoming_packet, بلاک_سائز,
		    &cp)) != 0)
			جاؤ برآمد;
		اگر ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->داخلہ),
		    بلاک_سائز, 0, 0)) != 0)
			جاؤ برآمد;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		اگر (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_سائز) {
#اگر_تعریف_شدہ PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->داخلہ, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#اگر_ختم
			logit("Bad packet length %u.", state->packlen);
			واپس ssh_packet_آغاز_discard(ssh, enc, mac, 0,
			    PACKET_MAX_سائز);
		}
		اگر ((r = sshbuf_consume(state->داخلہ, بلاک_سائز)) != 0)
			جاؤ برآمد;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	اگر (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} ورنہ {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - بلاک_سائز;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", بلاک_سائز, need, maclen, authlen, aadlen));
	اگر (need % بلاک_سائز != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, بلاک_سائز, need % بلاک_سائز);
		واپس ssh_packet_آغاز_discard(ssh, enc, mac, 0,
		    PACKET_MAX_سائز - بلاک_سائز);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet:
	 * 'aadlen' bytes are unencrypted, but authenticated.
	 * 'need' bytes are encrypted, followed by either
	 * 'authlen' bytes of authentication tag or
	 * 'maclen' bytes of message authentication code.
	 */
	اگر (sshbuf_len(state->داخلہ) < aadlen + need + authlen + maclen)
		واپس 0; /* packet is incomplete */
#اگر_تعریف_شدہ PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->داخلہ, stderr);
#اگر_ختم
	/* EtM: check mac over encrypted input */
	اگر (mac && mac->enabled && mac->etm) {
		اگر ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->داخلہ), aadlen + need,
		    sshbuf_ptr(state->داخلہ) + aadlen + need + authlen,
		    maclen)) != 0) {
			اگر (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			جاؤ برآمد;
		}
	}
	اگر ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		جاؤ برآمد;
	اگر ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->داخلہ), need, aadlen, authlen)) != 0)
		جاؤ برآمد;
	اگر ((r = sshbuf_consume(state->داخلہ, aadlen + need + authlen)) != 0)
		جاؤ برآمد;
	اگر (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		اگر (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->داخلہ), maclen)) != 0) {
			اگر (r != SSH_ERR_MAC_INVALID)
				جاؤ برآمد;
			logit("Corrupted MAC on input.");
			اگر (need + بلاک_سائز > PACKET_MAX_سائز)
				واپس SSH_ERR_اندرونی_ERROR;
			واپس ssh_packet_آغاز_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_سائز - need - بلاک_سائز);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		اگر ((r = sshbuf_consume(state->داخلہ, mac->mac_len)) != 0)
			جاؤ برآمد;
	}

	اگر (seqnr_p != تہی)
		*seqnr_p = state->p_read.seqnr;
	اگر (++state->p_read.seqnr == 0) {
		اگر ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	اگر (++state->p_read.packets == 0)
		واپس SSH_ERR_NEED_REKEY;
	state->p_read.بلاکیں += (state->packlen + 4) / بلاک_سائز;
	state->p_read.بائٹیں += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	اگر (padlen < 4)	{
		اگر ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			واپس r;
		واپس SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	اگر ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_انتہا(state->incoming_packet, padlen)) != 0))
		جاؤ برآمد;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	اگر (comp && comp->enabled) {
		sshbuf_reset(state->compression_بفر);
		اگر ((r = uncompress_بفر(ssh, state->incoming_packet,
		    state->compression_بفر)) != 0)
			جاؤ برآمد;
		sshbuf_reset(state->incoming_packet);
		اگر ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_بفر)) != 0)
			جاؤ برآمد;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	اگر ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		جاؤ برآمد;
	اگر (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	اگر (*typep < SSH2_پیغام_MIN) {
		اگر ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			واپس r;
		واپس SSH_ERR_PROTOCOL_ERROR;
	}
	اگر (state->hook_اندر != تہی &&
	    (r = state->hook_اندر(ssh, state->incoming_packet, typep,
	    state->hook_اندر_ctx)) != 0)
		واپس r;
	اگر (*typep == SSH2_پیغام_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	ورنہ
		r = 0;
#اگر_تعریف_شدہ PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#اگر_ختم
	/* reset for next packet */
	state->packlen = 0;
	اگر (*typep == SSH2_پیغام_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	اگر ((r = ssh_packet_check_rekey(ssh)) != 0)
		واپس r;
 برآمد:
	واپس r;
}

صحیح
ssh_packet_read_poll_seqnr(ساخت ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	ساخت session_state *state = ssh->state;
	u_int reason, seqnr;
	صحیح r;
	u_char *پیغام;
	ثابت u_char *d;
	سائز_t len;

	برائے (;;) {
		پیغام = تہی;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		اگر (r != 0)
			واپس r;
		اگر (*typep == 0) {
			/* no message ready */
			واپس 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		اگر (*typep == SSH2_پیغام_DISCONNECT) {
			اگر ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &پیغام, تہی)) != 0)
				واپس r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_پورٹ(ssh), reason, پیغام);
			آزاد(پیغام);
			واپس SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		اگر (ssh->kex != تہی &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			واپس 0;
		/* Implicitly handle transport-level messages */
		انتخاب (*typep) {
		حالت SSH2_پیغام_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			توڑو;
		حالت SSH2_پیغام_DEBUG:
			اگر ((r = sshpkt_get_u8(ssh, تہی)) != 0 ||
			    (r = sshpkt_get_string(ssh, &پیغام, تہی)) != 0 ||
			    (r = sshpkt_get_string(ssh, تہی, تہی)) != 0) {
				آزاد(پیغام);
				واپس r;
			}
			debug("Remote: %.900s", پیغام);
			آزاد(پیغام);
			توڑو;
		حالت SSH2_پیغام_UNIMPLEMENTED:
			اگر ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				واپس r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			توڑو;
		حالت SSH2_پیغام_PING:
			اگر ((r = sshpkt_get_string_براہ_راست(ssh, &d, &len)) != 0)
				واپس r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			اگر (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				توڑو;
			}
			اگر (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				توڑو;
			}
			اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				واپس r;
			توڑو;
		حالت SSH2_پیغام_PONG:
			اگر ((r = sshpkt_get_string_براہ_راست(ssh,
			    تہی, &len)) != 0)
				واپس r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			توڑو;
		طےشدہ:
			اگر (ssh->kex != تہی &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				واپس SSH_ERR_PROTOCOL_ERROR;
			}
			واپس 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
صحیح
ssh_packet_process_incoming(ساخت ssh *ssh, ثابت حرف *buf, u_int len)
{
	ساخت session_state *state = ssh->state;
	صحیح r;

	اگر (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		اگر (len >= state->packet_discard) {
			اگر ((r = ssh_packet_stop_discard(ssh)) != 0)
				واپس r;
		}
		state->packet_discard -= len;
		واپس 0;
	}
	اگر ((r = sshbuf_put(state->داخلہ, buf, len)) != 0)
		واپس r;

	واپس 0;
}

/* Reads and buffers data from the specified fd */
صحیح
ssh_packet_process_read(ساخت ssh *ssh, صحیح fd)
{
	ساخت session_state *state = ssh->state;
	صحیح r;
	سائز_t rlen;

	اگر ((r = sshbuf_read(fd, state->داخلہ, PACKET_MAX_سائز, &rlen)) != 0)
		واپس r;

	اگر (state->packet_discard) {
		اگر ((r = sshbuf_consume_انتہا(state->داخلہ, rlen)) != 0)
			واپس r;
		state->keep_alive_timeouts = 0; /* ?? */
		اگر (rlen >= state->packet_discard) {
			اگر ((r = ssh_packet_stop_discard(ssh)) != 0)
				واپس r;
		}
		state->packet_discard -= rlen;
		واپس 0;
	}
	واپس 0;
}

صحیح
ssh_packet_بقایا(ساخت ssh *ssh)
{
	واپس sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
خالی
ssh_packet_send_debug(ساخت ssh *ssh, ثابت حرف *fmt,...)
{
	حرف buf[1024];
	va_list دلائل;
	صحیح r;

	اگر ((ssh->compat & SSH_BUG_DEBUG))
		واپس;

	va_start(دلائل, fmt);
	vsnprintf(buf, حجم(buf), fmt, دلائل);
	va_end(دلائل);

	debug3("sending debug message: %s", buf);

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

خالی
sshpkt_fmt_connection_id(ساخت ssh *ssh, حرف *s, سائز_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
ساکن خالی
sshpkt_vfatal(ساخت ssh *ssh, صحیح r, ثابت حرف *fmt, va_list ap)
{
	حرف *لیبل = تہی, remote_id[512];
	صحیح oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));

	انتخاب (r) {
	حالت SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_کلیدیں(ssh);
		logdie("Connection closed by %s", remote_id);
	حالت SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_کلیدیں(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	حالت SSH_ERR_DISCONNECTED:
		ssh_packet_clear_کلیدیں(ssh);
		logdie("Disconnected from %s", remote_id);
	حالت SSH_ERR_SYSTEM_ERROR:
		اگر (errno == ECONNRESET) {
			ssh_packet_clear_کلیدیں(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	حالت SSH_ERR_NO_CIPHER_ALG_مطابقت:
	حالت SSH_ERR_NO_MAC_ALG_مطابقت:
	حالت SSH_ERR_NO_COMPRESS_ALG_مطابقت:
	حالت SSH_ERR_NO_KEX_ALG_مطابقت:
	حالت SSH_ERR_NO_HOSTKEY_ALG_مطابقت:
		اگر (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_کلیدیں(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	طےشدہ:
		اگر (vasprintf(&لیبل, fmt, ap) == -1) {
			ssh_packet_clear_کلیدیں(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_کلیدیں(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    لیبل != تہی ? لیبل : "", لیبل != تہی ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

خالی
sshpkt_fatal(ساخت ssh *ssh, صحیح r, ثابت حرف *fmt, ...)
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
خالی
ssh_packet_disconnect(ساخت ssh *ssh, ثابت حرف *fmt,...)
{
	حرف buf[1024], remote_id[512];
	va_list دلائل;
	صحیح r;

	/* Guard against recursive invocations. */
	اگر (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));
	va_start(دلائل, fmt);
	vsnprintf(buf, حجم(buf), fmt, دلائل);
	va_end(دلائل);

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
ssh_packet_write_poll(ساخت ssh *ssh)
{
	ساخت session_state *state = ssh->state;
	صحیح len = sshbuf_len(state->output);
	صحیح r;

	اگر (len > 0) {
		len = اكتب(state->connection_برآمد,
		    sshbuf_ptr(state->output), len);
		اگر (len == -1) {
			اگر (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				واپس 0;
			واپس SSH_ERR_SYSTEM_ERROR;
		}
		اگر (len == 0)
			واپس SSH_ERR_CONN_CLOSED;
		اگر ((r = sshbuf_consume(state->output, len)) != 0)
			واپس r;
	}
	واپس 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
صحیح
ssh_packet_write_wait(ساخت ssh *ssh)
{
	صحیح ret, r, ms_remain = 0;
	ساخت timeval آغاز;
	ساخت timespec timespec, *timespecp = تہی;
	ساخت session_state *state = ssh->state;
	ساخت pollfd pfd;

	اگر ((r = ssh_packet_write_poll(ssh)) != 0)
		واپس r;
	جب (ssh_packet_have_ڈیٹا_مقصد_write(ssh)) {
		pfd.fd = state->connection_برآمد;
		pfd.events = POLLOUT;

		اگر (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		برائے (;;) {
			اگر (state->packet_timeout_ms > 0) {
				ms_مقصد_timespec(&timespec, ms_remain);
				monotime_tv(&آغاز);
			}
			اگر ((ret = ppoll(&pfd, 1, timespecp, تہی)) >= 0)
				توڑو;
			اگر (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				توڑو;
			اگر (state->packet_timeout_ms <= 0)
				جاری;
			ms_تفریق_diff(&آغاز, &ms_remain);
			اگر (ms_remain <= 0) {
				ret = 0;
				توڑو;
			}
		}
		اگر (ret == 0)
			واپس SSH_ERR_CONN_TIMEOUT;
		اگر ((r = ssh_packet_write_poll(ssh)) != 0)
			واپس r;
	}
	واپس 0;
}

/* Returns true if there is buffered data to write to the connection. */

صحیح
ssh_packet_have_ڈیٹا_مقصد_write(ساخت ssh *ssh)
{
	واپس sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

صحیح
ssh_packet_not_very_much_ڈیٹا_مقصد_write(ساخت ssh *ssh)
{
	اگر (ssh->state->interactive_منوال)
		واپس sshbuf_len(ssh->state->output) < 16384;
	ورنہ
		واپس sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

صحیح
ssh_packet_interactive_ڈیٹا_مقصد_write(ساخت ssh *ssh)
{
	واپس ssh->state->interactive_منوال &&
	    sshbuf_len(ssh->state->output) < 256;
}

ساکن خالی
apply_qos(ساخت ssh *ssh)
{
	ساخت session_state *state = ssh->state;
	صحیح qos = state->interactive_منوال ?
	    state->qos_interactive : state->qos_other;

	اگر (!ssh_packet_connection_is_on_socket(ssh))
		واپس;
	اگر (!state->nodelay_سیٹ) {
		سیٹ_nodelay(state->connection_اندر);
		state->nodelay_سیٹ = 1;
	}
	سیٹ_sock_tos(ssh->state->connection_اندر, qos);
}

/* Informs that the current session is interactive. */
خالی
ssh_packet_سیٹ_interactive(ساخت ssh *ssh, صحیح interactive)
{
	ساخت session_state *state = ssh->state;

	state->interactive_منوال = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
خالی
ssh_packet_سیٹ_qos(ساخت ssh *ssh, صحیح qos_interactive, صحیح qos_other)
{
	ساخت session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

صحیح
ssh_packet_سیٹ_maxsize(ساخت ssh *ssh, u_int s)
{
	ساخت session_state *state = ssh->state;

	اگر (state->سیٹ_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_سائز, s);
		واپس -1;
	}
	اگر (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		واپس -1;
	}
	state->سیٹ_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_سائز = s;
	واپس s;
}

صحیح
ssh_packet_inc_alive_timeouts(ساخت ssh *ssh)
{
	واپس ++ssh->state->keep_alive_timeouts;
}

خالی
ssh_packet_سیٹ_alive_timeouts(ساخت ssh *ssh, صحیح ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(ساخت ssh *ssh)
{
	واپس ssh->state->max_packet_سائز;
}

خالی
ssh_packet_سیٹ_rekey_limits(ساخت ssh *ssh, uint64_t بائٹیں, uint32_t seconds)
{
	اگر (بائٹیں == 0 && seconds == 0)
		واپس;

	debug3("rekey after %llu bytes, %u seconds", (غیرعلامتی طویل طویل)بائٹیں,
	    (غیرعلامتی صحیح)seconds);
	ssh->state->rekey_حد_بندی = بائٹیں;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(ساخت ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_وقت + ssh->state->rekey_interval -
	    monotime();
	واپس (seconds <= 0 ? 1 : seconds);
}

خالی
ssh_packet_سیٹ_server(ساخت ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

خالی
ssh_packet_سیٹ_authenticated(ساخت ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

خالی *
ssh_packet_get_داخلہ(ساخت ssh *ssh)
{
	واپس (خالی *)ssh->state->داخلہ;
}

خالی *
ssh_packet_get_output(ساخت ssh *ssh)
{
	واپس (خالی *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
ساکن صحیح
ssh_packet_سیٹ_postauth(ساخت ssh *ssh)
{
	صحیح r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	اگر ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		واپس r;
	واپس 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
ساکن صحیح
kex_مقصد_blob(ساخت sshbuf *m, ساخت kex *kex)
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
	    (r = sshbuf_put_stringb(m, kex->client_نسخہ)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->server_نسخہ)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->flags)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->non_pq_kex_warned)) != 0)
		واپس r;
	واپس 0;
}

/* turn key exchange results into a blob for packet state serialization */
ساکن صحیح
newkeys_مقصد_blob(ساخت sshbuf *m, ساخت ssh *ssh, صحیح منوال)
{
	ساخت sshbuf *b;
	ساخت sshcipher_ctx *cc;
	ساخت sshcomp *comp;
	ساخت sshenc *enc;
	ساخت sshmac *mac;
	ساخت newkeys *newkey;
	صحیح r;

	اگر ((newkey = ssh->state->newkeys[منوال]) == تہی)
		واپس SSH_ERR_اندرونی_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (منوال == منوال_برآمد) ? ssh->state->send_context :
	    ssh->state->receive_context;
	اگر ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		واپس r;
	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->بلاک_سائز)) != 0 ||
	    (r = sshbuf_put_string(b, enc->کلید, enc->کلید_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		جاؤ برآمد;
	اگر (cipher_authlen(enc->cipher) == 0) {
		اگر ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->کلید, mac->کلید_len)) != 0)
			جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		جاؤ برآمد;
	r = sshbuf_put_stringb(m, b);
 برآمد:
	sshbuf_free(b);
	واپس r;
}

/* serialize packet state into a blob */
صحیح
ssh_packet_get_state(ساخت ssh *ssh, ساخت sshbuf *m)
{
	ساخت session_state *state = ssh->state;
	صحیح r;

#تعریف_کرو ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	اگر ((r = kex_مقصد_blob(m, ssh->kex)) != 0 ||
	    (r = newkeys_مقصد_blob(m, ssh, منوال_برآمد)) != 0 ||
	    (r = newkeys_مقصد_blob(m, ssh, منوال_اندر)) != 0 ||
	    (r = sshbuf_put_u64(m, state->rekey_حد_بندی)) != 0 ||
	    (r = sshbuf_put_u32(m, state->rekey_interval)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.بلاکیں)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.بائٹیں)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.بلاکیں)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.بائٹیں)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->داخلہ)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_منوال))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		واپس r;
#تعریف_منسوخ ENCODE_INT
	واپس 0;
}

/* restore key exchange results from blob for packet state de-serialization */
ساکن صحیح
newkeys_from_blob(ساخت sshbuf *m, ساخت ssh *ssh, صحیح منوال)
{
	ساخت sshbuf *b = تہی;
	ساخت sshcomp *comp;
	ساخت sshenc *enc;
	ساخت sshmac *mac;
	ساخت newkeys *newkey = تہی;
	سائز_t keylen, ivlen, maclen;
	صحیح r;

	اگر ((newkey = صفر_حافظہ_دو(1, حجم(*newkey))) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_froms(m, &b)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_PK
	sshbuf_dump(b, stderr);
#اگر_ختم
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	اگر ((r = sshbuf_get_cstring(b, &enc->name, تہی)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->بلاک_سائز)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->کلید, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		جاؤ برآمد;
	اگر ((enc->cipher = cipher_by_name(enc->name)) == تہی ||
	    enc->بلاک_سائز != cipher_blocksize(enc->cipher) ||
	    cipher_is_اندرونی(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (cipher_authlen(enc->cipher) == 0) {
		اگر ((r = sshbuf_get_cstring(b, &mac->name, تہی)) != 0)
			جاؤ برآمد;
		اگر ((r = mac_تیاری(mac, mac->name)) != 0)
			جاؤ برآمد;
		اگر ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->کلید, &maclen)) != 0)
			جاؤ برآمد;
		اگر (maclen != mac->کلید_len) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		mac->کلید_len = maclen;
	}
	اگر ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, تہی)) != 0)
		جاؤ برآمد;
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	enc->کلید_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[منوال] = newkey;
	newkey = تہی;
	r = 0;
 برآمد:
	آزاد(newkey);
	sshbuf_free(b);
	واپس r;
}

/* restore kex from blob for packet state de-serialization */
ساکن صحیح
kex_from_blob(ساخت sshbuf *m, ساخت kex **kexp)
{
	ساخت kex *kex;
	صحیح r;

	اگر ((kex = kex_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, تہی)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_type)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_type)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_strict)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->client_نسخہ)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->server_نسخہ)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->flags)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->non_pq_kex_warned)) != 0)
		جاؤ برآمد;
	اگر (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	kex->server = 1;
	kex->مکمل = 1;
	r = 0;
 برآمد:
	اگر (r != 0 || kexp == تہی) {
		kex_free(kex);
		اگر (kexp != تہی)
			*kexp = تہی;
	} ورنہ {
		kex_free(*kexp);
		*kexp = kex;
	}
	واپس r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
صحیح
ssh_packet_سیٹ_state(ساخت ssh *ssh, ساخت sshbuf *m)
{
	ساخت session_state *state = ssh->state;
	ثابت u_char *داخلہ, *output;
	سائز_t ilen, olen;
	صحیح r;
	u_int interactive, qos_interactive, qos_other;

	اگر ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, منوال_برآمد)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, منوال_اندر)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->rekey_حد_بندی)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->rekey_interval)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.بلاکیں)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.بائٹیں)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.بلاکیں)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.بائٹیں)) != 0)
		واپس r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_وقت = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	اگر ((r = ssh_سیٹ_newkeys(ssh, منوال_اندر)) != 0 ||
	    (r = ssh_سیٹ_newkeys(ssh, منوال_برآمد)) != 0)
		واپس r;

	اگر ((r = ssh_packet_سیٹ_postauth(ssh)) != 0)
		واپس r;

	sshbuf_reset(state->داخلہ);
	sshbuf_reset(state->output);
	اگر ((r = sshbuf_get_string_براہ_راست(m, &داخلہ, &ilen)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->داخلہ, داخلہ, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		واپس r;

	اگر ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		واپس r;
#تعریف_کرو DECODE_INT(v) ((v) > زیادہ_سے_زیادہ_عدد ? -1 : (صحیح)(v))
	state->interactive_منوال = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#تعریف_منسوخ DECODE_INT

	اگر (sshbuf_len(m))
		واپس SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	واپس 0;
}

/* NEW API */

/* put data to the outgoing packet */

صحیح
sshpkt_put(ساخت ssh *ssh, ثابت خالی *v, سائز_t len)
{
	واپس sshbuf_put(ssh->state->outgoing_packet, v, len);
}

صحیح
sshpkt_putb(ساخت ssh *ssh, ثابت ساخت sshbuf *b)
{
	واپس sshbuf_putb(ssh->state->outgoing_packet, b);
}

صحیح
sshpkt_put_u8(ساخت ssh *ssh, u_char val)
{
	واپس sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

صحیح
sshpkt_put_u32(ساخت ssh *ssh, uint32_t val)
{
	واپس sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

صحیح
sshpkt_put_u64(ساخت ssh *ssh, uint64_t val)
{
	واپس sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

صحیح
sshpkt_put_string(ساخت ssh *ssh, ثابت خالی *v, سائز_t len)
{
	واپس sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

صحیح
sshpkt_put_cstring(ساخت ssh *ssh, ثابت خالی *v)
{
	واپس sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

صحیح
sshpkt_put_stringb(ساخت ssh *ssh, ثابت ساخت sshbuf *v)
{
	واپس sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#اگر_تعریف_شدہ WITH_OPENSSL
صحیح
sshpkt_put_ec(ساخت ssh *ssh, ثابت EC_نقطہ *v, ثابت EC_گروہ *g)
{
	واپس sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

صحیح
sshpkt_put_ec_pkey(ساخت ssh *ssh, EVP_PKEY *pkey)
{
	واپس sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

صحیح
sshpkt_put_bignum2(ساخت ssh *ssh, ثابت BIGNUM *v)
{
	واپس sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#اگر_ختم /* WITH_OPENSSL */

/* fetch data from the incoming packet */

صحیح
sshpkt_get(ساخت ssh *ssh, خالی *valp, سائز_t len)
{
	واپس sshbuf_get(ssh->state->incoming_packet, valp, len);
}

صحیح
sshpkt_get_u8(ساخت ssh *ssh, u_char *valp)
{
	واپس sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

صحیح
sshpkt_get_u32(ساخت ssh *ssh, uint32_t *valp)
{
	واپس sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

صحیح
sshpkt_get_u64(ساخت ssh *ssh, uint64_t *valp)
{
	واپس sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

صحیح
sshpkt_get_string(ساخت ssh *ssh, u_char **valp, سائز_t *lenp)
{
	واپس sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

صحیح
sshpkt_get_string_براہ_راست(ساخت ssh *ssh, ثابت u_char **valp, سائز_t *lenp)
{
	واپس sshbuf_get_string_براہ_راست(ssh->state->incoming_packet, valp, lenp);
}

صحیح
sshpkt_peek_string_براہ_راست(ساخت ssh *ssh, ثابت u_char **valp, سائز_t *lenp)
{
	واپس sshbuf_peek_string_براہ_راست(ssh->state->incoming_packet, valp, lenp);
}

صحیح
sshpkt_get_cstring(ساخت ssh *ssh, حرف **valp, سائز_t *lenp)
{
	واپس sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

صحیح
sshpkt_getb_froms(ساخت ssh *ssh, ساخت sshbuf **valp)
{
	واپس sshbuf_froms(ssh->state->incoming_packet, valp);
}

#اگر_تعریف_شدہ WITH_OPENSSL
صحیح
sshpkt_get_ec(ساخت ssh *ssh, EC_نقطہ *v, ثابت EC_گروہ *g)
{
	واپس sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

صحیح
sshpkt_get_bignum2(ساخت ssh *ssh, BIGNUM **valp)
{
	واپس sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#اگر_ختم /* WITH_OPENSSL */

صحیح
sshpkt_get_انتہا(ساخت ssh *ssh)
{
	اگر (sshbuf_len(ssh->state->incoming_packet) > 0)
		واپس SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا;
	واپس 0;
}

ثابت u_char *
sshpkt_ptr(ساخت ssh *ssh, سائز_t *lenp)
{
	اگر (lenp != تہی)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	واپس sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

صحیح
sshpkt_آغاز(ساخت ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, حجم(buf));
	buf[حجم(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	واپس sshbuf_put(ssh->state->outgoing_packet, buf, حجم(buf));
}

ساکن صحیح
ssh_packet_send_mux(ساخت ssh *ssh)
{
	ساخت session_state *state = ssh->state;
	u_char type, *cp;
	سائز_t len;
	صحیح r;

	اگر (ssh->kex)
		واپس SSH_ERR_اندرونی_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	اگر (len < 6)
		واپس SSH_ERR_اندرونی_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	اگر (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	اگر (type >= SSH2_پیغام_CONNECTION_MIN &&
	    type <= SSH2_پیغام_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		اگر ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			واپس r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	واپس 0;
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
sshpkt_پیغام_ignore(ساخت ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	صحیح r;
	u_int i;

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		واپس r;
	برائے (i = 0; i < nbytes; i++) {
		اگر (i % 4 == 0)
			rnd = arc4random();
		اگر ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			واپس r;
		rnd >>= 8;
	}
	واپس 0;
}

/* send it */

صحیح
sshpkt_send(ساخت ssh *ssh)
{
	اگر (ssh->state && ssh->state->mux)
		واپس ssh_packet_send_mux(ssh);
	واپس ssh_packet_send2(ssh);
}

صحیح
sshpkt_disconnect(ساخت ssh *ssh, ثابت حرف *fmt,...)
{
	حرف buf[1024];
	va_list دلائل;
	صحیح r;

	va_start(دلائل, fmt);
	vsnprintf(buf, حجم(buf), fmt, دلائل);
	va_end(دلائل);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		واپس r;
	واپس 0;
}

/* roundup current message to pad bytes */
صحیح
sshpkt_جوڑو_padding(ساخت ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	واپس 0;
}

ساکن حرف *
format_traffic_stats(ساخت packet_state *ps)
{
	حرف *stats = تہی, بائٹیں[FMT_SCALED_STRSIZE];

	اگر (ps->بائٹیں > LLONG_MAX || fmt_scaled(ps->بائٹیں, بائٹیں) != 0)
		strlcpy(بائٹیں, "OVERFLOW", حجم(بائٹیں));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (غیرعلامتی طویل)ps->packets, (غیرعلامتی طویل طویل)ps->بلاکیں, بائٹیں);
	واپس stats;
}

ساکن حرف *
dedupe_alg_نام(ثابت حرف *اندر, ثابت حرف *برآمد)
{
	حرف *نام = تہی;

	اگر (اندر == تہی)
		اندر = "<implicit>";
	اگر (برآمد == تہی)
		برآمد = "<implicit>";

	اگر (strcmp(اندر, برآمد) == 0) {
		نام = xstrdup(اندر);
	} ورنہ {
		xasprintf(&نام, "%s in, %s out", اندر, برآمد);
	}
	واپس نام;
}

ساکن حرف *
comp_حالت_پیغام(ساخت ssh *ssh)
{
#اگر_تعریف_شدہ WITH_ZLIB
	حرف *ret = تہی;
	ساخت session_state *state = ssh->state;
	غیرعلامتی طویل طویل iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	حرف iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	حرف icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	اگر (state->compression_بفر) {
		اگر (state->compression_اندر_started) {
			iraw = state->compression_اندر_دھارا.کل_برآمد;
			icmp = state->compression_اندر_دھارا.کل_اندر;
			اگر (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", حجم(iraw_f));
			اگر (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", حجم(icmp_f));
		}
		اگر (state->compression_برآمد_started) {
			oraw = state->compression_برآمد_دھارا.کل_اندر;
			ocmp = state->compression_برآمد_دھارا.کل_برآمد;
			اگر (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", حجم(oraw_f));
			اگر (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", حجم(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (دوہرا)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (دوہرا)ocmp / oraw);
		واپس ret;
	}
#اگر_ختم	/* WITH_ZLIB */
	واپس xstrdup("");
}

حرف *
connection_info_پیغام(ساخت ssh *ssh)
{
	حرف *ret = تہی, *cipher = تہی, *mac = تہی, *comp = تہی;
	حرف *rekey_volume = تہی, *rekey_وقت = تہی, *comp_info = تہی;
	حرف thishost[NI_MAXHOST] = "unknown", *tcp_info = تہی;
	ساخت kex *kex;
	ساخت session_state *state;
	ساخت newkeys *nk_اندر, *nk_برآمد;
	حرف *stats_اندر = تہی, *stats_برآمد = تہی;
	uint64_t epoch = (uint64_t)time(تہی) - monotime();

	اگر (ssh == تہی)
		واپس تہی;
	state = ssh->state;
	kex = ssh->kex;

	(خالی)gethostname(thishost, حجم(thishost));

	اگر (ssh_local_پورٹ(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_پورٹ(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
	} ورنہ {
		tcp_info = xstrdup("");
	}

	nk_اندر = ssh->state->newkeys[منوال_اندر];
	nk_برآمد = ssh->state->newkeys[منوال_برآمد];
	stats_اندر = format_traffic_stats(&ssh->state->p_read);
	stats_برآمد = format_traffic_stats(&ssh->state->p_send);

	cipher = dedupe_alg_نام(nk_اندر->enc.name, nk_برآمد->enc.name);
	mac = dedupe_alg_نام(nk_اندر->mac.name, nk_برآمد->mac.name);
	comp = dedupe_alg_نام(nk_اندر->comp.name, nk_برآمد->comp.name);

	/* Volume based rekeying. */
	اگر (state->rekey_حد_بندی == 0) {
		xasprintf(&rekey_volume, "limit none");
	} ورنہ {
		حرف *volumes = تہی, اندر[32], برآمد[32];

		snprintf(اندر, حجم(اندر), "%llu",
		   (غیرعلامتی طویل طویل)state->max_بلاکیں_اندر);
		snprintf(برآمد, حجم(برآمد), "%llu",
		   (غیرعلامتی طویل طویل)state->max_بلاکیں_برآمد);
		volumes = dedupe_alg_نام(اندر, برآمد);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		آزاد(volumes);
	}

	/* Time based rekeying. */
	اگر (state->rekey_interval == 0) {
		rekey_وقت = xstrdup("interval none");
	} ورنہ {
		حرف rekey_اگلا[64];

		format_absolute_وقت(epoch + state->rekey_وقت +
		    state->rekey_interval, rekey_اگلا, حجم(rekey_اگلا));
		xasprintf(&rekey_وقت, "interval %s, next %s",
		    fmt_timeframe(state->rekey_interval), rekey_اگلا);
	}
	comp_info = comp_حالت_پیغام(ssh);

	xasprintf(&ret, "Connection information for %s pid %lld\r\n"
	    "  versions %s -> %s\r\n"
	    "%s"
	    "  duration %s\r\n"
	    "  kexalgorithm %s\r\n  hostkeyalgorithm %s\r\n"
	    "  cipher %s\r\n  mac %s\r\n  compression %s\r\n"
	    "  rekey %s %s\r\n"
	    "  traffic %s in, %s out\r\n"
	    "%s",
	    thishost, (طویل طویل)getpid(),
	    SSH_RELEASE, ssh->remote_نسخہ,
	    tcp_info,
	    fmt_timeframe(monotime() - state->آغاز_وقت),
	    kex->name, kex->hostkey_alg,
	    cipher, mac, comp,
	    rekey_volume, rekey_وقت,
	    stats_اندر, stats_برآمد,
	    comp_info
	);
	آزاد(tcp_info);
	آزاد(cipher);
	آزاد(mac);
	آزاد(comp);
	آزاد(stats_اندر);
	آزاد(stats_برآمد);
	آزاد(rekey_volume);
	آزاد(rekey_وقت);
	آزاد(comp_info);
	واپس ret;
}

