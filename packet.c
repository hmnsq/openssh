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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/time.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <util.h>

/*
 * Explicitly include OpenSSL before zlib as some versions of OpenSSL have
 * "free_func" in their headers, which zlib typedefs.
 */
#నిర్వచితమైతే WITH_OPENSSL
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/ec.h>
#అయితే_ముగింపు

#నిర్వచితమైతే WITH_ZLIB
#అన్తర్భావ <zlib.h>
#అయితే_ముగింపు

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "mac.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "version.h"

#నిర్వచితమైతే PACKET_DEBUG
#నిర్వచించు DBG(x) x
#లేకపోతే
#నిర్వచించు DBG(x)
#అయితే_ముగింపు

#నిర్వచించు PACKET_MAX_కొలత (256 * 1024)

నిర్మాణం packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t ఖండాలు;
	uint64_t బైట్లు;
};

నిర్మాణం packet {
	TAILQ_ENTRY(packet) తదుపరి;
	u_char type;
	నిర్మాణం sshbuf *payload;
};

నిర్మాణం session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	పూర్ణాంకం connection_లోపల;
	పూర్ణాంకం connection_బహిర్గతం;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	నిర్మాణం sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	నిర్మాణం sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	నిర్మాణం sshbuf *ఆదానం;

	/* Buffer for raw output data going to the socket. */
	నిర్మాణం sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	నిర్మాణం sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	నిర్మాణం sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	నిర్మాణం sshbuf *compression_బఫరు;

#నిర్వచితమైతే WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_ప్రవాహం compression_లోపల_ప్రవాహం;
	z_ప్రవాహం compression_బహిర్గతం_ప్రవాహం;
#అయితే_ముగింపు
	పూర్ణాంకం compression_లోపల_started;
	పూర్ణాంకం compression_బహిర్గతం_started;
	పూర్ణాంకం compression_లోపల_failures;
	పూర్ణాంకం compression_బహిర్గతం_failures;

	/* default maximum packet size */
	u_int max_packet_కొలత;

	/* Flag indicating whether this module has been initialized. */
	పూర్ణాంకం initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t ప్రారంభం_సమయం;

	/* Set to true if the connection is interactive. */
	పూర్ణాంకం interactive_బహుళకం;

	/* Set to true if we are the server side. */
	పూర్ణాంకం server_side;

	/* Set to true if we are authenticated. */
	పూర్ణాంకం after_authentication;

	పూర్ణాంకం keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	పూర్ణాంకం packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	నిర్మాణం newkeys *newkeys[బహుళకం_MAX];
	నిర్మాణం packet_state p_read, p_send;

	/* Volume-based rekeying */
	uint64_t hard_max_ఖండాలు_లోపల, hard_max_ఖండాలు_బహిర్గతం;
	uint64_t max_ఖండాలు_లోపల, max_ఖండాలు_బహిర్గతం, rekey_హద్దు;

	/* Time-based rekeying */
	uint32_t rekey_interval;	/* how often in seconds */
	time_t rekey_సమయం;	/* time of last rekeying */

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	కొలత_t packet_discard_mac_already;
	నిర్మాణం sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	పూర్ణాంకం rekeying;

	/* Used in ssh_packet_send_mux() */
	పూర్ణాంకం mux;

	/* QoS handling */
	పూర్ణాంకం qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	పూర్ణాంకం సమితి_maxsize_called;

	/* One-off warning about weak ciphers */
	పూర్ణాంకం cipher_warning_పూర్తి;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	పూర్ణాంకం disconnecting;

	/* Nagle disabled on socket */
	పూర్ణాంకం nodelay_సమితి;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_లోపల;
	శూన్య *hook_లోపల_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

నిర్మాణం ssh *
ssh_alloc_session_state(శూన్య)
{
	నిర్మాణం ssh *ssh = ఖాళీ;
	నిర్మాణం session_state *state = ఖాళీ;

	ఒకవేళ ((ssh = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ssh))) == ఖాళీ ||
	    (state = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*state))) == ఖాళీ ||
	    (ssh->kex = kex_new()) == ఖాళీ ||
	    (state->ఆదానం = sshbuf_new()) == ఖాళీ ||
	    (state->output = sshbuf_new()) == ఖాళీ ||
	    (state->outgoing_packet = sshbuf_new()) == ఖాళీ ||
	    (state->incoming_packet = sshbuf_new()) == ఖాళీ)
		వెళ్ళు fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->వ్యక్తిగత_కీలకాలు);
	TAILQ_INIT(&ssh->ప్రజా_కీలకాలు);
	state->connection_లోపల = -1;
	state->connection_బహిర్గతం = -1;
	state->max_packet_కొలత = 32768;
	state->packet_timeout_ms = -1;
	state->interactive_బహుళకం = 1;
	state->qos_interactive = state->qos_other = -1;
	state->p_send.packets = state->p_read.packets = 0;
	state->initialized = 1;
	/*
	 * ssh_packet_send2() needs to queue packets until
	 * we've done the initial key exchange.
	 */
	state->rekeying = 1;
	ssh->state = state;
	తిరిగి ssh;
 fail:
	ఒకవేళ (ssh) {
		kex_free(ssh->kex);
		విడుదల(ssh);
	}
	ఒకవేళ (state) {
		sshbuf_free(state->ఆదానం);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		విడుదల(state);
	}
	తిరిగి ఖాళీ;
}

శూన్య
ssh_packet_సమితి_ఆదానం_hook(నిర్మాణం ssh *ssh, ssh_packet_hook_fn *hook, శూన్య *ctx)
{
	ssh->state->hook_లోపల = hook;
	ssh->state->hook_లోపల_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
పూర్ణాంకం
ssh_packet_is_rekeying(నిర్మాణం ssh *ssh)
{
	తిరిగి ssh->state->rekeying ||
	    (ssh->kex != ఖాళీ && ssh->kex->పూర్తి == 0);
}

/*
 * Sets the descriptors used for communication.
 */
నిర్మాణం ssh *
ssh_packet_సమితి_connection(నిర్మాణం ssh *ssh, పూర్ణాంకం fd_లోపల, పూర్ణాంకం fd_బహిర్గతం)
{
	నిర్మాణం session_state *state;
	స్థిరరాశి నిర్మాణం sshcipher *none = cipher_by_name("none");
	పూర్ణాంకం r, wasnull = ssh == ఖాళీ;

	ఒకవేళ (none == ఖాళీ) {
		error_f("cannot load cipher 'none'");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (ssh == ఖాళీ)
		ssh = ssh_alloc_session_state();
	ఒకవేళ (ssh == ఖాళీ) {
		error_f("could not allocate state");
		తిరిగి ఖాళీ;
	}
	state = ssh->state;
	state->ప్రారంభం_సమయం = monotime();
	state->connection_లోపల = fd_లోపల;
	state->connection_బహిర్గతం = fd_బహిర్గతం;
	ఒకవేళ ((r = cipher_init(&state->send_context, none,
	    (స్థిరరాశి u_char *)"", 0, ఖాళీ, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (స్థిరరాశి u_char *)"", 0, ఖాళీ, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		ఒకవేళ (wasnull)
			విడుదల(ssh); /* XXX need ssh_free_session_state? */
		తిరిగి ఖాళీ;
	}
	state->newkeys[బహుళకం_లోపల] = state->newkeys[బహుళకం_బహిర్గతం] = ఖాళీ;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(శూన్య)ssh_remote_ipaddr(ssh);
	తిరిగి ssh;
}

శూన్య
ssh_packet_సమితి_timeout(నిర్మాణం ssh *ssh, పూర్ణాంకం timeout, పూర్ణాంకం లెక్క)
{
	నిర్మాణం session_state *state = ssh->state;

	ఒకవేళ (timeout <= 0 || లెక్క <= 0) {
		state->packet_timeout_ms = -1;
		తిరిగి;
	}
	ఒకవేళ ((గరిష్ఠ_పూర్ణాంకం / 1000) / లెక్క < timeout)
		state->packet_timeout_ms = గరిష్ఠ_పూర్ణాంకం;
	లేకపోతే
		state->packet_timeout_ms = timeout * లెక్క * 1000;
}

శూన్య
ssh_packet_సమితి_mux(నిర్మాణం ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = ఖాళీ;
}

పూర్ణాంకం
ssh_packet_get_mux(నిర్మాణం ssh *ssh)
{
	తిరిగి ssh->state->mux;
}

పూర్ణాంకం
ssh_packet_సమితి_log_preamble(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;
	పూర్ణాంకం r;

	విడుదల(ssh->log_preamble);
	ఒకవేళ (fmt == ఖాళీ)
		ssh->log_preamble = ఖాళీ;
	లేకపోతే {
		va_start(వాదనలు, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, వాదనలు);
		va_end(వాదనలు);
		ఒకవేళ (r < 0 || ssh->log_preamble == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	తిరిగి 0;
}

పూర్ణాంకం
ssh_packet_stop_discard(నిర్మాణం ssh *ssh)
{
	నిర్మాణం session_state *state = ssh->state;
	పూర్ణాంకం r;

	ఒకవేళ (state->packet_discard_mac) {
		అక్షరం buf[1024];
		కొలత_t dlen = PACKET_MAX_కొలత;

		ఒకవేళ (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		memset(buf, 'a', పరిమాణం(buf));
		అయితే (sshbuf_len(state->incoming_packet) < dlen)
			ఒకవేళ ((r = sshbuf_put(state->incoming_packet, buf,
			    పరిమాణం(buf))) != 0)
				తిరిగి r;
		(శూన్య) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    ఖాళీ, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
	తిరిగి SSH_ERR_MAC_INVALID;
}

స్థిర పూర్ణాంకం
ssh_packet_ప్రారంభం_discard(నిర్మాణం ssh *ssh, నిర్మాణం sshenc *enc,
    నిర్మాణం sshmac *mac, కొలత_t mac_already, u_int discard)
{
	నిర్మాణం session_state *state = ssh->state;
	పూర్ణాంకం r;

	ఒకవేళ (enc == ఖాళీ || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		ఒకవేళ ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			తిరిగి r;
		తిరిగి SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	ఒకవేళ (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	ఒకవేళ (sshbuf_len(state->ఆదానం) >= discard)
		తిరిగి ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->ఆదానం);
	తిరిగి 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

పూర్ణాంకం
ssh_packet_connection_is_on_socket(నిర్మాణం ssh *ssh)
{
	నిర్మాణం session_state *state;
	నిర్మాణం sockaddr_storage from, గమ్యం;
	socklen_t fromlen, tolen;

	ఒకవేళ (ssh == ఖాళీ || ssh->state == ఖాళీ)
		తిరిగి 0;

	state = ssh->state;
	ఒకవేళ (state->connection_లోపల == -1 || state->connection_బహిర్గతం == -1)
		తిరిగి 0;
	fromlen = పరిమాణం(from);
	memset(&from, 0, పరిమాణం(from));
	ఒకవేళ (getpeername(state->connection_లోపల, (నిర్మాణం sockaddr *)&from,
	    &fromlen) == -1)
		తిరిగి 0;
	ఒకవేళ (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		తిరిగి 0;
	/* filedescriptors in and out are the same, so it's a socket */
	ఒకవేళ (state->connection_లోపల == state->connection_బహిర్గతం)
		తిరిగి 1;
	tolen = పరిమాణం(గమ్యం);
	memset(&గమ్యం, 0, పరిమాణం(గమ్యం));
	ఒకవేళ (getpeername(state->connection_బహిర్గతం, (నిర్మాణం sockaddr *)&గమ్యం,
	    &tolen) == -1)
		తిరిగి 0;
	ఒకవేళ (fromlen != tolen || memcmp(&from, &గమ్యం, fromlen) != 0)
		తిరిగి 0;
	తిరిగి 1;
}

శూన్య
ssh_packet_get_బైట్లు(నిర్మాణం ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	ఒకవేళ (ibytes)
		*ibytes = ssh->state->p_read.బైట్లు;
	ఒకవేళ (obytes)
		*obytes = ssh->state->p_send.బైట్లు;
}

పూర్ణాంకం
ssh_packet_connection_af(నిర్మాణం ssh *ssh)
{
	తిరిగి get_sock_af(ssh->state->connection_బహిర్గతం);
}

/* Sets the connection into non-blocking mode. */

శూన్య
ssh_packet_సమితి_nonblocking(నిర్మాణం ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	సమితి_nonblock(ssh->state->connection_లోపల);

	ఒకవేళ (ssh->state->connection_బహిర్గతం != ssh->state->connection_లోపల)
		సమితి_nonblock(ssh->state->connection_బహిర్గతం);
}

/* Returns the socket used for reading. */

పూర్ణాంకం
ssh_packet_get_connection_లోపల(నిర్మాణం ssh *ssh)
{
	తిరిగి ssh->state->connection_లోపల;
}

/* Returns the descriptor used for writing. */

పూర్ణాంకం
ssh_packet_get_connection_బహిర్గతం(నిర్మాణం ssh *ssh)
{
	తిరిగి ssh->state->connection_బహిర్గతం;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

స్థిరరాశి అక్షరం *
ssh_remote_ipaddr(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం sock;

	/* Check whether we have cached the ipaddr. */
	ఒకవేళ (ssh->remote_ipaddr == ఖాళీ) {
		ఒకవేళ (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_లోపల;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_పోర్టు = get_peer_పోర్టు(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_పోర్టు = get_local_పోర్టు(sock);
		} లేకపోతే {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_పోర్టు = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_పోర్టు = 65535;
		}
	}
	తిరిగి ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

అక్షరం *
ssh_remote_hostname(నిర్మాణం ssh *ssh)
{
	నిర్మాణం sockaddr_storage from;
	socklen_t fromlen;
	నిర్మాణం addrinfo hints, *ai, *aitop;
	అక్షరం name[NI_MAXHOST], ntop2[NI_MAXHOST];
	స్థిరరాశి అక్షరం *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = పరిమాణం(from);
	memset(&from, 0, పరిమాణం(from));
	ఒకవేళ (getpeername(ssh_packet_get_connection_లోపల(ssh),
	    (నిర్మాణం sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		తిరిగి xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	ఒకవేళ (from.ss_family == AF_INET6)
		fromlen = పరిమాణం(నిర్మాణం sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	ఒకవేళ (getnameinfo((నిర్మాణం sockaddr *)&from, fromlen, name, పరిమాణం(name),
	    ఖాళీ, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		తిరిగి xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	ఒకవేళ (getaddrinfo(name, ఖాళీ, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		తిరిగి xstrdup(ntop);
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
	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	ఒకవేళ (getaddrinfo(name, ఖాళీ, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		తిరిగి xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	కొరకు (ai = aitop; ai; ai = ai->ai_next) {
		ఒకవేళ (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    పరిమాణం(ntop2), ఖాళీ, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				ఆపు;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	ఒకవేళ (ai == ఖాళీ) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		తిరిగి xstrdup(ntop);
	}
	తిరిగి xstrdup(name);
}

/* Returns the port number of the remote host. */

పూర్ణాంకం
ssh_remote_పోర్టు(నిర్మాణం ssh *ssh)
{
	(శూన్య)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	తిరిగి ssh->remote_పోర్టు;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

స్థిరరాశి అక్షరం *
ssh_local_ipaddr(నిర్మాణం ssh *ssh)
{
	(శూన్య)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	తిరిగి ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

పూర్ణాంకం
ssh_local_పోర్టు(నిర్మాణం ssh *ssh)
{
	(శూన్య)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	తిరిగి ssh->local_పోర్టు;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
స్థిరరాశి అక్షరం *
ssh_packet_rdomain_లోపల(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (ssh->rdomain_లోపల != ఖాళీ)
		తిరిగి ssh->rdomain_లోపల;
	ఒకవేళ (!ssh_packet_connection_is_on_socket(ssh))
		తిరిగి ఖాళీ;
	ssh->rdomain_లోపల = get_rdomain(ssh->state->connection_లోపల);
	తిరిగి ssh->rdomain_లోపల;
}

/* Closes the connection and clears and frees internal data structures. */

స్థిర శూన్య
ssh_packet_close_అంతర్గత(నిర్మాణం ssh *ssh, పూర్ణాంకం do_close)
{
	నిర్మాణం session_state *state = ssh->state;
	u_int బహుళకం;
	నిర్మాణం packet *p;

	ఒకవేళ (!state->initialized)
		తిరిగి;
	state->initialized = 0;
	ఒకవేళ (do_close) {
		ఒకవేళ (state->connection_లోపల == state->connection_బహిర్గతం) {
			close(state->connection_బహిర్గతం);
		} లేకపోతే {
			close(state->connection_లోపల);
			close(state->connection_బహిర్గతం);
		}
	}
	sshbuf_free(state->ఆదానం);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	అయితే ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, తదుపరి);
		విడుదల(p);
	}
	కొరకు (బహుళకం = 0; బహుళకం < బహుళకం_MAX; బహుళకం++) {
		kex_free_newkeys(state->newkeys[బహుళకం]);	/* current keys */
		state->newkeys[బహుళకం] = ఖాళీ;
		ssh_clear_newkeys(ssh, బహుళకం);		/* next keys */
	}
#నిర్వచితమైతే WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	ఒకవేళ (do_close && state->compression_బఫరు) {
		sshbuf_free(state->compression_బఫరు);
		ఒకవేళ (state->compression_బహిర్గతం_started) {
			z_streamp ప్రవాహం = &state->compression_బహిర్గతం_ప్రవాహం;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(గుర్తులేని దీర్ఘ దీర్ఘ)ప్రవాహం->మొత్తం_లోపల,
				(గుర్తులేని దీర్ఘ దీర్ఘ)ప్రవాహం->మొత్తం_బహిర్గతం,
				ప్రవాహం->మొత్తం_లోపల == 0 ? 0.0 :
				(ద్విగుణ) ప్రవాహం->మొత్తం_బహిర్గతం / ప్రవాహం->మొత్తం_లోపల);
			ఒకవేళ (state->compression_బహిర్గతం_failures == 0)
				deflate_చివర(ప్రవాహం);
		}
		ఒకవేళ (state->compression_లోపల_started) {
			z_streamp ప్రవాహం = &state->compression_లోపల_ప్రవాహం;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)ప్రవాహం->మొత్తం_బహిర్గతం,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)ప్రవాహం->మొత్తం_లోపల,
			    ప్రవాహం->మొత్తం_బహిర్గతం == 0 ? 0.0 :
			    (ద్విగుణ) ప్రవాహం->మొత్తం_లోపల / ప్రవాహం->మొత్తం_బహిర్గతం);
			ఒకవేళ (state->compression_లోపల_failures == 0)
				inflate_చివర(ప్రవాహం);
		}
	}
#అయితే_ముగింపు	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = ఖాళీ;
	ఒకవేళ (do_close) {
		విడుదల(ssh->local_ipaddr);
		ssh->local_ipaddr = ఖాళీ;
		విడుదల(ssh->remote_ipaddr);
		ssh->remote_ipaddr = ఖాళీ;
		విడుదల(ssh->state);
		ssh->state = ఖాళీ;
		kex_free(ssh->kex);
		ssh->kex = ఖాళీ;
	}
}

శూన్య
ssh_packet_free(నిర్మాణం ssh *ssh)
{
	ssh_packet_close_అంతర్గత(ssh, 1);
	freezero(ssh, పరిమాణం(*ssh));
}

శూన్య
ssh_packet_close(నిర్మాణం ssh *ssh)
{
	ssh_packet_close_అంతర్గత(ssh, 1);
}

శూన్య
ssh_packet_clear_కీలకాలు(నిర్మాణం ssh *ssh)
{
	ssh_packet_close_అంతర్గత(ssh, 0);
}

/* Sets remote side protocol flags. */

శూన్య
ssh_packet_సమితి_protocol_flags(నిర్మాణం ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(నిర్మాణం ssh *ssh)
{
	తిరిగి ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

స్థిర పూర్ణాంకం
ssh_packet_init_compression(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (!ssh->state->compression_బఫరు &&
	    ((ssh->state->compression_బఫరు = sshbuf_new()) == ఖాళీ))
		తిరిగి SSH_ERR_ALLOC_FAIL;
	తిరిగి 0;
}

#నిర్వచితమైతే WITH_ZLIB
స్థిర పూర్ణాంకం
ప్రారంభం_compression_బహిర్గతం(నిర్మాణం ssh *ssh)
{
	debug("Enabling compression.");
	ఒకవేళ (ssh->state->compression_బహిర్గతం_started == 1)
		deflate_చివర(&ssh->state->compression_బహిర్గతం_ప్రవాహం);
	ఎంపిక (deflateInit2(&ssh->state->compression_బహిర్గతం_ప్రవాహం,
	    Z_ఉత్తమ_వేగం, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	స్థితి Z_OK:
		ssh->state->compression_బహిర్గతం_started = 1;
		ఆపు;
	స్థితి Z_MEM_ERROR:
		తిరిగి SSH_ERR_ALLOC_FAIL;
	అప్రమేయ:
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ప్రారంభం_compression_లోపల(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (ssh->state->compression_లోపల_started == 1)
		inflate_చివర(&ssh->state->compression_లోపల_ప్రవాహం);
	ఎంపిక (inflateInit(&ssh->state->compression_లోపల_ప్రవాహం)) {
	స్థితి Z_OK:
		ssh->state->compression_లోపల_started = 1;
		ఆపు;
	స్థితి Z_MEM_ERROR:
		తిరిగి SSH_ERR_ALLOC_FAIL;
	అప్రమేయ:
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	తిరిగి 0;
}

/* XXX remove need for separate compression buffer */
స్థిర పూర్ణాంకం
compress_బఫరు(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *లోపల, నిర్మాణం sshbuf *బహిర్గతం)
{
	u_char buf[4096];
	పూర్ణాంకం r, స్థితి_2;

	ఒకవేళ (ssh->state->compression_బహిర్గతం_started != 1)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;

	/* This case is not handled below. */
	ఒకవేళ (sshbuf_len(లోపల) == 0)
		తిరిగి 0;

	/* Input is the contents of the input buffer. */
	ఒకవేళ ((ssh->state->compression_బహిర్గతం_ప్రవాహం.తదుపరి_లోపల =
	    sshbuf_mutable_ptr(లోపల)) == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	ssh->state->compression_బహిర్గతం_ప్రవాహం.avail_లోపల = sshbuf_len(లోపల);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	చేయి {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_బహిర్గతం_ప్రవాహం.తదుపరి_బహిర్గతం = buf;
		ssh->state->compression_బహిర్గతం_ప్రవాహం.avail_బహిర్గతం = పరిమాణం(buf);

		/* Compress as much data into the buffer as possible. */
		స్థితి_2 = deflate(&ssh->state->compression_బహిర్గతం_ప్రవాహం,
		    Z_PARTIAL_FLUSH);
		ఎంపిక (స్థితి_2) {
		స్థితి Z_MEM_ERROR:
			తిరిగి SSH_ERR_ALLOC_FAIL;
		స్థితి Z_OK:
			/* Append compressed data to output_buffer. */
			ఒకవేళ ((r = sshbuf_put(బహిర్గతం, buf, పరిమాణం(buf) -
			    ssh->state->compression_బహిర్గతం_ప్రవాహం.avail_బహిర్గతం)) != 0)
				తిరిగి r;
			ఆపు;
		స్థితి Z_ప్రవాహం_ERROR:
		అప్రమేయ:
			ssh->state->compression_బహిర్గతం_failures++;
			తిరిగి SSH_ERR_INVALID_FORMAT;
		}
	} అయితే (ssh->state->compression_బహిర్గతం_ప్రవాహం.avail_బహిర్గతం == 0);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
uncompress_బఫరు(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *లోపల, నిర్మాణం sshbuf *బహిర్గతం)
{
	u_char buf[4096];
	పూర్ణాంకం r, స్థితి_2;

	ఒకవేళ (ssh->state->compression_లోపల_started != 1)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ ((ssh->state->compression_లోపల_ప్రవాహం.తదుపరి_లోపల =
	    sshbuf_mutable_ptr(లోపల)) == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	ssh->state->compression_లోపల_ప్రవాహం.avail_లోపల = sshbuf_len(లోపల);

	కొరకు (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_లోపల_ప్రవాహం.తదుపరి_బహిర్గతం = buf;
		ssh->state->compression_లోపల_ప్రవాహం.avail_బహిర్గతం = పరిమాణం(buf);

		స్థితి_2 = inflate(&ssh->state->compression_లోపల_ప్రవాహం,
		    Z_SYNC_FLUSH);
		ఎంపిక (స్థితి_2) {
		స్థితి Z_OK:
			ఒకవేళ ((r = sshbuf_put(బహిర్గతం, buf, పరిమాణం(buf) -
			    ssh->state->compression_లోపల_ప్రవాహం.avail_బహిర్గతం)) != 0)
				తిరిగి r;
			ఒకవేళ (sshbuf_len(బహిర్గతం) >= PACKET_MAX_కొలత)
				తిరిగి SSH_ERR_INVALID_FORMAT;
			ఆపు;
		స్థితి Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			తిరిగి 0;
		స్థితి Z_దత్తాంశం_ERROR:
			తిరిగి SSH_ERR_INVALID_FORMAT;
		స్థితి Z_MEM_ERROR:
			తిరిగి SSH_ERR_ALLOC_FAIL;
		స్థితి Z_ప్రవాహం_ERROR:
		అప్రమేయ:
			ssh->state->compression_లోపల_failures++;
			తిరిగి SSH_ERR_అంతర్గత_ERROR;
		}
	}
	/* NOTREACHED */
}

#లేకపోతే	/* WITH_ZLIB */

స్థిర పూర్ణాంకం
ప్రారంభం_compression_బహిర్గతం(నిర్మాణం ssh *ssh)
{
	తిరిగి SSH_ERR_అంతర్గత_ERROR;
}

స్థిర పూర్ణాంకం
ప్రారంభం_compression_లోపల(నిర్మాణం ssh *ssh)
{
	తిరిగి SSH_ERR_అంతర్గత_ERROR;
}

స్థిర పూర్ణాంకం
compress_బఫరు(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *లోపల, నిర్మాణం sshbuf *బహిర్గతం)
{
	తిరిగి SSH_ERR_అంతర్గత_ERROR;
}

స్థిర పూర్ణాంకం
uncompress_బఫరు(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *లోపల, నిర్మాణం sshbuf *బహిర్గతం)
{
	తిరిగి SSH_ERR_అంతర్గత_ERROR;
}
#అయితే_ముగింపు	/* WITH_ZLIB */

శూన్య
ssh_clear_newkeys(నిర్మాణం ssh *ssh, పూర్ణాంకం బహుళకం)
{
	ఒకవేళ (ssh->kex && ssh->kex->newkeys[బహుళకం]) {
		kex_free_newkeys(ssh->kex->newkeys[బహుళకం]);
		ssh->kex->newkeys[బహుళకం] = ఖాళీ;
	}
}

పూర్ణాంకం
ssh_సమితి_newkeys(నిర్మాణం ssh *ssh, పూర్ణాంకం బహుళకం)
{
	నిర్మాణం session_state *state = ssh->state;
	నిర్మాణం sshenc *enc;
	నిర్మాణం sshmac *mac;
	నిర్మాణం sshcomp *comp;
	నిర్మాణం sshcipher_ctx **ccp;
	నిర్మాణం packet_state *ps;
	uint64_t *max_ఖండాలు, *hard_max_ఖండాలు;
	స్థిరరాశి అక్షరం *wmsg;
	పూర్ణాంకం r, crypt_type;
	స్థిరరాశి అక్షరం *dir = బహుళకం == బహుళకం_బహిర్గతం ? "out" : "in";

	debug2_f("mode %d", బహుళకం);

	ఒకవేళ (బహుళకం == బహుళకం_బహిర్గతం) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_ఖండాలు = &state->hard_max_ఖండాలు_బహిర్గతం;
		max_ఖండాలు = &state->max_ఖండాలు_బహిర్గతం;
	} లేకపోతే {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_ఖండాలు = &state->hard_max_ఖండాలు_లోపల;
		max_ఖండాలు = &state->max_ఖండాలు_లోపల;
	}
	ఒకవేళ (state->newkeys[బహుళకం] != ఖాళీ) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)state->p_read.బైట్లు,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)state->p_read.ఖండాలు,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)state->p_send.బైట్లు,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)state->p_send.ఖండాలు);
		kex_free_newkeys(state->newkeys[బహుళకం]);
		state->newkeys[బహుళకం] = ఖాళీ;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->ఖండాలు = 0;
	/* move newkeys from kex to state */
	ఒకవేళ ((state->newkeys[బహుళకం] = ssh->kex->newkeys[బహుళకం]) == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	ssh->kex->newkeys[బహుళకం] = ఖాళీ;
	enc  = &state->newkeys[బహుళకం]->enc;
	mac  = &state->newkeys[బహుళకం]->mac;
	comp = &state->newkeys[బహుళకం]->comp;
	ఒకవేళ (cipher_authlen(enc->cipher) == 0) {
		ఒకవేళ ((r = mac_init(mac)) != 0)
			తిరిగి r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = ఖాళీ;
	ఒకవేళ ((r = cipher_init(ccp, enc->cipher, enc->కీలకం, enc->కీలకం_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		తిరిగి r;
	ఒకవేళ (!state->cipher_warning_పూర్తి &&
	    (wmsg = cipher_warning_సందేశం(*ccp)) != ఖాళీ) {
		error("Warning: %s", wmsg);
		state->cipher_warning_పూర్తి = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	ఒకవేళ (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		ఒకవేళ ((r = ssh_packet_init_compression(ssh)) < 0)
			తిరిగి r;
		ఒకవేళ (బహుళకం == బహుళకం_బహిర్గతం) {
			ఒకవేళ ((r = ప్రారంభం_compression_బహిర్గతం(ssh)) != 0)
				తిరిగి r;
		} లేకపోతే {
			ఒకవేళ ((r = ప్రారంభం_compression_లోపల(ssh)) != 0)
				తిరిగి r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	ఒకవేళ (enc->ఖండం_కొలత >= 16)
		*hard_max_ఖండాలు = (uint64_t)1 << (enc->ఖండం_కొలత*2);
	లేకపోతే
		*hard_max_ఖండాలు = ((uint64_t)1 << 30) / enc->ఖండం_కొలత;
	*max_ఖండాలు = *hard_max_ఖండాలు;
	ఒకవేళ (state->rekey_హద్దు) {
		*max_ఖండాలు = MINIMUM(*max_ఖండాలు,
		    state->rekey_హద్దు / enc->ఖండం_కొలత);
	}
	debug("rekey %s after %llu blocks", dir,
	    (గుర్తులేని దీర్ఘ దీర్ఘ)*max_ఖండాలు);
	తిరిగి 0;
}

#నిర్వచించు MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
స్థిర అంతఃవరుస పూర్ణాంకం
ssh_packet_check_rekey_blocklimit(నిర్మాణం ssh *ssh, u_int packet_len, పూర్ణాంకం hard)
{
	నిర్మాణం session_state *state = ssh->state;
	uint32_t బహిర్గతం_ఖండాలు;
	స్థిరరాశి uint64_t max_ఖండాలు_లోపల = hard ?
	    state->hard_max_ఖండాలు_లోపల : state->max_ఖండాలు_లోపల;
	స్థిరరాశి uint64_t max_ఖండాలు_బహిర్గతం = hard ?
	    state->hard_max_ఖండాలు_బహిర్గతం : state->max_ఖండాలు_బహిర్గతం;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	ఒకవేళ (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		తిరిగి 1;

	ఒకవేళ (state->newkeys[బహుళకం_బహిర్గతం] == ఖాళీ)
		తిరిగి 0;

	/* Rekey after (cipher-specific) maximum blocks */
	బహిర్గతం_ఖండాలు = ROUNDUP(packet_len,
	    state->newkeys[బహుళకం_బహిర్గతం]->enc.ఖండం_కొలత);
	తిరిగి (max_ఖండాలు_బహిర్గతం &&
	    (state->p_send.ఖండాలు + బహిర్గతం_ఖండాలు > max_ఖండాలు_బహిర్గతం)) ||
	    (max_ఖండాలు_లోపల &&
	    (state->p_read.ఖండాలు > max_ఖండాలు_లోపల));
}

స్థిర పూర్ణాంకం
ssh_packet_need_rekeying(నిర్మాణం ssh *ssh, u_int outbound_packet_len)
{
	నిర్మాణం session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	ఒకవేళ (!state->after_authentication)
		తిరిగి 0;

	/* Haven't keyed yet or KEX in progress. */
	ఒకవేళ (ssh_packet_is_rekeying(ssh))
		తిరిగి 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	ఒకవేళ (state->p_send.packets == 0 && state->p_read.packets == 0)
		తిరిగి 0;

	/* Time-based rekeying */
	ఒకవేళ (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_సమయం + state->rekey_interval <= monotime())
		తిరిగి 1;

	తిరిగి ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
స్థిర పూర్ణాంకం
ssh_packet_check_rekey_preauth(నిర్మాణం ssh *ssh, u_int outgoing_packet_len)
{
	ఒకవేళ (ssh->state->after_authentication)
		తిరిగి 0;

	ఒకవేళ (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		తిరిగి SSH_ERR_NEED_REKEY;
	}
	తిరిగి 0;
}

పూర్ణాంకం
ssh_packet_check_rekey(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		తిరిగి r;
	ఒకవేళ (!ssh_packet_need_rekeying(ssh, 0))
		తిరిగి 0;
	debug3_f("rekex triggered");
	తిరిగి kex_ప్రారంభం_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
స్థిర పూర్ణాంకం
ssh_packet_enable_delayed_compress(నిర్మాణం ssh *ssh)
{
	నిర్మాణం session_state *state = ssh->state;
	నిర్మాణం sshcomp *comp = ఖాళీ;
	పూర్ణాంకం r, బహుళకం;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	కొరకు (బహుళకం = 0; బహుళకం < బహుళకం_MAX; బహుళకం++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		ఒకవేళ (state->newkeys[బహుళకం] == ఖాళీ)
			కొనసాగు;
		comp = &state->newkeys[బహుళకం]->comp;
		ఒకవేళ (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			ఒకవేళ ((r = ssh_packet_init_compression(ssh)) != 0)
				తిరిగి r;
			ఒకవేళ (బహుళకం == బహుళకం_బహిర్గతం) {
				ఒకవేళ ((r = ప్రారంభం_compression_బహిర్గతం(ssh)) != 0)
					తిరిగి r;
			} లేకపోతే {
				ఒకవేళ ((r = ప్రారంభం_compression_లోపల(ssh)) != 0)
					తిరిగి r;
			}
			comp->enabled = 1;
		}
	}
	తిరిగి 0;
}

/* Used to mute debug logging for noisy packet types */
పూర్ణాంకం
ssh_packet_log_type(u_char type)
{
	ఎంపిక (type) {
	స్థితి SSH2_సందేశం_PING:
	స్థితి SSH2_సందేశం_PONG:
	స్థితి SSH2_సందేశం_CHANNEL_దత్తాంశం:
	స్థితి SSH2_సందేశం_CHANNEL_EXTENDED_దత్తాంశం:
	స్థితి SSH2_సందేశం_CHANNEL_కిటికీ_ADJUST:
		తిరిగి 0;
	అప్రమేయ:
		తిరిగి 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
పూర్ణాంకం
ssh_packet_send2_wrapped(నిర్మాణం ssh *ssh)
{
	నిర్మాణం session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_నిడివి];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	నిర్మాణం sshenc *enc   = ఖాళీ;
	నిర్మాణం sshmac *mac   = ఖాళీ;
	నిర్మాణం sshcomp *comp = ఖాళీ;
	పూర్ణాంకం r, ఖండం_కొలత;

	ఒకవేళ (state->newkeys[బహుళకం_బహిర్గతం] != ఖాళీ) {
		enc  = &state->newkeys[బహుళకం_బహిర్గతం]->enc;
		mac  = &state->newkeys[బహుళకం_బహిర్గతం]->mac;
		comp = &state->newkeys[బహుళకం_బహిర్గతం]->comp;
		/* disable mac for authenticated encryption */
		ఒకవేళ ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ఖాళీ;
	}
	ఖండం_కొలత = enc ? enc->ఖండం_కొలత : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	ఒకవేళ (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#నిర్వచితమైతే PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#అయితే_ముగింపు

	ఒకవేళ (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		ఒకవేళ ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			వెళ్ళు బహిర్గతం;
		sshbuf_reset(state->compression_బఫరు);
		ఒకవేళ ((r = compress_బఫరు(ssh, state->outgoing_packet,
		    state->compression_బఫరు)) != 0)
			వెళ్ళు బహిర్గతం;
		sshbuf_reset(state->outgoing_packet);
		ఒకవేళ ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_బఫరు)) != 0)
			వెళ్ళు బహిర్గతం;
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
	padlen = ఖండం_కొలత - (len % ఖండం_కొలత);
	ఒకవేళ (padlen < 4)
		padlen += ఖండం_కొలత;
	ఒకవేళ (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, ఖండం_కొలత);
		/* check if roundup overflowed */
		ఒకవేళ (state->extra_pad < tmp)
			తిరిగి SSH_ERR_INVALID_వాదం;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		ఒకవేళ (tmp > state->extra_pad)
			తిరిగి SSH_ERR_INVALID_వాదం;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		ఒకవేళ (padlen < tmp)
			తిరిగి SSH_ERR_INVALID_వాదం; /*అధికప్రవాహం*/
		state->extra_pad = 0;
	}
	ఒకవేళ ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} లేకపోతే {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	ఒకవేళ (cp == ఖాళీ) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	ఒకవేళ (mac && mac->enabled && !mac->etm) {
		ఒకవేళ ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, పరిమాణం(macbuf))) != 0)
			వెళ్ళు బహిర్గతం;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	ఒకవేళ ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		వెళ్ళు బహిర్గతం;
	/* append unencrypted MAC */
	ఒకవేళ (mac && mac->enabled) {
		ఒకవేళ (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			ఒకవేళ ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, పరిమాణం(macbuf))) != 0)
				వెళ్ళు బహిర్గతం;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		ఒకవేళ ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#అయితే_ముగింపు
	/* increment sequence number for outgoing packets */
	ఒకవేళ (++state->p_send.seqnr == 0) {
		ఒకవేళ ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	ఒకవేళ (++state->p_send.packets == 0)
		తిరిగి SSH_ERR_NEED_REKEY;
	state->p_send.ఖండాలు += len / ఖండం_కొలత;
	state->p_send.బైట్లు += len;
	sshbuf_reset(state->outgoing_packet);

	ఒకవేళ (type == SSH2_సందేశం_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	ఒకవేళ (type == SSH2_సందేశం_NEWKEYS)
		r = ssh_సమితి_newkeys(ssh, బహుళకం_బహిర్గతం);
	లేకపోతే ఒకవేళ (type == SSH2_సందేశం_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	లేకపోతే
		r = 0;
 బహిర్గతం:
	తిరిగి r;
}

/* returns non-zero if the specified packet type is usec by KEX */
స్థిర పూర్ణాంకం
ssh_packet_type_is_kex(u_char type)
{
	తిరిగి
	    type >= SSH2_సందేశం_TRANSPORT_MIN &&
	    type <= SSH2_సందేశం_TRANSPORT_MAX &&
	    type != SSH2_సందేశం_SERVICE_REQUEST &&
	    type != SSH2_సందేశం_SERVICE_ACCEPT &&
	    type != SSH2_సందేశం_EXT_INFO;
}

పూర్ణాంకం
ssh_packet_send2(నిర్మాణం ssh *ssh)
{
	నిర్మాణం session_state *state = ssh->state;
	నిర్మాణం packet *p;
	u_char type;
	పూర్ణాంకం r, need_rekey;

	ఒకవేళ (sshbuf_len(state->outgoing_packet) < 6)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	ఒకవేళ (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		తిరిగి r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	ఒకవేళ ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		ఒకవేళ (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*p));
		ఒకవేళ (p == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, తదుపరి);
		state->outgoing_packet = sshbuf_new();
		ఒకవేళ (state->outgoing_packet == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
		ఒకవేళ (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			తిరిగి kex_ప్రారంభం_rekex(ssh);
		}
		తిరిగి 0;
	}

	/* rekeying starts with sending KEXINIT */
	ఒకవేళ (type == SSH2_సందేశం_KEXINIT)
		state->rekeying = 1;

	ఒకవేళ ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		తిరిగి r;

	/* after a NEWKEYS message we can send the complete queue */
	ఒకవేళ (type == SSH2_సందేశం_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_సమయం = monotime();
		అయితే ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			ఒకవేళ (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				తిరిగి kex_ప్రారంభం_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, తదుపరి);
			memset(p, 0, పరిమాణం(*p));
			విడుదల(p);
			ఒకవేళ ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				తిరిగి r;
		}
	}
	తిరిగి 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

పూర్ణాంకం
ssh_packet_read_seqnr(నిర్మాణం ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	నిర్మాణం session_state *state = ssh->state;
	పూర్ణాంకం len, r, ms_remain = 0;
	నిర్మాణం pollfd pfd;
	అక్షరం buf[8192];
	నిర్మాణం timeval ప్రారంభం;
	నిర్మాణం timespec timespec, *timespecp = ఖాళీ;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	ఒకవేళ ((r = ssh_packet_write_wait(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Stay in the loop until we have received a complete packet. */
	కొరకు (;;) {
		/* Try to read a packet from the buffer. */
		ఒకవేళ ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			ఆపు;
		/* If we got a packet, return it. */
		ఒకవేళ (*typep != SSH_సందేశం_NONE)
			ఆపు;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_లోపల;
		pfd.events = POLLIN;

		ఒకవేళ (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		కొరకు (;;) {
			ఒకవేళ (state->packet_timeout_ms > 0) {
				ms_గమ్యం_timespec(&timespec, ms_remain);
				monotime_tv(&ప్రారంభం);
			}
			ఒకవేళ ((r = ppoll(&pfd, 1, timespecp, ఖాళీ)) >= 0)
				ఆపు;
			ఒకవేళ (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (state->packet_timeout_ms <= 0)
				కొనసాగు;
			ms_వ్యవకలనం_diff(&ప్రారంభం, &ms_remain);
			ఒకవేళ (ms_remain <= 0) {
				r = 0;
				ఆపు;
			}
		}
		ఒకవేళ (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			వెళ్ళు బహిర్గతం;
		}
		/* Read data from the socket. */
		len = పఠ(state->connection_లోపల, buf, పరిమాణం(buf));
		ఒకవేళ (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			వెళ్ళు బహిర్గతం;
		}

		/* Append it to the buffer. */
		ఒకవేళ ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			వెళ్ళు బహిర్గతం;
	}
 బహిర్గతం:
	తిరిగి r;
}

పూర్ణాంకం
ssh_packet_read(నిర్మాణం ssh *ssh)
{
	u_char type;
	పూర్ణాంకం r;

	ఒకవేళ ((r = ssh_packet_read_seqnr(ssh, &type, ఖాళీ)) != 0)
		sshpkt_fatal(ssh, r, "read");
	తిరిగి type;
}

స్థిర పూర్ణాంకం
ssh_packet_read_poll2_mux(నిర్మాణం ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	నిర్మాణం session_state *state = ssh->state;
	స్థిరరాశి u_char *cp;
	కొలత_t need;
	పూర్ణాంకం r;

	ఒకవేళ (ssh->kex)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	*typep = SSH_సందేశం_NONE;
	cp = sshbuf_ptr(state->ఆదానం);
	ఒకవేళ (state->packlen == 0) {
		ఒకవేళ (sshbuf_len(state->ఆదానం) < 4 + 1)
			తిరిగి 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		ఒకవేళ (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_కొలత)
			తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	}
	need = state->packlen + 4;
	ఒకవేళ (sshbuf_len(state->ఆదానం) < need)
		తిరిగి 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	ఒకవేళ ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->ఆదానం, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		తిరిగి r;
	ఒకవేళ (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	తిరిగి r;
}

పూర్ణాంకం
ssh_packet_read_poll2(నిర్మాణం ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	నిర్మాణం session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, ఖండం_కొలత;
	నిర్మాణం sshenc *enc   = ఖాళీ;
	నిర్మాణం sshmac *mac   = ఖాళీ;
	నిర్మాణం sshcomp *comp = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (state->mux)
		తిరిగి ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_సందేశం_NONE;

	ఒకవేళ (state->packet_discard)
		తిరిగి 0;

	ఒకవేళ (state->newkeys[బహుళకం_లోపల] != ఖాళీ) {
		enc  = &state->newkeys[బహుళకం_లోపల]->enc;
		mac  = &state->newkeys[బహుళకం_లోపల]->mac;
		comp = &state->newkeys[బహుళకం_లోపల]->comp;
		/* disable mac for authenticated encryption */
		ఒకవేళ ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = ఖాళీ;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	ఖండం_కొలత = enc ? enc->ఖండం_కొలత : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	ఒకవేళ (aadlen && state->packlen == 0) {
		ఒకవేళ (cipher_get_నిడివి(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->ఆదానం), sshbuf_len(state->ఆదానం)) != 0)
			తిరిగి 0;
		ఒకవేళ (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_కొలత) {
#నిర్వచితమైతే PACKET_DEBUG
			sshbuf_dump(state->ఆదానం, stderr);
#అయితే_ముగింపు
			logit("Bad packet length %u.", state->packlen);
			ఒకవేళ ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				తిరిగి r;
			తిరిగి SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} లేకపోతే ఒకవేళ (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		ఒకవేళ (sshbuf_len(state->ఆదానం) < ఖండం_కొలత)
			తిరిగి 0;
		sshbuf_reset(state->incoming_packet);
		ఒకవేళ ((r = sshbuf_reserve(state->incoming_packet, ఖండం_కొలత,
		    &cp)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->ఆదానం),
		    ఖండం_కొలత, 0, 0)) != 0)
			వెళ్ళు బహిర్గతం;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		ఒకవేళ (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_కొలత) {
#నిర్వచితమైతే PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->ఆదానం, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#అయితే_ముగింపు
			logit("Bad packet length %u.", state->packlen);
			తిరిగి ssh_packet_ప్రారంభం_discard(ssh, enc, mac, 0,
			    PACKET_MAX_కొలత);
		}
		ఒకవేళ ((r = sshbuf_consume(state->ఆదానం, ఖండం_కొలత)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	ఒకవేళ (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} లేకపోతే {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - ఖండం_కొలత;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", ఖండం_కొలత, need, maclen, authlen, aadlen));
	ఒకవేళ (need % ఖండం_కొలత != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, ఖండం_కొలత, need % ఖండం_కొలత);
		తిరిగి ssh_packet_ప్రారంభం_discard(ssh, enc, mac, 0,
		    PACKET_MAX_కొలత - ఖండం_కొలత);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet:
	 * 'aadlen' bytes are unencrypted, but authenticated.
	 * 'need' bytes are encrypted, followed by either
	 * 'authlen' bytes of authentication tag or
	 * 'maclen' bytes of message authentication code.
	 */
	ఒకవేళ (sshbuf_len(state->ఆదానం) < aadlen + need + authlen + maclen)
		తిరిగి 0; /* packet is incomplete */
#నిర్వచితమైతే PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->ఆదానం, stderr);
#అయితే_ముగింపు
	/* EtM: check mac over encrypted input */
	ఒకవేళ (mac && mac->enabled && mac->etm) {
		ఒకవేళ ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->ఆదానం), aadlen + need,
		    sshbuf_ptr(state->ఆదానం) + aadlen + need + authlen,
		    maclen)) != 0) {
			ఒకవేళ (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->ఆదానం), need, aadlen, authlen)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = sshbuf_consume(state->ఆదానం, aadlen + need + authlen)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		ఒకవేళ (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->ఆదానం), maclen)) != 0) {
			ఒకవేళ (r != SSH_ERR_MAC_INVALID)
				వెళ్ళు బహిర్గతం;
			logit("Corrupted MAC on input.");
			ఒకవేళ (need + ఖండం_కొలత > PACKET_MAX_కొలత)
				తిరిగి SSH_ERR_అంతర్గత_ERROR;
			తిరిగి ssh_packet_ప్రారంభం_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_కొలత - need - ఖండం_కొలత);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		ఒకవేళ ((r = sshbuf_consume(state->ఆదానం, mac->mac_len)) != 0)
			వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (seqnr_p != ఖాళీ)
		*seqnr_p = state->p_read.seqnr;
	ఒకవేళ (++state->p_read.seqnr == 0) {
		ఒకవేళ ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	ఒకవేళ (++state->p_read.packets == 0)
		తిరిగి SSH_ERR_NEED_REKEY;
	state->p_read.ఖండాలు += (state->packlen + 4) / ఖండం_కొలత;
	state->p_read.బైట్లు += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	ఒకవేళ (padlen < 4)	{
		ఒకవేళ ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			తిరిగి r;
		తిరిగి SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	ఒకవేళ ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_చివర(state->incoming_packet, padlen)) != 0))
		వెళ్ళు బహిర్గతం;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	ఒకవేళ (comp && comp->enabled) {
		sshbuf_reset(state->compression_బఫరు);
		ఒకవేళ ((r = uncompress_బఫరు(ssh, state->incoming_packet,
		    state->compression_బఫరు)) != 0)
			వెళ్ళు బహిర్గతం;
		sshbuf_reset(state->incoming_packet);
		ఒకవేళ ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_బఫరు)) != 0)
			వెళ్ళు బహిర్గతం;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	ఒకవేళ ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	ఒకవేళ (*typep < SSH2_సందేశం_MIN) {
		ఒకవేళ ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			తిరిగి r;
		తిరిగి SSH_ERR_PROTOCOL_ERROR;
	}
	ఒకవేళ (state->hook_లోపల != ఖాళీ &&
	    (r = state->hook_లోపల(ssh, state->incoming_packet, typep,
	    state->hook_లోపల_ctx)) != 0)
		తిరిగి r;
	ఒకవేళ (*typep == SSH2_సందేశం_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	లేకపోతే
		r = 0;
#నిర్వచితమైతే PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#అయితే_ముగింపు
	/* reset for next packet */
	state->packlen = 0;
	ఒకవేళ (*typep == SSH2_సందేశం_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	ఒకవేళ ((r = ssh_packet_check_rekey(ssh)) != 0)
		తిరిగి r;
 బహిర్గతం:
	తిరిగి r;
}

పూర్ణాంకం
ssh_packet_read_poll_seqnr(నిర్మాణం ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	నిర్మాణం session_state *state = ssh->state;
	u_int reason, seqnr;
	పూర్ణాంకం r;
	u_char *సందేశం;
	స్థిరరాశి u_char *d;
	కొలత_t len;

	కొరకు (;;) {
		సందేశం = ఖాళీ;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		ఒకవేళ (r != 0)
			తిరిగి r;
		ఒకవేళ (*typep == 0) {
			/* no message ready */
			తిరిగి 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		ఒకవేళ (*typep == SSH2_సందేశం_DISCONNECT) {
			ఒకవేళ ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &సందేశం, ఖాళీ)) != 0)
				తిరిగి r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_పోర్టు(ssh), reason, సందేశం);
			విడుదల(సందేశం);
			తిరిగి SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		ఒకవేళ (ssh->kex != ఖాళీ &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			తిరిగి 0;
		/* Implicitly handle transport-level messages */
		ఎంపిక (*typep) {
		స్థితి SSH2_సందేశం_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			ఆపు;
		స్థితి SSH2_సందేశం_DEBUG:
			ఒకవేళ ((r = sshpkt_get_u8(ssh, ఖాళీ)) != 0 ||
			    (r = sshpkt_get_string(ssh, &సందేశం, ఖాళీ)) != 0 ||
			    (r = sshpkt_get_string(ssh, ఖాళీ, ఖాళీ)) != 0) {
				విడుదల(సందేశం);
				తిరిగి r;
			}
			debug("Remote: %.900s", సందేశం);
			విడుదల(సందేశం);
			ఆపు;
		స్థితి SSH2_సందేశం_UNIMPLEMENTED:
			ఒకవేళ ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				తిరిగి r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			ఆపు;
		స్థితి SSH2_సందేశం_PING:
			ఒకవేళ ((r = sshpkt_get_string_ప్రత్యక్ష(ssh, &d, &len)) != 0)
				తిరిగి r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			ఒకవేళ (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				ఆపు;
			}
			ఒకవేళ (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				ఆపు;
			}
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				తిరిగి r;
			ఆపు;
		స్థితి SSH2_సందేశం_PONG:
			ఒకవేళ ((r = sshpkt_get_string_ప్రత్యక్ష(ssh,
			    ఖాళీ, &len)) != 0)
				తిరిగి r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			ఆపు;
		అప్రమేయ:
			ఒకవేళ (ssh->kex != ఖాళీ &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				తిరిగి SSH_ERR_PROTOCOL_ERROR;
			}
			తిరిగి 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
పూర్ణాంకం
ssh_packet_process_incoming(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *buf, u_int len)
{
	నిర్మాణం session_state *state = ssh->state;
	పూర్ణాంకం r;

	ఒకవేళ (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		ఒకవేళ (len >= state->packet_discard) {
			ఒకవేళ ((r = ssh_packet_stop_discard(ssh)) != 0)
				తిరిగి r;
		}
		state->packet_discard -= len;
		తిరిగి 0;
	}
	ఒకవేళ ((r = sshbuf_put(state->ఆదానం, buf, len)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

/* Reads and buffers data from the specified fd */
పూర్ణాంకం
ssh_packet_process_read(నిర్మాణం ssh *ssh, పూర్ణాంకం fd)
{
	నిర్మాణం session_state *state = ssh->state;
	పూర్ణాంకం r;
	కొలత_t rlen;

	ఒకవేళ ((r = sshbuf_read(fd, state->ఆదానం, PACKET_MAX_కొలత, &rlen)) != 0)
		తిరిగి r;

	ఒకవేళ (state->packet_discard) {
		ఒకవేళ ((r = sshbuf_consume_చివర(state->ఆదానం, rlen)) != 0)
			తిరిగి r;
		state->keep_alive_timeouts = 0; /* ?? */
		ఒకవేళ (rlen >= state->packet_discard) {
			ఒకవేళ ((r = ssh_packet_stop_discard(ssh)) != 0)
				తిరిగి r;
		}
		state->packet_discard -= rlen;
		తిరిగి 0;
	}
	తిరిగి 0;
}

పూర్ణాంకం
ssh_packet_మిగిలిన(నిర్మాణం ssh *ssh)
{
	తిరిగి sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
శూన్య
ssh_packet_send_debug(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *fmt,...)
{
	అక్షరం buf[1024];
	va_list వాదనలు;
	పూర్ణాంకం r;

	ఒకవేళ ((ssh->compat & SSH_BUG_DEBUG))
		తిరిగి;

	va_start(వాదనలు, fmt);
	vsnprintf(buf, పరిమాణం(buf), fmt, వాదనలు);
	va_end(వాదనలు);

	debug3("sending debug message: %s", buf);

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

శూన్య
sshpkt_fmt_connection_id(నిర్మాణం ssh *ssh, అక్షరం *s, కొలత_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
స్థిర శూన్య
sshpkt_vfatal(నిర్మాణం ssh *ssh, పూర్ణాంకం r, స్థిరరాశి అక్షరం *fmt, va_list ap)
{
	అక్షరం *ట్యాగ్ = ఖాళీ, remote_id[512];
	పూర్ణాంకం oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, పరిమాణం(remote_id));

	ఎంపిక (r) {
	స్థితి SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_కీలకాలు(ssh);
		logdie("Connection closed by %s", remote_id);
	స్థితి SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_కీలకాలు(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	స్థితి SSH_ERR_DISCONNECTED:
		ssh_packet_clear_కీలకాలు(ssh);
		logdie("Disconnected from %s", remote_id);
	స్థితి SSH_ERR_SYSTEM_ERROR:
		ఒకవేళ (errno == ECONNRESET) {
			ssh_packet_clear_కీలకాలు(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	స్థితి SSH_ERR_NO_CIPHER_ALG_సరిపోలిక:
	స్థితి SSH_ERR_NO_MAC_ALG_సరిపోలిక:
	స్థితి SSH_ERR_NO_COMPRESS_ALG_సరిపోలిక:
	స్థితి SSH_ERR_NO_KEX_ALG_సరిపోలిక:
	స్థితి SSH_ERR_NO_HOSTKEY_ALG_సరిపోలిక:
		ఒకవేళ (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_కీలకాలు(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	అప్రమేయ:
		ఒకవేళ (vasprintf(&ట్యాగ్, fmt, ap) == -1) {
			ssh_packet_clear_కీలకాలు(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_కీలకాలు(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    ట్యాగ్ != ఖాళీ ? ట్యాగ్ : "", ట్యాగ్ != ఖాళీ ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

శూన్య
sshpkt_fatal(నిర్మాణం ssh *ssh, పూర్ణాంకం r, స్థిరరాశి అక్షరం *fmt, ...)
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
శూన్య
ssh_packet_disconnect(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *fmt,...)
{
	అక్షరం buf[1024], remote_id[512];
	va_list వాదనలు;
	పూర్ణాంకం r;

	/* Guard against recursive invocations. */
	ఒకవేళ (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, పరిమాణం(remote_id));
	va_start(వాదనలు, fmt);
	vsnprintf(buf, పరిమాణం(buf), fmt, వాదనలు);
	va_end(వాదనలు);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	ఒకవేళ ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	ఒకవేళ ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
పూర్ణాంకం
ssh_packet_write_poll(నిర్మాణం ssh *ssh)
{
	నిర్మాణం session_state *state = ssh->state;
	పూర్ణాంకం len = sshbuf_len(state->output);
	పూర్ణాంకం r;

	ఒకవేళ (len > 0) {
		len = లిఖ(state->connection_బహిర్గతం,
		    sshbuf_ptr(state->output), len);
		ఒకవేళ (len == -1) {
			ఒకవేళ (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				తిరిగి 0;
			తిరిగి SSH_ERR_SYSTEM_ERROR;
		}
		ఒకవేళ (len == 0)
			తిరిగి SSH_ERR_CONN_CLOSED;
		ఒకవేళ ((r = sshbuf_consume(state->output, len)) != 0)
			తిరిగి r;
	}
	తిరిగి 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
పూర్ణాంకం
ssh_packet_write_wait(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం ret, r, ms_remain = 0;
	నిర్మాణం timeval ప్రారంభం;
	నిర్మాణం timespec timespec, *timespecp = ఖాళీ;
	నిర్మాణం session_state *state = ssh->state;
	నిర్మాణం pollfd pfd;

	ఒకవేళ ((r = ssh_packet_write_poll(ssh)) != 0)
		తిరిగి r;
	అయితే (ssh_packet_have_దత్తాంశం_గమ్యం_write(ssh)) {
		pfd.fd = state->connection_బహిర్గతం;
		pfd.events = POLLOUT;

		ఒకవేళ (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		కొరకు (;;) {
			ఒకవేళ (state->packet_timeout_ms > 0) {
				ms_గమ్యం_timespec(&timespec, ms_remain);
				monotime_tv(&ప్రారంభం);
			}
			ఒకవేళ ((ret = ppoll(&pfd, 1, timespecp, ఖాళీ)) >= 0)
				ఆపు;
			ఒకవేళ (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				ఆపు;
			ఒకవేళ (state->packet_timeout_ms <= 0)
				కొనసాగు;
			ms_వ్యవకలనం_diff(&ప్రారంభం, &ms_remain);
			ఒకవేళ (ms_remain <= 0) {
				ret = 0;
				ఆపు;
			}
		}
		ఒకవేళ (ret == 0)
			తిరిగి SSH_ERR_CONN_TIMEOUT;
		ఒకవేళ ((r = ssh_packet_write_poll(ssh)) != 0)
			తిరిగి r;
	}
	తిరిగి 0;
}

/* Returns true if there is buffered data to write to the connection. */

పూర్ణాంకం
ssh_packet_have_దత్తాంశం_గమ్యం_write(నిర్మాణం ssh *ssh)
{
	తిరిగి sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

పూర్ణాంకం
ssh_packet_not_very_much_దత్తాంశం_గమ్యం_write(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (ssh->state->interactive_బహుళకం)
		తిరిగి sshbuf_len(ssh->state->output) < 16384;
	లేకపోతే
		తిరిగి sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

పూర్ణాంకం
ssh_packet_interactive_దత్తాంశం_గమ్యం_write(నిర్మాణం ssh *ssh)
{
	తిరిగి ssh->state->interactive_బహుళకం &&
	    sshbuf_len(ssh->state->output) < 256;
}

స్థిర శూన్య
apply_qos(నిర్మాణం ssh *ssh)
{
	నిర్మాణం session_state *state = ssh->state;
	పూర్ణాంకం qos = state->interactive_బహుళకం ?
	    state->qos_interactive : state->qos_other;

	ఒకవేళ (!ssh_packet_connection_is_on_socket(ssh))
		తిరిగి;
	ఒకవేళ (!state->nodelay_సమితి) {
		సమితి_nodelay(state->connection_లోపల);
		state->nodelay_సమితి = 1;
	}
	సమితి_sock_tos(ssh->state->connection_లోపల, qos);
}

/* Informs that the current session is interactive. */
శూన్య
ssh_packet_సమితి_interactive(నిర్మాణం ssh *ssh, పూర్ణాంకం interactive)
{
	నిర్మాణం session_state *state = ssh->state;

	state->interactive_బహుళకం = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
శూన్య
ssh_packet_సమితి_qos(నిర్మాణం ssh *ssh, పూర్ణాంకం qos_interactive, పూర్ణాంకం qos_other)
{
	నిర్మాణం session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

పూర్ణాంకం
ssh_packet_సమితి_maxsize(నిర్మాణం ssh *ssh, u_int s)
{
	నిర్మాణం session_state *state = ssh->state;

	ఒకవేళ (state->సమితి_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_కొలత, s);
		తిరిగి -1;
	}
	ఒకవేళ (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		తిరిగి -1;
	}
	state->సమితి_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_కొలత = s;
	తిరిగి s;
}

పూర్ణాంకం
ssh_packet_inc_alive_timeouts(నిర్మాణం ssh *ssh)
{
	తిరిగి ++ssh->state->keep_alive_timeouts;
}

శూన్య
ssh_packet_సమితి_alive_timeouts(నిర్మాణం ssh *ssh, పూర్ణాంకం ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(నిర్మాణం ssh *ssh)
{
	తిరిగి ssh->state->max_packet_కొలత;
}

శూన్య
ssh_packet_సమితి_rekey_limits(నిర్మాణం ssh *ssh, uint64_t బైట్లు, uint32_t seconds)
{
	ఒకవేళ (బైట్లు == 0 && seconds == 0)
		తిరిగి;

	debug3("rekey after %llu bytes, %u seconds", (గుర్తులేని దీర్ఘ దీర్ఘ)బైట్లు,
	    (గుర్తులేని పూర్ణాంకం)seconds);
	ssh->state->rekey_హద్దు = బైట్లు;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(నిర్మాణం ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_సమయం + ssh->state->rekey_interval -
	    monotime();
	తిరిగి (seconds <= 0 ? 1 : seconds);
}

శూన్య
ssh_packet_సమితి_server(నిర్మాణం ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

శూన్య
ssh_packet_సమితి_authenticated(నిర్మాణం ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

శూన్య *
ssh_packet_get_ఆదానం(నిర్మాణం ssh *ssh)
{
	తిరిగి (శూన్య *)ssh->state->ఆదానం;
}

శూన్య *
ssh_packet_get_output(నిర్మాణం ssh *ssh)
{
	తిరిగి (శూన్య *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
స్థిర పూర్ణాంకం
ssh_packet_సమితి_postauth(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	ఒకవేళ ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
స్థిర పూర్ణాంకం
kex_గమ్యం_blob(నిర్మాణం sshbuf *m, నిర్మాణం kex *kex)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
	    (r = sshbuf_put_cstring(m, kex->hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_strict)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->client_సంస్కరణ)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->server_సంస్కరణ)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->flags)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->non_pq_kex_warned)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

/* turn key exchange results into a blob for packet state serialization */
స్థిర పూర్ణాంకం
newkeys_గమ్యం_blob(నిర్మాణం sshbuf *m, నిర్మాణం ssh *ssh, పూర్ణాంకం బహుళకం)
{
	నిర్మాణం sshbuf *b;
	నిర్మాణం sshcipher_ctx *cc;
	నిర్మాణం sshcomp *comp;
	నిర్మాణం sshenc *enc;
	నిర్మాణం sshmac *mac;
	నిర్మాణం newkeys *newkey;
	పూర్ణాంకం r;

	ఒకవేళ ((newkey = ssh->state->newkeys[బహుళకం]) == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (బహుళకం == బహుళకం_బహిర్గతం) ? ssh->state->send_context :
	    ssh->state->receive_context;
	ఒకవేళ ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		తిరిగి r;
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->ఖండం_కొలత)) != 0 ||
	    (r = sshbuf_put_string(b, enc->కీలకం, enc->కీలకం_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (cipher_authlen(enc->cipher) == 0) {
		ఒకవేళ ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->కీలకం, mac->కీలకం_len)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		వెళ్ళు బహిర్గతం;
	r = sshbuf_put_stringb(m, b);
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

/* serialize packet state into a blob */
పూర్ణాంకం
ssh_packet_get_state(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *m)
{
	నిర్మాణం session_state *state = ssh->state;
	పూర్ణాంకం r;

#నిర్వచించు ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	ఒకవేళ ((r = kex_గమ్యం_blob(m, ssh->kex)) != 0 ||
	    (r = newkeys_గమ్యం_blob(m, ssh, బహుళకం_బహిర్గతం)) != 0 ||
	    (r = newkeys_గమ్యం_blob(m, ssh, బహుళకం_లోపల)) != 0 ||
	    (r = sshbuf_put_u64(m, state->rekey_హద్దు)) != 0 ||
	    (r = sshbuf_put_u32(m, state->rekey_interval)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.ఖండాలు)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.బైట్లు)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.ఖండాలు)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.బైట్లు)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->ఆదానం)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_బహుళకం))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		తిరిగి r;
#నిర్వచనం_రద్దు ENCODE_INT
	తిరిగి 0;
}

/* restore key exchange results from blob for packet state de-serialization */
స్థిర పూర్ణాంకం
newkeys_from_blob(నిర్మాణం sshbuf *m, నిర్మాణం ssh *ssh, పూర్ణాంకం బహుళకం)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	నిర్మాణం sshcomp *comp;
	నిర్మాణం sshenc *enc;
	నిర్మాణం sshmac *mac;
	నిర్మాణం newkeys *newkey = ఖాళీ;
	కొలత_t keylen, ivlen, maclen;
	పూర్ణాంకం r;

	ఒకవేళ ((newkey = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*newkey))) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_froms(m, &b)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_PK
	sshbuf_dump(b, stderr);
#అయితే_ముగింపు
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	ఒకవేళ ((r = sshbuf_get_cstring(b, &enc->name, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->ఖండం_కొలత)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->కీలకం, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((enc->cipher = cipher_by_name(enc->name)) == ఖాళీ ||
	    enc->ఖండం_కొలత != cipher_blocksize(enc->cipher) ||
	    cipher_is_అంతర్గత(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (cipher_authlen(enc->cipher) == 0) {
		ఒకవేళ ((r = sshbuf_get_cstring(b, &mac->name, ఖాళీ)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ ((r = mac_అమరిక(mac, mac->name)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->కీలకం, &maclen)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (maclen != mac->కీలకం_len) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		mac->కీలకం_len = maclen;
	}
	ఒకవేళ ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	enc->కీలకం_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[బహుళకం] = newkey;
	newkey = ఖాళీ;
	r = 0;
 బహిర్గతం:
	విడుదల(newkey);
	sshbuf_free(b);
	తిరిగి r;
}

/* restore kex from blob for packet state de-serialization */
స్థిర పూర్ణాంకం
kex_from_blob(నిర్మాణం sshbuf *m, నిర్మాణం kex **kexp)
{
	నిర్మాణం kex *kex;
	పూర్ణాంకం r;

	ఒకవేళ ((kex = kex_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_type)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_type)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_strict)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->client_సంస్కరణ)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->server_సంస్కరణ)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->flags)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->non_pq_kex_warned)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	kex->server = 1;
	kex->పూర్తి = 1;
	r = 0;
 బహిర్గతం:
	ఒకవేళ (r != 0 || kexp == ఖాళీ) {
		kex_free(kex);
		ఒకవేళ (kexp != ఖాళీ)
			*kexp = ఖాళీ;
	} లేకపోతే {
		kex_free(*kexp);
		*kexp = kex;
	}
	తిరిగి r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
పూర్ణాంకం
ssh_packet_సమితి_state(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *m)
{
	నిర్మాణం session_state *state = ssh->state;
	స్థిరరాశి u_char *ఆదానం, *output;
	కొలత_t ilen, olen;
	పూర్ణాంకం r;
	u_int interactive, qos_interactive, qos_other;

	ఒకవేళ ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, బహుళకం_బహిర్గతం)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, బహుళకం_లోపల)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->rekey_హద్దు)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->rekey_interval)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.ఖండాలు)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.బైట్లు)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.ఖండాలు)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.బైట్లు)) != 0)
		తిరిగి r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_సమయం = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	ఒకవేళ ((r = ssh_సమితి_newkeys(ssh, బహుళకం_లోపల)) != 0 ||
	    (r = ssh_సమితి_newkeys(ssh, బహుళకం_బహిర్గతం)) != 0)
		తిరిగి r;

	ఒకవేళ ((r = ssh_packet_సమితి_postauth(ssh)) != 0)
		తిరిగి r;

	sshbuf_reset(state->ఆదానం);
	sshbuf_reset(state->output);
	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(m, &ఆదానం, &ilen)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->ఆదానం, ఆదానం, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		తిరిగి r;

	ఒకవేళ ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		తిరిగి r;
#నిర్వచించు DECODE_INT(v) ((v) > గరిష్ఠ_పూర్ణాంకం ? -1 : (పూర్ణాంకం)(v))
	state->interactive_బహుళకం = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#నిర్వచనం_రద్దు DECODE_INT

	ఒకవేళ (sshbuf_len(m))
		తిరిగి SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	తిరిగి 0;
}

/* NEW API */

/* put data to the outgoing packet */

పూర్ణాంకం
sshpkt_put(నిర్మాణం ssh *ssh, స్థిరరాశి శూన్య *v, కొలత_t len)
{
	తిరిగి sshbuf_put(ssh->state->outgoing_packet, v, len);
}

పూర్ణాంకం
sshpkt_putb(నిర్మాణం ssh *ssh, స్థిరరాశి నిర్మాణం sshbuf *b)
{
	తిరిగి sshbuf_putb(ssh->state->outgoing_packet, b);
}

పూర్ణాంకం
sshpkt_put_u8(నిర్మాణం ssh *ssh, u_char val)
{
	తిరిగి sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

పూర్ణాంకం
sshpkt_put_u32(నిర్మాణం ssh *ssh, uint32_t val)
{
	తిరిగి sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

పూర్ణాంకం
sshpkt_put_u64(నిర్మాణం ssh *ssh, uint64_t val)
{
	తిరిగి sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

పూర్ణాంకం
sshpkt_put_string(నిర్మాణం ssh *ssh, స్థిరరాశి శూన్య *v, కొలత_t len)
{
	తిరిగి sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

పూర్ణాంకం
sshpkt_put_cstring(నిర్మాణం ssh *ssh, స్థిరరాశి శూన్య *v)
{
	తిరిగి sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

పూర్ణాంకం
sshpkt_put_stringb(నిర్మాణం ssh *ssh, స్థిరరాశి నిర్మాణం sshbuf *v)
{
	తిరిగి sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#నిర్వచితమైతే WITH_OPENSSL
పూర్ణాంకం
sshpkt_put_ec(నిర్మాణం ssh *ssh, స్థిరరాశి EC_బిందువు *v, స్థిరరాశి EC_సమూహం *g)
{
	తిరిగి sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

పూర్ణాంకం
sshpkt_put_ec_pkey(నిర్మాణం ssh *ssh, EVP_PKEY *pkey)
{
	తిరిగి sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

పూర్ణాంకం
sshpkt_put_bignum2(నిర్మాణం ssh *ssh, స్థిరరాశి BIGNUM *v)
{
	తిరిగి sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#అయితే_ముగింపు /* WITH_OPENSSL */

/* fetch data from the incoming packet */

పూర్ణాంకం
sshpkt_get(నిర్మాణం ssh *ssh, శూన్య *valp, కొలత_t len)
{
	తిరిగి sshbuf_get(ssh->state->incoming_packet, valp, len);
}

పూర్ణాంకం
sshpkt_get_u8(నిర్మాణం ssh *ssh, u_char *valp)
{
	తిరిగి sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

పూర్ణాంకం
sshpkt_get_u32(నిర్మాణం ssh *ssh, uint32_t *valp)
{
	తిరిగి sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

పూర్ణాంకం
sshpkt_get_u64(నిర్మాణం ssh *ssh, uint64_t *valp)
{
	తిరిగి sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

పూర్ణాంకం
sshpkt_get_string(నిర్మాణం ssh *ssh, u_char **valp, కొలత_t *lenp)
{
	తిరిగి sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

పూర్ణాంకం
sshpkt_get_string_ప్రత్యక్ష(నిర్మాణం ssh *ssh, స్థిరరాశి u_char **valp, కొలత_t *lenp)
{
	తిరిగి sshbuf_get_string_ప్రత్యక్ష(ssh->state->incoming_packet, valp, lenp);
}

పూర్ణాంకం
sshpkt_peek_string_ప్రత్యక్ష(నిర్మాణం ssh *ssh, స్థిరరాశి u_char **valp, కొలత_t *lenp)
{
	తిరిగి sshbuf_peek_string_ప్రత్యక్ష(ssh->state->incoming_packet, valp, lenp);
}

పూర్ణాంకం
sshpkt_get_cstring(నిర్మాణం ssh *ssh, అక్షరం **valp, కొలత_t *lenp)
{
	తిరిగి sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

పూర్ణాంకం
sshpkt_getb_froms(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf **valp)
{
	తిరిగి sshbuf_froms(ssh->state->incoming_packet, valp);
}

#నిర్వచితమైతే WITH_OPENSSL
పూర్ణాంకం
sshpkt_get_ec(నిర్మాణం ssh *ssh, EC_బిందువు *v, స్థిరరాశి EC_సమూహం *g)
{
	తిరిగి sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

పూర్ణాంకం
sshpkt_get_bignum2(నిర్మాణం ssh *ssh, BIGNUM **valp)
{
	తిరిగి sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#అయితే_ముగింపు /* WITH_OPENSSL */

పూర్ణాంకం
sshpkt_get_చివర(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (sshbuf_len(ssh->state->incoming_packet) > 0)
		తిరిగి SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం;
	తిరిగి 0;
}

స్థిరరాశి u_char *
sshpkt_ptr(నిర్మాణం ssh *ssh, కొలత_t *lenp)
{
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	తిరిగి sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

పూర్ణాంకం
sshpkt_ప్రారంభం(నిర్మాణం ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, పరిమాణం(buf));
	buf[పరిమాణం(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	తిరిగి sshbuf_put(ssh->state->outgoing_packet, buf, పరిమాణం(buf));
}

స్థిర పూర్ణాంకం
ssh_packet_send_mux(నిర్మాణం ssh *ssh)
{
	నిర్మాణం session_state *state = ssh->state;
	u_char type, *cp;
	కొలత_t len;
	పూర్ణాంకం r;

	ఒకవేళ (ssh->kex)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	ఒకవేళ (len < 6)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	ఒకవేళ (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	ఒకవేళ (type >= SSH2_సందేశం_CONNECTION_MIN &&
	    type <= SSH2_సందేశం_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		ఒకవేళ ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			తిరిగి r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	తిరిగి 0;
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
పూర్ణాంకం
sshpkt_సందేశం_ignore(నిర్మాణం ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	పూర్ణాంకం r;
	u_int i;

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		తిరిగి r;
	కొరకు (i = 0; i < nbytes; i++) {
		ఒకవేళ (i % 4 == 0)
			rnd = arc4random();
		ఒకవేళ ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			తిరిగి r;
		rnd >>= 8;
	}
	తిరిగి 0;
}

/* send it */

పూర్ణాంకం
sshpkt_send(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (ssh->state && ssh->state->mux)
		తిరిగి ssh_packet_send_mux(ssh);
	తిరిగి ssh_packet_send2(ssh);
}

పూర్ణాంకం
sshpkt_disconnect(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *fmt,...)
{
	అక్షరం buf[1024];
	va_list వాదనలు;
	పూర్ణాంకం r;

	va_start(వాదనలు, fmt);
	vsnprintf(buf, పరిమాణం(buf), fmt, వాదనలు);
	va_end(వాదనలు);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

/* roundup current message to pad bytes */
పూర్ణాంకం
sshpkt_కూడు_padding(నిర్మాణం ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	తిరిగి 0;
}

స్థిర అక్షరం *
format_traffic_stats(నిర్మాణం packet_state *ps)
{
	అక్షరం *stats = ఖాళీ, బైట్లు[FMT_SCALED_STRSIZE];

	ఒకవేళ (ps->బైట్లు > LLONG_MAX || fmt_scaled(ps->బైట్లు, బైట్లు) != 0)
		strlcpy(బైట్లు, "OVERFLOW", పరిమాణం(బైట్లు));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (గుర్తులేని దీర్ఘ)ps->packets, (గుర్తులేని దీర్ఘ దీర్ఘ)ps->ఖండాలు, బైట్లు);
	తిరిగి stats;
}

స్థిర అక్షరం *
dedupe_alg_పేర్లు(స్థిరరాశి అక్షరం *లోపల, స్థిరరాశి అక్షరం *బహిర్గతం)
{
	అక్షరం *పేర్లు = ఖాళీ;

	ఒకవేళ (లోపల == ఖాళీ)
		లోపల = "<implicit>";
	ఒకవేళ (బహిర్గతం == ఖాళీ)
		బహిర్గతం = "<implicit>";

	ఒకవేళ (strcmp(లోపల, బహిర్గతం) == 0) {
		పేర్లు = xstrdup(లోపల);
	} లేకపోతే {
		xasprintf(&పేర్లు, "%s in, %s out", లోపల, బహిర్గతం);
	}
	తిరిగి పేర్లు;
}

స్థిర అక్షరం *
comp_స్థితి_సందేశం(నిర్మాణం ssh *ssh)
{
#నిర్వచితమైతే WITH_ZLIB
	అక్షరం *ret = ఖాళీ;
	నిర్మాణం session_state *state = ssh->state;
	గుర్తులేని దీర్ఘ దీర్ఘ iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	అక్షరం iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	అక్షరం icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	ఒకవేళ (state->compression_బఫరు) {
		ఒకవేళ (state->compression_లోపల_started) {
			iraw = state->compression_లోపల_ప్రవాహం.మొత్తం_బహిర్గతం;
			icmp = state->compression_లోపల_ప్రవాహం.మొత్తం_లోపల;
			ఒకవేళ (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", పరిమాణం(iraw_f));
			ఒకవేళ (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", పరిమాణం(icmp_f));
		}
		ఒకవేళ (state->compression_బహిర్గతం_started) {
			oraw = state->compression_బహిర్గతం_ప్రవాహం.మొత్తం_లోపల;
			ocmp = state->compression_బహిర్గతం_ప్రవాహం.మొత్తం_బహిర్గతం;
			ఒకవేళ (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", పరిమాణం(oraw_f));
			ఒకవేళ (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", పరిమాణం(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (ద్విగుణ)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (ద్విగుణ)ocmp / oraw);
		తిరిగి ret;
	}
#అయితే_ముగింపు	/* WITH_ZLIB */
	తిరిగి xstrdup("");
}

అక్షరం *
connection_info_సందేశం(నిర్మాణం ssh *ssh)
{
	అక్షరం *ret = ఖాళీ, *cipher = ఖాళీ, *mac = ఖాళీ, *comp = ఖాళీ;
	అక్షరం *rekey_volume = ఖాళీ, *rekey_సమయం = ఖాళీ, *comp_info = ఖాళీ;
	అక్షరం thishost[NI_MAXHOST] = "unknown", *tcp_info = ఖాళీ;
	నిర్మాణం kex *kex;
	నిర్మాణం session_state *state;
	నిర్మాణం newkeys *nk_లోపల, *nk_బహిర్గతం;
	అక్షరం *stats_లోపల = ఖాళీ, *stats_బహిర్గతం = ఖాళీ;
	uint64_t epoch = (uint64_t)time(ఖాళీ) - monotime();

	ఒకవేళ (ssh == ఖాళీ)
		తిరిగి ఖాళీ;
	state = ssh->state;
	kex = ssh->kex;

	(శూన్య)gethostname(thishost, పరిమాణం(thishost));

	ఒకవేళ (ssh_local_పోర్టు(ssh) != 65535 ||
	     strcmp(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_పోర్టు(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
	} లేకపోతే {
		tcp_info = xstrdup("");
	}

	nk_లోపల = ssh->state->newkeys[బహుళకం_లోపల];
	nk_బహిర్గతం = ssh->state->newkeys[బహుళకం_బహిర్గతం];
	stats_లోపల = format_traffic_stats(&ssh->state->p_read);
	stats_బహిర్గతం = format_traffic_stats(&ssh->state->p_send);

	cipher = dedupe_alg_పేర్లు(nk_లోపల->enc.name, nk_బహిర్గతం->enc.name);
	mac = dedupe_alg_పేర్లు(nk_లోపల->mac.name, nk_బహిర్గతం->mac.name);
	comp = dedupe_alg_పేర్లు(nk_లోపల->comp.name, nk_బహిర్గతం->comp.name);

	/* Volume based rekeying. */
	ఒకవేళ (state->rekey_హద్దు == 0) {
		xasprintf(&rekey_volume, "limit none");
	} లేకపోతే {
		అక్షరం *volumes = ఖాళీ, లోపల[32], బహిర్గతం[32];

		snprintf(లోపల, పరిమాణం(లోపల), "%llu",
		   (గుర్తులేని దీర్ఘ దీర్ఘ)state->max_ఖండాలు_లోపల);
		snprintf(బహిర్గతం, పరిమాణం(బహిర్గతం), "%llu",
		   (గుర్తులేని దీర్ఘ దీర్ఘ)state->max_ఖండాలు_బహిర్గతం);
		volumes = dedupe_alg_పేర్లు(లోపల, బహిర్గతం);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		విడుదల(volumes);
	}

	/* Time based rekeying. */
	ఒకవేళ (state->rekey_interval == 0) {
		rekey_సమయం = xstrdup("interval none");
	} లేకపోతే {
		అక్షరం rekey_తదుపరి[64];

		format_absolute_సమయం(epoch + state->rekey_సమయం +
		    state->rekey_interval, rekey_తదుపరి, పరిమాణం(rekey_తదుపరి));
		xasprintf(&rekey_సమయం, "interval %s, next %s",
		    fmt_timeframe(state->rekey_interval), rekey_తదుపరి);
	}
	comp_info = comp_స్థితి_సందేశం(ssh);

	xasprintf(&ret, "Connection information for %s pid %lld\r\n"
	    "  versions %s -> %s\r\n"
	    "%s"
	    "  duration %s\r\n"
	    "  kexalgorithm %s\r\n  hostkeyalgorithm %s\r\n"
	    "  cipher %s\r\n  mac %s\r\n  compression %s\r\n"
	    "  rekey %s %s\r\n"
	    "  traffic %s in, %s out\r\n"
	    "%s",
	    thishost, (దీర్ఘ దీర్ఘ)getpid(),
	    SSH_RELEASE, ssh->remote_సంస్కరణ,
	    tcp_info,
	    fmt_timeframe(monotime() - state->ప్రారంభం_సమయం),
	    kex->name, kex->hostkey_alg,
	    cipher, mac, comp,
	    rekey_volume, rekey_సమయం,
	    stats_లోపల, stats_బహిర్గతం,
	    comp_info
	);
	విడుదల(tcp_info);
	విడుదల(cipher);
	విడుదల(mac);
	విడుదల(comp);
	విడుదల(stats_లోపల);
	విడుదల(stats_బహిర్గతం);
	విడుదల(rekey_volume);
	విడుదల(rekey_సమయం);
	విడుదల(comp_info);
	తిరిగి ret;
}

