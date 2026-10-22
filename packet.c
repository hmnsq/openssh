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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/time.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <util.h>

/*
 * Explicitly include OpenSSL before zlib as some versions of OpenSSL have
 * "free_func" in their headers, which zlib typedefs.
 */
#यदि_परिभाषितम् WITH_OPENSSL
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/ec.h>
#यदि_अन्तः

#यदि_परिभाषितम् WITH_ZLIB
#अन्तर्भाव <zlib.h>
#यदि_अन्तः

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "version.h"

#यदि_परिभाषितम् PACKET_DEBUG
#परिभाषय DBG(x) x
#अन्यथा
#परिभाषय DBG(x)
#यदि_अन्तः

#परिभाषय PACKET_MAX_आकार (256 * 1024)

संरचना packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t खण्डानि;
	uint64_t अष्टकानि;
};

संरचना packet {
	TAILQ_ENTRY(packet) अग्र;
	u_char type;
	संरचना sshbuf *payload;
};

संरचना session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	पूर्णाङ्क connection_अन्तर्;
	पूर्णाङ्क connection_बहिर्गमनम्;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	संरचना sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	संरचना sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	संरचना sshbuf *निवेशः;

	/* Buffer for raw output data going to the socket. */
	संरचना sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	संरचना sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	संरचना sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	संरचना sshbuf *compression_बफर;

#यदि_परिभाषितम् WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_प्रवाहः compression_अन्तर्_प्रवाहः;
	z_प्रवाहः compression_बहिर्गमनम्_प्रवाहः;
#यदि_अन्तः
	पूर्णाङ्क compression_अन्तर्_started;
	पूर्णाङ्क compression_बहिर्गमनम्_started;
	पूर्णाङ्क compression_अन्तर्_failures;
	पूर्णाङ्क compression_बहिर्गमनम्_failures;

	/* default maximum packet size */
	u_int max_packet_आकार;

	/* Flag indicating whether this module has been initialized. */
	पूर्णाङ्क initialized;

	/* Monotonic clock timestamp when the connection was started. */
	time_t start_time;

	/* Set to true if the connection is interactive. */
	पूर्णाङ्क interactive_बहुलकम्;

	/* Set to true if we are the server side. */
	पूर्णाङ्क server_side;

	/* Set to true if we are authenticated. */
	पूर्णाङ्क after_authentication;

	पूर्णाङ्क keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	पूर्णाङ्क packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	संरचना newkeys *newkeys[बहुलकम्_MAX];
	संरचना packet_state p_read, p_send;

	/* Volume-based rekeying */
	uint64_t hard_max_खण्डानि_अन्तर्, hard_max_खण्डानि_बहिर्गमनम्;
	uint64_t max_खण्डानि_अन्तर्, max_खण्डानि_बहिर्गमनम्, rekey_सीमा;

	/* Time-based rekeying */
	uint32_t rekey_interval;	/* how often in seconds */
	time_t rekey_time;	/* time of last rekeying */

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	आकार_t packet_discard_mac_already;
	संरचना sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	पूर्णाङ्क rekeying;

	/* Used in ssh_packet_send_mux() */
	पूर्णाङ्क mux;

	/* QoS handling */
	पूर्णाङ्क qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	पूर्णाङ्क समुच्चयः_maxsize_called;

	/* One-off warning about weak ciphers */
	पूर्णाङ्क cipher_warning_समाप्तम्;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	पूर्णाङ्क disconnecting;

	/* Nagle disabled on socket */
	पूर्णाङ्क nodelay_समुच्चयः;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_अन्तर्;
	शून्य *hook_अन्तर्_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

संरचना ssh *
ssh_alloc_session_state(शून्य)
{
	संरचना ssh *ssh = रिक्त;
	संरचना session_state *state = रिक्त;

	यदि ((ssh = शून्यस्मृतिं_देहि(1, परिमाण(*ssh))) == रिक्त ||
	    (state = शून्यस्मृतिं_देहि(1, परिमाण(*state))) == रिक्त ||
	    (ssh->kex = kex_new()) == रिक्त ||
	    (state->निवेशः = sshbuf_new()) == रिक्त ||
	    (state->output = sshbuf_new()) == रिक्त ||
	    (state->outgoing_packet = sshbuf_new()) == रिक्त ||
	    (state->incoming_packet = sshbuf_new()) == रिक्त)
		गच्छ fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->वैयक्तिकम्_कुञ्चिकाः);
	TAILQ_INIT(&ssh->लौकिकम्_कुञ्चिकाः);
	state->connection_अन्तर् = -1;
	state->connection_बहिर्गमनम् = -1;
	state->max_packet_आकार = 32768;
	state->packet_timeout_ms = -1;
	state->interactive_बहुलकम् = 1;
	state->qos_interactive = state->qos_other = -1;
	state->p_send.packets = state->p_read.packets = 0;
	state->initialized = 1;
	/*
	 * ssh_packet_send2() needs to queue packets until
	 * we've done the initial key exchange.
	 */
	state->rekeying = 1;
	ssh->state = state;
	प्रत्यागम ssh;
 fail:
	यदि (ssh) {
		kex_free(ssh->kex);
		मुक्त(ssh);
	}
	यदि (state) {
		sshbuf_free(state->निवेशः);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		मुक्त(state);
	}
	प्रत्यागम रिक्त;
}

शून्य
ssh_packet_समुच्चयः_निवेशः_hook(संरचना ssh *ssh, ssh_packet_hook_fn *hook, शून्य *ctx)
{
	ssh->state->hook_अन्तर् = hook;
	ssh->state->hook_अन्तर्_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
पूर्णाङ्क
ssh_packet_is_rekeying(संरचना ssh *ssh)
{
	प्रत्यागम ssh->state->rekeying ||
	    (ssh->kex != रिक्त && ssh->kex->समाप्तम् == 0);
}

/*
 * Sets the descriptors used for communication.
 */
संरचना ssh *
ssh_packet_समुच्चयः_connection(संरचना ssh *ssh, पूर्णाङ्क fd_अन्तर्, पूर्णाङ्क fd_बहिर्गमनम्)
{
	संरचना session_state *state;
	ध्रुव संरचना sshcipher *none = cipher_by_name("none");
	पूर्णाङ्क r, wasnull = ssh == रिक्त;

	यदि (none == रिक्त) {
		error_f("cannot load cipher 'none'");
		प्रत्यागम रिक्त;
	}
	यदि (ssh == रिक्त)
		ssh = ssh_alloc_session_state();
	यदि (ssh == रिक्त) {
		error_f("could not allocate state");
		प्रत्यागम रिक्त;
	}
	state = ssh->state;
	state->start_time = monotime();
	state->connection_अन्तर् = fd_अन्तर्;
	state->connection_बहिर्गमनम् = fd_बहिर्गमनम्;
	यदि ((r = cipher_init(&state->send_context, none,
	    (ध्रुव u_char *)"", 0, रिक्त, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (ध्रुव u_char *)"", 0, रिक्त, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		यदि (wasnull)
			मुक्त(ssh); /* XXX need ssh_free_session_state? */
		प्रत्यागम रिक्त;
	}
	state->newkeys[बहुलकम्_अन्तर्] = state->newkeys[बहुलकम्_बहिर्गमनम्] = रिक्त;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(शून्य)ssh_remote_ipaddr(ssh);
	प्रत्यागम ssh;
}

शून्य
ssh_packet_समुच्चयः_timeout(संरचना ssh *ssh, पूर्णाङ्क timeout, पूर्णाङ्क गणनम्)
{
	संरचना session_state *state = ssh->state;

	यदि (timeout <= 0 || गणनम् <= 0) {
		state->packet_timeout_ms = -1;
		प्रत्यागम;
	}
	यदि ((अधिकतम_पूर्णाङ्कः / 1000) / गणनम् < timeout)
		state->packet_timeout_ms = अधिकतम_पूर्णाङ्कः;
	अन्यथा
		state->packet_timeout_ms = timeout * गणनम् * 1000;
}

शून्य
ssh_packet_समुच्चयः_mux(संरचना ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = रिक्त;
}

पूर्णाङ्क
ssh_packet_get_mux(संरचना ssh *ssh)
{
	प्रत्यागम ssh->state->mux;
}

पूर्णाङ्क
ssh_packet_समुच्चयः_log_preamble(संरचना ssh *ssh, ध्रुव वर्ण *fmt, ...)
{
	va_list तर्काः;
	पूर्णाङ्क r;

	मुक्त(ssh->log_preamble);
	यदि (fmt == रिक्त)
		ssh->log_preamble = रिक्त;
	अन्यथा {
		va_start(तर्काः, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, तर्काः);
		va_end(तर्काः);
		यदि (r < 0 || ssh->log_preamble == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_packet_stop_discard(संरचना ssh *ssh)
{
	संरचना session_state *state = ssh->state;
	पूर्णाङ्क r;

	यदि (state->packet_discard_mac) {
		वर्ण buf[1024];
		आकार_t dlen = PACKET_MAX_आकार;

		यदि (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		स्मृतिं_पूरय(buf, 'a', परिमाण(buf));
		यावत् (sshbuf_len(state->incoming_packet) < dlen)
			यदि ((r = sshbuf_put(state->incoming_packet, buf,
			    परिमाण(buf))) != 0)
				प्रत्यागम r;
		(शून्य) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    रिक्त, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_पत्तनम्(ssh));
	प्रत्यागम SSH_ERR_MAC_INVALID;
}

स्थिर पूर्णाङ्क
ssh_packet_start_discard(संरचना ssh *ssh, संरचना sshenc *enc,
    संरचना sshmac *mac, आकार_t mac_already, u_int discard)
{
	संरचना session_state *state = ssh->state;
	पूर्णाङ्क r;

	यदि (enc == रिक्त || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		यदि ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			प्रत्यागम r;
		प्रत्यागम SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	यदि (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	यदि (sshbuf_len(state->निवेशः) >= discard)
		प्रत्यागम ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->निवेशः);
	प्रत्यागम 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

पूर्णाङ्क
ssh_packet_connection_is_on_socket(संरचना ssh *ssh)
{
	संरचना session_state *state;
	संरचना sockaddr_storage from, गन्तव्यम्;
	socklen_t fromlen, tolen;

	यदि (ssh == रिक्त || ssh->state == रिक्त)
		प्रत्यागम 0;

	state = ssh->state;
	यदि (state->connection_अन्तर् == -1 || state->connection_बहिर्गमनम् == -1)
		प्रत्यागम 0;
	fromlen = परिमाण(from);
	स्मृतिं_पूरय(&from, 0, परिमाण(from));
	यदि (getpeername(state->connection_अन्तर्, (संरचना sockaddr *)&from,
	    &fromlen) == -1)
		प्रत्यागम 0;
	यदि (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		प्रत्यागम 0;
	/* filedescriptors in and out are the same, so it's a socket */
	यदि (state->connection_अन्तर् == state->connection_बहिर्गमनम्)
		प्रत्यागम 1;
	tolen = परिमाण(गन्तव्यम्);
	स्मृतिं_पूरय(&गन्तव्यम्, 0, परिमाण(गन्तव्यम्));
	यदि (getpeername(state->connection_बहिर्गमनम्, (संरचना sockaddr *)&गन्तव्यम्,
	    &tolen) == -1)
		प्रत्यागम 0;
	यदि (fromlen != tolen || memcmp(&from, &गन्तव्यम्, fromlen) != 0)
		प्रत्यागम 0;
	प्रत्यागम 1;
}

शून्य
ssh_packet_get_अष्टकानि(संरचना ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	यदि (ibytes)
		*ibytes = ssh->state->p_read.अष्टकानि;
	यदि (obytes)
		*obytes = ssh->state->p_send.अष्टकानि;
}

पूर्णाङ्क
ssh_packet_connection_af(संरचना ssh *ssh)
{
	प्रत्यागम get_sock_af(ssh->state->connection_बहिर्गमनम्);
}

/* Sets the connection into non-blocking mode. */

शून्य
ssh_packet_समुच्चयः_nonblocking(संरचना ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	समुच्चयः_nonblock(ssh->state->connection_अन्तर्);

	यदि (ssh->state->connection_बहिर्गमनम् != ssh->state->connection_अन्तर्)
		समुच्चयः_nonblock(ssh->state->connection_बहिर्गमनम्);
}

/* Returns the socket used for reading. */

पूर्णाङ्क
ssh_packet_get_connection_अन्तर्(संरचना ssh *ssh)
{
	प्रत्यागम ssh->state->connection_अन्तर्;
}

/* Returns the descriptor used for writing. */

पूर्णाङ्क
ssh_packet_get_connection_बहिर्गमनम्(संरचना ssh *ssh)
{
	प्रत्यागम ssh->state->connection_बहिर्गमनम्;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

ध्रुव वर्ण *
ssh_remote_ipaddr(संरचना ssh *ssh)
{
	पूर्णाङ्क sock;

	/* Check whether we have cached the ipaddr. */
	यदि (ssh->remote_ipaddr == रिक्त) {
		यदि (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_अन्तर्;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_पत्तनम् = get_peer_पत्तनम्(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_पत्तनम् = get_local_पत्तनम्(sock);
		} अन्यथा {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_पत्तनम् = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_पत्तनम् = 65535;
		}
	}
	प्रत्यागम ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

वर्ण *
ssh_remote_hostname(संरचना ssh *ssh)
{
	संरचना sockaddr_storage from;
	socklen_t fromlen;
	संरचना addrinfo hints, *ai, *aitop;
	वर्ण name[NI_MAXHOST], ntop2[NI_MAXHOST];
	ध्रुव वर्ण *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = परिमाण(from);
	स्मृतिं_पूरय(&from, 0, परिमाण(from));
	यदि (getpeername(ssh_packet_get_connection_अन्तर्(ssh),
	    (संरचना sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", strerror(errno));
		प्रत्यागम xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	यदि (from.ss_family == AF_INET6)
		fromlen = परिमाण(संरचना sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	यदि (getnameinfo((संरचना sockaddr *)&from, fromlen, name, परिमाण(name),
	    रिक्त, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		प्रत्यागम xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	स्मृतिं_पूरय(&hints, 0, परिमाण(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	यदि (getaddrinfo(name, रिक्त, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		प्रत्यागम xstrdup(ntop);
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
	स्मृतिं_पूरय(&hints, 0, परिमाण(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	यदि (getaddrinfo(name, रिक्त, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		प्रत्यागम xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	प्रति (ai = aitop; ai; ai = ai->ai_next) {
		यदि (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    परिमाण(ntop2), रिक्त, 0, NI_NUMERICHOST) == 0 &&
		    (वाक्यं_तुलय(ntop, ntop2) == 0))
				भङ्ग;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	यदि (ai == रिक्त) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		प्रत्यागम xstrdup(ntop);
	}
	प्रत्यागम xstrdup(name);
}

/* Returns the port number of the remote host. */

पूर्णाङ्क
ssh_remote_पत्तनम्(संरचना ssh *ssh)
{
	(शून्य)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	प्रत्यागम ssh->remote_पत्तनम्;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

ध्रुव वर्ण *
ssh_local_ipaddr(संरचना ssh *ssh)
{
	(शून्य)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	प्रत्यागम ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

पूर्णाङ्क
ssh_local_पत्तनम्(संरचना ssh *ssh)
{
	(शून्य)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	प्रत्यागम ssh->local_पत्तनम्;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
ध्रुव वर्ण *
ssh_packet_rdomain_अन्तर्(संरचना ssh *ssh)
{
	यदि (ssh->rdomain_अन्तर् != रिक्त)
		प्रत्यागम ssh->rdomain_अन्तर्;
	यदि (!ssh_packet_connection_is_on_socket(ssh))
		प्रत्यागम रिक्त;
	ssh->rdomain_अन्तर् = get_rdomain(ssh->state->connection_अन्तर्);
	प्रत्यागम ssh->rdomain_अन्तर्;
}

/* Closes the connection and clears and frees internal data structures. */

स्थिर शून्य
ssh_packet_close_आन्तरिकम्(संरचना ssh *ssh, पूर्णाङ्क do_close)
{
	संरचना session_state *state = ssh->state;
	u_int बहुलकम्;
	संरचना packet *p;

	यदि (!state->initialized)
		प्रत्यागम;
	state->initialized = 0;
	यदि (do_close) {
		यदि (state->connection_अन्तर् == state->connection_बहिर्गमनम्) {
			close(state->connection_बहिर्गमनम्);
		} अन्यथा {
			close(state->connection_अन्तर्);
			close(state->connection_बहिर्गमनम्);
		}
	}
	sshbuf_free(state->निवेशः);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	यावत् ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, अग्र);
		मुक्त(p);
	}
	प्रति (बहुलकम् = 0; बहुलकम् < बहुलकम्_MAX; बहुलकम्++) {
		kex_free_newkeys(state->newkeys[बहुलकम्]);	/* current keys */
		state->newkeys[बहुलकम्] = रिक्त;
		ssh_clear_newkeys(ssh, बहुलकम्);		/* next keys */
	}
#यदि_परिभाषितम् WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	यदि (do_close && state->compression_बफर) {
		sshbuf_free(state->compression_बफर);
		यदि (state->compression_बहिर्गमनम्_started) {
			z_streamp प्रवाहः = &state->compression_बहिर्गमनम्_प्रवाहः;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(अचिह्नित दीर्घ दीर्घ)प्रवाहः->योग_अन्तर्,
				(अचिह्नित दीर्घ दीर्घ)प्रवाहः->योग_बहिर्गमनम्,
				प्रवाहः->योग_अन्तर् == 0 ? 0.0 :
				(द्विगुण) प्रवाहः->योग_बहिर्गमनम् / प्रवाहः->योग_अन्तर्);
			यदि (state->compression_बहिर्गमनम्_failures == 0)
				deflate_अन्तः(प्रवाहः);
		}
		यदि (state->compression_अन्तर्_started) {
			z_streamp प्रवाहः = &state->compression_अन्तर्_प्रवाहः;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (अचिह्नित दीर्घ दीर्घ)प्रवाहः->योग_बहिर्गमनम्,
			    (अचिह्नित दीर्घ दीर्घ)प्रवाहः->योग_अन्तर्,
			    प्रवाहः->योग_बहिर्गमनम् == 0 ? 0.0 :
			    (द्विगुण) प्रवाहः->योग_अन्तर् / प्रवाहः->योग_बहिर्गमनम्);
			यदि (state->compression_अन्तर्_failures == 0)
				inflate_अन्तः(प्रवाहः);
		}
	}
#यदि_अन्तः	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = रिक्त;
	यदि (do_close) {
		मुक्त(ssh->local_ipaddr);
		ssh->local_ipaddr = रिक्त;
		मुक्त(ssh->remote_ipaddr);
		ssh->remote_ipaddr = रिक्त;
		मुक्त(ssh->state);
		ssh->state = रिक्त;
		kex_free(ssh->kex);
		ssh->kex = रिक्त;
	}
}

शून्य
ssh_packet_free(संरचना ssh *ssh)
{
	ssh_packet_close_आन्तरिकम्(ssh, 1);
	freezero(ssh, परिमाण(*ssh));
}

शून्य
ssh_packet_close(संरचना ssh *ssh)
{
	ssh_packet_close_आन्तरिकम्(ssh, 1);
}

शून्य
ssh_packet_clear_कुञ्चिकाः(संरचना ssh *ssh)
{
	ssh_packet_close_आन्तरिकम्(ssh, 0);
}

/* Sets remote side protocol flags. */

शून्य
ssh_packet_समुच्चयः_protocol_flags(संरचना ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(संरचना ssh *ssh)
{
	प्रत्यागम ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

स्थिर पूर्णाङ्क
ssh_packet_init_compression(संरचना ssh *ssh)
{
	यदि (!ssh->state->compression_बफर &&
	    ((ssh->state->compression_बफर = sshbuf_new()) == रिक्त))
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	प्रत्यागम 0;
}

#यदि_परिभाषितम् WITH_ZLIB
स्थिर पूर्णाङ्क
start_compression_बहिर्गमनम्(संरचना ssh *ssh)
{
	debug("Enabling compression.");
	यदि (ssh->state->compression_बहिर्गमनम्_started == 1)
		deflate_अन्तः(&ssh->state->compression_बहिर्गमनम्_प्रवाहः);
	विकल्प (deflateInit2(&ssh->state->compression_बहिर्गमनम्_प्रवाहः,
	    Z_BEST_जवः, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	पक्ष Z_OK:
		ssh->state->compression_बहिर्गमनम्_started = 1;
		भङ्ग;
	पक्ष Z_MEM_ERROR:
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	स्वभाव:
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
start_compression_अन्तर्(संरचना ssh *ssh)
{
	यदि (ssh->state->compression_अन्तर्_started == 1)
		inflate_अन्तः(&ssh->state->compression_अन्तर्_प्रवाहः);
	विकल्प (inflateInit(&ssh->state->compression_अन्तर्_प्रवाहः)) {
	पक्ष Z_OK:
		ssh->state->compression_अन्तर्_started = 1;
		भङ्ग;
	पक्ष Z_MEM_ERROR:
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	स्वभाव:
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	प्रत्यागम 0;
}

/* XXX remove need for separate compression buffer */
स्थिर पूर्णाङ्क
compress_बफर(संरचना ssh *ssh, संरचना sshbuf *अन्तर्, संरचना sshbuf *बहिर्गमनम्)
{
	u_char buf[4096];
	पूर्णाङ्क r, स्थितिः;

	यदि (ssh->state->compression_बहिर्गमनम्_started != 1)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;

	/* This case is not handled below. */
	यदि (sshbuf_len(अन्तर्) == 0)
		प्रत्यागम 0;

	/* Input is the contents of the input buffer. */
	यदि ((ssh->state->compression_बहिर्गमनम्_प्रवाहः.अग्र_अन्तर् =
	    sshbuf_mutable_ptr(अन्तर्)) == रिक्त)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	ssh->state->compression_बहिर्गमनम्_प्रवाहः.avail_अन्तर् = sshbuf_len(अन्तर्);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	कुरु {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_बहिर्गमनम्_प्रवाहः.अग्र_बहिर्गमनम् = buf;
		ssh->state->compression_बहिर्गमनम्_प्रवाहः.avail_बहिर्गमनम् = परिमाण(buf);

		/* Compress as much data into the buffer as possible. */
		स्थितिः = deflate(&ssh->state->compression_बहिर्गमनम्_प्रवाहः,
		    Z_PARTIAL_FLUSH);
		विकल्प (स्थितिः) {
		पक्ष Z_MEM_ERROR:
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		पक्ष Z_OK:
			/* Append compressed data to output_buffer. */
			यदि ((r = sshbuf_put(बहिर्गमनम्, buf, परिमाण(buf) -
			    ssh->state->compression_बहिर्गमनम्_प्रवाहः.avail_बहिर्गमनम्)) != 0)
				प्रत्यागम r;
			भङ्ग;
		पक्ष Z_प्रवाहः_ERROR:
		स्वभाव:
			ssh->state->compression_बहिर्गमनम्_failures++;
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		}
	} यावत् (ssh->state->compression_बहिर्गमनम्_प्रवाहः.avail_बहिर्गमनम् == 0);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
uncompress_बफर(संरचना ssh *ssh, संरचना sshbuf *अन्तर्, संरचना sshbuf *बहिर्गमनम्)
{
	u_char buf[4096];
	पूर्णाङ्क r, स्थितिः;

	यदि (ssh->state->compression_अन्तर्_started != 1)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;

	यदि ((ssh->state->compression_अन्तर्_प्रवाहः.अग्र_अन्तर् =
	    sshbuf_mutable_ptr(अन्तर्)) == रिक्त)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	ssh->state->compression_अन्तर्_प्रवाहः.avail_अन्तर् = sshbuf_len(अन्तर्);

	प्रति (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_अन्तर्_प्रवाहः.अग्र_बहिर्गमनम् = buf;
		ssh->state->compression_अन्तर्_प्रवाहः.avail_बहिर्गमनम् = परिमाण(buf);

		स्थितिः = inflate(&ssh->state->compression_अन्तर्_प्रवाहः,
		    Z_SYNC_FLUSH);
		विकल्प (स्थितिः) {
		पक्ष Z_OK:
			यदि ((r = sshbuf_put(बहिर्गमनम्, buf, परिमाण(buf) -
			    ssh->state->compression_अन्तर्_प्रवाहः.avail_बहिर्गमनम्)) != 0)
				प्रत्यागम r;
			यदि (sshbuf_len(बहिर्गमनम्) >= PACKET_MAX_आकार)
				प्रत्यागम SSH_ERR_INVALID_FORMAT;
			भङ्ग;
		पक्ष Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			प्रत्यागम 0;
		पक्ष Z_दत्त_ERROR:
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		पक्ष Z_MEM_ERROR:
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		पक्ष Z_प्रवाहः_ERROR:
		स्वभाव:
			ssh->state->compression_अन्तर्_failures++;
			प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
		}
	}
	/* NOTREACHED */
}

#अन्यथा	/* WITH_ZLIB */

स्थिर पूर्णाङ्क
start_compression_बहिर्गमनम्(संरचना ssh *ssh)
{
	प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
}

स्थिर पूर्णाङ्क
start_compression_अन्तर्(संरचना ssh *ssh)
{
	प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
}

स्थिर पूर्णाङ्क
compress_बफर(संरचना ssh *ssh, संरचना sshbuf *अन्तर्, संरचना sshbuf *बहिर्गमनम्)
{
	प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
}

स्थिर पूर्णाङ्क
uncompress_बफर(संरचना ssh *ssh, संरचना sshbuf *अन्तर्, संरचना sshbuf *बहिर्गमनम्)
{
	प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
}
#यदि_अन्तः	/* WITH_ZLIB */

शून्य
ssh_clear_newkeys(संरचना ssh *ssh, पूर्णाङ्क बहुलकम्)
{
	यदि (ssh->kex && ssh->kex->newkeys[बहुलकम्]) {
		kex_free_newkeys(ssh->kex->newkeys[बहुलकम्]);
		ssh->kex->newkeys[बहुलकम्] = रिक्त;
	}
}

पूर्णाङ्क
ssh_समुच्चयः_newkeys(संरचना ssh *ssh, पूर्णाङ्क बहुलकम्)
{
	संरचना session_state *state = ssh->state;
	संरचना sshenc *enc;
	संरचना sshmac *mac;
	संरचना sshcomp *comp;
	संरचना sshcipher_ctx **ccp;
	संरचना packet_state *ps;
	uint64_t *max_खण्डानि, *hard_max_खण्डानि;
	ध्रुव वर्ण *wmsg;
	पूर्णाङ्क r, crypt_type;
	ध्रुव वर्ण *dir = बहुलकम् == बहुलकम्_बहिर्गमनम् ? "out" : "in";

	debug2_f("mode %d", बहुलकम्);

	यदि (बहुलकम् == बहुलकम्_बहिर्गमनम्) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_खण्डानि = &state->hard_max_खण्डानि_बहिर्गमनम्;
		max_खण्डानि = &state->max_खण्डानि_बहिर्गमनम्;
	} अन्यथा {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_खण्डानि = &state->hard_max_खण्डानि_अन्तर्;
		max_खण्डानि = &state->max_खण्डानि_अन्तर्;
	}
	यदि (state->newkeys[बहुलकम्] != रिक्त) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (अचिह्नित दीर्घ दीर्घ)state->p_read.अष्टकानि,
		    (अचिह्नित दीर्घ दीर्घ)state->p_read.खण्डानि,
		    (अचिह्नित दीर्घ दीर्घ)state->p_send.अष्टकानि,
		    (अचिह्नित दीर्घ दीर्घ)state->p_send.खण्डानि);
		kex_free_newkeys(state->newkeys[बहुलकम्]);
		state->newkeys[बहुलकम्] = रिक्त;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->खण्डानि = 0;
	/* move newkeys from kex to state */
	यदि ((state->newkeys[बहुलकम्] = ssh->kex->newkeys[बहुलकम्]) == रिक्त)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	ssh->kex->newkeys[बहुलकम्] = रिक्त;
	enc  = &state->newkeys[बहुलकम्]->enc;
	mac  = &state->newkeys[बहुलकम्]->mac;
	comp = &state->newkeys[बहुलकम्]->comp;
	यदि (cipher_authlen(enc->cipher) == 0) {
		यदि ((r = mac_init(mac)) != 0)
			प्रत्यागम r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = रिक्त;
	यदि ((r = cipher_init(ccp, enc->cipher, enc->कुञ्चिका, enc->कुञ्चिका_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		प्रत्यागम r;
	यदि (!state->cipher_warning_समाप्तम् &&
	    (wmsg = cipher_warning_सन्देशः(*ccp)) != रिक्त) {
		error("Warning: %s", wmsg);
		state->cipher_warning_समाप्तम् = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	यदि (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		यदि ((r = ssh_packet_init_compression(ssh)) < 0)
			प्रत्यागम r;
		यदि (बहुलकम् == बहुलकम्_बहिर्गमनम्) {
			यदि ((r = start_compression_बहिर्गमनम्(ssh)) != 0)
				प्रत्यागम r;
		} अन्यथा {
			यदि ((r = start_compression_अन्तर्(ssh)) != 0)
				प्रत्यागम r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	यदि (enc->खण्डम्_आकार >= 16)
		*hard_max_खण्डानि = (uint64_t)1 << (enc->खण्डम्_आकार*2);
	अन्यथा
		*hard_max_खण्डानि = ((uint64_t)1 << 30) / enc->खण्डम्_आकार;
	*max_खण्डानि = *hard_max_खण्डानि;
	यदि (state->rekey_सीमा) {
		*max_खण्डानि = MINIMUM(*max_खण्डानि,
		    state->rekey_सीमा / enc->खण्डम्_आकार);
	}
	debug("rekey %s after %llu blocks", dir,
	    (अचिह्नित दीर्घ दीर्घ)*max_खण्डानि);
	प्रत्यागम 0;
}

#परिभाषय MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
स्थिर अन्तःस्थ पूर्णाङ्क
ssh_packet_check_rekey_blocklimit(संरचना ssh *ssh, u_int packet_len, पूर्णाङ्क hard)
{
	संरचना session_state *state = ssh->state;
	uint32_t बहिर्गमनम्_खण्डानि;
	ध्रुव uint64_t max_खण्डानि_अन्तर् = hard ?
	    state->hard_max_खण्डानि_अन्तर् : state->max_खण्डानि_अन्तर्;
	ध्रुव uint64_t max_खण्डानि_बहिर्गमनम् = hard ?
	    state->hard_max_खण्डानि_बहिर्गमनम् : state->max_खण्डानि_बहिर्गमनम्;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	यदि (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		प्रत्यागम 1;

	यदि (state->newkeys[बहुलकम्_बहिर्गमनम्] == रिक्त)
		प्रत्यागम 0;

	/* Rekey after (cipher-specific) maximum blocks */
	बहिर्गमनम्_खण्डानि = ROUNDUP(packet_len,
	    state->newkeys[बहुलकम्_बहिर्गमनम्]->enc.खण्डम्_आकार);
	प्रत्यागम (max_खण्डानि_बहिर्गमनम् &&
	    (state->p_send.खण्डानि + बहिर्गमनम्_खण्डानि > max_खण्डानि_बहिर्गमनम्)) ||
	    (max_खण्डानि_अन्तर् &&
	    (state->p_read.खण्डानि > max_खण्डानि_अन्तर्));
}

स्थिर पूर्णाङ्क
ssh_packet_need_rekeying(संरचना ssh *ssh, u_int outbound_packet_len)
{
	संरचना session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	यदि (!state->after_authentication)
		प्रत्यागम 0;

	/* Haven't keyed yet or KEX in progress. */
	यदि (ssh_packet_is_rekeying(ssh))
		प्रत्यागम 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	यदि (state->p_send.packets == 0 && state->p_read.packets == 0)
		प्रत्यागम 0;

	/* Time-based rekeying */
	यदि (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_time + state->rekey_interval <= monotime())
		प्रत्यागम 1;

	प्रत्यागम ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
स्थिर पूर्णाङ्क
ssh_packet_check_rekey_preauth(संरचना ssh *ssh, u_int outgoing_packet_len)
{
	यदि (ssh->state->after_authentication)
		प्रत्यागम 0;

	यदि (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		प्रत्यागम SSH_ERR_NEED_REKEY;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_packet_check_rekey(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	यदि ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		प्रत्यागम r;
	यदि (!ssh_packet_need_rekeying(ssh, 0))
		प्रत्यागम 0;
	debug3_f("rekex triggered");
	प्रत्यागम kex_start_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
स्थिर पूर्णाङ्क
ssh_packet_enable_delayed_compress(संरचना ssh *ssh)
{
	संरचना session_state *state = ssh->state;
	संरचना sshcomp *comp = रिक्त;
	पूर्णाङ्क r, बहुलकम्;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	प्रति (बहुलकम् = 0; बहुलकम् < बहुलकम्_MAX; बहुलकम्++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		यदि (state->newkeys[बहुलकम्] == रिक्त)
			अनुवर्त;
		comp = &state->newkeys[बहुलकम्]->comp;
		यदि (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			यदि ((r = ssh_packet_init_compression(ssh)) != 0)
				प्रत्यागम r;
			यदि (बहुलकम् == बहुलकम्_बहिर्गमनम्) {
				यदि ((r = start_compression_बहिर्गमनम्(ssh)) != 0)
					प्रत्यागम r;
			} अन्यथा {
				यदि ((r = start_compression_अन्तर्(ssh)) != 0)
					प्रत्यागम r;
			}
			comp->enabled = 1;
		}
	}
	प्रत्यागम 0;
}

/* Used to mute debug logging for noisy packet types */
पूर्णाङ्क
ssh_packet_log_type(u_char type)
{
	विकल्प (type) {
	पक्ष SSH2_सन्देशः_PING:
	पक्ष SSH2_सन्देशः_PONG:
	पक्ष SSH2_सन्देशः_CHANNEL_दत्त:
	पक्ष SSH2_सन्देशः_CHANNEL_EXTENDED_दत्त:
	पक्ष SSH2_सन्देशः_CHANNEL_गवाक्षः_ADJUST:
		प्रत्यागम 0;
	स्वभाव:
		प्रत्यागम 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
पूर्णाङ्क
ssh_packet_send2_wrapped(संरचना ssh *ssh)
{
	संरचना session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_दीर्घता];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	संरचना sshenc *enc   = रिक्त;
	संरचना sshmac *mac   = रिक्त;
	संरचना sshcomp *comp = रिक्त;
	पूर्णाङ्क r, खण्डम्_आकार;

	यदि (state->newkeys[बहुलकम्_बहिर्गमनम्] != रिक्त) {
		enc  = &state->newkeys[बहुलकम्_बहिर्गमनम्]->enc;
		mac  = &state->newkeys[बहुलकम्_बहिर्गमनम्]->mac;
		comp = &state->newkeys[बहुलकम्_बहिर्गमनम्]->comp;
		/* disable mac for authenticated encryption */
		यदि ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = रिक्त;
	}
	खण्डम्_आकार = enc ? enc->खण्डम्_आकार : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	यदि (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#यदि_परिभाषितम् PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	sshbuf_dump(state->outgoing_packet, stderr);
#यदि_अन्तः

	यदि (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		यदि ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			गच्छ बहिर्गमनम्;
		sshbuf_reset(state->compression_बफर);
		यदि ((r = compress_बफर(ssh, state->outgoing_packet,
		    state->compression_बफर)) != 0)
			गच्छ बहिर्गमनम्;
		sshbuf_reset(state->outgoing_packet);
		यदि ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_बफर)) != 0)
			गच्छ बहिर्गमनम्;
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
	padlen = खण्डम्_आकार - (len % खण्डम्_आकार);
	यदि (padlen < 4)
		padlen += खण्डम्_आकार;
	यदि (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, खण्डम्_आकार);
		/* check if roundup overflowed */
		यदि (state->extra_pad < tmp)
			प्रत्यागम SSH_ERR_INVALID_तर्कः;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		यदि (tmp > state->extra_pad)
			प्रत्यागम SSH_ERR_INVALID_तर्कः;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		यदि (padlen < tmp)
			प्रत्यागम SSH_ERR_INVALID_तर्कः; /*अतिप्रवाहः*/
		state->extra_pad = 0;
	}
	यदि ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} अन्यथा {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	यदि (cp == रिक्त) {
		r = SSH_ERR_आन्तरिकम्_ERROR;
		गच्छ बहिर्गमनम्;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	यदि (mac && mac->enabled && !mac->etm) {
		यदि ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, परिमाण(macbuf))) != 0)
			गच्छ बहिर्गमनम्;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	यदि ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		गच्छ बहिर्गमनम्;
	/* append unencrypted MAC */
	यदि (mac && mac->enabled) {
		यदि (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			यदि ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, परिमाण(macbuf))) != 0)
				गच्छ बहिर्गमनम्;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		यदि ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			गच्छ बहिर्गमनम्;
	}
#यदि_परिभाषितम् PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	sshbuf_dump(state->output, stderr);
#यदि_अन्तः
	/* increment sequence number for outgoing packets */
	यदि (++state->p_send.seqnr == 0) {
		यदि ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	यदि (++state->p_send.packets == 0)
		प्रत्यागम SSH_ERR_NEED_REKEY;
	state->p_send.खण्डानि += len / खण्डम्_आकार;
	state->p_send.अष्टकानि += len;
	sshbuf_reset(state->outgoing_packet);

	यदि (type == SSH2_सन्देशः_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	यदि (type == SSH2_सन्देशः_NEWKEYS)
		r = ssh_समुच्चयः_newkeys(ssh, बहुलकम्_बहिर्गमनम्);
	अन्यथा यदि (type == SSH2_सन्देशः_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	अन्यथा
		r = 0;
 बहिर्गमनम्:
	प्रत्यागम r;
}

/* returns non-zero if the specified packet type is usec by KEX */
स्थिर पूर्णाङ्क
ssh_packet_type_is_kex(u_char type)
{
	प्रत्यागम
	    type >= SSH2_सन्देशः_TRANSPORT_MIN &&
	    type <= SSH2_सन्देशः_TRANSPORT_MAX &&
	    type != SSH2_सन्देशः_SERVICE_REQUEST &&
	    type != SSH2_सन्देशः_SERVICE_ACCEPT &&
	    type != SSH2_सन्देशः_EXT_INFO;
}

पूर्णाङ्क
ssh_packet_send2(संरचना ssh *ssh)
{
	संरचना session_state *state = ssh->state;
	संरचना packet *p;
	u_char type;
	पूर्णाङ्क r, need_rekey;

	यदि (sshbuf_len(state->outgoing_packet) < 6)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	यदि (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		प्रत्यागम r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	यदि ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		यदि (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = शून्यस्मृतिं_देहि(1, परिमाण(*p));
		यदि (p == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, अग्र);
		state->outgoing_packet = sshbuf_new();
		यदि (state->outgoing_packet == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		यदि (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			प्रत्यागम kex_start_rekex(ssh);
		}
		प्रत्यागम 0;
	}

	/* rekeying starts with sending KEXINIT */
	यदि (type == SSH2_सन्देशः_KEXINIT)
		state->rekeying = 1;

	यदि ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		प्रत्यागम r;

	/* after a NEWKEYS message we can send the complete queue */
	यदि (type == SSH2_सन्देशः_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_time = monotime();
		यावत् ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			यदि (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				प्रत्यागम kex_start_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, अग्र);
			स्मृतिं_पूरय(p, 0, परिमाण(*p));
			मुक्त(p);
			यदि ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				प्रत्यागम r;
		}
	}
	प्रत्यागम 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

पूर्णाङ्क
ssh_packet_read_seqnr(संरचना ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	संरचना session_state *state = ssh->state;
	पूर्णाङ्क len, r, ms_remain = 0;
	संरचना pollfd pfd;
	वर्ण buf[8192];
	संरचना timeval start;
	संरचना timespec timespec, *timespecp = रिक्त;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	यदि ((r = ssh_packet_write_wait(ssh)) != 0)
		गच्छ बहिर्गमनम्;

	/* Stay in the loop until we have received a complete packet. */
	प्रति (;;) {
		/* Try to read a packet from the buffer. */
		यदि ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			भङ्ग;
		/* If we got a packet, return it. */
		यदि (*typep != SSH_सन्देशः_NONE)
			भङ्ग;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_अन्तर्;
		pfd.events = POLLIN;

		यदि (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		प्रति (;;) {
			यदि (state->packet_timeout_ms > 0) {
				ms_गन्तव्यम्_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			यदि ((r = ppoll(&pfd, 1, timespecp, रिक्त)) >= 0)
				भङ्ग;
			यदि (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				गच्छ बहिर्गमनम्;
			}
			यदि (state->packet_timeout_ms <= 0)
				अनुवर्त;
			ms_व्यवकलय_diff(&start, &ms_remain);
			यदि (ms_remain <= 0) {
				r = 0;
				भङ्ग;
			}
		}
		यदि (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			गच्छ बहिर्गमनम्;
		}
		/* Read data from the socket. */
		len = पठ(state->connection_अन्तर्, buf, परिमाण(buf));
		यदि (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			गच्छ बहिर्गमनम्;
		}
		यदि (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ बहिर्गमनम्;
		}

		/* Append it to the buffer. */
		यदि ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			गच्छ बहिर्गमनम्;
	}
 बहिर्गमनम्:
	प्रत्यागम r;
}

पूर्णाङ्क
ssh_packet_read(संरचना ssh *ssh)
{
	u_char type;
	पूर्णाङ्क r;

	यदि ((r = ssh_packet_read_seqnr(ssh, &type, रिक्त)) != 0)
		sshpkt_fatal(ssh, r, "read");
	प्रत्यागम type;
}

स्थिर पूर्णाङ्क
ssh_packet_read_poll2_mux(संरचना ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	संरचना session_state *state = ssh->state;
	ध्रुव u_char *cp;
	आकार_t need;
	पूर्णाङ्क r;

	यदि (ssh->kex)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	*typep = SSH_सन्देशः_NONE;
	cp = sshbuf_ptr(state->निवेशः);
	यदि (state->packlen == 0) {
		यदि (sshbuf_len(state->निवेशः) < 4 + 1)
			प्रत्यागम 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		यदि (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_आकार)
			प्रत्यागम SSH_ERR_सन्देशः_INCOMPLETE;
	}
	need = state->packlen + 4;
	यदि (sshbuf_len(state->निवेशः) < need)
		प्रत्यागम 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	यदि ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->निवेशः, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, रिक्त)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		प्रत्यागम r;
	यदि (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	प्रत्यागम r;
}

पूर्णाङ्क
ssh_packet_read_poll2(संरचना ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	संरचना session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, खण्डम्_आकार;
	संरचना sshenc *enc   = रिक्त;
	संरचना sshmac *mac   = रिक्त;
	संरचना sshcomp *comp = रिक्त;
	पूर्णाङ्क r;

	यदि (state->mux)
		प्रत्यागम ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_सन्देशः_NONE;

	यदि (state->packet_discard)
		प्रत्यागम 0;

	यदि (state->newkeys[बहुलकम्_अन्तर्] != रिक्त) {
		enc  = &state->newkeys[बहुलकम्_अन्तर्]->enc;
		mac  = &state->newkeys[बहुलकम्_अन्तर्]->mac;
		comp = &state->newkeys[बहुलकम्_अन्तर्]->comp;
		/* disable mac for authenticated encryption */
		यदि ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = रिक्त;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	खण्डम्_आकार = enc ? enc->खण्डम्_आकार : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	यदि (aadlen && state->packlen == 0) {
		यदि (cipher_get_दीर्घता(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->निवेशः), sshbuf_len(state->निवेशः)) != 0)
			प्रत्यागम 0;
		यदि (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_आकार) {
#यदि_परिभाषितम् PACKET_DEBUG
			sshbuf_dump(state->निवेशः, stderr);
#यदि_अन्तः
			logit("Bad packet length %u.", state->packlen);
			यदि ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				प्रत्यागम r;
			प्रत्यागम SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} अन्यथा यदि (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		यदि (sshbuf_len(state->निवेशः) < खण्डम्_आकार)
			प्रत्यागम 0;
		sshbuf_reset(state->incoming_packet);
		यदि ((r = sshbuf_reserve(state->incoming_packet, खण्डम्_आकार,
		    &cp)) != 0)
			गच्छ बहिर्गमनम्;
		यदि ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->निवेशः),
		    खण्डम्_आकार, 0, 0)) != 0)
			गच्छ बहिर्गमनम्;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		यदि (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_आकार) {
#यदि_परिभाषितम् PACKET_DEBUG
			fprintf(stderr, "input: \n");
			sshbuf_dump(state->निवेशः, stderr);
			fprintf(stderr, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, stderr);
#यदि_अन्तः
			logit("Bad packet length %u.", state->packlen);
			प्रत्यागम ssh_packet_start_discard(ssh, enc, mac, 0,
			    PACKET_MAX_आकार);
		}
		यदि ((r = sshbuf_consume(state->निवेशः, खण्डम्_आकार)) != 0)
			गच्छ बहिर्गमनम्;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	यदि (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} अन्यथा {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - खण्डम्_आकार;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", खण्डम्_आकार, need, maclen, authlen, aadlen));
	यदि (need % खण्डम्_आकार != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, खण्डम्_आकार, need % खण्डम्_आकार);
		प्रत्यागम ssh_packet_start_discard(ssh, enc, mac, 0,
		    PACKET_MAX_आकार - खण्डम्_आकार);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet:
	 * 'aadlen' bytes are unencrypted, but authenticated.
	 * 'need' bytes are encrypted, followed by either
	 * 'authlen' bytes of authentication tag or
	 * 'maclen' bytes of message authentication code.
	 */
	यदि (sshbuf_len(state->निवेशः) < aadlen + need + authlen + maclen)
		प्रत्यागम 0; /* packet is incomplete */
#यदि_परिभाषितम् PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	sshbuf_dump(state->निवेशः, stderr);
#यदि_अन्तः
	/* EtM: check mac over encrypted input */
	यदि (mac && mac->enabled && mac->etm) {
		यदि ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->निवेशः), aadlen + need,
		    sshbuf_ptr(state->निवेशः) + aadlen + need + authlen,
		    maclen)) != 0) {
			यदि (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			गच्छ बहिर्गमनम्;
		}
	}
	यदि ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->निवेशः), need, aadlen, authlen)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = sshbuf_consume(state->निवेशः, aadlen + need + authlen)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		यदि (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->निवेशः), maclen)) != 0) {
			यदि (r != SSH_ERR_MAC_INVALID)
				गच्छ बहिर्गमनम्;
			logit("Corrupted MAC on input.");
			यदि (need + खण्डम्_आकार > PACKET_MAX_आकार)
				प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
			प्रत्यागम ssh_packet_start_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_आकार - need - खण्डम्_आकार);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		यदि ((r = sshbuf_consume(state->निवेशः, mac->mac_len)) != 0)
			गच्छ बहिर्गमनम्;
	}

	यदि (seqnr_p != रिक्त)
		*seqnr_p = state->p_read.seqnr;
	यदि (++state->p_read.seqnr == 0) {
		यदि ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	यदि (++state->p_read.packets == 0)
		प्रत्यागम SSH_ERR_NEED_REKEY;
	state->p_read.खण्डानि += (state->packlen + 4) / खण्डम्_आकार;
	state->p_read.अष्टकानि += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	यदि (padlen < 4)	{
		यदि ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			प्रत्यागम r;
		प्रत्यागम SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	यदि ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_अन्तः(state->incoming_packet, padlen)) != 0))
		गच्छ बहिर्गमनम्;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	यदि (comp && comp->enabled) {
		sshbuf_reset(state->compression_बफर);
		यदि ((r = uncompress_बफर(ssh, state->incoming_packet,
		    state->compression_बफर)) != 0)
			गच्छ बहिर्गमनम्;
		sshbuf_reset(state->incoming_packet);
		यदि ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_बफर)) != 0)
			गच्छ बहिर्गमनम्;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	यदि ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	यदि (*typep < SSH2_सन्देशः_MIN) {
		यदि ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			प्रत्यागम r;
		प्रत्यागम SSH_ERR_PROTOCOL_ERROR;
	}
	यदि (state->hook_अन्तर् != रिक्त &&
	    (r = state->hook_अन्तर्(ssh, state->incoming_packet, typep,
	    state->hook_अन्तर्_ctx)) != 0)
		प्रत्यागम r;
	यदि (*typep == SSH2_सन्देशः_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	अन्यथा
		r = 0;
#यदि_परिभाषितम् PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, stderr);
#यदि_अन्तः
	/* reset for next packet */
	state->packlen = 0;
	यदि (*typep == SSH2_सन्देशः_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	यदि ((r = ssh_packet_check_rekey(ssh)) != 0)
		प्रत्यागम r;
 बहिर्गमनम्:
	प्रत्यागम r;
}

पूर्णाङ्क
ssh_packet_read_poll_seqnr(संरचना ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	संरचना session_state *state = ssh->state;
	u_int reason, seqnr;
	पूर्णाङ्क r;
	u_char *सन्देशः;
	ध्रुव u_char *d;
	आकार_t len;

	प्रति (;;) {
		सन्देशः = रिक्त;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		यदि (r != 0)
			प्रत्यागम r;
		यदि (*typep == 0) {
			/* no message ready */
			प्रत्यागम 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		यदि (*typep == SSH2_सन्देशः_DISCONNECT) {
			यदि ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &सन्देशः, रिक्त)) != 0)
				प्रत्यागम r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_पत्तनम्(ssh), reason, सन्देशः);
			मुक्त(सन्देशः);
			प्रत्यागम SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		यदि (ssh->kex != रिक्त &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			प्रत्यागम 0;
		/* Implicitly handle transport-level messages */
		विकल्प (*typep) {
		पक्ष SSH2_सन्देशः_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			भङ्ग;
		पक्ष SSH2_सन्देशः_DEBUG:
			यदि ((r = sshpkt_get_u8(ssh, रिक्त)) != 0 ||
			    (r = sshpkt_get_string(ssh, &सन्देशः, रिक्त)) != 0 ||
			    (r = sshpkt_get_string(ssh, रिक्त, रिक्त)) != 0) {
				मुक्त(सन्देशः);
				प्रत्यागम r;
			}
			debug("Remote: %.900s", सन्देशः);
			मुक्त(सन्देशः);
			भङ्ग;
		पक्ष SSH2_सन्देशः_UNIMPLEMENTED:
			यदि ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				प्रत्यागम r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			भङ्ग;
		पक्ष SSH2_सन्देशः_PING:
			यदि ((r = sshpkt_get_string_प्रत्यक्षम्(ssh, &d, &len)) != 0)
				प्रत्यागम r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			यदि (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				भङ्ग;
			}
			यदि (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				भङ्ग;
			}
			यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				प्रत्यागम r;
			भङ्ग;
		पक्ष SSH2_सन्देशः_PONG:
			यदि ((r = sshpkt_get_string_प्रत्यक्षम्(ssh,
			    रिक्त, &len)) != 0)
				प्रत्यागम r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			भङ्ग;
		स्वभाव:
			यदि (ssh->kex != रिक्त &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				प्रत्यागम SSH_ERR_PROTOCOL_ERROR;
			}
			प्रत्यागम 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
पूर्णाङ्क
ssh_packet_process_incoming(संरचना ssh *ssh, ध्रुव वर्ण *buf, u_int len)
{
	संरचना session_state *state = ssh->state;
	पूर्णाङ्क r;

	यदि (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		यदि (len >= state->packet_discard) {
			यदि ((r = ssh_packet_stop_discard(ssh)) != 0)
				प्रत्यागम r;
		}
		state->packet_discard -= len;
		प्रत्यागम 0;
	}
	यदि ((r = sshbuf_put(state->निवेशः, buf, len)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

/* Reads and buffers data from the specified fd */
पूर्णाङ्क
ssh_packet_process_read(संरचना ssh *ssh, पूर्णाङ्क fd)
{
	संरचना session_state *state = ssh->state;
	पूर्णाङ्क r;
	आकार_t rlen;

	यदि ((r = sshbuf_read(fd, state->निवेशः, PACKET_MAX_आकार, &rlen)) != 0)
		प्रत्यागम r;

	यदि (state->packet_discard) {
		यदि ((r = sshbuf_consume_अन्तः(state->निवेशः, rlen)) != 0)
			प्रत्यागम r;
		state->keep_alive_timeouts = 0; /* ?? */
		यदि (rlen >= state->packet_discard) {
			यदि ((r = ssh_packet_stop_discard(ssh)) != 0)
				प्रत्यागम r;
		}
		state->packet_discard -= rlen;
		प्रत्यागम 0;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_packet_remaining(संरचना ssh *ssh)
{
	प्रत्यागम sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
शून्य
ssh_packet_send_debug(संरचना ssh *ssh, ध्रुव वर्ण *fmt,...)
{
	वर्ण buf[1024];
	va_list तर्काः;
	पूर्णाङ्क r;

	यदि ((ssh->compat & SSH_BUG_DEBUG))
		प्रत्यागम;

	va_start(तर्काः, fmt);
	vsnprintf(buf, परिमाण(buf), fmt, तर्काः);
	va_end(तर्काः);

	debug3("sending debug message: %s", buf);

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

शून्य
sshpkt_fmt_connection_id(संरचना ssh *ssh, वर्ण *s, आकार_t l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_पत्तनम्(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
स्थिर शून्य
sshpkt_vfatal(संरचना ssh *ssh, पूर्णाङ्क r, ध्रुव वर्ण *fmt, va_list ap)
{
	वर्ण *चिह्नकम् = रिक्त, remote_id[512];
	पूर्णाङ्क oerrno = errno;

	sshpkt_fmt_connection_id(ssh, remote_id, परिमाण(remote_id));

	विकल्प (r) {
	पक्ष SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_कुञ्चिकाः(ssh);
		logdie("Connection closed by %s", remote_id);
	पक्ष SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_कुञ्चिकाः(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	पक्ष SSH_ERR_DISCONNECTED:
		ssh_packet_clear_कुञ्चिकाः(ssh);
		logdie("Disconnected from %s", remote_id);
	पक्ष SSH_ERR_SYSTEM_ERROR:
		यदि (errno == ECONNRESET) {
			ssh_packet_clear_कुञ्चिकाः(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	पक्ष SSH_ERR_NO_CIPHER_ALG_मेलनम्:
	पक्ष SSH_ERR_NO_MAC_ALG_मेलनम्:
	पक्ष SSH_ERR_NO_COMPRESS_ALG_मेलनम्:
	पक्ष SSH_ERR_NO_KEX_ALG_मेलनम्:
	पक्ष SSH_ERR_NO_HOSTKEY_ALG_मेलनम्:
		यदि (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_कुञ्चिकाः(ssh);
			errno = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	स्वभाव:
		यदि (vasprintf(&चिह्नकम्, fmt, ap) == -1) {
			ssh_packet_clear_कुञ्चिकाः(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_कुञ्चिकाः(ssh);
		errno = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    चिह्नकम् != रिक्त ? चिह्नकम् : "", चिह्नकम् != रिक्त ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

शून्य
sshpkt_fatal(संरचना ssh *ssh, पूर्णाङ्क r, ध्रुव वर्ण *fmt, ...)
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
शून्य
ssh_packet_disconnect(संरचना ssh *ssh, ध्रुव वर्ण *fmt,...)
{
	वर्ण buf[1024], remote_id[512];
	va_list तर्काः;
	पूर्णाङ्क r;

	/* Guard against recursive invocations. */
	यदि (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, परिमाण(remote_id));
	va_start(तर्काः, fmt);
	vsnprintf(buf, परिमाण(buf), fmt, तर्काः);
	va_end(तर्काः);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	यदि ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	यदि ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
पूर्णाङ्क
ssh_packet_write_poll(संरचना ssh *ssh)
{
	संरचना session_state *state = ssh->state;
	पूर्णाङ्क len = sshbuf_len(state->output);
	पूर्णाङ्क r;

	यदि (len > 0) {
		len = लिख(state->connection_बहिर्गमनम्,
		    sshbuf_ptr(state->output), len);
		यदि (len == -1) {
			यदि (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				प्रत्यागम 0;
			प्रत्यागम SSH_ERR_SYSTEM_ERROR;
		}
		यदि (len == 0)
			प्रत्यागम SSH_ERR_CONN_CLOSED;
		यदि ((r = sshbuf_consume(state->output, len)) != 0)
			प्रत्यागम r;
	}
	प्रत्यागम 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
पूर्णाङ्क
ssh_packet_write_wait(संरचना ssh *ssh)
{
	पूर्णाङ्क ret, r, ms_remain = 0;
	संरचना timeval start;
	संरचना timespec timespec, *timespecp = रिक्त;
	संरचना session_state *state = ssh->state;
	संरचना pollfd pfd;

	यदि ((r = ssh_packet_write_poll(ssh)) != 0)
		प्रत्यागम r;
	यावत् (ssh_packet_have_दत्त_गन्तव्यम्_write(ssh)) {
		pfd.fd = state->connection_बहिर्गमनम्;
		pfd.events = POLLOUT;

		यदि (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		प्रति (;;) {
			यदि (state->packet_timeout_ms > 0) {
				ms_गन्तव्यम्_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			यदि ((ret = ppoll(&pfd, 1, timespecp, रिक्त)) >= 0)
				भङ्ग;
			यदि (errno != EAGAIN && errno != EINTR &&
			    errno != EWOULDBLOCK)
				भङ्ग;
			यदि (state->packet_timeout_ms <= 0)
				अनुवर्त;
			ms_व्यवकलय_diff(&start, &ms_remain);
			यदि (ms_remain <= 0) {
				ret = 0;
				भङ्ग;
			}
		}
		यदि (ret == 0)
			प्रत्यागम SSH_ERR_CONN_TIMEOUT;
		यदि ((r = ssh_packet_write_poll(ssh)) != 0)
			प्रत्यागम r;
	}
	प्रत्यागम 0;
}

/* Returns true if there is buffered data to write to the connection. */

पूर्णाङ्क
ssh_packet_have_दत्त_गन्तव्यम्_write(संरचना ssh *ssh)
{
	प्रत्यागम sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

पूर्णाङ्क
ssh_packet_not_very_much_दत्त_गन्तव्यम्_write(संरचना ssh *ssh)
{
	यदि (ssh->state->interactive_बहुलकम्)
		प्रत्यागम sshbuf_len(ssh->state->output) < 16384;
	अन्यथा
		प्रत्यागम sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

पूर्णाङ्क
ssh_packet_interactive_दत्त_गन्तव्यम्_write(संरचना ssh *ssh)
{
	प्रत्यागम ssh->state->interactive_बहुलकम् &&
	    sshbuf_len(ssh->state->output) < 256;
}

स्थिर शून्य
apply_qos(संरचना ssh *ssh)
{
	संरचना session_state *state = ssh->state;
	पूर्णाङ्क qos = state->interactive_बहुलकम् ?
	    state->qos_interactive : state->qos_other;

	यदि (!ssh_packet_connection_is_on_socket(ssh))
		प्रत्यागम;
	यदि (!state->nodelay_समुच्चयः) {
		समुच्चयः_nodelay(state->connection_अन्तर्);
		state->nodelay_समुच्चयः = 1;
	}
	समुच्चयः_sock_tos(ssh->state->connection_अन्तर्, qos);
}

/* Informs that the current session is interactive. */
शून्य
ssh_packet_समुच्चयः_interactive(संरचना ssh *ssh, पूर्णाङ्क interactive)
{
	संरचना session_state *state = ssh->state;

	state->interactive_बहुलकम् = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
शून्य
ssh_packet_समुच्चयः_qos(संरचना ssh *ssh, पूर्णाङ्क qos_interactive, पूर्णाङ्क qos_other)
{
	संरचना session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

पूर्णाङ्क
ssh_packet_समुच्चयः_maxsize(संरचना ssh *ssh, u_int s)
{
	संरचना session_state *state = ssh->state;

	यदि (state->समुच्चयः_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_आकार, s);
		प्रत्यागम -1;
	}
	यदि (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		प्रत्यागम -1;
	}
	state->समुच्चयः_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_आकार = s;
	प्रत्यागम s;
}

पूर्णाङ्क
ssh_packet_inc_alive_timeouts(संरचना ssh *ssh)
{
	प्रत्यागम ++ssh->state->keep_alive_timeouts;
}

शून्य
ssh_packet_समुच्चयः_alive_timeouts(संरचना ssh *ssh, पूर्णाङ्क ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(संरचना ssh *ssh)
{
	प्रत्यागम ssh->state->max_packet_आकार;
}

शून्य
ssh_packet_समुच्चयः_rekey_limits(संरचना ssh *ssh, uint64_t अष्टकानि, uint32_t seconds)
{
	यदि (अष्टकानि == 0 && seconds == 0)
		प्रत्यागम;

	debug3("rekey after %llu bytes, %u seconds", (अचिह्नित दीर्घ दीर्घ)अष्टकानि,
	    (अचिह्नित पूर्णाङ्क)seconds);
	ssh->state->rekey_सीमा = अष्टकानि;
	ssh->state->rekey_interval = seconds;
}

time_t
ssh_packet_get_rekey_timeout(संरचना ssh *ssh)
{
	time_t seconds;

	seconds = ssh->state->rekey_time + ssh->state->rekey_interval -
	    monotime();
	प्रत्यागम (seconds <= 0 ? 1 : seconds);
}

शून्य
ssh_packet_समुच्चयः_server(संरचना ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

शून्य
ssh_packet_समुच्चयः_authenticated(संरचना ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

शून्य *
ssh_packet_get_निवेशः(संरचना ssh *ssh)
{
	प्रत्यागम (शून्य *)ssh->state->निवेशः;
}

शून्य *
ssh_packet_get_output(संरचना ssh *ssh)
{
	प्रत्यागम (शून्य *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
स्थिर पूर्णाङ्क
ssh_packet_समुच्चयः_postauth(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	यदि ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
स्थिर पूर्णाङ्क
kex_गन्तव्यम्_blob(संरचना sshbuf *m, संरचना kex *kex)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
	    (r = sshbuf_put_cstring(m, kex->hostkey_alg)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_type)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->kex_strict)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->client_संस्करणम्)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->server_संस्करणम्)) != 0 ||
	    (r = sshbuf_put_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->flags)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_put_u32(m, kex->non_pq_kex_warned)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

/* turn key exchange results into a blob for packet state serialization */
स्थिर पूर्णाङ्क
newkeys_गन्तव्यम्_blob(संरचना sshbuf *m, संरचना ssh *ssh, पूर्णाङ्क बहुलकम्)
{
	संरचना sshbuf *b;
	संरचना sshcipher_ctx *cc;
	संरचना sshcomp *comp;
	संरचना sshenc *enc;
	संरचना sshmac *mac;
	संरचना newkeys *newkey;
	पूर्णाङ्क r;

	यदि ((newkey = ssh->state->newkeys[बहुलकम्]) == रिक्त)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (बहुलकम् == बहुलकम्_बहिर्गमनम्) ? ssh->state->send_context :
	    ssh->state->receive_context;
	यदि ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		प्रत्यागम r;
	यदि ((b = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->खण्डम्_आकार)) != 0 ||
	    (r = sshbuf_put_string(b, enc->कुञ्चिका, enc->कुञ्चिका_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (cipher_authlen(enc->cipher) == 0) {
		यदि ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->कुञ्चिका, mac->कुञ्चिका_len)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		गच्छ बहिर्गमनम्;
	r = sshbuf_put_stringb(m, b);
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम r;
}

/* serialize packet state into a blob */
पूर्णाङ्क
ssh_packet_get_state(संरचना ssh *ssh, संरचना sshbuf *m)
{
	संरचना session_state *state = ssh->state;
	पूर्णाङ्क r;

#परिभाषय ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	यदि ((r = kex_गन्तव्यम्_blob(m, ssh->kex)) != 0 ||
	    (r = newkeys_गन्तव्यम्_blob(m, ssh, बहुलकम्_बहिर्गमनम्)) != 0 ||
	    (r = newkeys_गन्तव्यम्_blob(m, ssh, बहुलकम्_अन्तर्)) != 0 ||
	    (r = sshbuf_put_u64(m, state->rekey_सीमा)) != 0 ||
	    (r = sshbuf_put_u32(m, state->rekey_interval)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.खण्डानि)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_send.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_send.अष्टकानि)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.खण्डानि)) != 0 ||
	    (r = sshbuf_put_u32(m, state->p_read.packets)) != 0 ||
	    (r = sshbuf_put_u64(m, state->p_read.अष्टकानि)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->निवेशः)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_बहुलकम्))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		प्रत्यागम r;
#अपरिभाषय ENCODE_INT
	प्रत्यागम 0;
}

/* restore key exchange results from blob for packet state de-serialization */
स्थिर पूर्णाङ्क
newkeys_from_blob(संरचना sshbuf *m, संरचना ssh *ssh, पूर्णाङ्क बहुलकम्)
{
	संरचना sshbuf *b = रिक्त;
	संरचना sshcomp *comp;
	संरचना sshenc *enc;
	संरचना sshmac *mac;
	संरचना newkeys *newkey = रिक्त;
	आकार_t keylen, ivlen, maclen;
	पूर्णाङ्क r;

	यदि ((newkey = शून्यस्मृतिं_देहि(1, परिमाण(*newkey))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_froms(m, &b)) != 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_PK
	sshbuf_dump(b, stderr);
#यदि_अन्तः
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	यदि ((r = sshbuf_get_cstring(b, &enc->name, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->खण्डम्_आकार)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->कुञ्चिका, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((enc->cipher = cipher_by_name(enc->name)) == रिक्त ||
	    enc->खण्डम्_आकार != cipher_blocksize(enc->cipher) ||
	    cipher_is_आन्तरिकम्(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (cipher_authlen(enc->cipher) == 0) {
		यदि ((r = sshbuf_get_cstring(b, &mac->name, रिक्त)) != 0)
			गच्छ बहिर्गमनम्;
		यदि ((r = mac_सज्जता(mac, mac->name)) != 0)
			गच्छ बहिर्गमनम्;
		यदि ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->कुञ्चिका, &maclen)) != 0)
			गच्छ बहिर्गमनम्;
		यदि (maclen != mac->कुञ्चिका_len) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
		mac->कुञ्चिका_len = maclen;
	}
	यदि ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, रिक्त)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	enc->कुञ्चिका_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[बहुलकम्] = newkey;
	newkey = रिक्त;
	r = 0;
 बहिर्गमनम्:
	मुक्त(newkey);
	sshbuf_free(b);
	प्रत्यागम r;
}

/* restore kex from blob for packet state de-serialization */
स्थिर पूर्णाङ्क
kex_from_blob(संरचना sshbuf *m, संरचना kex **kexp)
{
	संरचना kex *kex;
	पूर्णाङ्क r;

	यदि ((kex = kex_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_type)) != 0 ||
	    (r = sshbuf_get_u32(m, (u_int *)&kex->hostkey_nid)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_type)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->kex_strict)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->my)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->peer)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->client_संस्करणम्)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->server_संस्करणम्)) != 0 ||
	    (r = sshbuf_get_stringb(m, kex->session_id)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->flags)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->warn_weak_crypto)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->pq_kex_negotiated)) != 0 ||
	    (r = sshbuf_get_u32(m, &kex->non_pq_kex_warned)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	kex->server = 1;
	kex->समाप्तम् = 1;
	r = 0;
 बहिर्गमनम्:
	यदि (r != 0 || kexp == रिक्त) {
		kex_free(kex);
		यदि (kexp != रिक्त)
			*kexp = रिक्त;
	} अन्यथा {
		kex_free(*kexp);
		*kexp = kex;
	}
	प्रत्यागम r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
पूर्णाङ्क
ssh_packet_समुच्चयः_state(संरचना ssh *ssh, संरचना sshbuf *m)
{
	संरचना session_state *state = ssh->state;
	ध्रुव u_char *निवेशः, *output;
	आकार_t ilen, olen;
	पूर्णाङ्क r;
	u_int interactive, qos_interactive, qos_other;

	यदि ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, बहुलकम्_बहिर्गमनम्)) != 0 ||
	    (r = newkeys_from_blob(m, ssh, बहुलकम्_अन्तर्)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->rekey_सीमा)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->rekey_interval)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.खण्डानि)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_send.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_send.अष्टकानि)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.seqnr)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.खण्डानि)) != 0 ||
	    (r = sshbuf_get_u32(m, &state->p_read.packets)) != 0 ||
	    (r = sshbuf_get_u64(m, &state->p_read.अष्टकानि)) != 0)
		प्रत्यागम r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_time = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	यदि ((r = ssh_समुच्चयः_newkeys(ssh, बहुलकम्_अन्तर्)) != 0 ||
	    (r = ssh_समुच्चयः_newkeys(ssh, बहुलकम्_बहिर्गमनम्)) != 0)
		प्रत्यागम r;

	यदि ((r = ssh_packet_समुच्चयः_postauth(ssh)) != 0)
		प्रत्यागम r;

	sshbuf_reset(state->निवेशः);
	sshbuf_reset(state->output);
	यदि ((r = sshbuf_get_string_प्रत्यक्षम्(m, &निवेशः, &ilen)) != 0 ||
	    (r = sshbuf_get_string_प्रत्यक्षम्(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->निवेशः, निवेशः, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		प्रत्यागम r;

	यदि ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		प्रत्यागम r;
#परिभाषय DECODE_INT(v) ((v) > अधिकतम_पूर्णाङ्कः ? -1 : (पूर्णाङ्क)(v))
	state->interactive_बहुलकम् = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#अपरिभाषय DECODE_INT

	यदि (sshbuf_len(m))
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	प्रत्यागम 0;
}

/* NEW API */

/* put data to the outgoing packet */

पूर्णाङ्क
sshpkt_put(संरचना ssh *ssh, ध्रुव शून्य *v, आकार_t len)
{
	प्रत्यागम sshbuf_put(ssh->state->outgoing_packet, v, len);
}

पूर्णाङ्क
sshpkt_putb(संरचना ssh *ssh, ध्रुव संरचना sshbuf *b)
{
	प्रत्यागम sshbuf_putb(ssh->state->outgoing_packet, b);
}

पूर्णाङ्क
sshpkt_put_u8(संरचना ssh *ssh, u_char val)
{
	प्रत्यागम sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

पूर्णाङ्क
sshpkt_put_u32(संरचना ssh *ssh, uint32_t val)
{
	प्रत्यागम sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

पूर्णाङ्क
sshpkt_put_u64(संरचना ssh *ssh, uint64_t val)
{
	प्रत्यागम sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

पूर्णाङ्क
sshpkt_put_string(संरचना ssh *ssh, ध्रुव शून्य *v, आकार_t len)
{
	प्रत्यागम sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

पूर्णाङ्क
sshpkt_put_cstring(संरचना ssh *ssh, ध्रुव शून्य *v)
{
	प्रत्यागम sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

पूर्णाङ्क
sshpkt_put_stringb(संरचना ssh *ssh, ध्रुव संरचना sshbuf *v)
{
	प्रत्यागम sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#यदि_परिभाषितम् WITH_OPENSSL
पूर्णाङ्क
sshpkt_put_ec(संरचना ssh *ssh, ध्रुव EC_POINT *v, ध्रुव EC_गणः *g)
{
	प्रत्यागम sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

पूर्णाङ्क
sshpkt_put_ec_pkey(संरचना ssh *ssh, EVP_PKEY *pkey)
{
	प्रत्यागम sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

पूर्णाङ्क
sshpkt_put_bignum2(संरचना ssh *ssh, ध्रुव BIGNUM *v)
{
	प्रत्यागम sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#यदि_अन्तः /* WITH_OPENSSL */

/* fetch data from the incoming packet */

पूर्णाङ्क
sshpkt_get(संरचना ssh *ssh, शून्य *valp, आकार_t len)
{
	प्रत्यागम sshbuf_get(ssh->state->incoming_packet, valp, len);
}

पूर्णाङ्क
sshpkt_get_u8(संरचना ssh *ssh, u_char *valp)
{
	प्रत्यागम sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

पूर्णाङ्क
sshpkt_get_u32(संरचना ssh *ssh, uint32_t *valp)
{
	प्रत्यागम sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

पूर्णाङ्क
sshpkt_get_u64(संरचना ssh *ssh, uint64_t *valp)
{
	प्रत्यागम sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

पूर्णाङ्क
sshpkt_get_string(संरचना ssh *ssh, u_char **valp, आकार_t *lenp)
{
	प्रत्यागम sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

पूर्णाङ्क
sshpkt_get_string_प्रत्यक्षम्(संरचना ssh *ssh, ध्रुव u_char **valp, आकार_t *lenp)
{
	प्रत्यागम sshbuf_get_string_प्रत्यक्षम्(ssh->state->incoming_packet, valp, lenp);
}

पूर्णाङ्क
sshpkt_peek_string_प्रत्यक्षम्(संरचना ssh *ssh, ध्रुव u_char **valp, आकार_t *lenp)
{
	प्रत्यागम sshbuf_peek_string_प्रत्यक्षम्(ssh->state->incoming_packet, valp, lenp);
}

पूर्णाङ्क
sshpkt_get_cstring(संरचना ssh *ssh, वर्ण **valp, आकार_t *lenp)
{
	प्रत्यागम sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

पूर्णाङ्क
sshpkt_getb_froms(संरचना ssh *ssh, संरचना sshbuf **valp)
{
	प्रत्यागम sshbuf_froms(ssh->state->incoming_packet, valp);
}

#यदि_परिभाषितम् WITH_OPENSSL
पूर्णाङ्क
sshpkt_get_ec(संरचना ssh *ssh, EC_POINT *v, ध्रुव EC_गणः *g)
{
	प्रत्यागम sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

पूर्णाङ्क
sshpkt_get_bignum2(संरचना ssh *ssh, BIGNUM **valp)
{
	प्रत्यागम sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#यदि_अन्तः /* WITH_OPENSSL */

पूर्णाङ्क
sshpkt_get_अन्तः(संरचना ssh *ssh)
{
	यदि (sshbuf_len(ssh->state->incoming_packet) > 0)
		प्रत्यागम SSH_ERR_UNEXPECTED_TRAILING_दत्त;
	प्रत्यागम 0;
}

ध्रुव u_char *
sshpkt_ptr(संरचना ssh *ssh, आकार_t *lenp)
{
	यदि (lenp != रिक्त)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	प्रत्यागम sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

पूर्णाङ्क
sshpkt_start(संरचना ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	स्मृतिं_पूरय(buf, 0, परिमाण(buf));
	buf[परिमाण(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	प्रत्यागम sshbuf_put(ssh->state->outgoing_packet, buf, परिमाण(buf));
}

स्थिर पूर्णाङ्क
ssh_packet_send_mux(संरचना ssh *ssh)
{
	संरचना session_state *state = ssh->state;
	u_char type, *cp;
	आकार_t len;
	पूर्णाङ्क r;

	यदि (ssh->kex)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	यदि (len < 6)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	यदि (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	यदि (type >= SSH2_सन्देशः_CONNECTION_MIN &&
	    type <= SSH2_सन्देशः_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		यदि ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			प्रत्यागम r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	प्रत्यागम 0;
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
पूर्णाङ्क
sshpkt_सन्देशः_ignore(संरचना ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		प्रत्यागम r;
	प्रति (i = 0; i < nbytes; i++) {
		यदि (i % 4 == 0)
			rnd = arc4random();
		यदि ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			प्रत्यागम r;
		rnd >>= 8;
	}
	प्रत्यागम 0;
}

/* send it */

पूर्णाङ्क
sshpkt_send(संरचना ssh *ssh)
{
	यदि (ssh->state && ssh->state->mux)
		प्रत्यागम ssh_packet_send_mux(ssh);
	प्रत्यागम ssh_packet_send2(ssh);
}

पूर्णाङ्क
sshpkt_disconnect(संरचना ssh *ssh, ध्रुव वर्ण *fmt,...)
{
	वर्ण buf[1024];
	va_list तर्काः;
	पूर्णाङ्क r;

	va_start(तर्काः, fmt);
	vsnprintf(buf, परिमाण(buf), fmt, तर्काः);
	va_end(तर्काः);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

/* roundup current message to pad bytes */
पूर्णाङ्क
sshpkt_सङ्कलय_padding(संरचना ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	प्रत्यागम 0;
}

स्थिर वर्ण *
format_traffic_stats(संरचना packet_state *ps)
{
	वर्ण *stats = रिक्त, अष्टकानि[FMT_SCALED_STRSIZE];

	यदि (ps->अष्टकानि > LLONG_MAX || fmt_scaled(ps->अष्टकानि, अष्टकानि) != 0)
		strlcpy(अष्टकानि, "OVERFLOW", परिमाण(अष्टकानि));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (अचिह्नित दीर्घ)ps->packets, (अचिह्नित दीर्घ दीर्घ)ps->खण्डानि, अष्टकानि);
	प्रत्यागम stats;
}

स्थिर वर्ण *
dedupe_alg_नामानि(ध्रुव वर्ण *अन्तर्, ध्रुव वर्ण *बहिर्गमनम्)
{
	वर्ण *नामानि = रिक्त;

	यदि (अन्तर् == रिक्त)
		अन्तर् = "<implicit>";
	यदि (बहिर्गमनम् == रिक्त)
		बहिर्गमनम् = "<implicit>";

	यदि (वाक्यं_तुलय(अन्तर्, बहिर्गमनम्) == 0) {
		नामानि = xstrdup(अन्तर्);
	} अन्यथा {
		xasprintf(&नामानि, "%s in, %s out", अन्तर्, बहिर्गमनम्);
	}
	प्रत्यागम नामानि;
}

स्थिर वर्ण *
comp_स्थितिः_सन्देशः(संरचना ssh *ssh)
{
#यदि_परिभाषितम् WITH_ZLIB
	वर्ण *ret = रिक्त;
	संरचना session_state *state = ssh->state;
	अचिह्नित दीर्घ दीर्घ iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	वर्ण iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	वर्ण icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	यदि (state->compression_बफर) {
		यदि (state->compression_अन्तर्_started) {
			iraw = state->compression_अन्तर्_प्रवाहः.योग_बहिर्गमनम्;
			icmp = state->compression_अन्तर्_प्रवाहः.योग_अन्तर्;
			यदि (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", परिमाण(iraw_f));
			यदि (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", परिमाण(icmp_f));
		}
		यदि (state->compression_बहिर्गमनम्_started) {
			oraw = state->compression_बहिर्गमनम्_प्रवाहः.योग_अन्तर्;
			ocmp = state->compression_बहिर्गमनम्_प्रवाहः.योग_बहिर्गमनम्;
			यदि (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", परिमाण(oraw_f));
			यदि (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", परिमाण(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (द्विगुण)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (द्विगुण)ocmp / oraw);
		प्रत्यागम ret;
	}
#यदि_अन्तः	/* WITH_ZLIB */
	प्रत्यागम xstrdup("");
}

वर्ण *
connection_info_सन्देशः(संरचना ssh *ssh)
{
	वर्ण *ret = रिक्त, *cipher = रिक्त, *mac = रिक्त, *comp = रिक्त;
	वर्ण *rekey_volume = रिक्त, *rekey_time = रिक्त, *comp_info = रिक्त;
	वर्ण thishost[NI_MAXHOST] = "unknown", *tcp_info = रिक्त;
	संरचना kex *kex;
	संरचना session_state *state;
	संरचना newkeys *nk_अन्तर्, *nk_बहिर्गमनम्;
	वर्ण *stats_अन्तर् = रिक्त, *stats_बहिर्गमनम् = रिक्त;
	uint64_t epoch = (uint64_t)time(रिक्त) - monotime();

	यदि (ssh == रिक्त)
		प्रत्यागम रिक्त;
	state = ssh->state;
	kex = ssh->kex;

	(शून्य)gethostname(thishost, परिमाण(thishost));

	यदि (ssh_local_पत्तनम्(ssh) != 65535 ||
	     वाक्यं_तुलय(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_पत्तनम्(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_पत्तनम्(ssh));
	} अन्यथा {
		tcp_info = xstrdup("");
	}

	nk_अन्तर् = ssh->state->newkeys[बहुलकम्_अन्तर्];
	nk_बहिर्गमनम् = ssh->state->newkeys[बहुलकम्_बहिर्गमनम्];
	stats_अन्तर् = format_traffic_stats(&ssh->state->p_read);
	stats_बहिर्गमनम् = format_traffic_stats(&ssh->state->p_send);

	cipher = dedupe_alg_नामानि(nk_अन्तर्->enc.name, nk_बहिर्गमनम्->enc.name);
	mac = dedupe_alg_नामानि(nk_अन्तर्->mac.name, nk_बहिर्गमनम्->mac.name);
	comp = dedupe_alg_नामानि(nk_अन्तर्->comp.name, nk_बहिर्गमनम्->comp.name);

	/* Volume based rekeying. */
	यदि (state->rekey_सीमा == 0) {
		xasprintf(&rekey_volume, "limit none");
	} अन्यथा {
		वर्ण *volumes = रिक्त, अन्तर्[32], बहिर्गमनम्[32];

		snprintf(अन्तर्, परिमाण(अन्तर्), "%llu",
		   (अचिह्नित दीर्घ दीर्घ)state->max_खण्डानि_अन्तर्);
		snprintf(बहिर्गमनम्, परिमाण(बहिर्गमनम्), "%llu",
		   (अचिह्नित दीर्घ दीर्घ)state->max_खण्डानि_बहिर्गमनम्);
		volumes = dedupe_alg_नामानि(अन्तर्, बहिर्गमनम्);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		मुक्त(volumes);
	}

	/* Time based rekeying. */
	यदि (state->rekey_interval == 0) {
		rekey_time = xstrdup("interval none");
	} अन्यथा {
		वर्ण rekey_अग्र[64];

		format_absolute_time(epoch + state->rekey_time +
		    state->rekey_interval, rekey_अग्र, परिमाण(rekey_अग्र));
		xasprintf(&rekey_time, "interval %s, next %s",
		    fmt_timeframe(state->rekey_interval), rekey_अग्र);
	}
	comp_info = comp_स्थितिः_सन्देशः(ssh);

	xasprintf(&ret, "Connection information for %s pid %lld\r\n"
	    "  versions %s -> %s\r\n"
	    "%s"
	    "  duration %s\r\n"
	    "  kexalgorithm %s\r\n  hostkeyalgorithm %s\r\n"
	    "  cipher %s\r\n  mac %s\r\n  compression %s\r\n"
	    "  rekey %s %s\r\n"
	    "  traffic %s in, %s out\r\n"
	    "%s",
	    thishost, (दीर्घ दीर्घ)getpid(),
	    SSH_RELEASE, ssh->remote_संस्करणम्,
	    tcp_info,
	    fmt_timeframe(monotime() - state->start_time),
	    kex->name, kex->hostkey_alg,
	    cipher, mac, comp,
	    rekey_volume, rekey_time,
	    stats_अन्तर्, stats_बहिर्गमनम्,
	    comp_info
	);
	मुक्त(tcp_info);
	मुक्त(cipher);
	मुक्त(mac);
	मुक्त(comp);
	मुक्त(stats_अन्तर्);
	मुक्त(stats_बहिर्गमनम्);
	मुक्त(rekey_volume);
	मुक्त(rekey_time);
	मुक्त(comp_info);
	प्रत्यागम ret;
}

