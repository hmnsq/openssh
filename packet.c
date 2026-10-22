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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/queue.h>
#समावेश <sys/socket.h>
#समावेश <sys/time.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश <errno.h>
#समावेश <netdb.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <limits.h>
#समावेश <poll.h>
#समावेश <signal.h>
#समावेश <time.h>
#समावेश <util.h>

/*
 * Explicitly include OpenSSL before zlib as some versions of OpenSSL have
 * "free_func" in their headers, which zlib typedefs.
 */
#अगर_घोषित WITH_OPENSSL
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/ec.h>
#पूर्ण_अगर

#अगर_घोषित WITH_ZLIB
#समावेश <zlib.h>
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "compat.h"
#समावेश "ssh2.h"
#समावेश "cipher.h"
#समावेश "kex.h"
#समावेश "digest.h"
#समावेश "mac.h"
#समावेश "log.h"
#समावेश "canohost.h"
#समावेश "misc.h"
#समावेश "packet.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "version.h"

#अगर_घोषित PACKET_DEBUG
#घोषणा DBG(x) x
#अन्यथा
#घोषणा DBG(x)
#पूर्ण_अगर

#घोषणा PACKET_MAX_आकार (256 * 1024)

काष्ठा packet_state {
	uint32_t seqnr;
	uint32_t packets;
	uint64_t blocks;
	uint64_t bytes;
};

काष्ठा packet {
	TAILQ_ENTRY(packet) अग्र;
	u_char type;
	काष्ठा sshbuf *payload;
};

काष्ठा session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	पूर्णांक connection_in;
	पूर्णांक connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	काष्ठा sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	काष्ठा sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	काष्ठा sshbuf *निवेश;

	/* Buffer for raw output data going to the socket. */
	काष्ठा sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	काष्ठा sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	काष्ठा sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	काष्ठा sshbuf *compression_बफर;

#अगर_घोषित WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_stream compression_in_stream;
	z_stream compression_out_stream;
#पूर्ण_अगर
	पूर्णांक compression_in_started;
	पूर्णांक compression_out_started;
	पूर्णांक compression_in_failures;
	पूर्णांक compression_out_failures;

	/* default maximum packet size */
	u_int max_packet_आकार;

	/* Flag indicating whether this module has been initialized. */
	पूर्णांक initialized;

	/* Monotonic clock timestamp when the connection was started. */
	समय_प्रकार start_time;

	/* Set to true if the connection is interactive. */
	पूर्णांक interactive_mode;

	/* Set to true if we are the server side. */
	पूर्णांक server_side;

	/* Set to true if we are authenticated. */
	पूर्णांक after_authentication;

	पूर्णांक keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	पूर्णांक packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	काष्ठा newkeys *newkeys[MODE_MAX];
	काष्ठा packet_state p_read, p_send;

	/* Volume-based rekeying */
	uint64_t hard_max_blocks_in, hard_max_blocks_out;
	uint64_t max_blocks_in, max_blocks_out, rekey_limit;

	/* Time-based rekeying */
	uint32_t rekey_interval;	/* how often in seconds */
	समय_प्रकार rekey_time;	/* time of last rekeying */

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	माप_प्रकार packet_discard_mac_already;
	काष्ठा sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	पूर्णांक rekeying;

	/* Used in ssh_packet_send_mux() */
	पूर्णांक mux;

	/* QoS handling */
	पूर्णांक qos_interactive, qos_other;

	/* Used in packet_set_maxsize */
	पूर्णांक set_maxsize_called;

	/* One-off warning about weak ciphers */
	पूर्णांक cipher_warning_done;

	/*
	 * Disconnect in progress. Used to prevent reentry in
	 * ssh_packet_disconnect()
	 */
	पूर्णांक disconnecting;

	/* Nagle disabled on socket */
	पूर्णांक nodelay_set;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_in;
	व्योम *hook_in_ctx;

	TAILQ_HEAD(, packet) outgoing;
};

काष्ठा ssh *
ssh_alloc_session_state(व्योम)
{
	काष्ठा ssh *ssh = शून्य;
	काष्ठा session_state *state = शून्य;

	अगर ((ssh = सुस्मृति(1, माप(*ssh))) == शून्य ||
	    (state = सुस्मृति(1, माप(*state))) == शून्य ||
	    (ssh->kex = kex_new()) == शून्य ||
	    (state->निवेश = sshbuf_new()) == शून्य ||
	    (state->output = sshbuf_new()) == शून्य ||
	    (state->outgoing_packet = sshbuf_new()) == शून्य ||
	    (state->incoming_packet = sshbuf_new()) == शून्य)
		जाओ fail;
	TAILQ_INIT(&state->outgoing);
	TAILQ_INIT(&ssh->private_कुंजियाँ);
	TAILQ_INIT(&ssh->public_कुंजियाँ);
	state->connection_in = -1;
	state->connection_out = -1;
	state->max_packet_आकार = 32768;
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
	वापस ssh;
 fail:
	अगर (ssh) {
		kex_free(ssh->kex);
		मुक्त(ssh);
	}
	अगर (state) {
		sshbuf_free(state->निवेश);
		sshbuf_free(state->output);
		sshbuf_free(state->incoming_packet);
		sshbuf_free(state->outgoing_packet);
		मुक्त(state);
	}
	वापस शून्य;
}

व्योम
ssh_packet_set_निवेश_hook(काष्ठा ssh *ssh, ssh_packet_hook_fn *hook, व्योम *ctx)
{
	ssh->state->hook_in = hook;
	ssh->state->hook_in_ctx = ctx;
}

/* Returns nonzero if rekeying is in progress */
पूर्णांक
ssh_packet_is_rekeying(काष्ठा ssh *ssh)
{
	वापस ssh->state->rekeying ||
	    (ssh->kex != शून्य && ssh->kex->done == 0);
}

/*
 * Sets the descriptors used for communication.
 */
काष्ठा ssh *
ssh_packet_set_connection(काष्ठा ssh *ssh, पूर्णांक fd_in, पूर्णांक fd_out)
{
	काष्ठा session_state *state;
	स्थिर काष्ठा sshcipher *none = cipher_by_name("none");
	पूर्णांक r, wasnull = ssh == शून्य;

	अगर (none == शून्य) {
		error_f("cannot load cipher 'none'");
		वापस शून्य;
	}
	अगर (ssh == शून्य)
		ssh = ssh_alloc_session_state();
	अगर (ssh == शून्य) {
		error_f("could not allocate state");
		वापस शून्य;
	}
	state = ssh->state;
	state->start_time = monotime();
	state->connection_in = fd_in;
	state->connection_out = fd_out;
	अगर ((r = cipher_init(&state->send_context, none,
	    (स्थिर u_char *)"", 0, शून्य, 0, CIPHER_ENCRYPT)) != 0 ||
	    (r = cipher_init(&state->receive_context, none,
	    (स्थिर u_char *)"", 0, शून्य, 0, CIPHER_DECRYPT)) != 0) {
		error_fr(r, "cipher_init failed");
		अगर (wasnull)
			मुक्त(ssh); /* XXX need ssh_free_session_state? */
		वापस शून्य;
	}
	state->newkeys[MODE_IN] = state->newkeys[MODE_OUT] = शून्य;
	/*
	 * Cache the IP address of the remote connection for use in error
	 * messages that might be generated after the connection has closed.
	 */
	(व्योम)ssh_remote_ipaddr(ssh);
	वापस ssh;
}

व्योम
ssh_packet_set_timeout(काष्ठा ssh *ssh, पूर्णांक timeout, पूर्णांक गिनती)
{
	काष्ठा session_state *state = ssh->state;

	अगर (timeout <= 0 || गिनती <= 0) {
		state->packet_timeout_ms = -1;
		वापस;
	}
	अगर ((पूर्णांक_उच्च / 1000) / गिनती < timeout)
		state->packet_timeout_ms = पूर्णांक_उच्च;
	अन्यथा
		state->packet_timeout_ms = timeout * गिनती * 1000;
}

व्योम
ssh_packet_set_mux(काष्ठा ssh *ssh)
{
	ssh->state->mux = 1;
	ssh->state->rekeying = 0;
	kex_free(ssh->kex);
	ssh->kex = शून्य;
}

पूर्णांक
ssh_packet_get_mux(काष्ठा ssh *ssh)
{
	वापस ssh->state->mux;
}

पूर्णांक
ssh_packet_set_log_preamble(काष्ठा ssh *ssh, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची args;
	पूर्णांक r;

	मुक्त(ssh->log_preamble);
	अगर (fmt == शून्य)
		ssh->log_preamble = शून्य;
	अन्यथा {
		बहु_शुरू(args, fmt);
		r = vasprintf(&ssh->log_preamble, fmt, args);
		बहु_पूर्ण(args);
		अगर (r < 0 || ssh->log_preamble == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
	}
	वापस 0;
}

पूर्णांक
ssh_packet_stop_discard(काष्ठा ssh *ssh)
{
	काष्ठा session_state *state = ssh->state;
	पूर्णांक r;

	अगर (state->packet_discard_mac) {
		अक्षर buf[1024];
		माप_प्रकार dlen = PACKET_MAX_आकार;

		अगर (dlen > state->packet_discard_mac_already)
			dlen -= state->packet_discard_mac_already;
		स_रखो(buf, 'a', माप(buf));
		जबतक (sshbuf_len(state->incoming_packet) < dlen)
			अगर ((r = sshbuf_put(state->incoming_packet, buf,
			    माप(buf))) != 0)
				वापस r;
		(व्योम) mac_compute(state->packet_discard_mac,
		    state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet), dlen,
		    शून्य, 0);
	}
	logit("Finished discarding for %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	वापस SSH_ERR_MAC_INVALID;
}

अटल पूर्णांक
ssh_packet_start_discard(काष्ठा ssh *ssh, काष्ठा sshenc *enc,
    काष्ठा sshmac *mac, माप_प्रकार mac_already, u_int discard)
{
	काष्ठा session_state *state = ssh->state;
	पूर्णांक r;

	अगर (enc == शून्य || !cipher_is_cbc(enc->cipher) || (mac && mac->etm)) {
		अगर ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
			वापस r;
		वापस SSH_ERR_MAC_INVALID;
	}
	/*
	 * Record number of bytes over which the mac has already
	 * been computed in order to minimize timing attacks.
	 */
	अगर (mac && mac->enabled) {
		state->packet_discard_mac = mac;
		state->packet_discard_mac_already = mac_already;
	}
	अगर (sshbuf_len(state->निवेश) >= discard)
		वापस ssh_packet_stop_discard(ssh);
	state->packet_discard = discard - sshbuf_len(state->निवेश);
	वापस 0;
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

पूर्णांक
ssh_packet_connection_is_on_socket(काष्ठा ssh *ssh)
{
	काष्ठा session_state *state;
	काष्ठा sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	अगर (ssh == शून्य || ssh->state == शून्य)
		वापस 0;

	state = ssh->state;
	अगर (state->connection_in == -1 || state->connection_out == -1)
		वापस 0;
	fromlen = माप(from);
	स_रखो(&from, 0, माप(from));
	अगर (getpeername(state->connection_in, (काष्ठा sockaddr *)&from,
	    &fromlen) == -1)
		वापस 0;
	अगर (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		वापस 0;
	/* filedescriptors in and out are the same, so it's a socket */
	अगर (state->connection_in == state->connection_out)
		वापस 1;
	tolen = माप(to);
	स_रखो(&to, 0, माप(to));
	अगर (getpeername(state->connection_out, (काष्ठा sockaddr *)&to,
	    &tolen) == -1)
		वापस 0;
	अगर (fromlen != tolen || स_भेद(&from, &to, fromlen) != 0)
		वापस 0;
	वापस 1;
}

व्योम
ssh_packet_get_bytes(काष्ठा ssh *ssh, uint64_t *ibytes, uint64_t *obytes)
{
	अगर (ibytes)
		*ibytes = ssh->state->p_read.bytes;
	अगर (obytes)
		*obytes = ssh->state->p_send.bytes;
}

पूर्णांक
ssh_packet_connection_af(काष्ठा ssh *ssh)
{
	वापस get_sock_af(ssh->state->connection_out);
}

/* Sets the connection into non-blocking mode. */

व्योम
ssh_packet_set_nonblocking(काष्ठा ssh *ssh)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(ssh->state->connection_in);

	अगर (ssh->state->connection_out != ssh->state->connection_in)
		set_nonblock(ssh->state->connection_out);
}

/* Returns the socket used for reading. */

पूर्णांक
ssh_packet_get_connection_in(काष्ठा ssh *ssh)
{
	वापस ssh->state->connection_in;
}

/* Returns the descriptor used for writing. */

पूर्णांक
ssh_packet_get_connection_out(काष्ठा ssh *ssh)
{
	वापस ssh->state->connection_out;
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

स्थिर अक्षर *
ssh_remote_ipaddr(काष्ठा ssh *ssh)
{
	पूर्णांक sock;

	/* Check whether we have cached the ipaddr. */
	अगर (ssh->remote_ipaddr == शून्य) {
		अगर (ssh_packet_connection_is_on_socket(ssh)) {
			sock = ssh->state->connection_in;
			ssh->remote_ipaddr = get_peer_ipaddr(sock);
			ssh->remote_port = get_peer_port(sock);
			ssh->local_ipaddr = get_local_ipaddr(sock);
			ssh->local_port = get_local_port(sock);
		} अन्यथा {
			ssh->remote_ipaddr = xstrdup("UNKNOWN");
			ssh->remote_port = 65535;
			ssh->local_ipaddr = xstrdup("UNKNOWN");
			ssh->local_port = 65535;
		}
	}
	वापस ssh->remote_ipaddr;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query. Return value is on
 * heap and no caching is performed.
 * This function does additional checks on the hostname to mitigate some
 * attacks based on conflation of hostnames and addresses and will
 * fall back to returning an address on error.
 */

अक्षर *
ssh_remote_hostname(काष्ठा ssh *ssh)
{
	काष्ठा sockaddr_storage from;
	socklen_t fromlen;
	काष्ठा addrinfo hints, *ai, *aitop;
	अक्षर name[NI_MAXHOST], ntop2[NI_MAXHOST];
	स्थिर अक्षर *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = माप(from);
	स_रखो(&from, 0, माप(from));
	अगर (getpeername(ssh_packet_get_connection_in(ssh),
	    (काष्ठा sockaddr *)&from, &fromlen) == -1) {
		debug_f("getpeername failed: %.100s", म_त्रुटि(त्रुटि_सं));
		वापस xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	अगर (from.ss_family == AF_INET6)
		fromlen = माप(काष्ठा sockaddr_in6);

	debug3("trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	अगर (getnameinfo((काष्ठा sockaddr *)&from, fromlen, name, माप(name),
	    शून्य, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		वापस xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	स_रखो(&hints, 0, माप(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	अगर (getaddrinfo(name, शून्य, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		वापस xstrdup(ntop);
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
	स_रखो(&hints, 0, माप(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	अगर (getaddrinfo(name, शून्य, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		वापस xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	क्रम (ai = aitop; ai; ai = ai->ai_next) {
		अगर (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    माप(ntop2), शून्य, 0, NI_NUMERICHOST) == 0 &&
		    (म_भेद(ntop, ntop2) == 0))
				अवरोध;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	अगर (ai == शून्य) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		वापस xstrdup(ntop);
	}
	वापस xstrdup(name);
}

/* Returns the port number of the remote host. */

पूर्णांक
ssh_remote_port(काष्ठा ssh *ssh)
{
	(व्योम)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	वापस ssh->remote_port;
}

/*
 * Returns the IP-address of the local host as a string.  The returned
 * string must not be freed.
 */

स्थिर अक्षर *
ssh_local_ipaddr(काष्ठा ssh *ssh)
{
	(व्योम)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	वापस ssh->local_ipaddr;
}

/* Returns the port number of the local host. */

पूर्णांक
ssh_local_port(काष्ठा ssh *ssh)
{
	(व्योम)ssh_remote_ipaddr(ssh); /* Will lookup and cache. */
	वापस ssh->local_port;
}

/* Returns the routing domain of the input socket, or NULL if unavailable */
स्थिर अक्षर *
ssh_packet_rdomain_in(काष्ठा ssh *ssh)
{
	अगर (ssh->rdomain_in != शून्य)
		वापस ssh->rdomain_in;
	अगर (!ssh_packet_connection_is_on_socket(ssh))
		वापस शून्य;
	ssh->rdomain_in = get_rdomain(ssh->state->connection_in);
	वापस ssh->rdomain_in;
}

/* Closes the connection and clears and frees internal data structures. */

अटल व्योम
ssh_packet_close_internal(काष्ठा ssh *ssh, पूर्णांक do_close)
{
	काष्ठा session_state *state = ssh->state;
	u_int mode;
	काष्ठा packet *p;

	अगर (!state->initialized)
		वापस;
	state->initialized = 0;
	अगर (do_close) {
		अगर (state->connection_in == state->connection_out) {
			बंद(state->connection_out);
		} अन्यथा {
			बंद(state->connection_in);
			बंद(state->connection_out);
		}
	}
	sshbuf_free(state->निवेश);
	sshbuf_free(state->output);
	sshbuf_free(state->outgoing_packet);
	sshbuf_free(state->incoming_packet);
	जबतक ((p = TAILQ_FIRST(&state->outgoing))) {
		sshbuf_free(p->payload);
		TAILQ_REMOVE(&state->outgoing, p, अग्र);
		मुक्त(p);
	}
	क्रम (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(state->newkeys[mode]);	/* current keys */
		state->newkeys[mode] = शून्य;
		ssh_clear_newkeys(ssh, mode);		/* next keys */
	}
#अगर_घोषित WITH_ZLIB
	/* compression state is in shared mem, so we can only release it once */
	अगर (do_close && state->compression_बफर) {
		sshbuf_free(state->compression_बफर);
		अगर (state->compression_out_started) {
			z_streamp stream = &state->compression_out_stream;
			debug("compress outgoing: "
			    "raw data %llu, compressed %llu, factor %.2f",
				(अचिन्हित दीर्घ दीर्घ)stream->योग_in,
				(अचिन्हित दीर्घ दीर्घ)stream->योग_out,
				stream->योग_in == 0 ? 0.0 :
				(द्विगुन) stream->योग_out / stream->योग_in);
			अगर (state->compression_out_failures == 0)
				deflateEnd(stream);
		}
		अगर (state->compression_in_started) {
			z_streamp stream = &state->compression_in_stream;
			debug("compress incoming: "
			    "raw data %llu, compressed %llu, factor %.2f",
			    (अचिन्हित दीर्घ दीर्घ)stream->योग_out,
			    (अचिन्हित दीर्घ दीर्घ)stream->योग_in,
			    stream->योग_out == 0 ? 0.0 :
			    (द्विगुन) stream->योग_in / stream->योग_out);
			अगर (state->compression_in_failures == 0)
				inflateEnd(stream);
		}
	}
#पूर्ण_अगर	/* WITH_ZLIB */
	cipher_free(state->send_context);
	cipher_free(state->receive_context);
	state->send_context = state->receive_context = शून्य;
	अगर (do_close) {
		मुक्त(ssh->local_ipaddr);
		ssh->local_ipaddr = शून्य;
		मुक्त(ssh->remote_ipaddr);
		ssh->remote_ipaddr = शून्य;
		मुक्त(ssh->state);
		ssh->state = शून्य;
		kex_free(ssh->kex);
		ssh->kex = शून्य;
	}
}

व्योम
ssh_packet_free(काष्ठा ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
	freezero(ssh, माप(*ssh));
}

व्योम
ssh_packet_close(काष्ठा ssh *ssh)
{
	ssh_packet_close_internal(ssh, 1);
}

व्योम
ssh_packet_clear_कुंजियाँ(काष्ठा ssh *ssh)
{
	ssh_packet_close_internal(ssh, 0);
}

/* Sets remote side protocol flags. */

व्योम
ssh_packet_set_protocol_flags(काष्ठा ssh *ssh, u_int protocol_flags)
{
	ssh->state->remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
ssh_packet_get_protocol_flags(काष्ठा ssh *ssh)
{
	वापस ssh->state->remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

अटल पूर्णांक
ssh_packet_init_compression(काष्ठा ssh *ssh)
{
	अगर (!ssh->state->compression_बफर &&
	    ((ssh->state->compression_बफर = sshbuf_new()) == शून्य))
		वापस SSH_ERR_ALLOC_FAIL;
	वापस 0;
}

#अगर_घोषित WITH_ZLIB
अटल पूर्णांक
start_compression_out(काष्ठा ssh *ssh)
{
	debug("Enabling compression.");
	अगर (ssh->state->compression_out_started == 1)
		deflateEnd(&ssh->state->compression_out_stream);
	चयन (deflateInit2(&ssh->state->compression_out_stream,
	    Z_BEST_SPEED, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)) {
	हाल Z_OK:
		ssh->state->compression_out_started = 1;
		अवरोध;
	हाल Z_MEM_ERROR:
		वापस SSH_ERR_ALLOC_FAIL;
	शेष:
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	वापस 0;
}

अटल पूर्णांक
start_compression_in(काष्ठा ssh *ssh)
{
	अगर (ssh->state->compression_in_started == 1)
		inflateEnd(&ssh->state->compression_in_stream);
	चयन (inflateInit(&ssh->state->compression_in_stream)) {
	हाल Z_OK:
		ssh->state->compression_in_started = 1;
		अवरोध;
	हाल Z_MEM_ERROR:
		वापस SSH_ERR_ALLOC_FAIL;
	शेष:
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	वापस 0;
}

/* XXX remove need for separate compression buffer */
अटल पूर्णांक
compress_बफर(काष्ठा ssh *ssh, काष्ठा sshbuf *in, काष्ठा sshbuf *out)
{
	u_char buf[4096];
	पूर्णांक r, status;

	अगर (ssh->state->compression_out_started != 1)
		वापस SSH_ERR_INTERNAL_ERROR;

	/* This case is not handled below. */
	अगर (sshbuf_len(in) == 0)
		वापस 0;

	/* Input is the contents of the input buffer. */
	अगर ((ssh->state->compression_out_stream.अग्र_in =
	    sshbuf_mutable_ptr(in)) == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_out_stream.avail_in = sshbuf_len(in);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	करो {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_out_stream.अग्र_out = buf;
		ssh->state->compression_out_stream.avail_out = माप(buf);

		/* Compress as much data into the buffer as possible. */
		status = deflate(&ssh->state->compression_out_stream,
		    Z_PARTIAL_FLUSH);
		चयन (status) {
		हाल Z_MEM_ERROR:
			वापस SSH_ERR_ALLOC_FAIL;
		हाल Z_OK:
			/* Append compressed data to output_buffer. */
			अगर ((r = sshbuf_put(out, buf, माप(buf) -
			    ssh->state->compression_out_stream.avail_out)) != 0)
				वापस r;
			अवरोध;
		हाल Z_STREAM_ERROR:
		शेष:
			ssh->state->compression_out_failures++;
			वापस SSH_ERR_INVALID_FORMAT;
		}
	} जबतक (ssh->state->compression_out_stream.avail_out == 0);
	वापस 0;
}

अटल पूर्णांक
uncompress_बफर(काष्ठा ssh *ssh, काष्ठा sshbuf *in, काष्ठा sshbuf *out)
{
	u_char buf[4096];
	पूर्णांक r, status;

	अगर (ssh->state->compression_in_started != 1)
		वापस SSH_ERR_INTERNAL_ERROR;

	अगर ((ssh->state->compression_in_stream.अग्र_in =
	    sshbuf_mutable_ptr(in)) == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;
	ssh->state->compression_in_stream.avail_in = sshbuf_len(in);

	क्रम (;;) {
		/* Set up fixed-size output buffer. */
		ssh->state->compression_in_stream.अग्र_out = buf;
		ssh->state->compression_in_stream.avail_out = माप(buf);

		status = inflate(&ssh->state->compression_in_stream,
		    Z_SYNC_FLUSH);
		चयन (status) {
		हाल Z_OK:
			अगर ((r = sshbuf_put(out, buf, माप(buf) -
			    ssh->state->compression_in_stream.avail_out)) != 0)
				वापस r;
			अगर (sshbuf_len(out) >= PACKET_MAX_आकार)
				वापस SSH_ERR_INVALID_FORMAT;
			अवरोध;
		हाल Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			वापस 0;
		हाल Z_तथ्य_ERROR:
			वापस SSH_ERR_INVALID_FORMAT;
		हाल Z_MEM_ERROR:
			वापस SSH_ERR_ALLOC_FAIL;
		हाल Z_STREAM_ERROR:
		शेष:
			ssh->state->compression_in_failures++;
			वापस SSH_ERR_INTERNAL_ERROR;
		}
	}
	/* NOTREACHED */
}

#अन्यथा	/* WITH_ZLIB */

अटल पूर्णांक
start_compression_out(काष्ठा ssh *ssh)
{
	वापस SSH_ERR_INTERNAL_ERROR;
}

अटल पूर्णांक
start_compression_in(काष्ठा ssh *ssh)
{
	वापस SSH_ERR_INTERNAL_ERROR;
}

अटल पूर्णांक
compress_बफर(काष्ठा ssh *ssh, काष्ठा sshbuf *in, काष्ठा sshbuf *out)
{
	वापस SSH_ERR_INTERNAL_ERROR;
}

अटल पूर्णांक
uncompress_बफर(काष्ठा ssh *ssh, काष्ठा sshbuf *in, काष्ठा sshbuf *out)
{
	वापस SSH_ERR_INTERNAL_ERROR;
}
#पूर्ण_अगर	/* WITH_ZLIB */

व्योम
ssh_clear_newkeys(काष्ठा ssh *ssh, पूर्णांक mode)
{
	अगर (ssh->kex && ssh->kex->newkeys[mode]) {
		kex_free_newkeys(ssh->kex->newkeys[mode]);
		ssh->kex->newkeys[mode] = शून्य;
	}
}

पूर्णांक
ssh_set_newkeys(काष्ठा ssh *ssh, पूर्णांक mode)
{
	काष्ठा session_state *state = ssh->state;
	काष्ठा sshenc *enc;
	काष्ठा sshmac *mac;
	काष्ठा sshcomp *comp;
	काष्ठा sshcipher_ctx **ccp;
	काष्ठा packet_state *ps;
	uint64_t *max_blocks, *hard_max_blocks;
	स्थिर अक्षर *wmsg;
	पूर्णांक r, crypt_type;
	स्थिर अक्षर *dir = mode == MODE_OUT ? "out" : "in";

	debug2_f("mode %d", mode);

	अगर (mode == MODE_OUT) {
		ccp = &state->send_context;
		crypt_type = CIPHER_ENCRYPT;
		ps = &state->p_send;
		hard_max_blocks = &state->hard_max_blocks_out;
		max_blocks = &state->max_blocks_out;
	} अन्यथा {
		ccp = &state->receive_context;
		crypt_type = CIPHER_DECRYPT;
		ps = &state->p_read;
		hard_max_blocks = &state->hard_max_blocks_in;
		max_blocks = &state->max_blocks_in;
	}
	अगर (state->newkeys[mode] != शून्य) {
		debug_f("rekeying %s, input %llu bytes %llu blocks, "
		    "output %llu bytes %llu blocks", dir,
		    (अचिन्हित दीर्घ दीर्घ)state->p_read.bytes,
		    (अचिन्हित दीर्घ दीर्घ)state->p_read.blocks,
		    (अचिन्हित दीर्घ दीर्घ)state->p_send.bytes,
		    (अचिन्हित दीर्घ दीर्घ)state->p_send.blocks);
		kex_free_newkeys(state->newkeys[mode]);
		state->newkeys[mode] = शून्य;
	}
	/* note that both bytes and the seqnr are not reset */
	ps->packets = ps->blocks = 0;
	/* move newkeys from kex to state */
	अगर ((state->newkeys[mode] = ssh->kex->newkeys[mode]) == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;
	ssh->kex->newkeys[mode] = शून्य;
	enc  = &state->newkeys[mode]->enc;
	mac  = &state->newkeys[mode]->mac;
	comp = &state->newkeys[mode]->comp;
	अगर (cipher_authlen(enc->cipher) == 0) {
		अगर ((r = mac_init(mac)) != 0)
			वापस r;
	}
	mac->enabled = 1;
	DBG(debug_f("cipher_init: %s", dir));
	cipher_free(*ccp);
	*ccp = शून्य;
	अगर ((r = cipher_init(ccp, enc->cipher, enc->कुंजी, enc->कुंजी_len,
	    enc->iv, enc->iv_len, crypt_type)) != 0)
		वापस r;
	अगर (!state->cipher_warning_done &&
	    (wmsg = cipher_warning_message(*ccp)) != शून्य) {
		error("Warning: %s", wmsg);
		state->cipher_warning_done = 1;
	}
	/* Deleting the keys does not gain extra security */
	/* explicit_bzero(enc->iv,  enc->block_size);
	   explicit_bzero(enc->key, enc->key_len);
	   explicit_bzero(mac->key, mac->key_len); */
	अगर (((comp->type == COMP_DELAYED && state->after_authentication)) &&
	    comp->enabled == 0) {
		अगर ((r = ssh_packet_init_compression(ssh)) < 0)
			वापस r;
		अगर (mode == MODE_OUT) {
			अगर ((r = start_compression_out(ssh)) != 0)
				वापस r;
		} अन्यथा {
			अगर ((r = start_compression_in(ssh)) != 0)
				वापस r;
		}
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * so enforce a 1GB limit for small blocksizes.
	 * See RFC4344 section 3.2.
	 */
	अगर (enc->block_आकार >= 16)
		*hard_max_blocks = (uint64_t)1 << (enc->block_आकार*2);
	अन्यथा
		*hard_max_blocks = ((uint64_t)1 << 30) / enc->block_आकार;
	*max_blocks = *hard_max_blocks;
	अगर (state->rekey_limit) {
		*max_blocks = MINIMUM(*max_blocks,
		    state->rekey_limit / enc->block_आकार);
	}
	debug("rekey %s after %llu blocks", dir,
	    (अचिन्हित दीर्घ दीर्घ)*max_blocks);
	वापस 0;
}

#घोषणा MAX_PACKETS	(1U<<31)
/*
 * Checks whether the packet- or block- based rekeying limits have been
 * exceeded. If the 'hard' flag is set, the checks are performed against the
 * absolute maximum we're willing to accept for the given cipher. Otherwise
 * the checks are performed against the RekeyLimit volume, which may be lower.
 */
अटल अंतरभूत पूर्णांक
ssh_packet_check_rekey_blocklimit(काष्ठा ssh *ssh, u_int packet_len, पूर्णांक hard)
{
	काष्ठा session_state *state = ssh->state;
	uint32_t out_blocks;
	स्थिर uint64_t max_blocks_in = hard ?
	    state->hard_max_blocks_in : state->max_blocks_in;
	स्थिर uint64_t max_blocks_out = hard ?
	    state->hard_max_blocks_out : state->max_blocks_out;

	/*
	 * Always rekey when MAX_PACKETS sent in either direction
	 * As per RFC4344 section 3.1 we do this after 2^31 packets.
	 */
	अगर (state->p_send.packets > MAX_PACKETS ||
	    state->p_read.packets > MAX_PACKETS)
		वापस 1;

	अगर (state->newkeys[MODE_OUT] == शून्य)
		वापस 0;

	/* Rekey after (cipher-specific) maximum blocks */
	out_blocks = ROUNDUP(packet_len,
	    state->newkeys[MODE_OUT]->enc.block_आकार);
	वापस (max_blocks_out &&
	    (state->p_send.blocks + out_blocks > max_blocks_out)) ||
	    (max_blocks_in &&
	    (state->p_read.blocks > max_blocks_in));
}

अटल पूर्णांक
ssh_packet_need_rekeying(काष्ठा ssh *ssh, u_int outbound_packet_len)
{
	काष्ठा session_state *state = ssh->state;

	/* Don't attempt rekeying during pre-auth */
	अगर (!state->after_authentication)
		वापस 0;

	/* Haven't keyed yet or KEX in progress. */
	अगर (ssh_packet_is_rekeying(ssh))
		वापस 0;

	/*
	 * Permit one packet in or out per rekey - this allows us to
	 * make progress when rekey limits are very small.
	 */
	अगर (state->p_send.packets == 0 && state->p_read.packets == 0)
		वापस 0;

	/* Time-based rekeying */
	अगर (state->rekey_interval != 0 &&
	    (int64_t)state->rekey_time + state->rekey_interval <= monotime())
		वापस 1;

	वापस ssh_packet_check_rekey_blocklimit(ssh, outbound_packet_len, 0);
}

/* Checks that the hard rekey limits have not been exceeded during preauth */
अटल पूर्णांक
ssh_packet_check_rekey_preauth(काष्ठा ssh *ssh, u_int outgoing_packet_len)
{
	अगर (ssh->state->after_authentication)
		वापस 0;

	अगर (ssh_packet_check_rekey_blocklimit(ssh, 0, 1)) {
		error("RekeyLimit exceeded before authentication completed");
		वापस SSH_ERR_NEED_REKEY;
	}
	वापस 0;
}

पूर्णांक
ssh_packet_check_rekey(काष्ठा ssh *ssh)
{
	पूर्णांक r;

	अगर ((r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		वापस r;
	अगर (!ssh_packet_need_rekeying(ssh, 0))
		वापस 0;
	debug3_f("rekex triggered");
	वापस kex_start_rekex(ssh);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happens on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
अटल पूर्णांक
ssh_packet_enable_delayed_compress(काष्ठा ssh *ssh)
{
	काष्ठा session_state *state = ssh->state;
	काष्ठा sshcomp *comp = शून्य;
	पूर्णांक r, mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	state->after_authentication = 1;
	क्रम (mode = 0; mode < MODE_MAX; mode++) {
		/* protocol error: USERAUTH_SUCCESS received before NEWKEYS */
		अगर (state->newkeys[mode] == शून्य)
			जारी;
		comp = &state->newkeys[mode]->comp;
		अगर (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			अगर ((r = ssh_packet_init_compression(ssh)) != 0)
				वापस r;
			अगर (mode == MODE_OUT) {
				अगर ((r = start_compression_out(ssh)) != 0)
					वापस r;
			} अन्यथा {
				अगर ((r = start_compression_in(ssh)) != 0)
					वापस r;
			}
			comp->enabled = 1;
		}
	}
	वापस 0;
}

/* Used to mute debug logging for noisy packet types */
पूर्णांक
ssh_packet_log_type(u_char type)
{
	चयन (type) {
	हाल SSH2_संदेश_PING:
	हाल SSH2_संदेश_PONG:
	हाल SSH2_संदेश_CHANNEL_तथ्य:
	हाल SSH2_संदेश_CHANNEL_EXTENDED_तथ्य:
	हाल SSH2_संदेश_CHANNEL_WINDOW_ADJUST:
		वापस 0;
	शेष:
		वापस 1;
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
पूर्णांक
ssh_packet_send2_wrapped(काष्ठा ssh *ssh)
{
	काष्ठा session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_लंबाई];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	काष्ठा sshenc *enc   = शून्य;
	काष्ठा sshmac *mac   = शून्य;
	काष्ठा sshcomp *comp = शून्य;
	पूर्णांक r, block_आकार;

	अगर (state->newkeys[MODE_OUT] != शून्य) {
		enc  = &state->newkeys[MODE_OUT]->enc;
		mac  = &state->newkeys[MODE_OUT]->mac;
		comp = &state->newkeys[MODE_OUT]->comp;
		/* disable mac for authenticated encryption */
		अगर ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = शून्य;
	}
	block_आकार = enc ? enc->block_आकार : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	type = (sshbuf_ptr(state->outgoing_packet))[5];
	अगर (ssh_packet_log_type(type))
		debug3("send packet: type %u", type);
#अगर_घोषित PACKET_DEBUG
	ख_लिखो(मानक_त्रुटि, "plain:     ");
	sshbuf_dump(state->outgoing_packet, मानक_त्रुटि);
#पूर्ण_अगर

	अगर (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		अगर ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			जाओ out;
		sshbuf_reset(state->compression_बफर);
		अगर ((r = compress_बफर(ssh, state->outgoing_packet,
		    state->compression_बफर)) != 0)
			जाओ out;
		sshbuf_reset(state->outgoing_packet);
		अगर ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_बफर)) != 0)
			जाओ out;
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
	padlen = block_आकार - (len % block_आकार);
	अगर (padlen < 4)
		padlen += block_आकार;
	अगर (state->extra_pad) {
		tmp = state->extra_pad;
		state->extra_pad =
		    ROUNDUP(state->extra_pad, block_आकार);
		/* check if roundup overflowed */
		अगर (state->extra_pad < tmp)
			वापस SSH_ERR_INVALID_ARGUMENT;
		tmp = (len + padlen) % state->extra_pad;
		/* Check whether pad calculation below will underflow */
		अगर (tmp > state->extra_pad)
			वापस SSH_ERR_INVALID_ARGUMENT;
		pad = state->extra_pad - tmp;
		DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, state->extra_pad));
		tmp = padlen;
		padlen += pad;
		/* Check whether padlen calculation overflowed */
		अगर (padlen < tmp)
			वापस SSH_ERR_INVALID_ARGUMENT; /* overflow */
		state->extra_pad = 0;
	}
	अगर ((r = sshbuf_reserve(state->outgoing_packet, padlen, &cp)) != 0)
		जाओ out;
	अगर (enc && !cipher_ctx_is_plaintext(state->send_context)) {
		/* random padding */
		arc4random_buf(cp, padlen);
	} अन्यथा {
		/* clear padding */
		explicit_bzero(cp, padlen);
	}
	/* sizeof (packet_len + pad_len + payload + padding) */
	len = sshbuf_len(state->outgoing_packet);
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	अगर (cp == शून्य) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
	/* packet_length includes payload, padding and padding length field */
	POKE_U32(cp, len - 4);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
	    len, padlen, aadlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	अगर (mac && mac->enabled && !mac->etm) {
		अगर ((r = mac_compute(mac, state->p_send.seqnr,
		    sshbuf_ptr(state->outgoing_packet), len,
		    macbuf, माप(macbuf))) != 0)
			जाओ out;
		DBG(debug("done calc MAC out #%d", state->p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	अगर ((r = sshbuf_reserve(state->output,
	    sshbuf_len(state->outgoing_packet) + authlen, &cp)) != 0)
		जाओ out;
	अगर ((r = cipher_crypt(state->send_context, state->p_send.seqnr, cp,
	    sshbuf_ptr(state->outgoing_packet),
	    len - aadlen, aadlen, authlen)) != 0)
		जाओ out;
	/* append unencrypted MAC */
	अगर (mac && mac->enabled) {
		अगर (mac->etm) {
			/* EtM: compute mac over aadlen + cipher text */
			अगर ((r = mac_compute(mac, state->p_send.seqnr,
			    cp, len, macbuf, माप(macbuf))) != 0)
				जाओ out;
			DBG(debug("done calc MAC(EtM) out #%d",
			    state->p_send.seqnr));
		}
		अगर ((r = sshbuf_put(state->output, macbuf, mac->mac_len)) != 0)
			जाओ out;
	}
#अगर_घोषित PACKET_DEBUG
	ख_लिखो(मानक_त्रुटि, "encrypted: ");
	sshbuf_dump(state->output, मानक_त्रुटि);
#पूर्ण_अगर
	/* increment sequence number for outgoing packets */
	अगर (++state->p_send.seqnr == 0) {
		अगर ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "outgoing sequence number "
			    "wrapped during initial key exchange");
		}
		logit("outgoing seqnr wraps around");
	}
	अगर (++state->p_send.packets == 0)
		वापस SSH_ERR_NEED_REKEY;
	state->p_send.blocks += len / block_आकार;
	state->p_send.bytes += len;
	sshbuf_reset(state->outgoing_packet);

	अगर (type == SSH2_संदेश_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting send seqnr %u", state->p_send.seqnr);
		state->p_send.seqnr = 0;
	}

	अगर (type == SSH2_संदेश_NEWKEYS)
		r = ssh_set_newkeys(ssh, MODE_OUT);
	अन्यथा अगर (type == SSH2_संदेश_USERAUTH_SUCCESS && state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	अन्यथा
		r = 0;
 out:
	वापस r;
}

/* returns non-zero if the specified packet type is usec by KEX */
अटल पूर्णांक
ssh_packet_type_is_kex(u_char type)
{
	वापस
	    type >= SSH2_संदेश_TRANSPORT_MIN &&
	    type <= SSH2_संदेश_TRANSPORT_MAX &&
	    type != SSH2_संदेश_SERVICE_REQUEST &&
	    type != SSH2_संदेश_SERVICE_ACCEPT &&
	    type != SSH2_संदेश_EXT_INFO;
}

पूर्णांक
ssh_packet_send2(काष्ठा ssh *ssh)
{
	काष्ठा session_state *state = ssh->state;
	काष्ठा packet *p;
	u_char type;
	पूर्णांक r, need_rekey;

	अगर (sshbuf_len(state->outgoing_packet) < 6)
		वापस SSH_ERR_INTERNAL_ERROR;
	type = sshbuf_ptr(state->outgoing_packet)[5];
	need_rekey = !ssh_packet_type_is_kex(type) &&
	    ssh_packet_need_rekeying(ssh, sshbuf_len(state->outgoing_packet));

	/* Enforce hard rekey limit during pre-auth */
	अगर (!state->rekeying && !ssh_packet_type_is_kex(type) &&
	    (r = ssh_packet_check_rekey_preauth(ssh, 0)) != 0)
		वापस r;

	/*
	 * During rekeying we can only send key exchange messages.
	 * Queue everything else.
	 */
	अगर ((need_rekey || state->rekeying) && !ssh_packet_type_is_kex(type)) {
		अगर (need_rekey)
			debug3_f("rekex triggered");
		debug("enqueue packet: %u", type);
		p = सुस्मृति(1, माप(*p));
		अगर (p == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
		p->type = type;
		p->payload = state->outgoing_packet;
		TAILQ_INSERT_TAIL(&state->outgoing, p, अग्र);
		state->outgoing_packet = sshbuf_new();
		अगर (state->outgoing_packet == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
		अगर (need_rekey) {
			/*
			 * This packet triggered a rekey, so send the
			 * KEXINIT now.
			 * NB. reenters this function via kex_start_rekex().
			 */
			वापस kex_start_rekex(ssh);
		}
		वापस 0;
	}

	/* rekeying starts with sending KEXINIT */
	अगर (type == SSH2_संदेश_KEXINIT)
		state->rekeying = 1;

	अगर ((r = ssh_packet_send2_wrapped(ssh)) != 0)
		वापस r;

	/* after a NEWKEYS message we can send the complete queue */
	अगर (type == SSH2_संदेश_NEWKEYS) {
		state->rekeying = 0;
		state->rekey_time = monotime();
		जबतक ((p = TAILQ_FIRST(&state->outgoing))) {
			type = p->type;
			/*
			 * If this packet triggers a rekex, then skip the
			 * remaining packets in the queue for now.
			 * NB. re-enters this function via kex_start_rekex.
			 */
			अगर (ssh_packet_need_rekeying(ssh,
			    sshbuf_len(p->payload))) {
				debug3_f("queued packet triggered rekex");
				वापस kex_start_rekex(ssh);
			}
			debug("dequeue packet: %u", type);
			sshbuf_free(state->outgoing_packet);
			state->outgoing_packet = p->payload;
			TAILQ_REMOVE(&state->outgoing, p, अग्र);
			स_रखो(p, 0, माप(*p));
			मुक्त(p);
			अगर ((r = ssh_packet_send2_wrapped(ssh)) != 0)
				वापस r;
		}
	}
	वापस 0;
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

पूर्णांक
ssh_packet_read_seqnr(काष्ठा ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	काष्ठा session_state *state = ssh->state;
	पूर्णांक len, r, ms_remain = 0;
	काष्ठा pollfd pfd;
	अक्षर buf[8192];
	काष्ठा timeval start;
	काष्ठा timespec timespec, *timespecp = शून्य;

	DBG(debug("packet_read()"));

	/*
	 * Since we are blocking, ensure that all written packets have
	 * been sent.
	 */
	अगर ((r = ssh_packet_write_wait(ssh)) != 0)
		जाओ out;

	/* Stay in the loop until we have received a complete packet. */
	क्रम (;;) {
		/* Try to read a packet from the buffer. */
		अगर ((r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p)) != 0)
			अवरोध;
		/* If we got a packet, return it. */
		अगर (*typep != SSH_संदेश_NONE)
			अवरोध;
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		pfd.fd = state->connection_in;
		pfd.events = POLLIN;

		अगर (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		/* Wait for some data to arrive. */
		क्रम (;;) {
			अगर (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			अगर ((r = ppoll(&pfd, 1, timespecp, शून्य)) >= 0)
				अवरोध;
			अगर (त्रुटि_सं != EAGAIN && त्रुटि_सं != EINTR &&
			    त्रुटि_सं != EWOULDBLOCK) {
				r = SSH_ERR_SYSTEM_ERROR;
				जाओ out;
			}
			अगर (state->packet_timeout_ms <= 0)
				जारी;
			ms_subtract_diff(&start, &ms_remain);
			अगर (ms_remain <= 0) {
				r = 0;
				अवरोध;
			}
		}
		अगर (r == 0) {
			r = SSH_ERR_CONN_TIMEOUT;
			जाओ out;
		}
		/* Read data from the socket. */
		len = पढ़ो(state->connection_in, buf, माप(buf));
		अगर (len == 0) {
			r = SSH_ERR_CONN_CLOSED;
			जाओ out;
		}
		अगर (len == -1) {
			r = SSH_ERR_SYSTEM_ERROR;
			जाओ out;
		}

		/* Append it to the buffer. */
		अगर ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
			जाओ out;
	}
 out:
	वापस r;
}

पूर्णांक
ssh_packet_read(काष्ठा ssh *ssh)
{
	u_char type;
	पूर्णांक r;

	अगर ((r = ssh_packet_read_seqnr(ssh, &type, शून्य)) != 0)
		sshpkt_fatal(ssh, r, "read");
	वापस type;
}

अटल पूर्णांक
ssh_packet_read_poll2_mux(काष्ठा ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	काष्ठा session_state *state = ssh->state;
	स्थिर u_char *cp;
	माप_प्रकार need;
	पूर्णांक r;

	अगर (ssh->kex)
		वापस SSH_ERR_INTERNAL_ERROR;
	*typep = SSH_संदेश_NONE;
	cp = sshbuf_ptr(state->निवेश);
	अगर (state->packlen == 0) {
		अगर (sshbuf_len(state->निवेश) < 4 + 1)
			वापस 0; /* packet is incomplete */
		state->packlen = PEEK_U32(cp);
		अगर (state->packlen < 4 + 1 ||
		    state->packlen > PACKET_MAX_आकार)
			वापस SSH_ERR_MESSAGE_INCOMPLETE;
	}
	need = state->packlen + 4;
	अगर (sshbuf_len(state->निवेश) < need)
		वापस 0; /* packet is incomplete */
	sshbuf_reset(state->incoming_packet);
	अगर ((r = sshbuf_put(state->incoming_packet, cp + 4,
	    state->packlen)) != 0 ||
	    (r = sshbuf_consume(state->निवेश, need)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, शून्य)) != 0 ||
	    (r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		वापस r;
	अगर (ssh_packet_log_type(*typep))
		debug3_f("type %u", *typep);
	/* sshbuf_dump(state->incoming_packet, stderr); */
	/* reset for next packet */
	state->packlen = 0;
	वापस r;
}

पूर्णांक
ssh_packet_read_poll2(काष्ठा ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	काष्ठा session_state *state = ssh->state;
	u_int padlen, need;
	u_char *cp;
	u_int maclen, aadlen = 0, authlen = 0, block_आकार;
	काष्ठा sshenc *enc   = शून्य;
	काष्ठा sshmac *mac   = शून्य;
	काष्ठा sshcomp *comp = शून्य;
	पूर्णांक r;

	अगर (state->mux)
		वापस ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);

	*typep = SSH_संदेश_NONE;

	अगर (state->packet_discard)
		वापस 0;

	अगर (state->newkeys[MODE_IN] != शून्य) {
		enc  = &state->newkeys[MODE_IN]->enc;
		mac  = &state->newkeys[MODE_IN]->mac;
		comp = &state->newkeys[MODE_IN]->comp;
		/* disable mac for authenticated encryption */
		अगर ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = शून्य;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_आकार = enc ? enc->block_आकार : 8;
	aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;

	अगर (aadlen && state->packlen == 0) {
		अगर (cipher_get_लंबाई(state->receive_context,
		    &state->packlen, state->p_read.seqnr,
		    sshbuf_ptr(state->निवेश), sshbuf_len(state->निवेश)) != 0)
			वापस 0;
		अगर (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_आकार) {
#अगर_घोषित PACKET_DEBUG
			sshbuf_dump(state->निवेश, मानक_त्रुटि);
#पूर्ण_अगर
			logit("Bad packet length %u.", state->packlen);
			अगर ((r = sshpkt_disconnect(ssh, "Packet corrupt")) != 0)
				वापस r;
			वापस SSH_ERR_CONN_CORRUPT;
		}
		sshbuf_reset(state->incoming_packet);
	} अन्यथा अगर (state->packlen == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		अगर (sshbuf_len(state->निवेश) < block_आकार)
			वापस 0;
		sshbuf_reset(state->incoming_packet);
		अगर ((r = sshbuf_reserve(state->incoming_packet, block_आकार,
		    &cp)) != 0)
			जाओ out;
		अगर ((r = cipher_crypt(state->receive_context,
		    state->p_send.seqnr, cp, sshbuf_ptr(state->निवेश),
		    block_आकार, 0, 0)) != 0)
			जाओ out;
		state->packlen = PEEK_U32(sshbuf_ptr(state->incoming_packet));
		अगर (state->packlen < 1 + 4 ||
		    state->packlen > PACKET_MAX_आकार) {
#अगर_घोषित PACKET_DEBUG
			ख_लिखो(मानक_त्रुटि, "input: \n");
			sshbuf_dump(state->निवेश, मानक_त्रुटि);
			ख_लिखो(मानक_त्रुटि, "incoming_packet: \n");
			sshbuf_dump(state->incoming_packet, मानक_त्रुटि);
#पूर्ण_अगर
			logit("Bad packet length %u.", state->packlen);
			वापस ssh_packet_start_discard(ssh, enc, mac, 0,
			    PACKET_MAX_आकार);
		}
		अगर ((r = sshbuf_consume(state->निवेश, block_आकार)) != 0)
			जाओ out;
	}
	DBG(debug("input: packet len %u", state->packlen+4));

	अगर (aadlen) {
		/* only the payload is encrypted */
		need = state->packlen;
	} अन्यथा {
		/*
		 * the payload size and the payload are encrypted, but we
		 * have a partial packet of block_size bytes
		 */
		need = 4 + state->packlen - block_आकार;
	}
	DBG(debug("partial packet: block %d, need %d, maclen %d, authlen %d,"
	    " aadlen %d", block_आकार, need, maclen, authlen, aadlen));
	अगर (need % block_आकार != 0) {
		logit("padding error: need %d block %d mod %d",
		    need, block_आकार, need % block_आकार);
		वापस ssh_packet_start_discard(ssh, enc, mac, 0,
		    PACKET_MAX_आकार - block_आकार);
	}
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet:
	 * 'aadlen' bytes are unencrypted, but authenticated.
	 * 'need' bytes are encrypted, followed by either
	 * 'authlen' bytes of authentication tag or
	 * 'maclen' bytes of message authentication code.
	 */
	अगर (sshbuf_len(state->निवेश) < aadlen + need + authlen + maclen)
		वापस 0; /* packet is incomplete */
#अगर_घोषित PACKET_DEBUG
	ख_लिखो(मानक_त्रुटि, "read_poll enc/full: ");
	sshbuf_dump(state->निवेश, मानक_त्रुटि);
#पूर्ण_अगर
	/* EtM: check mac over encrypted input */
	अगर (mac && mac->enabled && mac->etm) {
		अगर ((r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->निवेश), aadlen + need,
		    sshbuf_ptr(state->निवेश) + aadlen + need + authlen,
		    maclen)) != 0) {
			अगर (r == SSH_ERR_MAC_INVALID)
				logit("Corrupted MAC on input.");
			जाओ out;
		}
	}
	अगर ((r = sshbuf_reserve(state->incoming_packet, aadlen + need,
	    &cp)) != 0)
		जाओ out;
	अगर ((r = cipher_crypt(state->receive_context, state->p_read.seqnr, cp,
	    sshbuf_ptr(state->निवेश), need, aadlen, authlen)) != 0)
		जाओ out;
	अगर ((r = sshbuf_consume(state->निवेश, aadlen + need + authlen)) != 0)
		जाओ out;
	अगर (mac && mac->enabled) {
		/* Not EtM: check MAC over cleartext */
		अगर (!mac->etm && (r = mac_check(mac, state->p_read.seqnr,
		    sshbuf_ptr(state->incoming_packet),
		    sshbuf_len(state->incoming_packet),
		    sshbuf_ptr(state->निवेश), maclen)) != 0) {
			अगर (r != SSH_ERR_MAC_INVALID)
				जाओ out;
			logit("Corrupted MAC on input.");
			अगर (need + block_आकार > PACKET_MAX_आकार)
				वापस SSH_ERR_INTERNAL_ERROR;
			वापस ssh_packet_start_discard(ssh, enc, mac,
			    sshbuf_len(state->incoming_packet),
			    PACKET_MAX_आकार - need - block_आकार);
		}
		/* Remove MAC from input buffer */
		DBG(debug("MAC #%d ok", state->p_read.seqnr));
		अगर ((r = sshbuf_consume(state->निवेश, mac->mac_len)) != 0)
			जाओ out;
	}

	अगर (seqnr_p != शून्य)
		*seqnr_p = state->p_read.seqnr;
	अगर (++state->p_read.seqnr == 0) {
		अगर ((ssh->kex->flags & KEX_INITIAL) != 0) {
			ssh_packet_disconnect(ssh, "incoming sequence number "
			    "wrapped during initial key exchange");
		}
		logit("incoming seqnr wraps around");
	}
	अगर (++state->p_read.packets == 0)
		वापस SSH_ERR_NEED_REKEY;
	state->p_read.blocks += (state->packlen + 4) / block_आकार;
	state->p_read.bytes += state->packlen + 4;

	/* get padlen */
	padlen = sshbuf_ptr(state->incoming_packet)[4];
	DBG(debug("input: padlen %d", padlen));
	अगर (padlen < 4)	{
		अगर ((r = sshpkt_disconnect(ssh,
		    "Corrupted padlen %d on input.", padlen)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			वापस r;
		वापस SSH_ERR_CONN_CORRUPT;
	}

	/* skip packet size + padlen, discard padding */
	अगर ((r = sshbuf_consume(state->incoming_packet, 4 + 1)) != 0 ||
	    ((r = sshbuf_consume_end(state->incoming_packet, padlen)) != 0))
		जाओ out;

	DBG(debug("input: len before de-compress %zd",
	    sshbuf_len(state->incoming_packet)));
	अगर (comp && comp->enabled) {
		sshbuf_reset(state->compression_बफर);
		अगर ((r = uncompress_बफर(ssh, state->incoming_packet,
		    state->compression_बफर)) != 0)
			जाओ out;
		sshbuf_reset(state->incoming_packet);
		अगर ((r = sshbuf_putb(state->incoming_packet,
		    state->compression_बफर)) != 0)
			जाओ out;
		DBG(debug("input: len after de-compress %zd",
		    sshbuf_len(state->incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	अगर ((r = sshbuf_get_u8(state->incoming_packet, typep)) != 0)
		जाओ out;
	अगर (ssh_packet_log_type(*typep))
		debug3("receive packet: type %u", *typep);
	अगर (*typep < SSH2_संदेश_MIN) {
		अगर ((r = sshpkt_disconnect(ssh,
		    "Invalid ssh2 packet type: %d", *typep)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			वापस r;
		वापस SSH_ERR_PROTOCOL_ERROR;
	}
	अगर (state->hook_in != शून्य &&
	    (r = state->hook_in(ssh, state->incoming_packet, typep,
	    state->hook_in_ctx)) != 0)
		वापस r;
	अगर (*typep == SSH2_संदेश_USERAUTH_SUCCESS && !state->server_side)
		r = ssh_packet_enable_delayed_compress(ssh);
	अन्यथा
		r = 0;
#अगर_घोषित PACKET_DEBUG
	ख_लिखो(मानक_त्रुटि, "read/plain[%d]:\r\n", *typep);
	sshbuf_dump(state->incoming_packet, मानक_त्रुटि);
#पूर्ण_अगर
	/* reset for next packet */
	state->packlen = 0;
	अगर (*typep == SSH2_संदेश_NEWKEYS && ssh->kex->kex_strict) {
		debug_f("resetting read seqnr %u", state->p_read.seqnr);
		state->p_read.seqnr = 0;
	}

	अगर ((r = ssh_packet_check_rekey(ssh)) != 0)
		वापस r;
 out:
	वापस r;
}

पूर्णांक
ssh_packet_read_poll_seqnr(काष्ठा ssh *ssh, u_char *typep, uint32_t *seqnr_p)
{
	काष्ठा session_state *state = ssh->state;
	u_int reason, seqnr;
	पूर्णांक r;
	u_char *संदेश;
	स्थिर u_char *d;
	माप_प्रकार len;

	क्रम (;;) {
		संदेश = शून्य;
		r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
		अगर (r != 0)
			वापस r;
		अगर (*typep == 0) {
			/* no message ready */
			वापस 0;
		}
		state->keep_alive_timeouts = 0;
		DBG(debug("received packet type %d", *typep));

		/* Always process disconnect messages */
		अगर (*typep == SSH2_संदेश_DISCONNECT) {
			अगर ((r = sshpkt_get_u32(ssh, &reason)) != 0 ||
			    (r = sshpkt_get_string(ssh, &संदेश, शून्य)) != 0)
				वापस r;
			/* Ignore normal client exit notifications */
			do_log2(ssh->state->server_side &&
			    reason == SSH2_DISCONNECT_BY_APPLICATION ?
			    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_ERROR,
			    "Received disconnect from %s port %d:"
			    "%u: %.400s", ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh), reason, संदेश);
			मुक्त(संदेश);
			वापस SSH_ERR_DISCONNECTED;
		}

		/*
		 * Do not implicitly handle any messages here during initial
		 * KEX when in strict mode. They will be need to be allowed
		 * explicitly by the KEX dispatch table or they will generate
		 * protocol errors.
		 */
		अगर (ssh->kex != शून्य &&
		    (ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)
			वापस 0;
		/* Implicitly handle transport-level messages */
		चयन (*typep) {
		हाल SSH2_संदेश_IGNORE:
			debug3("Received SSH2_MSG_IGNORE");
			अवरोध;
		हाल SSH2_संदेश_DEBUG:
			अगर ((r = sshpkt_get_u8(ssh, शून्य)) != 0 ||
			    (r = sshpkt_get_string(ssh, &संदेश, शून्य)) != 0 ||
			    (r = sshpkt_get_string(ssh, शून्य, शून्य)) != 0) {
				मुक्त(संदेश);
				वापस r;
			}
			debug("Remote: %.900s", संदेश);
			मुक्त(संदेश);
			अवरोध;
		हाल SSH2_संदेश_UNIMPLEMENTED:
			अगर ((r = sshpkt_get_u32(ssh, &seqnr)) != 0)
				वापस r;
			debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
			    seqnr);
			अवरोध;
		हाल SSH2_संदेश_PING:
			अगर ((r = sshpkt_get_string_direct(ssh, &d, &len)) != 0)
				वापस r;
			DBG(debug("Received SSH2_MSG_PING len %zu", len));
			अगर (!ssh->state->after_authentication) {
				DBG(debug("Won't reply to PING in preauth"));
				अवरोध;
			}
			अगर (ssh_packet_is_rekeying(ssh)) {
				DBG(debug("Won't reply to PING during KEX"));
				अवरोध;
			}
			अगर ((r = sshpkt_start(ssh, SSH2_संदेश_PONG)) != 0 ||
			    (r = sshpkt_put_string(ssh, d, len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				वापस r;
			अवरोध;
		हाल SSH2_संदेश_PONG:
			अगर ((r = sshpkt_get_string_direct(ssh,
			    शून्य, &len)) != 0)
				वापस r;
			DBG(debug("Received SSH2_MSG_PONG len %zu", len));
			अवरोध;
		शेष:
			अगर (ssh->kex != शून्य &&
			    (ssh->kex->flags & KEX_INIT_RECVD) != 0 &&
			    !ssh_packet_type_is_kex(*typep)) {
				error("non-transport message %u received "
				    "from peer during key exchange", *typep);
				वापस SSH_ERR_PROTOCOL_ERROR;
			}
			वापस 0;
		}
	}
}

/*
 * Buffers the supplied input data. This is intended to be used together
 * with packet_read_poll().
 */
पूर्णांक
ssh_packet_process_incoming(काष्ठा ssh *ssh, स्थिर अक्षर *buf, u_int len)
{
	काष्ठा session_state *state = ssh->state;
	पूर्णांक r;

	अगर (state->packet_discard) {
		state->keep_alive_timeouts = 0; /* ?? */
		अगर (len >= state->packet_discard) {
			अगर ((r = ssh_packet_stop_discard(ssh)) != 0)
				वापस r;
		}
		state->packet_discard -= len;
		वापस 0;
	}
	अगर ((r = sshbuf_put(state->निवेश, buf, len)) != 0)
		वापस r;

	वापस 0;
}

/* Reads and buffers data from the specified fd */
पूर्णांक
ssh_packet_process_read(काष्ठा ssh *ssh, पूर्णांक fd)
{
	काष्ठा session_state *state = ssh->state;
	पूर्णांक r;
	माप_प्रकार rlen;

	अगर ((r = sshbuf_read(fd, state->निवेश, PACKET_MAX_आकार, &rlen)) != 0)
		वापस r;

	अगर (state->packet_discard) {
		अगर ((r = sshbuf_consume_end(state->निवेश, rlen)) != 0)
			वापस r;
		state->keep_alive_timeouts = 0; /* ?? */
		अगर (rlen >= state->packet_discard) {
			अगर ((r = ssh_packet_stop_discard(ssh)) != 0)
				वापस r;
		}
		state->packet_discard -= rlen;
		वापस 0;
	}
	वापस 0;
}

पूर्णांक
ssh_packet_remaining(काष्ठा ssh *ssh)
{
	वापस sshbuf_len(ssh->state->incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call ssh_packet_write_wait.
 */
व्योम
ssh_packet_send_debug(काष्ठा ssh *ssh, स्थिर अक्षर *fmt,...)
{
	अक्षर buf[1024];
	बहु_सूची args;
	पूर्णांक r;

	अगर ((ssh->compat & SSH_BUG_DEBUG))
		वापस;

	बहु_शुरू(args, fmt);
	vsnprintf(buf, माप(buf), fmt, args);
	बहु_पूर्ण(args);

	debug3("sending debug message: %s", buf);

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_DEBUG)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* always display */
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "send DEBUG");
}

व्योम
sshpkt_fmt_connection_id(काष्ठा ssh *ssh, अक्षर *s, माप_प्रकार l)
{
	snprintf(s, l, "%.200s%s%s port %d",
	    ssh->log_preamble ? ssh->log_preamble : "",
	    ssh->log_preamble ? " " : "",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
}

/*
 * Pretty-print connection-terminating errors and exit.
 */
अटल व्योम
sshpkt_vfatal(काष्ठा ssh *ssh, पूर्णांक r, स्थिर अक्षर *fmt, बहु_सूची ap)
{
	अक्षर *tag = शून्य, remote_id[512];
	पूर्णांक oerrno = त्रुटि_सं;

	sshpkt_fmt_connection_id(ssh, remote_id, माप(remote_id));

	चयन (r) {
	हाल SSH_ERR_CONN_CLOSED:
		ssh_packet_clear_कुंजियाँ(ssh);
		logdie("Connection closed by %s", remote_id);
	हाल SSH_ERR_CONN_TIMEOUT:
		ssh_packet_clear_कुंजियाँ(ssh);
		logdie("Connection %s %s timed out",
		    ssh->state->server_side ? "from" : "to", remote_id);
	हाल SSH_ERR_DISCONNECTED:
		ssh_packet_clear_कुंजियाँ(ssh);
		logdie("Disconnected from %s", remote_id);
	हाल SSH_ERR_SYSTEM_ERROR:
		अगर (त्रुटि_सं == ECONNRESET) {
			ssh_packet_clear_कुंजियाँ(ssh);
			logdie("Connection reset by %s", remote_id);
		}
		/* FALLTHROUGH */
	हाल SSH_ERR_NO_CIPHER_ALG_MATCH:
	हाल SSH_ERR_NO_MAC_ALG_MATCH:
	हाल SSH_ERR_NO_COMPRESS_ALG_MATCH:
	हाल SSH_ERR_NO_KEX_ALG_MATCH:
	हाल SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		अगर (ssh->kex && ssh->kex->failed_choice) {
			ssh_packet_clear_कुंजियाँ(ssh);
			त्रुटि_सं = oerrno;
			logdie("Unable to negotiate with %s: %s. "
			    "Their offer: %s", remote_id, ssh_err(r),
			    ssh->kex->failed_choice);
		}
		/* FALLTHROUGH */
	शेष:
		अगर (vasprintf(&tag, fmt, ap) == -1) {
			ssh_packet_clear_कुंजियाँ(ssh);
			logdie_f("could not allocate failure message");
		}
		ssh_packet_clear_कुंजियाँ(ssh);
		त्रुटि_सं = oerrno;
		logdie_r(r, "%s%sConnection %s %s",
		    tag != शून्य ? tag : "", tag != शून्य ? ": " : "",
		    ssh->state->server_side ? "from" : "to", remote_id);
	}
}

व्योम
sshpkt_fatal(काष्ठा ssh *ssh, पूर्णांक r, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	sshpkt_vfatal(ssh, r, fmt, ap);
	/* NOTREACHED */
	बहु_पूर्ण(ap);
	logdie_f("should have exited");
}

/*
 * Logs the error plus constructs and sends a disconnect packet, closes the
 * connection, and exits.  This function never returns. The error message
 * should not contain a newline.  The length of the formatted message must
 * not exceed 1024 bytes.
 */
व्योम
ssh_packet_disconnect(काष्ठा ssh *ssh, स्थिर अक्षर *fmt,...)
{
	अक्षर buf[1024], remote_id[512];
	बहु_सूची args;
	पूर्णांक r;

	/* Guard against recursive invocations. */
	अगर (ssh->state->disconnecting)
		fatal("packet_disconnect called recursively.");
	ssh->state->disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	sshpkt_fmt_connection_id(ssh, remote_id, माप(remote_id));
	बहु_शुरू(args, fmt);
	vsnprintf(buf, माप(buf), fmt, args);
	बहु_पूर्ण(args);

	/* Display the error locally */
	logit("Disconnecting %s: %.100s", remote_id, buf);

	/*
	 * Send the disconnect message to the other side, and wait
	 * for it to get sent.
	 */
	अगर ((r = sshpkt_disconnect(ssh, "%s", buf)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	अगर ((r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);

	/* Close the connection. */
	ssh_packet_close(ssh);
	cleanup_exit(255);
}

/*
 * Checks if there is any buffered output, and tries to write some of
 * the output.
 */
पूर्णांक
ssh_packet_write_poll(काष्ठा ssh *ssh)
{
	काष्ठा session_state *state = ssh->state;
	पूर्णांक len = sshbuf_len(state->output);
	पूर्णांक r;

	अगर (len > 0) {
		len = ग_लिखो(state->connection_out,
		    sshbuf_ptr(state->output), len);
		अगर (len == -1) {
			अगर (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN ||
			    त्रुटि_सं == EWOULDBLOCK)
				वापस 0;
			वापस SSH_ERR_SYSTEM_ERROR;
		}
		अगर (len == 0)
			वापस SSH_ERR_CONN_CLOSED;
		अगर ((r = sshbuf_consume(state->output, len)) != 0)
			वापस r;
	}
	वापस 0;
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */
पूर्णांक
ssh_packet_write_wait(काष्ठा ssh *ssh)
{
	पूर्णांक ret, r, ms_remain = 0;
	काष्ठा timeval start;
	काष्ठा timespec timespec, *timespecp = शून्य;
	काष्ठा session_state *state = ssh->state;
	काष्ठा pollfd pfd;

	अगर ((r = ssh_packet_write_poll(ssh)) != 0)
		वापस r;
	जबतक (ssh_packet_have_तथ्य_to_write(ssh)) {
		pfd.fd = state->connection_out;
		pfd.events = POLLOUT;

		अगर (state->packet_timeout_ms > 0) {
			ms_remain = state->packet_timeout_ms;
			timespecp = &timespec;
		}
		क्रम (;;) {
			अगर (state->packet_timeout_ms > 0) {
				ms_to_timespec(&timespec, ms_remain);
				monotime_tv(&start);
			}
			अगर ((ret = ppoll(&pfd, 1, timespecp, शून्य)) >= 0)
				अवरोध;
			अगर (त्रुटि_सं != EAGAIN && त्रुटि_सं != EINTR &&
			    त्रुटि_सं != EWOULDBLOCK)
				अवरोध;
			अगर (state->packet_timeout_ms <= 0)
				जारी;
			ms_subtract_diff(&start, &ms_remain);
			अगर (ms_remain <= 0) {
				ret = 0;
				अवरोध;
			}
		}
		अगर (ret == 0)
			वापस SSH_ERR_CONN_TIMEOUT;
		अगर ((r = ssh_packet_write_poll(ssh)) != 0)
			वापस r;
	}
	वापस 0;
}

/* Returns true if there is buffered data to write to the connection. */

पूर्णांक
ssh_packet_have_तथ्य_to_write(काष्ठा ssh *ssh)
{
	वापस sshbuf_len(ssh->state->output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

पूर्णांक
ssh_packet_not_very_much_तथ्य_to_write(काष्ठा ssh *ssh)
{
	अगर (ssh->state->interactive_mode)
		वापस sshbuf_len(ssh->state->output) < 16384;
	अन्यथा
		वापस sshbuf_len(ssh->state->output) < 128 * 1024;
}

/*
 * returns true when there are at most a few keystrokes of data to write
 * and the connection is in interactive mode.
 */

पूर्णांक
ssh_packet_interactive_तथ्य_to_write(काष्ठा ssh *ssh)
{
	वापस ssh->state->interactive_mode &&
	    sshbuf_len(ssh->state->output) < 256;
}

अटल व्योम
apply_qos(काष्ठा ssh *ssh)
{
	काष्ठा session_state *state = ssh->state;
	पूर्णांक qos = state->interactive_mode ?
	    state->qos_interactive : state->qos_other;

	अगर (!ssh_packet_connection_is_on_socket(ssh))
		वापस;
	अगर (!state->nodelay_set) {
		set_nodelay(state->connection_in);
		state->nodelay_set = 1;
	}
	set_sock_tos(ssh->state->connection_in, qos);
}

/* Informs that the current session is interactive. */
व्योम
ssh_packet_set_interactive(काष्ठा ssh *ssh, पूर्णांक interactive)
{
	काष्ठा session_state *state = ssh->state;

	state->interactive_mode = interactive;
	apply_qos(ssh);
}

/* Set QoS flags to be used for interactive and non-interactive sessions */
व्योम
ssh_packet_set_qos(काष्ठा ssh *ssh, पूर्णांक qos_interactive, पूर्णांक qos_other)
{
	काष्ठा session_state *state = ssh->state;

	state->qos_interactive = qos_interactive;
	state->qos_other = qos_other;
	apply_qos(ssh);
}

पूर्णांक
ssh_packet_set_maxsize(काष्ठा ssh *ssh, u_int s)
{
	काष्ठा session_state *state = ssh->state;

	अगर (state->set_maxsize_called) {
		logit_f("called twice: old %d new %d",
		    state->max_packet_आकार, s);
		वापस -1;
	}
	अगर (s < 4 * 1024 || s > 1024 * 1024) {
		logit_f("bad size %d", s);
		वापस -1;
	}
	state->set_maxsize_called = 1;
	debug_f("setting to %d", s);
	state->max_packet_आकार = s;
	वापस s;
}

पूर्णांक
ssh_packet_inc_alive_timeouts(काष्ठा ssh *ssh)
{
	वापस ++ssh->state->keep_alive_timeouts;
}

व्योम
ssh_packet_set_alive_timeouts(काष्ठा ssh *ssh, पूर्णांक ka)
{
	ssh->state->keep_alive_timeouts = ka;
}

u_int
ssh_packet_get_maxsize(काष्ठा ssh *ssh)
{
	वापस ssh->state->max_packet_आकार;
}

व्योम
ssh_packet_set_rekey_limits(काष्ठा ssh *ssh, uint64_t bytes, uint32_t seconds)
{
	अगर (bytes == 0 && seconds == 0)
		वापस;

	debug3("rekey after %llu bytes, %u seconds", (अचिन्हित दीर्घ दीर्घ)bytes,
	    (अचिन्हित पूर्णांक)seconds);
	ssh->state->rekey_limit = bytes;
	ssh->state->rekey_interval = seconds;
}

समय_प्रकार
ssh_packet_get_rekey_timeout(काष्ठा ssh *ssh)
{
	समय_प्रकार seconds;

	seconds = ssh->state->rekey_time + ssh->state->rekey_interval -
	    monotime();
	वापस (seconds <= 0 ? 1 : seconds);
}

व्योम
ssh_packet_set_server(काष्ठा ssh *ssh)
{
	ssh->state->server_side = 1;
	ssh->kex->server = 1; /* XXX unify? */
}

व्योम
ssh_packet_set_authenticated(काष्ठा ssh *ssh)
{
	ssh->state->after_authentication = 1;
}

व्योम *
ssh_packet_get_निवेश(काष्ठा ssh *ssh)
{
	वापस (व्योम *)ssh->state->निवेश;
}

व्योम *
ssh_packet_get_output(काष्ठा ssh *ssh)
{
	वापस (व्योम *)ssh->state->output;
}

/* Reset after_authentication and reset compression in post-auth privsep */
अटल पूर्णांक
ssh_packet_set_postauth(काष्ठा ssh *ssh)
{
	पूर्णांक r;

	debug_f("called");
	/* This was set in net child, but is not visible in user child */
	ssh->state->after_authentication = 1;
	ssh->state->rekeying = 0;
	अगर ((r = ssh_packet_enable_delayed_compress(ssh)) != 0)
		वापस r;
	वापस 0;
}

/* Packet state (de-)serialization for privsep */

/* turn kex into a blob for packet state serialization */
अटल पूर्णांक
kex_to_blob(काष्ठा sshbuf *m, काष्ठा kex *kex)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u32(m, kex->we_need)) != 0 ||
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
		वापस r;
	वापस 0;
}

/* turn key exchange results into a blob for packet state serialization */
अटल पूर्णांक
newkeys_to_blob(काष्ठा sshbuf *m, काष्ठा ssh *ssh, पूर्णांक mode)
{
	काष्ठा sshbuf *b;
	काष्ठा sshcipher_ctx *cc;
	काष्ठा sshcomp *comp;
	काष्ठा sshenc *enc;
	काष्ठा sshmac *mac;
	काष्ठा newkeys *newkey;
	पूर्णांक r;

	अगर ((newkey = ssh->state->newkeys[mode]) == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;
	cc = (mode == MODE_OUT) ? ssh->state->send_context :
	    ssh->state->receive_context;
	अगर ((r = cipher_get_keyiv(cc, enc->iv, enc->iv_len)) != 0)
		वापस r;
	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_cstring(b, enc->name)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->enabled)) != 0 ||
	    (r = sshbuf_put_u32(b, enc->block_आकार)) != 0 ||
	    (r = sshbuf_put_string(b, enc->कुंजी, enc->कुंजी_len)) != 0 ||
	    (r = sshbuf_put_string(b, enc->iv, enc->iv_len)) != 0)
		जाओ out;
	अगर (cipher_authlen(enc->cipher) == 0) {
		अगर ((r = sshbuf_put_cstring(b, mac->name)) != 0 ||
		    (r = sshbuf_put_u32(b, mac->enabled)) != 0 ||
		    (r = sshbuf_put_string(b, mac->कुंजी, mac->कुंजी_len)) != 0)
			जाओ out;
	}
	अगर ((r = sshbuf_put_u32(b, comp->type)) != 0 ||
	    (r = sshbuf_put_cstring(b, comp->name)) != 0)
		जाओ out;
	r = sshbuf_put_stringb(m, b);
 out:
	sshbuf_free(b);
	वापस r;
}

/* serialize packet state into a blob */
पूर्णांक
ssh_packet_get_state(काष्ठा ssh *ssh, काष्ठा sshbuf *m)
{
	काष्ठा session_state *state = ssh->state;
	पूर्णांक r;

#घोषणा ENCODE_INT(v) (((v) < 0) ? 0xFFFFFFFF : (u_int)v)
	अगर ((r = kex_to_blob(m, ssh->kex)) != 0 ||
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
	    (r = sshbuf_put_stringb(m, state->निवेश)) != 0 ||
	    (r = sshbuf_put_stringb(m, state->output)) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->interactive_mode))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_interactive))) != 0 ||
	    (r = sshbuf_put_u32(m, ENCODE_INT(state->qos_other))) != 0)
		वापस r;
#अघोषित ENCODE_INT
	वापस 0;
}

/* restore key exchange results from blob for packet state de-serialization */
अटल पूर्णांक
newkeys_from_blob(काष्ठा sshbuf *m, काष्ठा ssh *ssh, पूर्णांक mode)
{
	काष्ठा sshbuf *b = शून्य;
	काष्ठा sshcomp *comp;
	काष्ठा sshenc *enc;
	काष्ठा sshmac *mac;
	काष्ठा newkeys *newkey = शून्य;
	माप_प्रकार keylen, ivlen, maclen;
	पूर्णांक r;

	अगर ((newkey = सुस्मृति(1, माप(*newkey))) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_froms(m, &b)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_PK
	sshbuf_dump(b, मानक_त्रुटि);
#पूर्ण_अगर
	enc = &newkey->enc;
	mac = &newkey->mac;
	comp = &newkey->comp;

	अगर ((r = sshbuf_get_cstring(b, &enc->name, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(b, (u_int *)&enc->enabled)) != 0 ||
	    (r = sshbuf_get_u32(b, &enc->block_आकार)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->कुंजी, &keylen)) != 0 ||
	    (r = sshbuf_get_string(b, &enc->iv, &ivlen)) != 0)
		जाओ out;
	अगर ((enc->cipher = cipher_by_name(enc->name)) == शून्य ||
	    enc->block_आकार != cipher_blocksize(enc->cipher) ||
	    cipher_is_internal(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (keylen != cipher_keylen(enc->cipher) ||
	    ivlen != cipher_ivlen(enc->cipher)) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (cipher_authlen(enc->cipher) == 0) {
		अगर ((r = sshbuf_get_cstring(b, &mac->name, शून्य)) != 0)
			जाओ out;
		अगर ((r = mac_setup(mac, mac->name)) != 0)
			जाओ out;
		अगर ((r = sshbuf_get_u32(b, (u_int *)&mac->enabled)) != 0 ||
		    (r = sshbuf_get_string(b, &mac->कुंजी, &maclen)) != 0)
			जाओ out;
		अगर (maclen != mac->कुंजी_len) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		mac->कुंजी_len = maclen;
	}
	अगर ((r = sshbuf_get_u32(b, &comp->type)) != 0 ||
	    (r = sshbuf_get_cstring(b, &comp->name, शून्य)) != 0)
		जाओ out;
	अगर (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	enc->कुंजी_len = keylen;
	enc->iv_len = ivlen;
	ssh->kex->newkeys[mode] = newkey;
	newkey = शून्य;
	r = 0;
 out:
	मुक्त(newkey);
	sshbuf_free(b);
	वापस r;
}

/* restore kex from blob for packet state de-serialization */
अटल पूर्णांक
kex_from_blob(काष्ठा sshbuf *m, काष्ठा kex **kexp)
{
	काष्ठा kex *kex;
	पूर्णांक r;

	अगर ((kex = kex_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_get_u32(m, &kex->we_need)) != 0 ||
	    (r = sshbuf_get_cstring(m, &kex->hostkey_alg, शून्य)) != 0 ||
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
		जाओ out;
	अगर (kex->we_need > 1024) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	kex->server = 1;
	kex->done = 1;
	r = 0;
 out:
	अगर (r != 0 || kexp == शून्य) {
		kex_free(kex);
		अगर (kexp != शून्य)
			*kexp = शून्य;
	} अन्यथा {
		kex_free(*kexp);
		*kexp = kex;
	}
	वापस r;
}

/*
 * Restore packet state from content of blob 'm' (de-serialization).
 * Note that 'm' will be partially consumed on parsing or any other errors.
 */
पूर्णांक
ssh_packet_set_state(काष्ठा ssh *ssh, काष्ठा sshbuf *m)
{
	काष्ठा session_state *state = ssh->state;
	स्थिर u_char *निवेश, *output;
	माप_प्रकार ilen, olen;
	पूर्णांक r;
	u_int interactive, qos_interactive, qos_other;

	अगर ((r = kex_from_blob(m, &ssh->kex)) != 0 ||
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
		वापस r;
	/*
	 * We set the time here so that in post-auth privsep child we
	 * count from the completion of the authentication.
	 */
	state->rekey_time = monotime();
	/* XXX ssh_set_newkeys overrides p_read.packets? XXX */
	अगर ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0 ||
	    (r = ssh_set_newkeys(ssh, MODE_OUT)) != 0)
		वापस r;

	अगर ((r = ssh_packet_set_postauth(ssh)) != 0)
		वापस r;

	sshbuf_reset(state->निवेश);
	sshbuf_reset(state->output);
	अगर ((r = sshbuf_get_string_direct(m, &निवेश, &ilen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &output, &olen)) != 0 ||
	    (r = sshbuf_put(state->निवेश, निवेश, ilen)) != 0 ||
	    (r = sshbuf_put(state->output, output, olen)) != 0)
		वापस r;

	अगर ((r = sshbuf_get_u32(m, &interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_interactive)) != 0 ||
	    (r = sshbuf_get_u32(m, &qos_other)) != 0)
		वापस r;
#घोषणा DECODE_INT(v) ((v) > पूर्णांक_उच्च ? -1 : (पूर्णांक)(v))
	state->interactive_mode = DECODE_INT(interactive);
	state->qos_interactive = DECODE_INT(qos_interactive);
	state->qos_other = DECODE_INT(qos_other);
#अघोषित DECODE_INT

	अगर (sshbuf_len(m))
		वापस SSH_ERR_INVALID_FORMAT;
	debug3_f("done");
	वापस 0;
}

/* NEW API */

/* put data to the outgoing packet */

पूर्णांक
sshpkt_put(काष्ठा ssh *ssh, स्थिर व्योम *v, माप_प्रकार len)
{
	वापस sshbuf_put(ssh->state->outgoing_packet, v, len);
}

पूर्णांक
sshpkt_putb(काष्ठा ssh *ssh, स्थिर काष्ठा sshbuf *b)
{
	वापस sshbuf_putb(ssh->state->outgoing_packet, b);
}

पूर्णांक
sshpkt_put_u8(काष्ठा ssh *ssh, u_char val)
{
	वापस sshbuf_put_u8(ssh->state->outgoing_packet, val);
}

पूर्णांक
sshpkt_put_u32(काष्ठा ssh *ssh, uint32_t val)
{
	वापस sshbuf_put_u32(ssh->state->outgoing_packet, val);
}

पूर्णांक
sshpkt_put_u64(काष्ठा ssh *ssh, uint64_t val)
{
	वापस sshbuf_put_u64(ssh->state->outgoing_packet, val);
}

पूर्णांक
sshpkt_put_string(काष्ठा ssh *ssh, स्थिर व्योम *v, माप_प्रकार len)
{
	वापस sshbuf_put_string(ssh->state->outgoing_packet, v, len);
}

पूर्णांक
sshpkt_put_cstring(काष्ठा ssh *ssh, स्थिर व्योम *v)
{
	वापस sshbuf_put_cstring(ssh->state->outgoing_packet, v);
}

पूर्णांक
sshpkt_put_stringb(काष्ठा ssh *ssh, स्थिर काष्ठा sshbuf *v)
{
	वापस sshbuf_put_stringb(ssh->state->outgoing_packet, v);
}

#अगर_घोषित WITH_OPENSSL
पूर्णांक
sshpkt_put_ec(काष्ठा ssh *ssh, स्थिर EC_POINT *v, स्थिर EC_GROUP *g)
{
	वापस sshbuf_put_ec(ssh->state->outgoing_packet, v, g);
}

पूर्णांक
sshpkt_put_ec_pkey(काष्ठा ssh *ssh, EVP_PKEY *pkey)
{
	वापस sshbuf_put_ec_pkey(ssh->state->outgoing_packet, pkey);
}

पूर्णांक
sshpkt_put_bignum2(काष्ठा ssh *ssh, स्थिर BIGNUM *v)
{
	वापस sshbuf_put_bignum2(ssh->state->outgoing_packet, v);
}
#पूर्ण_अगर /* WITH_OPENSSL */

/* fetch data from the incoming packet */

पूर्णांक
sshpkt_get(काष्ठा ssh *ssh, व्योम *valp, माप_प्रकार len)
{
	वापस sshbuf_get(ssh->state->incoming_packet, valp, len);
}

पूर्णांक
sshpkt_get_u8(काष्ठा ssh *ssh, u_char *valp)
{
	वापस sshbuf_get_u8(ssh->state->incoming_packet, valp);
}

पूर्णांक
sshpkt_get_u32(काष्ठा ssh *ssh, uint32_t *valp)
{
	वापस sshbuf_get_u32(ssh->state->incoming_packet, valp);
}

पूर्णांक
sshpkt_get_u64(काष्ठा ssh *ssh, uint64_t *valp)
{
	वापस sshbuf_get_u64(ssh->state->incoming_packet, valp);
}

पूर्णांक
sshpkt_get_string(काष्ठा ssh *ssh, u_char **valp, माप_प्रकार *lenp)
{
	वापस sshbuf_get_string(ssh->state->incoming_packet, valp, lenp);
}

पूर्णांक
sshpkt_get_string_direct(काष्ठा ssh *ssh, स्थिर u_char **valp, माप_प्रकार *lenp)
{
	वापस sshbuf_get_string_direct(ssh->state->incoming_packet, valp, lenp);
}

पूर्णांक
sshpkt_peek_string_direct(काष्ठा ssh *ssh, स्थिर u_char **valp, माप_प्रकार *lenp)
{
	वापस sshbuf_peek_string_direct(ssh->state->incoming_packet, valp, lenp);
}

पूर्णांक
sshpkt_get_cstring(काष्ठा ssh *ssh, अक्षर **valp, माप_प्रकार *lenp)
{
	वापस sshbuf_get_cstring(ssh->state->incoming_packet, valp, lenp);
}

पूर्णांक
sshpkt_getb_froms(काष्ठा ssh *ssh, काष्ठा sshbuf **valp)
{
	वापस sshbuf_froms(ssh->state->incoming_packet, valp);
}

#अगर_घोषित WITH_OPENSSL
पूर्णांक
sshpkt_get_ec(काष्ठा ssh *ssh, EC_POINT *v, स्थिर EC_GROUP *g)
{
	वापस sshbuf_get_ec(ssh->state->incoming_packet, v, g);
}

पूर्णांक
sshpkt_get_bignum2(काष्ठा ssh *ssh, BIGNUM **valp)
{
	वापस sshbuf_get_bignum2(ssh->state->incoming_packet, valp);
}
#पूर्ण_अगर /* WITH_OPENSSL */

पूर्णांक
sshpkt_get_end(काष्ठा ssh *ssh)
{
	अगर (sshbuf_len(ssh->state->incoming_packet) > 0)
		वापस SSH_ERR_UNEXPECTED_TRAILING_तथ्य;
	वापस 0;
}

स्थिर u_char *
sshpkt_ptr(काष्ठा ssh *ssh, माप_प्रकार *lenp)
{
	अगर (lenp != शून्य)
		*lenp = sshbuf_len(ssh->state->incoming_packet);
	वापस sshbuf_ptr(ssh->state->incoming_packet);
}

/* start a new packet */

पूर्णांक
sshpkt_start(काष्ठा ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	स_रखो(buf, 0, माप(buf));
	buf[माप(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	वापस sshbuf_put(ssh->state->outgoing_packet, buf, माप(buf));
}

अटल पूर्णांक
ssh_packet_send_mux(काष्ठा ssh *ssh)
{
	काष्ठा session_state *state = ssh->state;
	u_char type, *cp;
	माप_प्रकार len;
	पूर्णांक r;

	अगर (ssh->kex)
		वापस SSH_ERR_INTERNAL_ERROR;
	len = sshbuf_len(state->outgoing_packet);
	अगर (len < 6)
		वापस SSH_ERR_INTERNAL_ERROR;
	cp = sshbuf_mutable_ptr(state->outgoing_packet);
	type = cp[5];
	अगर (ssh_packet_log_type(type))
		debug3_f("type %u", type);
	/* drop everything, but the connection protocol */
	अगर (type >= SSH2_संदेश_CONNECTION_MIN &&
	    type <= SSH2_संदेश_CONNECTION_MAX) {
		POKE_U32(cp, len - 4);
		अगर ((r = sshbuf_putb(state->output,
		    state->outgoing_packet)) != 0)
			वापस r;
		/* sshbuf_dump(state->output, stderr); */
	}
	sshbuf_reset(state->outgoing_packet);
	वापस 0;
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
पूर्णांक
sshpkt_संदेश_ignore(काष्ठा ssh *ssh, u_int nbytes)
{
	uint32_t rnd = 0;
	पूर्णांक r;
	u_int i;

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_IGNORE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, nbytes)) != 0)
		वापस r;
	क्रम (i = 0; i < nbytes; i++) {
		अगर (i % 4 == 0)
			rnd = arc4random();
		अगर ((r = sshpkt_put_u8(ssh, (u_char)rnd & 0xff)) != 0)
			वापस r;
		rnd >>= 8;
	}
	वापस 0;
}

/* send it */

पूर्णांक
sshpkt_send(काष्ठा ssh *ssh)
{
	अगर (ssh->state && ssh->state->mux)
		वापस ssh_packet_send_mux(ssh);
	वापस ssh_packet_send2(ssh);
}

पूर्णांक
sshpkt_disconnect(काष्ठा ssh *ssh, स्थिर अक्षर *fmt,...)
{
	अक्षर buf[1024];
	बहु_सूची args;
	पूर्णांक r;

	बहु_शुरू(args, fmt);
	vsnprintf(buf, माप(buf), fmt, args);
	बहु_पूर्ण(args);

	debug2_f("sending SSH2_MSG_DISCONNECT: %s", buf);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_PROTOCOL_ERROR)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, buf)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		वापस r;
	वापस 0;
}

/* roundup current message to pad bytes */
पूर्णांक
sshpkt_add_padding(काष्ठा ssh *ssh, u_char pad)
{
	ssh->state->extra_pad = pad;
	वापस 0;
}

अटल अक्षर *
format_traffic_stats(काष्ठा packet_state *ps)
{
	अक्षर *stats = शून्य, bytes[FMT_SCALED_STRSIZE];

	अगर (ps->bytes > LLONG_MAX || fmt_scaled(ps->bytes, bytes) != 0)
		strlcpy(bytes, "OVERFLOW", माप(bytes));

	xasprintf(&stats, "%lu pkts %llu blks %sB",
	    (अचिन्हित दीर्घ)ps->packets, (अचिन्हित दीर्घ दीर्घ)ps->blocks, bytes);
	वापस stats;
}

अटल अक्षर *
dedupe_alg_names(स्थिर अक्षर *in, स्थिर अक्षर *out)
{
	अक्षर *names = शून्य;

	अगर (in == शून्य)
		in = "<implicit>";
	अगर (out == शून्य)
		out = "<implicit>";

	अगर (म_भेद(in, out) == 0) {
		names = xstrdup(in);
	} अन्यथा {
		xasprintf(&names, "%s in, %s out", in, out);
	}
	वापस names;
}

अटल अक्षर *
comp_status_message(काष्ठा ssh *ssh)
{
#अगर_घोषित WITH_ZLIB
	अक्षर *ret = शून्य;
	काष्ठा session_state *state = ssh->state;
	अचिन्हित दीर्घ दीर्घ iraw = 0, icmp = 0, oraw = 0, ocmp = 0;
	अक्षर iraw_f[FMT_SCALED_STRSIZE] = "", oraw_f[FMT_SCALED_STRSIZE] = "";
	अक्षर icmp_f[FMT_SCALED_STRSIZE] = "", ocmp_f[FMT_SCALED_STRSIZE] = "";

	अगर (state->compression_बफर) {
		अगर (state->compression_in_started) {
			iraw = state->compression_in_stream.योग_out;
			icmp = state->compression_in_stream.योग_in;
			अगर (fmt_scaled(iraw, iraw_f) != 0)
				strlcpy(iraw_f, "OVERFLOW", माप(iraw_f));
			अगर (fmt_scaled(icmp, icmp_f) != 0)
				strlcpy(icmp_f, "OVERFLOW", माप(icmp_f));
		}
		अगर (state->compression_out_started) {
			oraw = state->compression_out_stream.योग_in;
			ocmp = state->compression_out_stream.योग_out;
			अगर (fmt_scaled(oraw, oraw_f) != 0)
				strlcpy(oraw_f, "OVERFLOW", माप(oraw_f));
			अगर (fmt_scaled(ocmp, ocmp_f) != 0)
				strlcpy(ocmp_f, "OVERFLOW", माप(ocmp_f));
		}
		xasprintf(&ret,
		    "    compressed %s/%s (*%.3f) in,"
		    " %s/%s (*%.3f) out\r\n",
		    icmp_f, iraw_f, iraw == 0 ? 0.0 : (द्विगुन)icmp / iraw,
		    ocmp_f, oraw_f, oraw == 0 ? 0.0 : (द्विगुन)ocmp / oraw);
		वापस ret;
	}
#पूर्ण_अगर	/* WITH_ZLIB */
	वापस xstrdup("");
}

अक्षर *
connection_info_message(काष्ठा ssh *ssh)
{
	अक्षर *ret = शून्य, *cipher = शून्य, *mac = शून्य, *comp = शून्य;
	अक्षर *rekey_volume = शून्य, *rekey_time = शून्य, *comp_info = शून्य;
	अक्षर thishost[NI_MAXHOST] = "unknown", *tcp_info = शून्य;
	काष्ठा kex *kex;
	काष्ठा session_state *state;
	काष्ठा newkeys *nk_in, *nk_out;
	अक्षर *stats_in = शून्य, *stats_out = शून्य;
	uint64_t epoch = (uint64_t)समय(शून्य) - monotime();

	अगर (ssh == शून्य)
		वापस शून्य;
	state = ssh->state;
	kex = ssh->kex;

	(व्योम)gethostname(thishost, माप(thishost));

	अगर (ssh_local_port(ssh) != 65535 ||
	     म_भेद(ssh_local_ipaddr(ssh), "UNKNOWN") != 0) {
		xasprintf(&tcp_info, "  tcp %s:%d -> %s:%d\r\n",
		    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	} अन्यथा {
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
	अगर (state->rekey_limit == 0) {
		xasprintf(&rekey_volume, "limit none");
	} अन्यथा {
		अक्षर *volumes = शून्य, in[32], out[32];

		snprintf(in, माप(in), "%llu",
		   (अचिन्हित दीर्घ दीर्घ)state->max_blocks_in);
		snprintf(out, माप(out), "%llu",
		   (अचिन्हित दीर्घ दीर्घ)state->max_blocks_out);
		volumes = dedupe_alg_names(in, out);
		xasprintf(&rekey_volume, "limit blocks %s", volumes);
		मुक्त(volumes);
	}

	/* Time based rekeying. */
	अगर (state->rekey_interval == 0) {
		rekey_time = xstrdup("interval none");
	} अन्यथा {
		अक्षर rekey_अग्र[64];

		format_absolute_time(epoch + state->rekey_time +
		    state->rekey_interval, rekey_अग्र, माप(rekey_अग्र));
		xasprintf(&rekey_time, "interval %s, next %s",
		    fmt_timeframe(state->rekey_interval), rekey_अग्र);
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
	    thishost, (दीर्घ दीर्घ)getpid(),
	    SSH_RELEASE, ssh->remote_version,
	    tcp_info,
	    fmt_timeframe(monotime() - state->start_time),
	    kex->name, kex->hostkey_alg,
	    cipher, mac, comp,
	    rekey_volume, rekey_time,
	    stats_in, stats_out,
	    comp_info
	);
	मुक्त(tcp_info);
	मुक्त(cipher);
	मुक्त(mac);
	मुक्त(comp);
	मुक्त(stats_in);
	मुक्त(stats_out);
	मुक्त(rekey_volume);
	मुक्त(rekey_time);
	मुक्त(comp_info);
	वापस ret;
}

