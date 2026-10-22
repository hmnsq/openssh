/* $OpenBSD: authfd.c,v 1.144 2026/06/29 08:57:06 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for connecting the local authentication agent.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 implementation,
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
#অন্তর্ভাব <sys/un.h>
#অন্তর্ভাব <sys/socket.h>

#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <errno.h>

#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
স্থির পূর্ণসংখ্যা
decode_reply(u_char type)
{
	যদি (agent_failed(type))
		ফেরত SSH_ERR_AGENT_FAILURE;
	অন্যথা যদি (type == SSH_AGENT_SUCCESS)
		ফেরত 0;
	অন্যথা
		ফেরত SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
পূর্ণসংখ্যা
ssh_get_authentication_socket_path(ধ্রুবক অক্ষর *authsocket, পূর্ণসংখ্যা *fdp)
{
	পূর্ণসংখ্যা sock, oerrno;
	কাঠামো sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, আকার(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, আকার(sunaddr.sun_path));

	যদি ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		ফেরত SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	যদি (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (কাঠামো sockaddr *)&sunaddr, আকার(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}
	যদি (fdp != ফাঁকা)
		*fdp = sock;
	অন্যথা
		close(sock);
	ফেরত 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
পূর্ণসংখ্যা
ssh_get_authentication_socket(পূর্ণসংখ্যা *fdp)
{
	ধ্রুবক অক্ষর *authsocket;

	যদি (fdp != ফাঁকা)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	যদি (authsocket == ফাঁকা || *authsocket == '\0')
		ফেরত SSH_ERR_AGENT_NOT_PRESENT;

	ফেরত ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
স্থির পূর্ণসংখ্যা
ssh_request_reply(পূর্ণসংখ্যা sock, কাঠামো sshbuf *request, কাঠামো sshbuf *reply)
{
	পূর্ণসংখ্যা r;
	আকার_t l, len;
	অক্ষর buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	যদি (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		ফেরত SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	যদি (atomicio(পঠ, sock, buf, 4) != 4)
	    ফেরত SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	যদি (len > MAX_AGENT_REPLY_LEN)
		ফেরত SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	যখন (len > 0) {
		l = len;
		যদি (l > আকার(buf))
			l = আকার(buf);
		যদি (atomicio(পঠ, sock, buf, l) != l)
			ফেরত SSH_ERR_AGENT_COMMUNICATION;
		যদি ((r = sshbuf_put(reply, buf, l)) != 0)
			ফেরত r;
		len -= l;
	}
	ফেরত 0;
}

/* Communicate with agent: sent request, read and decode status reply */
স্থির পূর্ণসংখ্যা
ssh_request_reply_decode(পূর্ণসংখ্যা sock, কাঠামো sshbuf *request)
{
	কাঠামো sshbuf *reply;
	পূর্ণসংখ্যা r;
	u_char type;

	যদি ((reply = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	ফেরত r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
শূন্য
ssh_close_authentication_socket(পূর্ণসংখ্যা sock)
{
	যদি (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != ফাঁকা)
		close(sock);
}

/* Lock/unlock agent */
পূর্ণসংখ্যা
ssh_lock_agent(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা lock, ধ্রুবক অক্ষর *password)
{
	পূর্ণসংখ্যা r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	কাঠামো sshbuf *বার্তা;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বার্তা, type)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, বার্তা)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বার্তা);
	ফেরত r;
}


স্থির পূর্ণসংখ্যা
deserialise_identity2(কাঠামো sshbuf *ids, কাঠামো sshkey **keyp, অক্ষর **commentp)
{
	পূর্ণসংখ্যা r;
	অক্ষর *comment = ফাঁকা;
	ধ্রুবক u_char *blob;
	আকার_t blen;

	যদি ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, ফাঁকা)) != 0)
		যাও out;
	যদি ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		যাও out;
	যদি (commentp != ফাঁকা) {
		*commentp = comment;
		comment = ফাঁকা;
	}
	r = 0;
 out:
	মুক্ত(comment);
	ফেরত r;
}

/*
 * Fetch list of identities held by the agent.
 */
পূর্ণসংখ্যা
ssh_fetch_identitylist(পূর্ণসংখ্যা sock, কাঠামো ssh_identitylist **idlp)
{
	u_char type;
	uint32_t অঙ্ক, i;
	কাঠামো sshbuf *বার্তা;
	কাঠামো ssh_identitylist *idl = ফাঁকা;
	পূর্ণসংখ্যা r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		যাও out;

	যদি ((r = ssh_request_reply(sock, বার্তা, বার্তা)) != 0)
		যাও out;

	/* Get message type, and verify that we got a proper answer. */
	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0)
		যাও out;
	যদি (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		যাও out;
	} অন্যথা যদি (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	যদি ((r = sshbuf_get_u32(বার্তা, &অঙ্ক)) != 0)
		যাও out;
	যদি (অঙ্ক > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (অঙ্ক == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		যাও out;
	}

	/* Deserialise the response into a list of keys/comments */
	যদি ((idl = calloc(1, আকার(*idl))) == ফাঁকা ||
	    (idl->চাবিগুলি = calloc(অঙ্ক, আকার(*idl->চাবিগুলি))) == ফাঁকা ||
	    (idl->comments = calloc(অঙ্ক, আকার(*idl->comments))) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	জন্য (i = 0; i < অঙ্ক;) {
		যদি ((r = deserialise_identity2(বার্তা, &(idl->চাবিগুলি[i]),
		    &(idl->comments[i]))) != 0) {
			যদি (r == SSH_ERR_চাবি_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				অঙ্ক--;
				চালু;
			} অন্যথা
				যাও out;
		}
		i++;
	}
	idl->nkeys = অঙ্ক;
	*idlp = idl;
	idl = ফাঁকা;
	r = 0;
 out:
	sshbuf_free(বার্তা);
	যদি (idl != ফাঁকা)
		ssh_free_identitylist(idl);
	ফেরত r;
}

শূন্য
ssh_free_identitylist(কাঠামো ssh_identitylist *idl)
{
	আকার_t i;

	যদি (idl == ফাঁকা)
		ফেরত;
	জন্য (i = 0; i < idl->nkeys; i++) {
		যদি (idl->চাবিগুলি != ফাঁকা)
			sshkey_free(idl->চাবিগুলি[i]);
		যদি (idl->comments != ফাঁকা)
			মুক্ত(idl->comments[i]);
	}
	মুক্ত(idl->চাবিগুলি);
	মুক্ত(idl->comments);
	মুক্ত(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
পূর্ণসংখ্যা
ssh_agent_has_চাবি(পূর্ণসংখ্যা sock, ধ্রুবক কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা r, ret = SSH_ERR_চাবি_NOT_FOUND;
	আকার_t i;
	কাঠামো ssh_identitylist *idlist = ফাঁকা;

	যদি ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		ফেরত r;
	}

	জন্য (i = 0; i < idlist->nkeys; i++) {
		যদি (sshkey_equal_public(idlist->চাবিগুলি[i], চাবি)) {
			ret = 0;
			বিরতি;
		}
	}

	ssh_free_identitylist(idlist);
	ফেরত ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
স্থির u_int
agent_encode_alg(ধ্রুবক কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *alg)
{
	যদি (alg != ফাঁকা && sshkey_type_plain(চাবি->type) == চাবি_RSA) {
		যদি (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			ফেরত SSH_AGENT_RSA_SHA2_256;
		যদি (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			ফেরত SSH_AGENT_RSA_SHA2_512;
	}
	ফেরত 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
পূর্ণসংখ্যা
ssh_agent_sign(পূর্ণসংখ্যা sock, ধ্রুবক কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen, ধ্রুবক অক্ষর *alg, u_int compat)
{
	কাঠামো sshbuf *বার্তা;
	u_char *sig = ফাঁকা, type = 0;
	আকার_t len = 0;
	u_int flags = 0;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	*sigp = ফাঁকা;
	*lenp = 0;

	যদি (datalen > SSH_চাবি_MAX_SIGN_তথ্য_আকার)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(চাবি, alg);
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(চাবি, বার্তা)) != 0 ||
	    (r = sshbuf_put_string(বার্তা, তথ্য, datalen)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, flags)) != 0)
		যাও out;
	যদি ((r = ssh_request_reply(sock, বার্তা, বার্তা)) != 0)
		যাও out;
	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0)
		যাও out;
	যদি (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		যাও out;
	} অন্যথা যদি (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((r = sshbuf_get_string(বার্তা, &sig, &len)) != 0)
		যাও out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	যদি (!sshkey_is_sk(চাবি) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		যাও out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = ফাঁকা;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(বার্তা);
	ফেরত r;
}

/* Encode key for a message to the agent. */

স্থির পূর্ণসংখ্যা
encode_dest_constraint_hop(কাঠামো sshbuf *m,
    ধ্রুবক কাঠামো dest_constraint_hop *dch)
{
	কাঠামো sshbuf *b;
	u_int i;
	পূর্ণসংখ্যা r;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, ফাঁকা, 0)) != 0) /* reserved */
		যাও out;
	জন্য (i = 0; i < dch->nkeys; i++) {
		যদি ((r = sshkey_puts(dch->চাবিগুলি[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->চাবি_is_ca[i] != 0)) != 0)
			যাও out;
	}
	যদি ((r = sshbuf_put_stringb(m, b)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
encode_dest_constraint(কাঠামো sshbuf *m, ধ্রুবক কাঠামো dest_constraint *dc)
{
	কাঠামো sshbuf *b;
	পূর্ণসংখ্যা r;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, ফাঁকা, 0)) != 0) /* reserved */
		যাও out;
	যদি ((r = sshbuf_put_stringb(m, b)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
encode_constraints(কাঠামো sshbuf *m, u_int life, u_int confirm,
    ধ্রুবক অক্ষর *provider,
    কাঠামো dest_constraint **dest_constraints, আকার_t ndest_constraints,
    পূর্ণসংখ্যা cert_only, কাঠামো sshkey **certs, আকার_t ncerts)
{
	পূর্ণসংখ্যা r;
	কাঠামো sshbuf *b = ফাঁকা;
	আকার_t i;

	যদি (life != 0) {
		যদি ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			যাও out;
	}
	যদি (confirm != 0) {
		যদি ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			যাও out;
	}
	যদি (provider != ফাঁকা) {
		যদি ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			যাও out;
	}
	যদি (dest_constraints != ফাঁকা && ndest_constraints > 0) {
		যদি ((b = sshbuf_new()) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		জন্য (i = 0; i < ndest_constraints; i++) {
			যদি ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				যাও out;
		}
		যদি ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			যাও out;
		sshbuf_free(b);
		b = ফাঁকা;
	}
	যদি (ncerts != 0) {
		যদি ((b = sshbuf_new()) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		জন্য (i = 0; i < ncerts; i++) {
			যদি ((r = sshkey_puts(certs[i], b)) != 0)
				যাও out;
		}
		যদি ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			যাও out;
		sshbuf_free(b);
		b = ফাঁকা;
	}
	r = 0;
 out:
	sshbuf_free(b);
	ফেরত r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
পূর্ণসংখ্যা
ssh_add_identity_constrained(পূর্ণসংখ্যা sock, কাঠামো sshkey *চাবি,
    ধ্রুবক অক্ষর *comment, u_int life, u_int confirm,
    ধ্রুবক অক্ষর *provider, কাঠামো dest_constraint **dest_constraints,
    আকার_t ndest_constraints)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	নির্বাচন (চাবি->type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র চাবি_RSA:
	ক্ষেত্র চাবি_RSA_CERT:
	ক্ষেত্র চাবি_ECDSA:
	ক্ষেত্র চাবি_ECDSA_CERT:
	ক্ষেত্র চাবি_ECDSA_SK:
	ক্ষেত্র চাবি_ECDSA_SK_CERT:
#endif
	ক্ষেত্র চাবি_ED25519:
	ক্ষেত্র চাবি_ED25519_CERT:
	ক্ষেত্র চাবি_MLDSA44_ED25519:
	ক্ষেত্র চাবি_MLDSA44_ED25519_CERT:
	ক্ষেত্র চাবি_ED25519_SK:
	ক্ষেত্র চাবি_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		যদি ((r = sshbuf_put_u8(বার্তা, type)) != 0 ||
		    (r = sshkey_private_serialize(চাবি, বার্তা)) != 0 ||
		    (r = sshbuf_put_cstring(বার্তা, comment)) != 0)
			যাও out;
		বিরতি;
	পূর্বনির্ধারিত:
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি (constrained &&
	    (r = encode_constraints(বার্তা, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, ফাঁকা, 0)) != 0)
		যাও out;
	যদি ((r = ssh_request_reply_decode(sock, বার্তা)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বার্তা);
	ফেরত r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
পূর্ণসংখ্যা
ssh_remove_identity(পূর্ণসংখ্যা sock, ধ্রুবক কাঠামো sshkey *চাবি)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;
	u_char *blob = ফাঁকা;
	আকার_t blen;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	যদি (চাবি->type != চাবি_UNSPEC) {
		যদি ((r = sshkey_to_blob(চাবি, &blob, &blen)) != 0)
			যাও out;
		যদি ((r = sshbuf_put_u8(বার্তা,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(বার্তা, blob, blen)) != 0)
			যাও out;
	} অন্যথা {
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি ((r = ssh_request_reply_decode(sock, বার্তা)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	যদি (blob != ফাঁকা)
		freezero(blob, blen);
	sshbuf_free(বার্তা);
	ফেরত r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
পূর্ণসংখ্যা
ssh_update_card(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা add, ধ্রুবক অক্ষর *reader_id, ধ্রুবক অক্ষর *pin,
    u_int life, u_int confirm,
    কাঠামো dest_constraint **dest_constraints, আকার_t ndest_constraints,
    পূর্ণসংখ্যা cert_only, কাঠামো sshkey **certs, আকার_t ncerts)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	যদি (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_চাবি_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_চাবি;
	} অন্যথা
		type = SSH_AGENTC_REMOVE_SMARTCARD_চাবি;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বার্তা, type)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, pin)) != 0)
		যাও out;
	যদি (constrained &&
	    (r = encode_constraints(বার্তা, life, confirm, ফাঁকা,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		যাও out;
	যদি ((r = ssh_request_reply_decode(sock, বার্তা)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বার্তা);
	ফেরত r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
পূর্ণসংখ্যা
ssh_remove_all_identities(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা version)
{
	কাঠামো sshbuf *বার্তা;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	পূর্ণসংখ্যা r;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বার্তা, type)) != 0)
		যাও out;
	যদি ((r = ssh_request_reply_decode(sock, বার্তা)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বার্তা);
	ফেরত r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
পূর্ণসংখ্যা
ssh_agent_bind_hostkey(পূর্ণসংখ্যা sock, ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক কাঠামো sshbuf *session_id, ধ্রুবক কাঠামো sshbuf *signature,
    পূর্ণসংখ্যা forwarding)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;

	যদি (চাবি == ফাঁকা || session_id == ফাঁকা || signature == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(চাবি, বার্তা)) != 0 ||
	    (r = sshbuf_put_stringb(বার্তা, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(বার্তা, signature)) != 0 ||
	    (r = sshbuf_put_u8(বার্তা, forwarding ? 1 : 0)) != 0)
		যাও out;
	যদি ((r = ssh_request_reply_decode(sock, বার্তা)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বার্তা);
	ফেরত r;
}

/* Queries supported extension request types */
পূর্ণসংখ্যা
ssh_agent_query_extensions(পূর্ণসংখ্যা sock, অক্ষর ***exts)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;
	u_char type;
	অক্ষর *cp = ফাঁকা, **ret = ফাঁকা;
	আকার_t i = 0;

	*exts = ফাঁকা;
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "query")) != 0)
		যাও out;
	যদি ((r = ssh_request_reply(sock, বার্তা, বার্তা)) != 0)
		যাও out;
	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0)
		যাও out;
	যদি (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		যাও out;
	}
	/* Reply should start with "query" */
	যদি (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(বার্তা, &cp, ফাঁকা)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	ret = xcalloc(1, আকার(*ret));
	যখন (sshbuf_len(বার্তা)) {
		ret = xrecallocarray(ret, i + 1, i + 2, আকার(*ret));
		যদি ((r = sshbuf_get_cstring(বার্তা, ret + i, ফাঁকা)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = ফাঁকা; /* transferred */
 out:
	মুক্ত(cp);
	stringlist_free(ret);
	sshbuf_free(বার্তা);
	ফেরত r;
}
