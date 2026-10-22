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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/un.h>
#অন্তর্ভাৱ <sys/socket.h>

#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <errno.h>

#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "authfd.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "atomicio.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
স্থির পূর্ণাঙ্ক
decode_reply(u_char type)
{
	যদি (agent_failed(type))
		ঘূৰাই SSH_ERR_AGENT_FAILURE;
	অন্যথা যদি (type == SSH_AGENT_SUCCESS)
		ঘূৰাই 0;
	অন্যথা
		ঘূৰাই SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
পূর্ণাঙ্ক
ssh_get_authentication_socket_path(ধ্রুৱ ৱর্ণ *authsocket, পূর্ণাঙ্ক *fdp)
{
	পূর্ণাঙ্ক sock, oerrno;
	সংরচনা sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, পরিমাণ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, পরিমাণ(sunaddr.sun_path));

	যদি ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		ঘূৰাই SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	যদি (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (সংরচনা sockaddr *)&sunaddr, পরিমাণ(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		ঘূৰাই SSH_ERR_SYSTEM_ERROR;
	}
	যদি (fdp != রিক্ত)
		*fdp = sock;
	অন্যথা
		close(sock);
	ঘূৰাই 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
পূর্ণাঙ্ক
ssh_get_authentication_socket(পূর্ণাঙ্ক *fdp)
{
	ধ্রুৱ ৱর্ণ *authsocket;

	যদি (fdp != রিক্ত)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	যদি (authsocket == রিক্ত || *authsocket == '\0')
		ঘূৰাই SSH_ERR_AGENT_NOT_PRESENT;

	ঘূৰাই ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
স্থির পূর্ণাঙ্ক
ssh_request_reply(পূর্ণাঙ্ক sock, সংরচনা sshbuf *request, সংরচনা sshbuf *reply)
{
	পূর্ণাঙ্ক r;
	size_t l, len;
	ৱর্ণ buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	যদি (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		ঘূৰাই SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	যদি (atomicio(পঠ, sock, buf, 4) != 4)
	    ঘূৰাই SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	যদি (len > MAX_AGENT_REPLY_LEN)
		ঘূৰাই SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	যেতিয়ালৈ (len > 0) {
		l = len;
		যদি (l > পরিমাণ(buf))
			l = পরিমাণ(buf);
		যদি (atomicio(পঠ, sock, buf, l) != l)
			ঘূৰাই SSH_ERR_AGENT_COMMUNICATION;
		যদি ((r = sshbuf_put(reply, buf, l)) != 0)
			ঘূৰাই r;
		len -= l;
	}
	ঘূৰাই 0;
}

/* Communicate with agent: sent request, read and decode status reply */
স্থির পূর্ণাঙ্ক
ssh_request_reply_decode(পূর্ণাঙ্ক sock, সংরচনা sshbuf *request)
{
	সংরচনা sshbuf *reply;
	পূর্ণাঙ্ক r;
	u_char type;

	যদি ((reply = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	ঘূৰাই r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
শূন্য
ssh_close_authentication_socket(পূর্ণাঙ্ক sock)
{
	যদি (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != রিক্ত)
		close(sock);
}

/* Lock/unlock agent */
পূর্ণাঙ্ক
ssh_lock_agent(পূর্ণাঙ্ক sock, পূর্ণাঙ্ক lock, ধ্রুৱ ৱর্ণ *password)
{
	পূর্ণাঙ্ক r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	সংরচনা sshbuf *বাৰ্তা;

	যদি ((বাৰ্তা = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বাৰ্তা, type)) != 0 ||
	    (r = sshbuf_put_cstring(বাৰ্তা, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, বাৰ্তা)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বাৰ্তা);
	ঘূৰাই r;
}


স্থির পূর্ণাঙ্ক
deserialise_identity2(সংরচনা sshbuf *ids, সংরচনা sshkey **keyp, ৱর্ণ **commentp)
{
	পূর্ণাঙ্ক r;
	ৱর্ণ *comment = রিক্ত;
	ধ্রুৱ u_char *blob;
	size_t blen;

	যদি ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, রিক্ত)) != 0)
		গচ্ছ out;
	যদি ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		গচ্ছ out;
	যদি (commentp != রিক্ত) {
		*commentp = comment;
		comment = রিক্ত;
	}
	r = 0;
 out:
	মুক্ত(comment);
	ঘূৰাই r;
}

/*
 * Fetch list of identities held by the agent.
 */
পূর্ণাঙ্ক
ssh_fetch_identitylist(পূর্ণাঙ্ক sock, সংরচনা ssh_identitylist **idlp)
{
	u_char type;
	uint32_t অঙ্ক, i;
	সংরচনা sshbuf *বাৰ্তা;
	সংরচনা ssh_identitylist *idl = রিক্ত;
	পূর্ণাঙ্ক r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	যদি ((বাৰ্তা = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বাৰ্তা, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		গচ্ছ out;

	যদি ((r = ssh_request_reply(sock, বাৰ্তা, বাৰ্তা)) != 0)
		গচ্ছ out;

	/* Get message type, and verify that we got a proper answer. */
	যদি ((r = sshbuf_get_u8(বাৰ্তা, &type)) != 0)
		গচ্ছ out;
	যদি (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		গচ্ছ out;
	} অন্যথা যদি (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	যদি ((r = sshbuf_get_u32(বাৰ্তা, &অঙ্ক)) != 0)
		গচ্ছ out;
	যদি (অঙ্ক > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (অঙ্ক == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		গচ্ছ out;
	}

	/* Deserialise the response into a list of keys/comments */
	যদি ((idl = calloc(1, পরিমাণ(*idl))) == রিক্ত ||
	    (idl->চাবিগুলি = calloc(অঙ্ক, পরিমাণ(*idl->চাবিগুলি))) == রিক্ত ||
	    (idl->comments = calloc(অঙ্ক, পরিমাণ(*idl->comments))) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	বাবে (i = 0; i < অঙ্ক;) {
		যদি ((r = deserialise_identity2(বাৰ্তা, &(idl->চাবিগুলি[i]),
		    &(idl->comments[i]))) != 0) {
			যদি (r == SSH_ERR_চাবি_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				অঙ্ক--;
				অনুৱর্ত;
			} অন্যথা
				গচ্ছ out;
		}
		i++;
	}
	idl->nkeys = অঙ্ক;
	*idlp = idl;
	idl = রিক্ত;
	r = 0;
 out:
	sshbuf_free(বাৰ্তা);
	যদি (idl != রিক্ত)
		ssh_free_identitylist(idl);
	ঘূৰাই r;
}

শূন্য
ssh_free_identitylist(সংরচনা ssh_identitylist *idl)
{
	size_t i;

	যদি (idl == রিক্ত)
		ঘূৰাই;
	বাবে (i = 0; i < idl->nkeys; i++) {
		যদি (idl->চাবিগুলি != রিক্ত)
			sshkey_free(idl->চাবিগুলি[i]);
		যদি (idl->comments != রিক্ত)
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
পূর্ণাঙ্ক
ssh_agent_has_চাবি(পূর্ণাঙ্ক sock, ধ্রুৱ সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r, ret = SSH_ERR_চাবি_NOT_FOUND;
	size_t i;
	সংরচনা ssh_identitylist *idlist = রিক্ত;

	যদি ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		ঘূৰাই r;
	}

	বাবে (i = 0; i < idlist->nkeys; i++) {
		যদি (sshkey_equal_public(idlist->চাবিগুলি[i], চাবি)) {
			ret = 0;
			ভঙ্গ;
		}
	}

	ssh_free_identitylist(idlist);
	ঘূৰাই ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
স্থির u_int
agent_encode_alg(ধ্রুৱ সংরচনা sshkey *চাবি, ধ্রুৱ ৱর্ণ *alg)
{
	যদি (alg != রিক্ত && sshkey_type_plain(চাবি->type) == চাবি_RSA) {
		যদি (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			ঘূৰাই SSH_AGENT_RSA_SHA2_256;
		যদি (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			ঘূৰাই SSH_AGENT_RSA_SHA2_512;
	}
	ঘূৰাই 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
পূর্ণাঙ্ক
ssh_agent_sign(পূর্ণাঙ্ক sock, ধ্রুৱ সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুৱ u_char *data, size_t datalen, ধ্রুৱ ৱর্ণ *alg, u_int compat)
{
	সংরচনা sshbuf *বাৰ্তা;
	u_char *sig = রিক্ত, type = 0;
	size_t len = 0;
	u_int flags = 0;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	*sigp = রিক্ত;
	*lenp = 0;

	যদি (datalen > SSH_চাবি_MAX_SIGN_DATA_SIZE)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি ((বাৰ্তা = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(চাবি, alg);
	যদি ((r = sshbuf_put_u8(বাৰ্তা, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(চাবি, বাৰ্তা)) != 0 ||
	    (r = sshbuf_put_string(বাৰ্তা, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(বাৰ্তা, flags)) != 0)
		গচ্ছ out;
	যদি ((r = ssh_request_reply(sock, বাৰ্তা, বাৰ্তা)) != 0)
		গচ্ছ out;
	যদি ((r = sshbuf_get_u8(বাৰ্তা, &type)) != 0)
		গচ্ছ out;
	যদি (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		গচ্ছ out;
	} অন্যথা যদি (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_get_string(বাৰ্তা, &sig, &len)) != 0)
		গচ্ছ out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	যদি (!sshkey_is_sk(চাবি) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		গচ্ছ out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = রিক্ত;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(বাৰ্তা);
	ঘূৰাই r;
}

/* Encode key for a message to the agent. */

স্থির পূর্ণাঙ্ক
encode_dest_constraint_hop(সংরচনা sshbuf *m,
    ধ্রুৱ সংরচনা dest_constraint_hop *dch)
{
	সংরচনা sshbuf *b;
	u_int i;
	পূর্ণাঙ্ক r;

	যদি ((b = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, রিক্ত, 0)) != 0) /* reserved */
		গচ্ছ out;
	বাবে (i = 0; i < dch->nkeys; i++) {
		যদি ((r = sshkey_puts(dch->চাবিগুলি[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->চাবি_is_ca[i] != 0)) != 0)
			গচ্ছ out;
	}
	যদি ((r = sshbuf_put_stringb(m, b)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
encode_dest_constraint(সংরচনা sshbuf *m, ধ্রুৱ সংরচনা dest_constraint *dc)
{
	সংরচনা sshbuf *b;
	পূর্ণাঙ্ক r;

	যদি ((b = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, রিক্ত, 0)) != 0) /* reserved */
		গচ্ছ out;
	যদি ((r = sshbuf_put_stringb(m, b)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
encode_constraints(সংরচনা sshbuf *m, u_int life, u_int confirm,
    ধ্রুৱ ৱর্ণ *provider,
    সংরচনা dest_constraint **dest_constraints, size_t ndest_constraints,
    পূর্ণাঙ্ক cert_only, সংরচনা sshkey **certs, size_t ncerts)
{
	পূর্ণাঙ্ক r;
	সংরচনা sshbuf *b = রিক্ত;
	size_t i;

	যদি (life != 0) {
		যদি ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			গচ্ছ out;
	}
	যদি (confirm != 0) {
		যদি ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			গচ্ছ out;
	}
	যদি (provider != রিক্ত) {
		যদি ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			গচ্ছ out;
	}
	যদি (dest_constraints != রিক্ত && ndest_constraints > 0) {
		যদি ((b = sshbuf_new()) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		বাবে (i = 0; i < ndest_constraints; i++) {
			যদি ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				গচ্ছ out;
		}
		যদি ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			গচ্ছ out;
		sshbuf_free(b);
		b = রিক্ত;
	}
	যদি (ncerts != 0) {
		যদি ((b = sshbuf_new()) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		বাবে (i = 0; i < ncerts; i++) {
			যদি ((r = sshkey_puts(certs[i], b)) != 0)
				গচ্ছ out;
		}
		যদি ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			গচ্ছ out;
		sshbuf_free(b);
		b = রিক্ত;
	}
	r = 0;
 out:
	sshbuf_free(b);
	ঘূৰাই r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
পূর্ণাঙ্ক
ssh_add_identity_constrained(পূর্ণাঙ্ক sock, সংরচনা sshkey *চাবি,
    ধ্রুৱ ৱর্ণ *comment, u_int life, u_int confirm,
    ধ্রুৱ ৱর্ণ *provider, সংরচনা dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	সংরচনা sshbuf *বাৰ্তা;
	পূর্ণাঙ্ক r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	যদি ((বাৰ্তা = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;

	ৱিকল্প (চাবি->type) {
#ifdef WITH_OPENSSL
	পক্ষ চাবি_RSA:
	পক্ষ চাবি_RSA_CERT:
	পক্ষ চাবি_ECDSA:
	পক্ষ চাবি_ECDSA_CERT:
	পক্ষ চাবি_ECDSA_SK:
	পক্ষ চাবি_ECDSA_SK_CERT:
#endif
	পক্ষ চাবি_ED25519:
	পক্ষ চাবি_ED25519_CERT:
	পক্ষ চাবি_MLDSA44_ED25519:
	পক্ষ চাবি_MLDSA44_ED25519_CERT:
	পক্ষ চাবি_ED25519_SK:
	পক্ষ চাবি_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		যদি ((r = sshbuf_put_u8(বাৰ্তা, type)) != 0 ||
		    (r = sshkey_private_serialize(চাবি, বাৰ্তা)) != 0 ||
		    (r = sshbuf_put_cstring(বাৰ্তা, comment)) != 0)
			গচ্ছ out;
		ভঙ্গ;
	স্ৱভাৱ:
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি (constrained &&
	    (r = encode_constraints(বাৰ্তা, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, রিক্ত, 0)) != 0)
		গচ্ছ out;
	যদি ((r = ssh_request_reply_decode(sock, বাৰ্তা)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বাৰ্তা);
	ঘূৰাই r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
পূর্ণাঙ্ক
ssh_remove_identity(পূর্ণাঙ্ক sock, ধ্রুৱ সংরচনা sshkey *চাবি)
{
	সংরচনা sshbuf *বাৰ্তা;
	পূর্ণাঙ্ক r;
	u_char *blob = রিক্ত;
	size_t blen;

	যদি ((বাৰ্তা = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;

	যদি (চাবি->type != চাবি_UNSPEC) {
		যদি ((r = sshkey_to_blob(চাবি, &blob, &blen)) != 0)
			গচ্ছ out;
		যদি ((r = sshbuf_put_u8(বাৰ্তা,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(বাৰ্তা, blob, blen)) != 0)
			গচ্ছ out;
	} অন্যথা {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি ((r = ssh_request_reply_decode(sock, বাৰ্তা)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	যদি (blob != রিক্ত)
		freezero(blob, blen);
	sshbuf_free(বাৰ্তা);
	ঘূৰাই r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
পূর্ণাঙ্ক
ssh_update_card(পূর্ণাঙ্ক sock, পূর্ণাঙ্ক add, ধ্রুৱ ৱর্ণ *reader_id, ধ্রুৱ ৱর্ণ *pin,
    u_int life, u_int confirm,
    সংরচনা dest_constraint **dest_constraints, size_t ndest_constraints,
    পূর্ণাঙ্ক cert_only, সংরচনা sshkey **certs, size_t ncerts)
{
	সংরচনা sshbuf *বাৰ্তা;
	পূর্ণাঙ্ক r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	যদি (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_চাবি_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_চাবি;
	} অন্যথা
		type = SSH_AGENTC_REMOVE_SMARTCARD_চাবি;

	যদি ((বাৰ্তা = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বাৰ্তা, type)) != 0 ||
	    (r = sshbuf_put_cstring(বাৰ্তা, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(বাৰ্তা, pin)) != 0)
		গচ্ছ out;
	যদি (constrained &&
	    (r = encode_constraints(বাৰ্তা, life, confirm, রিক্ত,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		গচ্ছ out;
	যদি ((r = ssh_request_reply_decode(sock, বাৰ্তা)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বাৰ্তা);
	ঘূৰাই r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
পূর্ণাঙ্ক
ssh_remove_all_identities(পূর্ণাঙ্ক sock, পূর্ণাঙ্ক version)
{
	সংরচনা sshbuf *বাৰ্তা;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	পূর্ণাঙ্ক r;

	যদি ((বাৰ্তা = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বাৰ্তা, type)) != 0)
		গচ্ছ out;
	যদি ((r = ssh_request_reply_decode(sock, বাৰ্তা)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বাৰ্তা);
	ঘূৰাই r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
পূর্ণাঙ্ক
ssh_agent_bind_hostkey(পূর্ণাঙ্ক sock, ধ্রুৱ সংরচনা sshkey *চাবি,
    ধ্রুৱ সংরচনা sshbuf *session_id, ধ্রুৱ সংরচনা sshbuf *signature,
    পূর্ণাঙ্ক forwarding)
{
	সংরচনা sshbuf *বাৰ্তা;
	পূর্ণাঙ্ক r;

	যদি (চাবি == রিক্ত || session_id == রিক্ত || signature == রিক্ত)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি ((বাৰ্তা = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বাৰ্তা, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(বাৰ্তা, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(চাবি, বাৰ্তা)) != 0 ||
	    (r = sshbuf_put_stringb(বাৰ্তা, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(বাৰ্তা, signature)) != 0 ||
	    (r = sshbuf_put_u8(বাৰ্তা, forwarding ? 1 : 0)) != 0)
		গচ্ছ out;
	যদি ((r = ssh_request_reply_decode(sock, বাৰ্তা)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(বাৰ্তা);
	ঘূৰাই r;
}

/* Queries supported extension request types */
পূর্ণাঙ্ক
ssh_agent_query_extensions(পূর্ণাঙ্ক sock, ৱর্ণ ***exts)
{
	সংরচনা sshbuf *বাৰ্তা;
	পূর্ণাঙ্ক r;
	u_char type;
	ৱর্ণ *cp = রিক্ত, **ret = রিক্ত;
	size_t i = 0;

	*exts = রিক্ত;
	যদি ((বাৰ্তা = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বাৰ্তা, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(বাৰ্তা, "query")) != 0)
		গচ্ছ out;
	যদি ((r = ssh_request_reply(sock, বাৰ্তা, বাৰ্তা)) != 0)
		গচ্ছ out;
	যদি ((r = sshbuf_get_u8(বাৰ্তা, &type)) != 0)
		গচ্ছ out;
	যদি (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		গচ্ছ out;
	}
	/* Reply should start with "query" */
	যদি (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(বাৰ্তা, &cp, রিক্ত)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	ret = xcalloc(1, পরিমাণ(*ret));
	যেতিয়ালৈ (sshbuf_len(বাৰ্তা)) {
		ret = xrecallocarray(ret, i + 1, i + 2, পরিমাণ(*ret));
		যদি ((r = sshbuf_get_cstring(বাৰ্তা, ret + i, রিক্ত)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = রিক্ত; /* transferred */
 out:
	মুক্ত(cp);
	stringlist_free(ret);
	sshbuf_free(বাৰ্তা);
	ঘূৰাই r;
}
