/* $OpenBSD: authfd.h,v 1.55 2026/03/05 05:44:15 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions to interface with the SSH_AUTHENTICATION_FD socket.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AUTHFD_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AUTHFD_H

ਬਣਤਰ sshbuf;
ਬਣਤਰ sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
ਬਣਤਰ ssh_identitylist {
	ਮਾਪ_t nkeys;
	ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ;
	ਅੱਖਰ **comments;
};

/* Key destination restrictions */
ਬਣਤਰ dest_constraint_hop {
	ਅੱਖਰ *user;	/* wildcards allowed */
	ਅੱਖਰ *hostname; /* used to matching cert principals and for display */
	ਪੂਰਨ is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ;
	ਪੂਰਨ *ਕੁੰਜੀ_is_ca;
};
ਬਣਤਰ dest_constraint {
	ਬਣਤਰ dest_constraint_hop from;
	ਬਣਤਰ dest_constraint_hop ਮੰਜ਼ਿਲ;
};

ਪੂਰਨ	ssh_get_authentication_socket(ਪੂਰਨ *fdp);
ਪੂਰਨ	ssh_get_authentication_socket_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *authsocket, ਪੂਰਨ *fdp);
ਖਾਲੀ	ssh_close_authentication_socket(ਪੂਰਨ sock);

ਪੂਰਨ	ssh_ਤਾਲਾ_agent(ਪੂਰਨ sock, ਪੂਰਨ ਤਾਲਾ, ਅਚਲ ਅੱਖਰ *password);
ਪੂਰਨ	ssh_fetch_identitylist(ਪੂਰਨ sock, ਬਣਤਰ ssh_identitylist **idlp);
ਖਾਲੀ	ssh_free_identitylist(ਬਣਤਰ ssh_identitylist *idl);
ਪੂਰਨ	ssh_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_constrained(ਪੂਰਨ sock, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *comment, u_int life, u_int confirm, ਅਚਲ ਅੱਖਰ *provider,
    ਬਣਤਰ dest_constraint **dest_constraints, ਮਾਪ_t ndest_constraints);
ਪੂਰਨ	ssh_agent_has_ਕੁੰਜੀ(ਪੂਰਨ sock, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ);
ਪੂਰਨ	ssh_remove_ਪਛਾਣ_ਤੱਤ(ਪੂਰਨ sock, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ);
ਪੂਰਨ	ssh_update_card(ਪੂਰਨ sock, ਪੂਰਨ ਜੋੜੋ, ਅਚਲ ਅੱਖਰ *reader_id,
	    ਅਚਲ ਅੱਖਰ *pin, u_int life, u_int confirm,
	    ਬਣਤਰ dest_constraint **dest_constraints,
	    ਮਾਪ_t ndest_constraints,
	    ਪੂਰਨ cert_only, ਬਣਤਰ sshkey **certs, ਮਾਪ_t ncerts);
ਪੂਰਨ	ssh_remove_all_identities(ਪੂਰਨ sock, ਪੂਰਨ ਸੰਸਕਰਣ);

ਪੂਰਨ	ssh_agent_sign(ਪੂਰਨ sock, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
	    u_char **sigp, ਮਾਪ_t *lenp,
	    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen, ਅਚਲ ਅੱਖਰ *alg, u_int compat);

ਪੂਰਨ	ssh_agent_bind_hostkey(ਪੂਰਨ sock, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਬਣਤਰ sshbuf *session_id, ਅਚਲ ਬਣਤਰ sshbuf *signature,
    ਪੂਰਨ forwarding);

ਪੂਰਨ	ssh_agent_query_extensions(ਪੂਰਨ sock, ਅੱਖਰ ***exts);

/* Messages for the authentication agent connection. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_RSA_CHALLENGE		3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENT_RSA_RESPONSE			4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENT_FAILURE			5
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENT_SUCCESS			6
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_ਜੋੜੋ_RSA_ਪਛਾਣ_ਤੱਤ		7
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_REMOVE_RSA_ਪਛਾਣ_ਤੱਤ		8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_AGENTC_REQUEST_IDENTITIES		11
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_AGENT_IDENTITIES_ANSWER		12
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_AGENTC_SIGN_REQUEST		13
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_AGENT_SIGN_RESPONSE		14
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_AGENTC_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ		17
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_AGENTC_REMOVE_ਪਛਾਣ_ਤੱਤ		18
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_ਜੋੜੋ_SMARTCARD_ਕੁੰਜੀ		20
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_REMOVE_SMARTCARD_ਕੁੰਜੀ		21

/* lock/unlock the agent */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_ਤਾਲਾ				22
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_ਜੋੜੋ_RSA_ID_CONSTRAINED	24
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_AGENTC_ਜੋੜੋ_ID_CONSTRAINED		25
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_ਜੋੜੋ_SMARTCARD_ਕੁੰਜੀ_CONSTRAINED 26

/* generic extension mechanism */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENTC_EXTENSION			27
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENT_EXTENSION_FAILURE		28
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AGENT_EXTENSION_RESPONSE		29

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_AGENT_CONSTRAIN_LIFETIME		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_AGENT_CONSTRAIN_CONFIRM		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_COM_AGENT2_FAILURE			102

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_AGENT_OLD_SIGNATURE			0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_AGENT_RSA_SHA2_256			0x02
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_AGENT_RSA_SHA2_512			0x04

#ਜੇ_ਅੰਤ				/* AUTHFD_H */
