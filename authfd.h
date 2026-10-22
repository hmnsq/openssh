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

#ifndef AUTHFD_H
#define AUTHFD_H

સંરચના sshbuf;
સંરચના sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
સંરચના ssh_identitylist {
	size_t nkeys;
	સંરચના sshkey **ચાવીઓ;
	અક્ષર **comments;
};

/* Key destination restrictions */
સંરચના dest_constraint_hop {
	અક્ષર *user;	/* wildcards allowed */
	અક્ષર *hostname; /* used to matching cert principals and for display */
	પૂર્ણાંક is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	સંરચના sshkey **ચાવીઓ;
	પૂર્ણાંક *ચાવી_is_ca;
};
સંરચના dest_constraint {
	સંરચના dest_constraint_hop from;
	સંરચના dest_constraint_hop to;
};

પૂર્ણાંક	ssh_get_authentication_socket(પૂર્ણાંક *fdp);
પૂર્ણાંક	ssh_get_authentication_socket_path(અચલ અક્ષર *authsocket, પૂર્ણાંક *fdp);
શૂન્ય	ssh_close_authentication_socket(પૂર્ણાંક sock);

પૂર્ણાંક	ssh_lock_agent(પૂર્ણાંક sock, પૂર્ણાંક lock, અચલ અક્ષર *password);
પૂર્ણાંક	ssh_fetch_identitylist(પૂર્ણાંક sock, સંરચના ssh_identitylist **idlp);
શૂન્ય	ssh_free_identitylist(સંરચના ssh_identitylist *idl);
પૂર્ણાંક	ssh_add_identity_constrained(પૂર્ણાંક sock, સંરચના sshkey *ચાવી,
    અચલ અક્ષર *comment, u_int life, u_int confirm, અચલ અક્ષર *provider,
    સંરચના dest_constraint **dest_constraints, size_t ndest_constraints);
પૂર્ણાંક	ssh_agent_has_ચાવી(પૂર્ણાંક sock, અચલ સંરચના sshkey *ચાવી);
પૂર્ણાંક	ssh_remove_identity(પૂર્ણાંક sock, અચલ સંરચના sshkey *ચાવી);
પૂર્ણાંક	ssh_update_card(પૂર્ણાંક sock, પૂર્ણાંક add, અચલ અક્ષર *reader_id,
	    અચલ અક્ષર *pin, u_int life, u_int confirm,
	    સંરચના dest_constraint **dest_constraints,
	    size_t ndest_constraints,
	    પૂર્ણાંક cert_only, સંરચના sshkey **certs, size_t ncerts);
પૂર્ણાંક	ssh_remove_all_identities(પૂર્ણાંક sock, પૂર્ણાંક version);

પૂર્ણાંક	ssh_agent_sign(પૂર્ણાંક sock, અચલ સંરચના sshkey *ચાવી,
	    u_char **sigp, size_t *lenp,
	    અચલ u_char *data, size_t datalen, અચલ અક્ષર *alg, u_int compat);

પૂર્ણાંક	ssh_agent_bind_hostkey(પૂર્ણાંક sock, અચલ સંરચના sshkey *ચાવી,
    અચલ સંરચના sshbuf *session_id, અચલ સંરચના sshbuf *signature,
    પૂર્ણાંક forwarding);

પૂર્ણાંક	ssh_agent_query_extensions(પૂર્ણાંક sock, અક્ષર ***exts);

/* Messages for the authentication agent connection. */
#define SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#define SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#define SSH_AGENTC_RSA_CHALLENGE		3
#define SSH_AGENT_RSA_RESPONSE			4
#define SSH_AGENT_FAILURE			5
#define SSH_AGENT_SUCCESS			6
#define SSH_AGENTC_ADD_RSA_IDENTITY		7
#define SSH_AGENTC_REMOVE_RSA_IDENTITY		8
#define SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#define SSH2_AGENTC_REQUEST_IDENTITIES		11
#define SSH2_AGENT_IDENTITIES_ANSWER		12
#define SSH2_AGENTC_SIGN_REQUEST		13
#define SSH2_AGENT_SIGN_RESPONSE		14
#define SSH2_AGENTC_ADD_IDENTITY		17
#define SSH2_AGENTC_REMOVE_IDENTITY		18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#define SSH_AGENTC_ADD_SMARTCARD_ચાવી		20
#define SSH_AGENTC_REMOVE_SMARTCARD_ચાવી		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_ચાવી_CONSTRAINED 26

/* generic extension mechanism */
#define SSH_AGENTC_EXTENSION			27
#define SSH_AGENT_EXTENSION_FAILURE		28
#define SSH_AGENT_EXTENSION_RESPONSE		29

#define	SSH_AGENT_CONSTRAIN_LIFETIME		1
#define	SSH_AGENT_CONSTRAIN_CONFIRM		2
#define	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#define SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#define SSH_COM_AGENT2_FAILURE			102

#define	SSH_AGENT_OLD_SIGNATURE			0x01
#define	SSH_AGENT_RSA_SHA2_256			0x02
#define	SSH_AGENT_RSA_SHA2_512			0x04

#endif				/* AUTHFD_H */
