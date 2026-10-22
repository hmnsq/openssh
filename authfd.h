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

ಸಂರಚನಾ sshbuf;
ಸಂರಚನಾ sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
ಸಂರಚನಾ ssh_identitylist {
	size_t nkeys;
	ಸಂರಚನಾ sshkey **ಕೀಲಿಗಳು;
	ವರ್ಣ **comments;
};

/* Key destination restrictions */
ಸಂರಚನಾ dest_constraint_hop {
	ವರ್ಣ *user;	/* wildcards allowed */
	ವರ್ಣ *hostname; /* used to matching cert principals and for display */
	ಪೂರ್ಣಾಙ್ಕ is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	ಸಂರಚನಾ sshkey **ಕೀಲಿಗಳು;
	ಪೂರ್ಣಾಙ್ಕ *ಕೀಲಿ_is_ca;
};
ಸಂರಚನಾ dest_constraint {
	ಸಂರಚನಾ dest_constraint_hop from;
	ಸಂರಚನಾ dest_constraint_hop to;
};

ಪೂರ್ಣಾಙ್ಕ	ssh_get_authentication_socket(ಪೂರ್ಣಾಙ್ಕ *fdp);
ಪೂರ್ಣಾಙ್ಕ	ssh_get_authentication_socket_path(ಧ್ರುವ ವರ್ಣ *authsocket, ಪೂರ್ಣಾಙ್ಕ *fdp);
ಶೂನ್ಯ	ssh_close_authentication_socket(ಪೂರ್ಣಾಙ್ಕ sock);

ಪೂರ್ಣಾಙ್ಕ	ssh_lock_agent(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ lock, ಧ್ರುವ ವರ್ಣ *password);
ಪೂರ್ಣಾಙ್ಕ	ssh_fetch_identitylist(ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ ssh_identitylist **idlp);
ಶೂನ್ಯ	ssh_free_identitylist(ಸಂರಚನಾ ssh_identitylist *idl);
ಪೂರ್ಣಾಙ್ಕ	ssh_add_identity_constrained(ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ವರ್ಣ *comment, u_int life, u_int confirm, ಧ್ರುವ ವರ್ಣ *provider,
    ಸಂರಚನಾ dest_constraint **dest_constraints, size_t ndest_constraints);
ಪೂರ್ಣಾಙ್ಕ	ssh_agent_has_ಕೀಲಿ(ಪೂರ್ಣಾಙ್ಕ sock, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಙ್ಕ	ssh_remove_identity(ಪೂರ್ಣಾಙ್ಕ sock, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಙ್ಕ	ssh_update_card(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ add, ಧ್ರುವ ವರ್ಣ *reader_id,
	    ಧ್ರುವ ವರ್ಣ *pin, u_int life, u_int confirm,
	    ಸಂರಚನಾ dest_constraint **dest_constraints,
	    size_t ndest_constraints,
	    ಪೂರ್ಣಾಙ್ಕ cert_only, ಸಂರಚನಾ sshkey **certs, size_t ncerts);
ಪೂರ್ಣಾಙ್ಕ	ssh_remove_all_identities(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ version);

ಪೂರ್ಣಾಙ್ಕ	ssh_agent_sign(ಪೂರ್ಣಾಙ್ಕ sock, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
	    u_char **sigp, size_t *lenp,
	    ಧ್ರುವ u_char *data, size_t datalen, ಧ್ರುವ ವರ್ಣ *alg, u_int compat);

ಪೂರ್ಣಾಙ್ಕ	ssh_agent_bind_hostkey(ಪೂರ್ಣಾಙ್ಕ sock, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *session_id, ಧ್ರುವ ಸಂರಚನಾ sshbuf *signature,
    ಪೂರ್ಣಾಙ್ಕ forwarding);

ಪೂರ್ಣಾಙ್ಕ	ssh_agent_query_extensions(ಪೂರ್ಣಾಙ್ಕ sock, ವರ್ಣ ***exts);

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
#define SSH_AGENTC_ADD_SMARTCARD_ಕೀಲಿ		20
#define SSH_AGENTC_REMOVE_SMARTCARD_ಕೀಲಿ		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_ಕೀಲಿ_CONSTRAINED 26

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
