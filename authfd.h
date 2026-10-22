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

sa_nracanaa sshbuf;
sa_nracanaa sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
sa_nracanaa ssh_identitylist {
	size_t nkeys;
	sa_nracanaa sshkey **keys;
	var_na **comments;
};

/* Key destination restrictions */
sa_nracanaa dest_constraint_hop {
	var_na *user;	/* wildcards allowed */
	var_na *hostname; /* used to matching cert principals and for display */
	පූර්ණ_සංඛ්‍යා is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	sa_nracanaa sshkey **keys;
	පූර්ණ_සංඛ්‍යා *key_is_ca;
};
sa_nracanaa dest_constraint {
	sa_nracanaa dest_constraint_hop from;
	sa_nracanaa dest_constraint_hop to;
};

පූර්ණ_සංඛ්‍යා	ssh_get_authentication_socket(පූර්ණ_සංඛ්‍යා *fdp);
පූර්ණ_සංඛ්‍යා	ssh_get_authentication_socket_path(const var_na *authsocket, පූර්ණ_සංඛ්‍යා *fdp);
void	ssh_close_authentication_socket(පූර්ණ_සංඛ්‍යා sock);

පූර්ණ_සංඛ්‍යා	ssh_lock_agent(පූර්ණ_සංඛ්‍යා sock, පූර්ණ_සංඛ්‍යා lock, const var_na *password);
පූර්ණ_සංඛ්‍යා	ssh_fetch_identitylist(පූර්ණ_සංඛ්‍යා sock, sa_nracanaa ssh_identitylist **idlp);
void	ssh_free_identitylist(sa_nracanaa ssh_identitylist *idl);
පූර්ණ_සංඛ්‍යා	ssh_add_identity_constrained(පූර්ණ_සංඛ්‍යා sock, sa_nracanaa sshkey *key,
    const var_na *comment, u_int life, u_int confirm, const var_na *provider,
    sa_nracanaa dest_constraint **dest_constraints, size_t ndest_constraints);
පූර්ණ_සංඛ්‍යා	ssh_agent_has_key(පූර්ණ_සංඛ්‍යා sock, const sa_nracanaa sshkey *key);
පූර්ණ_සංඛ්‍යා	ssh_remove_identity(පූර්ණ_සංඛ්‍යා sock, const sa_nracanaa sshkey *key);
පූර්ණ_සංඛ්‍යා	ssh_update_card(පූර්ණ_සංඛ්‍යා sock, පූර්ණ_සංඛ්‍යා add, const var_na *reader_id,
	    const var_na *pin, u_int life, u_int confirm,
	    sa_nracanaa dest_constraint **dest_constraints,
	    size_t ndest_constraints,
	    පූර්ණ_සංඛ්‍යා cert_only, sa_nracanaa sshkey **certs, size_t ncerts);
පූර්ණ_සංඛ්‍යා	ssh_remove_all_identities(පූර්ණ_සංඛ්‍යා sock, පූර්ණ_සංඛ්‍යා version);

පූර්ණ_සංඛ්‍යා	ssh_agent_sign(පූර්ණ_සංඛ්‍යා sock, const sa_nracanaa sshkey *key,
	    u_char **sigp, size_t *lenp,
	    const u_char *data, size_t datalen, const var_na *alg, u_int compat);

පූර්ණ_සංඛ්‍යා	ssh_agent_bind_hostkey(පූර්ණ_සංඛ්‍යා sock, const sa_nracanaa sshkey *key,
    const sa_nracanaa sshbuf *session_id, const sa_nracanaa sshbuf *signature,
    පූර්ණ_සංඛ්‍යා forwarding);

පූර්ණ_සංඛ්‍යා	ssh_agent_query_extensions(පූර්ණ_සංඛ්‍යා sock, var_na ***exts);

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
#define SSH_AGENTC_ADD_SMARTCARD_KEY		20
#define SSH_AGENTC_REMOVE_SMARTCARD_KEY		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED 26

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
