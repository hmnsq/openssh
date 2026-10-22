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

ഘടന sshbuf;
ഘടന sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
ഘടന ssh_identitylist {
	size_t nkeys;
	ഘടന sshkey **താക്കോലുകൾ;
	അക്ഷരം **comments;
};

/* Key destination restrictions */
ഘടന dest_constraint_hop {
	അക്ഷരം *user;	/* wildcards allowed */
	അക്ഷരം *hostname; /* used to matching cert principals and for display */
	പൂർണ്ണസംഖ്യ is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	ഘടന sshkey **താക്കോലുകൾ;
	പൂർണ്ണസംഖ്യ *താക്കോൽ_is_ca;
};
ഘടന dest_constraint {
	ഘടന dest_constraint_hop from;
	ഘടന dest_constraint_hop to;
};

പൂർണ്ണസംഖ്യ	ssh_get_authentication_socket(പൂർണ്ണസംഖ്യ *fdp);
പൂർണ്ണസംഖ്യ	ssh_get_authentication_socket_path(സ്ഥിരം അക്ഷരം *authsocket, പൂർണ്ണസംഖ്യ *fdp);
ശൂന്യം	ssh_close_authentication_socket(പൂർണ്ണസംഖ്യ sock);

പൂർണ്ണസംഖ്യ	ssh_lock_agent(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ lock, സ്ഥിരം അക്ഷരം *password);
പൂർണ്ണസംഖ്യ	ssh_fetch_identitylist(പൂർണ്ണസംഖ്യ sock, ഘടന ssh_identitylist **idlp);
ശൂന്യം	ssh_free_identitylist(ഘടന ssh_identitylist *idl);
പൂർണ്ണസംഖ്യ	ssh_add_identity_constrained(പൂർണ്ണസംഖ്യ sock, ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം അക്ഷരം *comment, u_int life, u_int confirm, സ്ഥിരം അക്ഷരം *provider,
    ഘടന dest_constraint **dest_constraints, size_t ndest_constraints);
പൂർണ്ണസംഖ്യ	ssh_agent_has_താക്കോൽ(പൂർണ്ണസംഖ്യ sock, സ്ഥിരം ഘടന sshkey *താക്കോൽ);
പൂർണ്ണസംഖ്യ	ssh_remove_identity(പൂർണ്ണസംഖ്യ sock, സ്ഥിരം ഘടന sshkey *താക്കോൽ);
പൂർണ്ണസംഖ്യ	ssh_update_card(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ add, സ്ഥിരം അക്ഷരം *reader_id,
	    സ്ഥിരം അക്ഷരം *pin, u_int life, u_int confirm,
	    ഘടന dest_constraint **dest_constraints,
	    size_t ndest_constraints,
	    പൂർണ്ണസംഖ്യ cert_only, ഘടന sshkey **certs, size_t ncerts);
പൂർണ്ണസംഖ്യ	ssh_remove_all_identities(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ version);

പൂർണ്ണസംഖ്യ	ssh_agent_sign(പൂർണ്ണസംഖ്യ sock, സ്ഥിരം ഘടന sshkey *താക്കോൽ,
	    u_char **sigp, size_t *lenp,
	    സ്ഥിരം u_char *data, size_t datalen, സ്ഥിരം അക്ഷരം *alg, u_int compat);

പൂർണ്ണസംഖ്യ	ssh_agent_bind_hostkey(പൂർണ്ണസംഖ്യ sock, സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം ഘടന sshbuf *session_id, സ്ഥിരം ഘടന sshbuf *signature,
    പൂർണ്ണസംഖ്യ forwarding);

പൂർണ്ണസംഖ്യ	ssh_agent_query_extensions(പൂർണ്ണസംഖ്യ sock, അക്ഷരം ***exts);

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
#define SSH_AGENTC_ADD_SMARTCARD_താക്കോൽ		20
#define SSH_AGENTC_REMOVE_SMARTCARD_താക്കോൽ		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_താക്കോൽ_CONSTRAINED 26

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
