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

संरचना sshbuf;
संरचना sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
संरचना ssh_identitylist {
	size_t nkeys;
	संरचना sshkey **कुञ्चिकाः;
	वर्ण **comments;
};

/* Key destination restrictions */
संरचना dest_constraint_hop {
	वर्ण *user;	/* wildcards allowed */
	वर्ण *hostname; /* used to matching cert principals and for display */
	पूर्णाङ्क is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	संरचना sshkey **कुञ्चिकाः;
	पूर्णाङ्क *कुञ्चिका_is_ca;
};
संरचना dest_constraint {
	संरचना dest_constraint_hop from;
	संरचना dest_constraint_hop to;
};

पूर्णाङ्क	ssh_get_authentication_socket(पूर्णाङ्क *fdp);
पूर्णाङ्क	ssh_get_authentication_socket_path(ध्रुव वर्ण *authsocket, पूर्णाङ्क *fdp);
शून्य	ssh_close_authentication_socket(पूर्णाङ्क sock);

पूर्णाङ्क	ssh_lock_agent(पूर्णाङ्क sock, पूर्णाङ्क lock, ध्रुव वर्ण *password);
पूर्णाङ्क	ssh_fetch_identitylist(पूर्णाङ्क sock, संरचना ssh_identitylist **idlp);
शून्य	ssh_free_identitylist(संरचना ssh_identitylist *idl);
पूर्णाङ्क	ssh_add_identity_constrained(पूर्णाङ्क sock, संरचना sshkey *कुञ्चिका,
    ध्रुव वर्ण *comment, u_int life, u_int confirm, ध्रुव वर्ण *provider,
    संरचना dest_constraint **dest_constraints, size_t ndest_constraints);
पूर्णाङ्क	ssh_agent_has_कुञ्चिका(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका);
पूर्णाङ्क	ssh_remove_identity(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका);
पूर्णाङ्क	ssh_update_card(पूर्णाङ्क sock, पूर्णाङ्क add, ध्रुव वर्ण *reader_id,
	    ध्रुव वर्ण *pin, u_int life, u_int confirm,
	    संरचना dest_constraint **dest_constraints,
	    size_t ndest_constraints,
	    पूर्णाङ्क cert_only, संरचना sshkey **certs, size_t ncerts);
पूर्णाङ्क	ssh_remove_all_identities(पूर्णाङ्क sock, पूर्णाङ्क version);

पूर्णाङ्क	ssh_agent_sign(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका,
	    u_char **sigp, size_t *lenp,
	    ध्रुव u_char *data, size_t datalen, ध्रुव वर्ण *alg, u_int compat);

पूर्णाङ्क	ssh_agent_bind_hostkey(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव संरचना sshbuf *session_id, ध्रुव संरचना sshbuf *signature,
    पूर्णाङ्क forwarding);

पूर्णाङ्क	ssh_agent_query_extensions(पूर्णाङ्क sock, वर्ण ***exts);

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
#define SSH_AGENTC_ADD_SMARTCARD_कुञ्चिका		20
#define SSH_AGENTC_REMOVE_SMARTCARD_कुञ्चिका		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_कुञ्चिका_CONSTRAINED 26

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
