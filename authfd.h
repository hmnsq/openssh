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

#अगर_अघोषित AUTHFD_H
#घोषणा AUTHFD_H

काष्ठा sshbuf;
काष्ठा sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
काष्ठा ssh_identitylist {
	माप_प्रकार nkeys;
	काष्ठा sshkey **कुंजियाँ;
	अक्षर **comments;
};

/* Key destination restrictions */
काष्ठा dest_constraint_hop {
	अक्षर *user;	/* wildcards allowed */
	अक्षर *hostname; /* used to matching cert principals and for display */
	पूर्णांक is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	काष्ठा sshkey **कुंजियाँ;
	पूर्णांक *कुंजी_is_ca;
};
काष्ठा dest_constraint {
	काष्ठा dest_constraint_hop from;
	काष्ठा dest_constraint_hop to;
};

पूर्णांक	ssh_get_authentication_socket(पूर्णांक *fdp);
पूर्णांक	ssh_get_authentication_socket_path(स्थिर अक्षर *authsocket, पूर्णांक *fdp);
व्योम	ssh_close_authentication_socket(पूर्णांक sock);

पूर्णांक	ssh_lock_agent(पूर्णांक sock, पूर्णांक lock, स्थिर अक्षर *password);
पूर्णांक	ssh_fetch_identitylist(पूर्णांक sock, काष्ठा ssh_identitylist **idlp);
व्योम	ssh_free_identitylist(काष्ठा ssh_identitylist *idl);
पूर्णांक	ssh_add_identity_constrained(पूर्णांक sock, काष्ठा sshkey *कुंजी,
    स्थिर अक्षर *comment, u_int life, u_int confirm, स्थिर अक्षर *provider,
    काष्ठा dest_constraint **dest_constraints, माप_प्रकार ndest_constraints);
पूर्णांक	ssh_agent_has_कुंजी(पूर्णांक sock, स्थिर काष्ठा sshkey *कुंजी);
पूर्णांक	ssh_remove_identity(पूर्णांक sock, स्थिर काष्ठा sshkey *कुंजी);
पूर्णांक	ssh_update_card(पूर्णांक sock, पूर्णांक add, स्थिर अक्षर *reader_id,
	    स्थिर अक्षर *pin, u_int life, u_int confirm,
	    काष्ठा dest_constraint **dest_constraints,
	    माप_प्रकार ndest_constraints,
	    पूर्णांक cert_only, काष्ठा sshkey **certs, माप_प्रकार ncerts);
पूर्णांक	ssh_remove_all_identities(पूर्णांक sock, पूर्णांक version);

पूर्णांक	ssh_agent_sign(पूर्णांक sock, स्थिर काष्ठा sshkey *कुंजी,
	    u_char **sigp, माप_प्रकार *lenp,
	    स्थिर u_char *तथ्य, माप_प्रकार datalen, स्थिर अक्षर *alg, u_int compat);

पूर्णांक	ssh_agent_bind_hostkey(पूर्णांक sock, स्थिर काष्ठा sshkey *कुंजी,
    स्थिर काष्ठा sshbuf *session_id, स्थिर काष्ठा sshbuf *signature,
    पूर्णांक forwarding);

पूर्णांक	ssh_agent_query_extensions(पूर्णांक sock, अक्षर ***exts);

/* Messages for the authentication agent connection. */
#घोषणा SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#घोषणा SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#घोषणा SSH_AGENTC_RSA_CHALLENGE		3
#घोषणा SSH_AGENT_RSA_RESPONSE			4
#घोषणा SSH_AGENT_FAILURE			5
#घोषणा SSH_AGENT_SUCCESS			6
#घोषणा SSH_AGENTC_ADD_RSA_IDENTITY		7
#घोषणा SSH_AGENTC_REMOVE_RSA_IDENTITY		8
#घोषणा SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#घोषणा SSH2_AGENTC_REQUEST_IDENTITIES		11
#घोषणा SSH2_AGENT_IDENTITIES_ANSWER		12
#घोषणा SSH2_AGENTC_SIGN_REQUEST		13
#घोषणा SSH2_AGENT_SIGN_RESPONSE		14
#घोषणा SSH2_AGENTC_ADD_IDENTITY		17
#घोषणा SSH2_AGENTC_REMOVE_IDENTITY		18
#घोषणा SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#घोषणा SSH_AGENTC_ADD_SMARTCARD_कुंजी		20
#घोषणा SSH_AGENTC_REMOVE_SMARTCARD_कुंजी		21

/* lock/unlock the agent */
#घोषणा SSH_AGENTC_LOCK				22
#घोषणा SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#घोषणा SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#घोषणा SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#घोषणा SSH_AGENTC_ADD_SMARTCARD_कुंजी_CONSTRAINED 26

/* generic extension mechanism */
#घोषणा SSH_AGENTC_EXTENSION			27
#घोषणा SSH_AGENT_EXTENSION_FAILURE		28
#घोषणा SSH_AGENT_EXTENSION_RESPONSE		29

#घोषणा	SSH_AGENT_CONSTRAIN_LIFETIME		1
#घोषणा	SSH_AGENT_CONSTRAIN_CONFIRM		2
#घोषणा	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#घोषणा SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#घोषणा SSH_COM_AGENT2_FAILURE			102

#घोषणा	SSH_AGENT_OLD_SIGNATURE			0x01
#घोषणा	SSH_AGENT_RSA_SHA2_256			0x02
#घोषणा	SSH_AGENT_RSA_SHA2_512			0x04

#पूर्ण_अगर				/* AUTHFD_H */
