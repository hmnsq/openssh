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

#اگر_تعریف_نشده AUTHFD_H
#تعریف_کن AUTHFD_H

بنية sshbuf;
بنية sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
بنية ssh_identitylist {
	اندازه_t nkeys;
	بنية sshkey **کلیدها;
	حرف **comments;
};

/* Key destination restrictions */
بنية dest_constraint_hop {
	حرف *user;	/* wildcards allowed */
	حرف *hostname; /* used to matching cert principals and for display */
	صحيح is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	بنية sshkey **کلیدها;
	صحيح *کلید_is_ca;
};
بنية dest_constraint {
	بنية dest_constraint_hop from;
	بنية dest_constraint_hop مقصد;
};

صحيح	ssh_get_authentication_socket(صحيح *fdp);
صحيح	ssh_get_authentication_socket_مسیر(ثابت حرف *authsocket, صحيح *fdp);
فراغ	ssh_close_authentication_socket(صحيح sock);

صحيح	ssh_قفل_agent(صحيح sock, صحيح قفل, ثابت حرف *password);
صحيح	ssh_fetch_identitylist(صحيح sock, بنية ssh_identitylist **idlp);
فراغ	ssh_free_identitylist(بنية ssh_identitylist *idl);
صحيح	ssh_جمع_کن_عنصر_خنثی_constrained(صحيح sock, بنية sshkey *کلید,
    ثابت حرف *comment, u_int life, u_int confirm, ثابت حرف *provider,
    بنية dest_constraint **dest_constraints, اندازه_t ndest_constraints);
صحيح	ssh_agent_has_کلید(صحيح sock, ثابت بنية sshkey *کلید);
صحيح	ssh_remove_عنصر_خنثی(صحيح sock, ثابت بنية sshkey *کلید);
صحيح	ssh_update_card(صحيح sock, صحيح جمع_کن, ثابت حرف *reader_id,
	    ثابت حرف *pin, u_int life, u_int confirm,
	    بنية dest_constraint **dest_constraints,
	    اندازه_t ndest_constraints,
	    صحيح cert_only, بنية sshkey **certs, اندازه_t ncerts);
صحيح	ssh_remove_all_identities(صحيح sock, صحيح نسخه);

صحيح	ssh_agent_sign(صحيح sock, ثابت بنية sshkey *کلید,
	    u_char **sigp, اندازه_t *lenp,
	    ثابت u_char *داده, اندازه_t datalen, ثابت حرف *alg, u_int compat);

صحيح	ssh_agent_bind_hostkey(صحيح sock, ثابت بنية sshkey *کلید,
    ثابت بنية sshbuf *session_id, ثابت بنية sshbuf *signature,
    صحيح forwarding);

صحيح	ssh_agent_query_extensions(صحيح sock, حرف ***exts);

/* Messages for the authentication agent connection. */
#تعریف_کن SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#تعریف_کن SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#تعریف_کن SSH_AGENTC_RSA_CHALLENGE		3
#تعریف_کن SSH_AGENT_RSA_RESPONSE			4
#تعریف_کن SSH_AGENT_FAILURE			5
#تعریف_کن SSH_AGENT_SUCCESS			6
#تعریف_کن SSH_AGENTC_جمع_کن_RSA_عنصر_خنثی		7
#تعریف_کن SSH_AGENTC_REMOVE_RSA_عنصر_خنثی		8
#تعریف_کن SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#تعریف_کن SSH2_AGENTC_REQUEST_IDENTITIES		11
#تعریف_کن SSH2_AGENT_IDENTITIES_ANSWER		12
#تعریف_کن SSH2_AGENTC_SIGN_REQUEST		13
#تعریف_کن SSH2_AGENT_SIGN_RESPONSE		14
#تعریف_کن SSH2_AGENTC_جمع_کن_عنصر_خنثی		17
#تعریف_کن SSH2_AGENTC_REMOVE_عنصر_خنثی		18
#تعریف_کن SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#تعریف_کن SSH_AGENTC_جمع_کن_SMARTCARD_کلید		20
#تعریف_کن SSH_AGENTC_REMOVE_SMARTCARD_کلید		21

/* lock/unlock the agent */
#تعریف_کن SSH_AGENTC_قفل				22
#تعریف_کن SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#تعریف_کن SSH_AGENTC_جمع_کن_RSA_ID_CONSTRAINED	24
#تعریف_کن SSH2_AGENTC_جمع_کن_ID_CONSTRAINED		25
#تعریف_کن SSH_AGENTC_جمع_کن_SMARTCARD_کلید_CONSTRAINED 26

/* generic extension mechanism */
#تعریف_کن SSH_AGENTC_EXTENSION			27
#تعریف_کن SSH_AGENT_EXTENSION_FAILURE		28
#تعریف_کن SSH_AGENT_EXTENSION_RESPONSE		29

#تعریف_کن	SSH_AGENT_CONSTRAIN_LIFETIME		1
#تعریف_کن	SSH_AGENT_CONSTRAIN_CONFIRM		2
#تعریف_کن	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#تعریف_کن SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#تعریف_کن SSH_COM_AGENT2_FAILURE			102

#تعریف_کن	SSH_AGENT_OLD_SIGNATURE			0x01
#تعریف_کن	SSH_AGENT_RSA_SHA2_256			0x02
#تعریف_کن	SSH_AGENT_RSA_SHA2_512			0x04

#پایان_اگر				/* AUTHFD_H */
