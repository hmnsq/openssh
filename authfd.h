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

#که_نه_تعریف_شوی AUTHFD_H
#تعریف_کړه AUTHFD_H

بنية sshbuf;
بنية sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
بنية ssh_identitylist {
	اندازه_t nkeys;
	بنية sshkey **کلیګانې;
	حرف **comments;
};

/* Key destination restrictions */
بنية dest_constraint_hop {
	حرف *user;	/* wildcards allowed */
	حرف *hostname; /* used to matching cert principals and for display */
	صحيح is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	بنية sshkey **کلیګانې;
	صحيح *کلی_is_ca;
};
بنية dest_constraint {
	بنية dest_constraint_hop from;
	بنية dest_constraint_hop منزل;
};

صحيح	ssh_get_authentication_socket(صحيح *fdp);
صحيح	ssh_get_authentication_socket_لار(ثابت حرف *authsocket, صحيح *fdp);
فراغ	ssh_close_authentication_socket(صحيح sock);

صحيح	ssh_قلف_agent(صحيح sock, صحيح قلف, ثابت حرف *password);
صحيح	ssh_fetch_identitylist(صحيح sock, بنية ssh_identitylist **idlp);
فراغ	ssh_free_identitylist(بنية ssh_identitylist *idl);
صحيح	ssh_جمع_کړه_بې_اغېزه_عنصر_constrained(صحيح sock, بنية sshkey *کلی,
    ثابت حرف *comment, u_int life, u_int confirm, ثابت حرف *provider,
    بنية dest_constraint **dest_constraints, اندازه_t ndest_constraints);
صحيح	ssh_agent_has_کلی(صحيح sock, ثابت بنية sshkey *کلی);
صحيح	ssh_remove_بې_اغېزه_عنصر(صحيح sock, ثابت بنية sshkey *کلی);
صحيح	ssh_update_card(صحيح sock, صحيح جمع_کړه, ثابت حرف *reader_id,
	    ثابت حرف *pin, u_int life, u_int confirm,
	    بنية dest_constraint **dest_constraints,
	    اندازه_t ndest_constraints,
	    صحيح cert_only, بنية sshkey **certs, اندازه_t ncerts);
صحيح	ssh_remove_all_identities(صحيح sock, صحيح نسخه);

صحيح	ssh_agent_sign(صحيح sock, ثابت بنية sshkey *کلی,
	    u_char **sigp, اندازه_t *lenp,
	    ثابت u_char *معلومات, اندازه_t datalen, ثابت حرف *alg, u_int compat);

صحيح	ssh_agent_bind_hostkey(صحيح sock, ثابت بنية sshkey *کلی,
    ثابت بنية sshbuf *session_id, ثابت بنية sshbuf *signature,
    صحيح forwarding);

صحيح	ssh_agent_query_extensions(صحيح sock, حرف ***exts);

/* Messages for the authentication agent connection. */
#تعریف_کړه SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#تعریف_کړه SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#تعریف_کړه SSH_AGENTC_RSA_CHALLENGE		3
#تعریف_کړه SSH_AGENT_RSA_RESPONSE			4
#تعریف_کړه SSH_AGENT_FAILURE			5
#تعریف_کړه SSH_AGENT_SUCCESS			6
#تعریف_کړه SSH_AGENTC_جمع_کړه_RSA_بې_اغېزه_عنصر		7
#تعریف_کړه SSH_AGENTC_REMOVE_RSA_بې_اغېزه_عنصر		8
#تعریف_کړه SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#تعریف_کړه SSH2_AGENTC_REQUEST_IDENTITIES		11
#تعریف_کړه SSH2_AGENT_IDENTITIES_ANSWER		12
#تعریف_کړه SSH2_AGENTC_SIGN_REQUEST		13
#تعریف_کړه SSH2_AGENT_SIGN_RESPONSE		14
#تعریف_کړه SSH2_AGENTC_جمع_کړه_بې_اغېزه_عنصر		17
#تعریف_کړه SSH2_AGENTC_REMOVE_بې_اغېزه_عنصر		18
#تعریف_کړه SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#تعریف_کړه SSH_AGENTC_جمع_کړه_SMARTCARD_کلی		20
#تعریف_کړه SSH_AGENTC_REMOVE_SMARTCARD_کلی		21

/* lock/unlock the agent */
#تعریف_کړه SSH_AGENTC_قلف				22
#تعریف_کړه SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#تعریف_کړه SSH_AGENTC_جمع_کړه_RSA_ID_CONSTRAINED	24
#تعریف_کړه SSH2_AGENTC_جمع_کړه_ID_CONSTRAINED		25
#تعریف_کړه SSH_AGENTC_جمع_کړه_SMARTCARD_کلی_CONSTRAINED 26

/* generic extension mechanism */
#تعریف_کړه SSH_AGENTC_EXTENSION			27
#تعریف_کړه SSH_AGENT_EXTENSION_FAILURE		28
#تعریف_کړه SSH_AGENT_EXTENSION_RESPONSE		29

#تعریف_کړه	SSH_AGENT_CONSTRAIN_LIFETIME		1
#تعریف_کړه	SSH_AGENT_CONSTRAIN_CONFIRM		2
#تعریف_کړه	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#تعریف_کړه SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#تعریف_کړه SSH_COM_AGENT2_FAILURE			102

#تعریف_کړه	SSH_AGENT_OLD_SIGNATURE			0x01
#تعریف_کړه	SSH_AGENT_RSA_SHA2_256			0x02
#تعریف_کړه	SSH_AGENT_RSA_SHA2_512			0x04

#د_که_پای				/* AUTHFD_H */
