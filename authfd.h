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

#جيڪڏهن_وصف_نه_ٿيل AUTHFD_H
#وصف_ڪريو AUTHFD_H

بنية sshbuf;
بنية sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
بنية ssh_identitylist {
	سائيز_t nkeys;
	بنية sshkey **ڪنجيون;
	حرف **comments;
};

/* Key destination restrictions */
بنية dest_constraint_hop {
	حرف *user;	/* wildcards allowed */
	حرف *hostname; /* used to matching cert principals and for display */
	صحيح is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	بنية sshkey **ڪنجيون;
	صحيح *ڪنجي_is_ca;
};
بنية dest_constraint {
	بنية dest_constraint_hop from;
	بنية dest_constraint_hop منزل;
};

صحيح	ssh_get_authentication_socket(صحيح *fdp);
صحيح	ssh_get_authentication_socket_رستو(ثابت حرف *authsocket, صحيح *fdp);
فراغ	ssh_close_authentication_socket(صحيح sock);

صحيح	ssh_تالو_agent(صحيح sock, صحيح تالو, ثابت حرف *password);
صحيح	ssh_fetch_identitylist(صحيح sock, بنية ssh_identitylist **idlp);
فراغ	ssh_free_identitylist(بنية ssh_identitylist *idl);
صحيح	ssh_جوڙيو_سڃاڻپ_عنصر_constrained(صحيح sock, بنية sshkey *ڪنجي,
    ثابت حرف *comment, u_int life, u_int confirm, ثابت حرف *provider,
    بنية dest_constraint **dest_constraints, سائيز_t ndest_constraints);
صحيح	ssh_agent_has_ڪنجي(صحيح sock, ثابت بنية sshkey *ڪنجي);
صحيح	ssh_remove_سڃاڻپ_عنصر(صحيح sock, ثابت بنية sshkey *ڪنجي);
صحيح	ssh_update_card(صحيح sock, صحيح جوڙيو, ثابت حرف *reader_id,
	    ثابت حرف *pin, u_int life, u_int confirm,
	    بنية dest_constraint **dest_constraints,
	    سائيز_t ndest_constraints,
	    صحيح cert_only, بنية sshkey **certs, سائيز_t ncerts);
صحيح	ssh_remove_all_identities(صحيح sock, صحيح نسخو);

صحيح	ssh_agent_sign(صحيح sock, ثابت بنية sshkey *ڪنجي,
	    u_char **sigp, سائيز_t *lenp,
	    ثابت u_char *معلومات, سائيز_t datalen, ثابت حرف *alg, u_int compat);

صحيح	ssh_agent_bind_hostkey(صحيح sock, ثابت بنية sshkey *ڪنجي,
    ثابت بنية sshbuf *session_id, ثابت بنية sshbuf *signature,
    صحيح forwarding);

صحيح	ssh_agent_query_extensions(صحيح sock, حرف ***exts);

/* Messages for the authentication agent connection. */
#وصف_ڪريو SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#وصف_ڪريو SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#وصف_ڪريو SSH_AGENTC_RSA_CHALLENGE		3
#وصف_ڪريو SSH_AGENT_RSA_RESPONSE			4
#وصف_ڪريو SSH_AGENT_FAILURE			5
#وصف_ڪريو SSH_AGENT_SUCCESS			6
#وصف_ڪريو SSH_AGENTC_جوڙيو_RSA_سڃاڻپ_عنصر		7
#وصف_ڪريو SSH_AGENTC_REMOVE_RSA_سڃاڻپ_عنصر		8
#وصف_ڪريو SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#وصف_ڪريو SSH2_AGENTC_REQUEST_IDENTITIES		11
#وصف_ڪريو SSH2_AGENT_IDENTITIES_ANSWER		12
#وصف_ڪريو SSH2_AGENTC_SIGN_REQUEST		13
#وصف_ڪريو SSH2_AGENT_SIGN_RESPONSE		14
#وصف_ڪريو SSH2_AGENTC_جوڙيو_سڃاڻپ_عنصر		17
#وصف_ڪريو SSH2_AGENTC_REMOVE_سڃاڻپ_عنصر		18
#وصف_ڪريو SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#وصف_ڪريو SSH_AGENTC_جوڙيو_SMARTCARD_ڪنجي		20
#وصف_ڪريو SSH_AGENTC_REMOVE_SMARTCARD_ڪنجي		21

/* lock/unlock the agent */
#وصف_ڪريو SSH_AGENTC_تالو				22
#وصف_ڪريو SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#وصف_ڪريو SSH_AGENTC_جوڙيو_RSA_ID_CONSTRAINED	24
#وصف_ڪريو SSH2_AGENTC_جوڙيو_ID_CONSTRAINED		25
#وصف_ڪريو SSH_AGENTC_جوڙيو_SMARTCARD_ڪنجي_CONSTRAINED 26

/* generic extension mechanism */
#وصف_ڪريو SSH_AGENTC_EXTENSION			27
#وصف_ڪريو SSH_AGENT_EXTENSION_FAILURE		28
#وصف_ڪريو SSH_AGENT_EXTENSION_RESPONSE		29

#وصف_ڪريو	SSH_AGENT_CONSTRAIN_LIFETIME		1
#وصف_ڪريو	SSH_AGENT_CONSTRAIN_CONFIRM		2
#وصف_ڪريو	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#وصف_ڪريو SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#وصف_ڪريو SSH_COM_AGENT2_FAILURE			102

#وصف_ڪريو	SSH_AGENT_OLD_SIGNATURE			0x01
#وصف_ڪريو	SSH_AGENT_RSA_SHA2_256			0x02
#وصف_ڪريو	SSH_AGENT_RSA_SHA2_512			0x04

#جيڪڏهن_پورو				/* AUTHFD_H */
