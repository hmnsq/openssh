/* $OpenBSD: sshconnect.h,v 1.52 2026/08/03 06:47:24 djm Exp $ */

/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

ರಚನೆ sshkey;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Sensitive Sensitive;
ರಚನೆ Sensitive {
	ರಚನೆ sshkey	**ಕೀಲಿಗಳು;
	ಪೂರ್ಣಾಂಕ		nkeys;
};

ರಚನೆ ssh_conn_info {
	ಅಕ್ಷರ *conn_hash_hex;
	ಅಕ್ಷರ *shorthost;
	ಅಕ್ಷರ *uidstr;
	ಅಕ್ಷರ *keyalias;
	ಅಕ್ಷರ *thishost;
	ಅಕ್ಷರ *host_arg;
	ಅಕ್ಷರ *portstr;
	ಅಕ್ಷರ *remhost;
	ಅಕ್ಷರ *remuser;
	ಅಕ್ಷರ *homedir;
	ಅಕ್ಷರ *locuser;
	ಅಕ್ಷರ *jmphost;
};

ರಚನೆ addrinfo;
ರಚನೆ ssh;
ರಚನೆ hostkeys;

/* default argument for client percent expansions, minus remote user */
#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_CLIENT_PERCENT_EXPAND_ವಾದಗಳು_NOUSER(conn_info) \
	"L", conn_info->shorthost, \
	"i", conn_info->uidstr, \
	"k", conn_info->keyalias, \
	"l", conn_info->thishost, \
	"n", conn_info->host_arg, \
	"p", conn_info->portstr, \
	"d", conn_info->homedir, \
	"h", conn_info->remhost, \
	"u", conn_info->locuser, \
	"j", conn_info->jmphost

/* same plus remote user and hash which has user as a component */
#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_CLIENT_PERCENT_EXPAND_ವಾದಗಳು(conn_info) \
	DEFAULT_CLIENT_PERCENT_EXPAND_ವಾದಗಳು_NOUSER(conn_info), \
	"C", conn_info->conn_hash_hex, \
	"r", conn_info->remuser

ಪೂರ್ಣಾಂಕ	 ssh_connect(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
	    ರಚನೆ addrinfo *, ರಚನೆ sockaddr_storage *, u_short,
	    ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 ssh_kill_proxy_command(ಶೂನ್ಯ);

ಶೂನ್ಯ	 ssh_login(ರಚನೆ ssh *, Sensitive *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ರಚನೆ sockaddr_storage *, u_short, ರಚನೆ passwd *, ಪೂರ್ಣಾಂಕ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *);

ಪೂರ್ಣಾಂಕ	 verify_host_ಕೀಲಿ(ಅಕ್ಷರ *, ರಚನೆ sockaddr *, ರಚನೆ sshkey *,
    ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *);

ಶೂನ್ಯ	 get_hostfile_hostname_ipaddr(ಅಕ್ಷರ *, ರಚನೆ sockaddr *, u_short,
    ಅಕ್ಷರ **, ಅಕ್ಷರ **);

ಶೂನ್ಯ	 ssh_kex2(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *, ರಚನೆ sockaddr_storage *, u_short,
    ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *);

ಶೂನ್ಯ	 ssh_userauth2(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಅಕ್ಷರ *, Sensitive *);

ಶೂನ್ಯ	 pubkey_dump(ರಚನೆ ssh *);

ಪೂರ್ಣಾಂಕ	 ssh_local_cmd(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಶೂನ್ಯ	 maybe_ಕೂಡಿಸು_ಕೀಲಿ_ಗಮ್ಯ_agent(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshkey *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಶೂನ್ಯ	 ತುಂಬು_hostkeys_command(ರಚನೆ hostkeys *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಪೂರ್ಣಾಂಕ hostkey_accepted_by_hostkeyalgs(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);

ಶೂನ್ಯ ssh_conn_info_free(ರಚನೆ ssh_conn_info *);
ರಚನೆ ssh_conn_info *ssh_conn_info_dup(ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *);
