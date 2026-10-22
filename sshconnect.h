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

ಸಂರಚನಾ sshkey;

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ Sensitive Sensitive;
ಸಂರಚನಾ Sensitive {
	ಸಂರಚನಾ sshkey	**ಕೀಲಿಗಳು;
	ಪೂರ್ಣಾಙ್ಕ		nkeys;
};

ಸಂರಚನಾ ssh_conn_info {
	ವರ್ಣ *conn_hash_hex;
	ವರ್ಣ *shorthost;
	ವರ್ಣ *uidstr;
	ವರ್ಣ *keyalias;
	ವರ್ಣ *thishost;
	ವರ್ಣ *host_arg;
	ವರ್ಣ *portstr;
	ವರ್ಣ *remhost;
	ವರ್ಣ *remuser;
	ವರ್ಣ *homedir;
	ವರ್ಣ *locuser;
	ವರ್ಣ *jmphost;
};

ಸಂರಚನಾ addrinfo;
ಸಂರಚನಾ ssh;
ಸಂರಚನಾ hostkeys;

/* default argument for client percent expansions, minus remote user */
#define DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(conn_info) \
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
#define DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(conn_info) \
	DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(conn_info), \
	"C", conn_info->conn_hash_hex, \
	"r", conn_info->remuser

ಪೂರ್ಣಾಙ್ಕ	 ssh_connect(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
	    ಸಂರಚನಾ addrinfo *, ಸಂರಚನಾ sockaddr_storage *, u_short,
	    ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 ssh_kill_proxy_command(ಶೂನ್ಯ);

ಶೂನ್ಯ	 ssh_login(ಸಂರಚನಾ ssh *, Sensitive *, ಧ್ರುವ ವರ್ಣ *,
    ಸಂರಚನಾ sockaddr_storage *, u_short, ಸಂರಚನಾ passwd *, ಪೂರ್ಣಾಙ್ಕ,
    ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *);

ಪೂರ್ಣಾಙ್ಕ	 verify_host_ಕೀಲಿ(ವರ್ಣ *, ಸಂರಚನಾ sockaddr *, ಸಂರಚನಾ sshkey *,
    ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *);

ಶೂನ್ಯ	 get_hostfile_hostname_ipaddr(ವರ್ಣ *, ಸಂರಚನಾ sockaddr *, u_short,
    ವರ್ಣ **, ವರ್ಣ **);

ಶೂನ್ಯ	 ssh_kex2(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *, ಸಂರಚನಾ sockaddr_storage *, u_short,
    ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *);

ಶೂನ್ಯ	 ssh_userauth2(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    ವರ್ಣ *, Sensitive *);

ಶೂನ್ಯ	 pubkey_dump(ಸಂರಚನಾ ssh *);

ಪೂರ್ಣಾಙ್ಕ	 ssh_local_cmd(ಧ್ರುವ ವರ್ಣ *);

ಶೂನ್ಯ	 maybe_add_ಕೀಲಿ_to_agent(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshkey *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

ಶೂನ್ಯ	 load_hostkeys_command(ಸಂರಚನಾ hostkeys *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಧ್ರುವ ವರ್ಣ *);

ಪೂರ್ಣಾಙ್ಕ hostkey_accepted_by_hostkeyalgs(ಧ್ರುವ ಸಂರಚನಾ sshkey *);

ಶೂನ್ಯ ssh_conn_info_free(ಸಂರಚನಾ ssh_conn_info *);
ಸಂರಚನಾ ssh_conn_info *ssh_conn_info_dup(ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *);
