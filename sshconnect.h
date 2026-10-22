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

काष्ठा sshkey;

प्रकार काष्ठा Sensitive Sensitive;
काष्ठा Sensitive {
	काष्ठा sshkey	**कुंजियाँ;
	पूर्णांक		nkeys;
};

काष्ठा ssh_conn_info {
	अक्षर *conn_hash_hex;
	अक्षर *shorthost;
	अक्षर *uidstr;
	अक्षर *keyalias;
	अक्षर *thishost;
	अक्षर *host_arg;
	अक्षर *portstr;
	अक्षर *remhost;
	अक्षर *remuser;
	अक्षर *homedir;
	अक्षर *locuser;
	अक्षर *jmphost;
};

काष्ठा addrinfo;
काष्ठा ssh;
काष्ठा hostkeys;

/* default argument for client percent expansions, minus remote user */
#घोषणा DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(conn_info) \
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
#घोषणा DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(conn_info) \
	DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(conn_info), \
	"C", conn_info->conn_hash_hex, \
	"r", conn_info->remuser

पूर्णांक	 ssh_connect(काष्ठा ssh *, स्थिर अक्षर *, स्थिर अक्षर *,
	    काष्ठा addrinfo *, काष्ठा sockaddr_storage *, u_short,
	    पूर्णांक, पूर्णांक *, पूर्णांक);
व्योम	 ssh_kill_proxy_command(व्योम);

व्योम	 ssh_login(काष्ठा ssh *, Sensitive *, स्थिर अक्षर *,
    काष्ठा sockaddr_storage *, u_short, काष्ठा passwd *, पूर्णांक,
    स्थिर काष्ठा ssh_conn_info *);

पूर्णांक	 verify_host_कुंजी(अक्षर *, काष्ठा sockaddr *, काष्ठा sshkey *,
    स्थिर काष्ठा ssh_conn_info *);

व्योम	 get_hostfile_hostname_ipaddr(अक्षर *, काष्ठा sockaddr *, u_short,
    अक्षर **, अक्षर **);

व्योम	 ssh_kex2(काष्ठा ssh *ssh, अक्षर *, काष्ठा sockaddr_storage *, u_short,
    स्थिर काष्ठा ssh_conn_info *);

व्योम	 ssh_userauth2(काष्ठा ssh *ssh, स्थिर अक्षर *, स्थिर अक्षर *,
    अक्षर *, Sensitive *);

व्योम	 pubkey_dump(काष्ठा ssh *);

पूर्णांक	 ssh_local_cmd(स्थिर अक्षर *);

व्योम	 maybe_add_कुंजी_to_agent(स्थिर अक्षर *, काष्ठा sshkey *,
    स्थिर अक्षर *, स्थिर अक्षर *);

व्योम	 load_hostkeys_command(काष्ठा hostkeys *, स्थिर अक्षर *,
    स्थिर अक्षर *, स्थिर काष्ठा ssh_conn_info *,
    स्थिर काष्ठा sshkey *, स्थिर अक्षर *);

पूर्णांक hostkey_accepted_by_hostkeyalgs(स्थिर काष्ठा sshkey *);

व्योम ssh_conn_info_free(काष्ठा ssh_conn_info *);
काष्ठा ssh_conn_info *ssh_conn_info_dup(स्थिर काष्ठा ssh_conn_info *);
