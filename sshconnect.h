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

ਬਣਤਰ sshkey;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ Sensitive Sensitive;
ਬਣਤਰ Sensitive {
	ਬਣਤਰ sshkey	**ਕੁੰਜੀਆਂ;
	ਪੂਰਨ		nkeys;
};

ਬਣਤਰ ssh_conn_info {
	ਅੱਖਰ *conn_hash_hex;
	ਅੱਖਰ *shorthost;
	ਅੱਖਰ *uidstr;
	ਅੱਖਰ *keyalias;
	ਅੱਖਰ *thishost;
	ਅੱਖਰ *host_arg;
	ਅੱਖਰ *portstr;
	ਅੱਖਰ *remhost;
	ਅੱਖਰ *remuser;
	ਅੱਖਰ *homedir;
	ਅੱਖਰ *locuser;
	ਅੱਖਰ *jmphost;
};

ਬਣਤਰ addrinfo;
ਬਣਤਰ ssh;
ਬਣਤਰ hostkeys;

/* default argument for client percent expansions, minus remote user */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_CLIENT_PERCENT_EXPAND_ਦਲੀਲਾਂ_NOUSER(conn_info) \
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
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_CLIENT_PERCENT_EXPAND_ਦਲੀਲਾਂ(conn_info) \
	DEFAULT_CLIENT_PERCENT_EXPAND_ਦਲੀਲਾਂ_NOUSER(conn_info), \
	"C", conn_info->conn_hash_hex, \
	"r", conn_info->remuser

ਪੂਰਨ	 ssh_connect(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
	    ਬਣਤਰ addrinfo *, ਬਣਤਰ sockaddr_storage *, u_short,
	    ਪੂਰਨ, ਪੂਰਨ *, ਪੂਰਨ);
ਖਾਲੀ	 ssh_kill_proxy_command(ਖਾਲੀ);

ਖਾਲੀ	 ssh_login(ਬਣਤਰ ssh *, Sensitive *, ਅਚਲ ਅੱਖਰ *,
    ਬਣਤਰ sockaddr_storage *, u_short, ਬਣਤਰ passwd *, ਪੂਰਨ,
    ਅਚਲ ਬਣਤਰ ssh_conn_info *);

ਪੂਰਨ	 verify_host_ਕੁੰਜੀ(ਅੱਖਰ *, ਬਣਤਰ sockaddr *, ਬਣਤਰ sshkey *,
    ਅਚਲ ਬਣਤਰ ssh_conn_info *);

ਖਾਲੀ	 get_hostfile_hostname_ipaddr(ਅੱਖਰ *, ਬਣਤਰ sockaddr *, u_short,
    ਅੱਖਰ **, ਅੱਖਰ **);

ਖਾਲੀ	 ssh_kex2(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *, ਬਣਤਰ sockaddr_storage *, u_short,
    ਅਚਲ ਬਣਤਰ ssh_conn_info *);

ਖਾਲੀ	 ssh_userauth2(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਅੱਖਰ *, Sensitive *);

ਖਾਲੀ	 pubkey_dump(ਬਣਤਰ ssh *);

ਪੂਰਨ	 ssh_local_cmd(ਅਚਲ ਅੱਖਰ *);

ਖਾਲੀ	 maybe_ਜੋੜੋ_ਕੁੰਜੀ_ਮੰਜ਼ਿਲ_agent(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshkey *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

ਖਾਲੀ	 ਲੱਦੋ_hostkeys_command(ਬਣਤਰ hostkeys *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਬਣਤਰ ssh_conn_info *,
    ਅਚਲ ਬਣਤਰ sshkey *, ਅਚਲ ਅੱਖਰ *);

ਪੂਰਨ hostkey_accepted_by_hostkeyalgs(ਅਚਲ ਬਣਤਰ sshkey *);

ਖਾਲੀ ssh_conn_info_free(ਬਣਤਰ ssh_conn_info *);
ਬਣਤਰ ssh_conn_info *ssh_conn_info_dup(ਅਚਲ ਬਣਤਰ ssh_conn_info *);
