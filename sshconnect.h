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

بنية sshkey;

تعريفنوع بنية Sensitive Sensitive;
بنية Sensitive {
	بنية sshkey	**مفاتيح;
	صحيح		nkeys;
};

بنية ssh_conn_info {
	حرف *conn_hash_hex;
	حرف *shorthost;
	حرف *uidstr;
	حرف *keyalias;
	حرف *thishost;
	حرف *host_arg;
	حرف *portstr;
	حرف *remhost;
	حرف *remuser;
	حرف *homedir;
	حرف *locuser;
	حرف *jmphost;
};

بنية addrinfo;
بنية ssh;
بنية hostkeys;

/* default argument for client percent expansions, minus remote user */
#define DEFAULT_CLIENT_PERCENT_EXPAND_وسائط_NOUSER(conn_info) \
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
#define DEFAULT_CLIENT_PERCENT_EXPAND_وسائط(conn_info) \
	DEFAULT_CLIENT_PERCENT_EXPAND_وسائط_NOUSER(conn_info), \
	"C", conn_info->conn_hash_hex, \
	"r", conn_info->remuser

صحيح	 ssh_connect(بنية ssh *, ثابت حرف *, ثابت حرف *,
	    بنية addrinfo *, بنية sockaddr_storage *, u_short,
	    صحيح, صحيح *, صحيح);
فراغ	 ssh_kill_proxy_command(فراغ);

فراغ	 ssh_login(بنية ssh *, Sensitive *, ثابت حرف *,
    بنية sockaddr_storage *, u_short, بنية passwd *, صحيح,
    ثابت بنية ssh_conn_info *);

صحيح	 verify_host_مفتاح(حرف *, بنية sockaddr *, بنية sshkey *,
    ثابت بنية ssh_conn_info *);

فراغ	 get_hostfile_hostname_ipaddr(حرف *, بنية sockaddr *, u_short,
    حرف **, حرف **);

فراغ	 ssh_kex2(بنية ssh *ssh, حرف *, بنية sockaddr_storage *, u_short,
    ثابت بنية ssh_conn_info *);

فراغ	 ssh_userauth2(بنية ssh *ssh, ثابت حرف *, ثابت حرف *,
    حرف *, Sensitive *);

فراغ	 pubkey_dump(بنية ssh *);

صحيح	 ssh_local_cmd(ثابت حرف *);

فراغ	 maybe_add_مفتاح_to_agent(ثابت حرف *, بنية sshkey *,
    ثابت حرف *, ثابت حرف *);

فراغ	 load_hostkeys_command(بنية hostkeys *, ثابت حرف *,
    ثابت حرف *, ثابت بنية ssh_conn_info *,
    ثابت بنية sshkey *, ثابت حرف *);

صحيح hostkey_accepted_by_hostkeyalgs(ثابت بنية sshkey *);

فراغ ssh_conn_info_free(بنية ssh_conn_info *);
بنية ssh_conn_info *ssh_conn_info_dup(ثابت بنية ssh_conn_info *);
