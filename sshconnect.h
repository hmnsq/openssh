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

ساختار sshkey;

تعریفنوع ساختار Sensitive Sensitive;
ساختار Sensitive {
	ساختار sshkey	**کلیدها;
	صحیح		nkeys;
};

ساختار ssh_conn_info {
	نویسه *conn_hash_hex;
	نویسه *shorthost;
	نویسه *uidstr;
	نویسه *keyalias;
	نویسه *thishost;
	نویسه *host_arg;
	نویسه *portstr;
	نویسه *remhost;
	نویسه *remuser;
	نویسه *homedir;
	نویسه *locuser;
	نویسه *jmphost;
};

ساختار addrinfo;
ساختار ssh;
ساختار hostkeys;

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

صحیح	 ssh_connect(ساختار ssh *, ثابت نویسه *, ثابت نویسه *,
	    ساختار addrinfo *, ساختار sockaddr_storage *, u_short,
	    صحیح, صحیح *, صحیح);
تهی	 ssh_kill_proxy_command(تهی);

تهی	 ssh_login(ساختار ssh *, Sensitive *, ثابت نویسه *,
    ساختار sockaddr_storage *, u_short, ساختار passwd *, صحیح,
    ثابت ساختار ssh_conn_info *);

صحیح	 verify_host_کلید(نویسه *, ساختار sockaddr *, ساختار sshkey *,
    ثابت ساختار ssh_conn_info *);

تهی	 get_hostfile_hostname_ipaddr(نویسه *, ساختار sockaddr *, u_short,
    نویسه **, نویسه **);

تهی	 ssh_kex2(ساختار ssh *ssh, نویسه *, ساختار sockaddr_storage *, u_short,
    ثابت ساختار ssh_conn_info *);

تهی	 ssh_userauth2(ساختار ssh *ssh, ثابت نویسه *, ثابت نویسه *,
    نویسه *, Sensitive *);

تهی	 pubkey_dump(ساختار ssh *);

صحیح	 ssh_local_cmd(ثابت نویسه *);

تهی	 maybe_add_کلید_to_agent(ثابت نویسه *, ساختار sshkey *,
    ثابت نویسه *, ثابت نویسه *);

تهی	 load_hostkeys_command(ساختار hostkeys *, ثابت نویسه *,
    ثابت نویسه *, ثابت ساختار ssh_conn_info *,
    ثابت ساختار sshkey *, ثابت نویسه *);

صحیح hostkey_accepted_by_hostkeyalgs(ثابت ساختار sshkey *);

تهی ssh_conn_info_free(ساختار ssh_conn_info *);
ساختار ssh_conn_info *ssh_conn_info_dup(ثابت ساختار ssh_conn_info *);
