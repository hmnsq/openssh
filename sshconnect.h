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

ساخت sshkey;

قسمتعریف ساخت Sensitive Sensitive;
ساخت Sensitive {
	ساخت sshkey	**کلیدیں;
	صحیح		nkeys;
};

ساخت ssh_conn_info {
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

ساخت addrinfo;
ساخت ssh;
ساخت hostkeys;

/* default argument for client percent expansions, minus remote user */
#تعریف_کرو DEFAULT_CLIENT_PERCENT_EXPAND_دلائل_NOUSER(conn_info) \
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
#تعریف_کرو DEFAULT_CLIENT_PERCENT_EXPAND_دلائل(conn_info) \
	DEFAULT_CLIENT_PERCENT_EXPAND_دلائل_NOUSER(conn_info), \
	"C", conn_info->conn_hash_hex, \
	"r", conn_info->remuser

صحیح	 ssh_connect(ساخت ssh *, ثابت حرف *, ثابت حرف *,
	    ساخت addrinfo *, ساخت sockaddr_storage *, u_short,
	    صحیح, صحیح *, صحیح);
خالی	 ssh_kill_proxy_command(خالی);

خالی	 ssh_login(ساخت ssh *, Sensitive *, ثابت حرف *,
    ساخت sockaddr_storage *, u_short, ساخت passwd *, صحیح,
    ثابت ساخت ssh_conn_info *);

صحیح	 verify_host_کلید(حرف *, ساخت sockaddr *, ساخت sshkey *,
    ثابت ساخت ssh_conn_info *);

خالی	 get_hostfile_hostname_ipaddr(حرف *, ساخت sockaddr *, u_short,
    حرف **, حرف **);

خالی	 ssh_kex2(ساخت ssh *ssh, حرف *, ساخت sockaddr_storage *, u_short,
    ثابت ساخت ssh_conn_info *);

خالی	 ssh_userauth2(ساخت ssh *ssh, ثابت حرف *, ثابت حرف *,
    حرف *, Sensitive *);

خالی	 pubkey_dump(ساخت ssh *);

صحیح	 ssh_local_cmd(ثابت حرف *);

خالی	 maybe_جوڑو_کلید_مقصد_agent(ثابت حرف *, ساخت sshkey *,
    ثابت حرف *, ثابت حرف *);

خالی	 بھرو_hostkeys_command(ساخت hostkeys *, ثابت حرف *,
    ثابت حرف *, ثابت ساخت ssh_conn_info *,
    ثابت ساخت sshkey *, ثابت حرف *);

صحیح hostkey_accepted_by_hostkeyalgs(ثابت ساخت sshkey *);

خالی ssh_conn_info_free(ساخت ssh_conn_info *);
ساخت ssh_conn_info *ssh_conn_info_dup(ثابت ساخت ssh_conn_info *);
