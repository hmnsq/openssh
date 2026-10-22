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

ഘടന sshkey;

തരനിർവചനം ഘടന Sensitive Sensitive;
ഘടന Sensitive {
	ഘടന sshkey	**താക്കോലുകൾ;
	പൂർണ്ണസംഖ്യ		nkeys;
};

ഘടന ssh_conn_info {
	അക്ഷരം *conn_hash_hex;
	അക്ഷരം *shorthost;
	അക്ഷരം *uidstr;
	അക്ഷരം *keyalias;
	അക്ഷരം *thishost;
	അക്ഷരം *host_arg;
	അക്ഷരം *portstr;
	അക്ഷരം *remhost;
	അക്ഷരം *remuser;
	അക്ഷരം *homedir;
	അക്ഷരം *locuser;
	അക്ഷരം *jmphost;
};

ഘടന addrinfo;
ഘടന ssh;
ഘടന hostkeys;

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

പൂർണ്ണസംഖ്യ	 ssh_connect(ഘടന ssh *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
	    ഘടന addrinfo *, ഘടന sockaddr_storage *, u_short,
	    പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ *, പൂർണ്ണസംഖ്യ);
ശൂന്യം	 ssh_kill_proxy_command(ശൂന്യം);

ശൂന്യം	 ssh_login(ഘടന ssh *, Sensitive *, സ്ഥിരം അക്ഷരം *,
    ഘടന sockaddr_storage *, u_short, ഘടന passwd *, പൂർണ്ണസംഖ്യ,
    സ്ഥിരം ഘടന ssh_conn_info *);

പൂർണ്ണസംഖ്യ	 verify_host_താക്കോൽ(അക്ഷരം *, ഘടന sockaddr *, ഘടന sshkey *,
    സ്ഥിരം ഘടന ssh_conn_info *);

ശൂന്യം	 get_hostfile_hostname_ipaddr(അക്ഷരം *, ഘടന sockaddr *, u_short,
    അക്ഷരം **, അക്ഷരം **);

ശൂന്യം	 ssh_kex2(ഘടന ssh *ssh, അക്ഷരം *, ഘടന sockaddr_storage *, u_short,
    സ്ഥിരം ഘടന ssh_conn_info *);

ശൂന്യം	 ssh_userauth2(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    അക്ഷരം *, Sensitive *);

ശൂന്യം	 pubkey_dump(ഘടന ssh *);

പൂർണ്ണസംഖ്യ	 ssh_local_cmd(സ്ഥിരം അക്ഷരം *);

ശൂന്യം	 maybe_add_താക്കോൽ_to_agent(സ്ഥിരം അക്ഷരം *, ഘടന sshkey *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

ശൂന്യം	 load_hostkeys_command(ഘടന hostkeys *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം ഘടന ssh_conn_info *,
    സ്ഥിരം ഘടന sshkey *, സ്ഥിരം അക്ഷരം *);

പൂർണ്ണസംഖ്യ hostkey_accepted_by_hostkeyalgs(സ്ഥിരം ഘടന sshkey *);

ശൂന്യം ssh_conn_info_free(ഘടന ssh_conn_info *);
ഘടന ssh_conn_info *ssh_conn_info_dup(സ്ഥിരം ഘടന ssh_conn_info *);
