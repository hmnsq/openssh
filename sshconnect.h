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

সংরচনা sshkey;

প্রকারনির্দেশ সংরচনা Sensitive Sensitive;
সংরচনা Sensitive {
	সংরচনা sshkey	**চাবিগুলি;
	পূর্ণাঙ্ক		nkeys;
};

সংরচনা ssh_conn_info {
	বর্ণ *conn_hash_hex;
	বর্ণ *shorthost;
	বর্ণ *uidstr;
	বর্ণ *keyalias;
	বর্ণ *thishost;
	বর্ণ *host_arg;
	বর্ণ *portstr;
	বর্ণ *remhost;
	বর্ণ *remuser;
	বর্ণ *homedir;
	বর্ণ *locuser;
	বর্ণ *jmphost;
};

সংরচনা addrinfo;
সংরচনা ssh;
সংরচনা hostkeys;

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

পূর্ণাঙ্ক	 ssh_connect(সংরচনা ssh *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *,
	    সংরচনা addrinfo *, সংরচনা sockaddr_storage *, u_short,
	    পূর্ণাঙ্ক, পূর্ণাঙ্ক *, পূর্ণাঙ্ক);
শূন্য	 ssh_kill_proxy_command(শূন্য);

শূন্য	 ssh_login(সংরচনা ssh *, Sensitive *, ধ্রুব বর্ণ *,
    সংরচনা sockaddr_storage *, u_short, সংরচনা passwd *, পূর্ণাঙ্ক,
    ধ্রুব সংরচনা ssh_conn_info *);

পূর্ণাঙ্ক	 verify_host_চাবি(বর্ণ *, সংরচনা sockaddr *, সংরচনা sshkey *,
    ধ্রুব সংরচনা ssh_conn_info *);

শূন্য	 get_hostfile_hostname_ipaddr(বর্ণ *, সংরচনা sockaddr *, u_short,
    বর্ণ **, বর্ণ **);

শূন্য	 ssh_kex2(সংরচনা ssh *ssh, বর্ণ *, সংরচনা sockaddr_storage *, u_short,
    ধ্রুব সংরচনা ssh_conn_info *);

শূন্য	 ssh_userauth2(সংরচনা ssh *ssh, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *,
    বর্ণ *, Sensitive *);

শূন্য	 pubkey_dump(সংরচনা ssh *);

পূর্ণাঙ্ক	 ssh_local_cmd(ধ্রুব বর্ণ *);

শূন্য	 maybe_add_চাবি_to_agent(ধ্রুব বর্ণ *, সংরচনা sshkey *,
    ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);

শূন্য	 load_hostkeys_command(সংরচনা hostkeys *, ধ্রুব বর্ণ *,
    ধ্রুব বর্ণ *, ধ্রুব সংরচনা ssh_conn_info *,
    ধ্রুব সংরচনা sshkey *, ধ্রুব বর্ণ *);

পূর্ণাঙ্ক hostkey_accepted_by_hostkeyalgs(ধ্রুব সংরচনা sshkey *);

শূন্য ssh_conn_info_free(সংরচনা ssh_conn_info *);
সংরচনা ssh_conn_info *ssh_conn_info_dup(ধ্রুব সংরচনা ssh_conn_info *);
