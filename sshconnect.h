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

સંરચના sshkey;

પ્રકારવ્યાખ્યા સંરચના Sensitive Sensitive;
સંરચના Sensitive {
	સંરચના sshkey	**ચાવીઓ;
	પૂર્ણાંક		nkeys;
};

સંરચના ssh_conn_info {
	અક્ષર *conn_hash_hex;
	અક્ષર *shorthost;
	અક્ષર *uidstr;
	અક્ષર *keyalias;
	અક્ષર *thishost;
	અક્ષર *host_arg;
	અક્ષર *portstr;
	અક્ષર *remhost;
	અક્ષર *remuser;
	અક્ષર *homedir;
	અક્ષર *locuser;
	અક્ષર *jmphost;
};

સંરચના addrinfo;
સંરચના ssh;
સંરચના hostkeys;

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

પૂર્ણાંક	 ssh_connect(સંરચના ssh *, અચલ અક્ષર *, અચલ અક્ષર *,
	    સંરચના addrinfo *, સંરચના sockaddr_storage *, u_short,
	    પૂર્ણાંક, પૂર્ણાંક *, પૂર્ણાંક);
શૂન્ય	 ssh_kill_proxy_command(શૂન્ય);

શૂન્ય	 ssh_login(સંરચના ssh *, Sensitive *, અચલ અક્ષર *,
    સંરચના sockaddr_storage *, u_short, સંરચના passwd *, પૂર્ણાંક,
    અચલ સંરચના ssh_conn_info *);

પૂર્ણાંક	 verify_host_ચાવી(અક્ષર *, સંરચના sockaddr *, સંરચના sshkey *,
    અચલ સંરચના ssh_conn_info *);

શૂન્ય	 get_hostfile_hostname_ipaddr(અક્ષર *, સંરચના sockaddr *, u_short,
    અક્ષર **, અક્ષર **);

શૂન્ય	 ssh_kex2(સંરચના ssh *ssh, અક્ષર *, સંરચના sockaddr_storage *, u_short,
    અચલ સંરચના ssh_conn_info *);

શૂન્ય	 ssh_userauth2(સંરચના ssh *ssh, અચલ અક્ષર *, અચલ અક્ષર *,
    અક્ષર *, Sensitive *);

શૂન્ય	 pubkey_dump(સંરચના ssh *);

પૂર્ણાંક	 ssh_local_cmd(અચલ અક્ષર *);

શૂન્ય	 maybe_add_ચાવી_to_agent(અચલ અક્ષર *, સંરચના sshkey *,
    અચલ અક્ષર *, અચલ અક્ષર *);

શૂન્ય	 load_hostkeys_command(સંરચના hostkeys *, અચલ અક્ષર *,
    અચલ અક્ષર *, અચલ સંરચના ssh_conn_info *,
    અચલ સંરચના sshkey *, અચલ અક્ષર *);

પૂર્ણાંક hostkey_accepted_by_hostkeyalgs(અચલ સંરચના sshkey *);

શૂન્ય ssh_conn_info_free(સંરચના ssh_conn_info *);
સંરચના ssh_conn_info *ssh_conn_info_dup(અચલ સંરચના ssh_conn_info *);
