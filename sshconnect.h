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

கட்டமைப்பு sshkey;

வகைவரை கட்டமைப்பு Sensitive Sensitive;
கட்டமைப்பு Sensitive {
	கட்டமைப்பு sshkey	**சாவிகள்;
	முழு		nkeys;
};

கட்டமைப்பு ssh_conn_info {
	எழுத்து *conn_hash_hex;
	எழுத்து *shorthost;
	எழுத்து *uidstr;
	எழுத்து *keyalias;
	எழுத்து *thishost;
	எழுத்து *host_arg;
	எழுத்து *portstr;
	எழுத்து *remhost;
	எழுத்து *remuser;
	எழுத்து *homedir;
	எழுத்து *locuser;
	எழுத்து *jmphost;
};

கட்டமைப்பு addrinfo;
கட்டமைப்பு ssh;
கட்டமைப்பு hostkeys;

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

முழு	 ssh_connect(கட்டமைப்பு ssh *, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
	    கட்டமைப்பு addrinfo *, கட்டமைப்பு sockaddr_storage *, u_short,
	    முழு, முழு *, முழு);
வெறுமை	 ssh_kill_proxy_command(வெறுமை);

வெறுமை	 ssh_login(கட்டமைப்பு ssh *, Sensitive *, மாறிலி எழுத்து *,
    கட்டமைப்பு sockaddr_storage *, u_short, கட்டமைப்பு passwd *, முழு,
    மாறிலி கட்டமைப்பு ssh_conn_info *);

முழு	 verify_host_சாவி(எழுத்து *, கட்டமைப்பு sockaddr *, கட்டமைப்பு sshkey *,
    மாறிலி கட்டமைப்பு ssh_conn_info *);

வெறுமை	 get_hostfile_hostname_ipaddr(எழுத்து *, கட்டமைப்பு sockaddr *, u_short,
    எழுத்து **, எழுத்து **);

வெறுமை	 ssh_kex2(கட்டமைப்பு ssh *ssh, எழுத்து *, கட்டமைப்பு sockaddr_storage *, u_short,
    மாறிலி கட்டமைப்பு ssh_conn_info *);

வெறுமை	 ssh_userauth2(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    எழுத்து *, Sensitive *);

வெறுமை	 pubkey_dump(கட்டமைப்பு ssh *);

முழு	 ssh_local_cmd(மாறிலி எழுத்து *);

வெறுமை	 maybe_add_சாவி_to_agent(மாறிலி எழுத்து *, கட்டமைப்பு sshkey *,
    மாறிலி எழுத்து *, மாறிலி எழுத்து *);

வெறுமை	 load_hostkeys_command(கட்டமைப்பு hostkeys *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, மாறிலி கட்டமைப்பு ssh_conn_info *,
    மாறிலி கட்டமைப்பு sshkey *, மாறிலி எழுத்து *);

முழு hostkey_accepted_by_hostkeyalgs(மாறிலி கட்டமைப்பு sshkey *);

வெறுமை ssh_conn_info_free(கட்டமைப்பு ssh_conn_info *);
கட்டமைப்பு ssh_conn_info *ssh_conn_info_dup(மாறிலி கட்டமைப்பு ssh_conn_info *);
