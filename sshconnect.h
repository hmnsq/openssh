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

संरचना sshkey;

प्रकारनिर्देश संरचना Sensitive Sensitive;
संरचना Sensitive {
	संरचना sshkey	**कुञ्चिकाः;
	पूर्णाङ्क		nkeys;
};

संरचना ssh_conn_info {
	वर्ण *conn_hash_hex;
	वर्ण *shorthost;
	वर्ण *uidstr;
	वर्ण *keyalias;
	वर्ण *thishost;
	वर्ण *host_arg;
	वर्ण *portstr;
	वर्ण *remhost;
	वर्ण *remuser;
	वर्ण *homedir;
	वर्ण *locuser;
	वर्ण *jmphost;
};

संरचना addrinfo;
संरचना ssh;
संरचना hostkeys;

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

पूर्णाङ्क	 ssh_connect(संरचना ssh *, ध्रुव वर्ण *, ध्रुव वर्ण *,
	    संरचना addrinfo *, संरचना sockaddr_storage *, u_short,
	    पूर्णाङ्क, पूर्णाङ्क *, पूर्णाङ्क);
शून्य	 ssh_kill_proxy_command(शून्य);

शून्य	 ssh_login(संरचना ssh *, Sensitive *, ध्रुव वर्ण *,
    संरचना sockaddr_storage *, u_short, संरचना passwd *, पूर्णाङ्क,
    ध्रुव संरचना ssh_conn_info *);

पूर्णाङ्क	 verify_host_कुञ्चिका(वर्ण *, संरचना sockaddr *, संरचना sshkey *,
    ध्रुव संरचना ssh_conn_info *);

शून्य	 get_hostfile_hostname_ipaddr(वर्ण *, संरचना sockaddr *, u_short,
    वर्ण **, वर्ण **);

शून्य	 ssh_kex2(संरचना ssh *ssh, वर्ण *, संरचना sockaddr_storage *, u_short,
    ध्रुव संरचना ssh_conn_info *);

शून्य	 ssh_userauth2(संरचना ssh *ssh, ध्रुव वर्ण *, ध्रुव वर्ण *,
    वर्ण *, Sensitive *);

शून्य	 pubkey_dump(संरचना ssh *);

पूर्णाङ्क	 ssh_local_cmd(ध्रुव वर्ण *);

शून्य	 maybe_add_कुञ्चिका_to_agent(ध्रुव वर्ण *, संरचना sshkey *,
    ध्रुव वर्ण *, ध्रुव वर्ण *);

शून्य	 load_hostkeys_command(संरचना hostkeys *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, ध्रुव संरचना ssh_conn_info *,
    ध्रुव संरचना sshkey *, ध्रुव वर्ण *);

पूर्णाङ्क hostkey_accepted_by_hostkeyalgs(ध्रुव संरचना sshkey *);

शून्य ssh_conn_info_free(संरचना ssh_conn_info *);
संरचना ssh_conn_info *ssh_conn_info_dup(ध्रुव संरचना ssh_conn_info *);
