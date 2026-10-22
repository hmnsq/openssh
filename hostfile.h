/* $OpenBSD: hostfile.h,v 1.29 2021/01/26 00:51:30 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
#جے_بنا_تعریف HOSTFILE_H
#تعریف_کرو HOSTFILE_H

تعريفنوع تعداد {
	HOST_OK, HOST_NEW, HOST_بدلیا, HOST_REVOKED, HOST_لبھیا
}       Host_حالت;

تعريفنوع تعداد {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

بنية hostkey_اندراج {
	حرف *host;
	حرف *file;
	u_long سطر;
	بنية sshkey *کلید;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
بنية hostkeys {
	بنية hostkey_اندراج *entries;
	u_int عدد_entries;
};

بنية hostkeys *init_hostkeys(فراغ);
فراغ	 لدو_hostkeys(بنية hostkeys *, ثابت حرف *,
    ثابت حرف *, u_int);
فراغ	 لدو_hostkeys_file(بنية hostkeys *, ثابت حرف *,
    ثابت حرف *, FILE *, u_int note);
فراغ	 free_hostkeys(بنية hostkeys *);

Host_حالت check_کلید_وچ_hostkeys(بنية hostkeys *, بنية sshkey *,
    ثابت بنية hostkey_اندراج **);
صحيح	 lookup_کلید_وچ_hostkeys_by_type(بنية hostkeys *, صحيح, صحيح,
    ثابت بنية hostkey_اندراج **);
صحيح	 lookup_marker_وچ_hostkeys(بنية hostkeys *, صحيح);

صحيح	 hostfile_read_کلید(حرف **, u_int *, بنية sshkey *);
صحيح	 جوڑو_host_منزل_hostfile(ثابت حرف *, ثابت حرف *,
    ثابت بنية sshkey *, صحيح);

صحيح	 hostfile_replace_entries(ثابت حرف *filename,
    ثابت حرف *host, ثابت حرف *ip, بنية sshkey **کلیدیں, ناپ_t nkeys,
    صحيح store_hash, صحيح quiet, صحيح hash_alg);

#تعریف_کرو HASH_MAGIC	"|1|"
#تعریف_کرو HASH_DELIM	'|'

#تعریف_کرو CA_MARKER	"@cert-authority"
#تعریف_کرو REVOKE_MARKER	"@revoked"

حرف	*host_hash(ثابت حرف *, ثابت حرف *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#تعریف_کرو HKF_WANT_میل		(1)	/* return only matching hosts/addrs */
#تعریف_کرو HKF_WANT_PARSE_کلید	(1<<1)	/* need key parsed */

#تعریف_کرو HKF_حالت_OK		0	/* Line parsed, didn't match host */
#تعریف_کرو HKF_حالت_INVALID	1	/* line had parse error */
#تعریف_کرو HKF_حالت_COMMENT	2	/* valid line contained no key */
#تعریف_کرو HKF_حالت_MATCHED	3	/* hostname or IP matched */

#تعریف_کرو HKF_میل_HOST		(1)	/* hostname matched */
#تعریف_کرو HKF_میل_IP		(1<<1)	/* address matched */
#تعریف_کرو HKF_میل_HOST_HASHED	(1<<2)	/* hostname was hashed */
#تعریف_کرو HKF_میل_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
بنية hostkey_foreach_سطر {
	ثابت حرف *رستہ; /* Path of file */
	u_long linenum;	/* Line number */
	u_int حالت;	/* One of HKF_STATUS_* */
	u_int میل;	/* Zero or more of HKF_MATCH_* OR'd together */
	حرف *سطر;	/* Entire key line; mutable by callback */
	صحيح marker;	/* CA/revocation markers; indicated by MRK_* value */
	ثابت حرف *hosts; /* Raw hosts text, may be hashed or list multiple */
	ثابت حرف *rawkey; /* Text of key and any comment following it */
	صحيح keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	بنية sshkey *کلید; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ثابت حرف *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
تعريفنوع صحيح hostkeys_foreach_fn(بنية hostkey_foreach_سطر *l, فراغ *ctx);

/* Iterate over a hostkeys file */
صحيح hostkeys_foreach(ثابت حرف *رستہ,
    hostkeys_foreach_fn *callback, فراغ *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note);
صحيح hostkeys_foreach_file(ثابت حرف *رستہ, FILE *f,
    hostkeys_foreach_fn *callback, فراغ *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note);

فراغ hostfile_create_user_ssh_dir(ثابت حرف *, صحيح);

#جے_انت
