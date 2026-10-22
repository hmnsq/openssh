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
#ifndef HOSTFILE_H
#define HOSTFILE_H

تعريفنوع تعداد {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

تعريفنوع تعداد {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

بنية hostkey_entry {
	حرف *host;
	حرف *file;
	u_long سطر;
	بنية sshkey *مفتاح;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
بنية hostkeys {
	بنية hostkey_entry *entries;
	u_int رقم_entries;
};

بنية hostkeys *init_hostkeys(فراغ);
فراغ	 load_hostkeys(بنية hostkeys *, ثابت حرف *,
    ثابت حرف *, u_int);
فراغ	 load_hostkeys_file(بنية hostkeys *, ثابت حرف *,
    ثابت حرف *, FILE *, u_int note);
فراغ	 free_hostkeys(بنية hostkeys *);

HostStatus check_مفتاح_in_hostkeys(بنية hostkeys *, بنية sshkey *,
    ثابت بنية hostkey_entry **);
صحيح	 lookup_مفتاح_in_hostkeys_by_type(بنية hostkeys *, صحيح, صحيح,
    ثابت بنية hostkey_entry **);
صحيح	 lookup_marker_in_hostkeys(بنية hostkeys *, صحيح);

صحيح	 hostfile_read_مفتاح(حرف **, u_int *, بنية sshkey *);
صحيح	 add_host_to_hostfile(ثابت حرف *, ثابت حرف *,
    ثابت بنية sshkey *, صحيح);

صحيح	 hostfile_replace_entries(ثابت حرف *filename,
    ثابت حرف *host, ثابت حرف *ip, بنية sshkey **مفاتيح, size_t nkeys,
    صحيح store_hash, صحيح quiet, صحيح hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

حرف	*host_hash(ثابت حرف *, ثابت حرف *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_مفتاح	(1<<1)	/* need key parsed */

#define HKF_STATUS_OK		0	/* Line parsed, didn't match host */
#define HKF_STATUS_INVALID	1	/* line had parse error */
#define HKF_STATUS_COMMENT	2	/* valid line contained no key */
#define HKF_STATUS_MATCHED	3	/* hostname or IP matched */

#define HKF_MATCH_HOST		(1)	/* hostname matched */
#define HKF_MATCH_IP		(1<<1)	/* address matched */
#define HKF_MATCH_HOST_HASHED	(1<<2)	/* hostname was hashed */
#define HKF_MATCH_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
بنية hostkey_foreach_سطر {
	ثابت حرف *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	حرف *سطر;	/* Entire key line; mutable by callback */
	صحيح marker;	/* CA/revocation markers; indicated by MRK_* value */
	ثابت حرف *hosts; /* Raw hosts text, may be hashed or list multiple */
	ثابت حرف *rawkey; /* Text of key and any comment following it */
	صحيح keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	بنية sshkey *مفتاح; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
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
صحيح hostkeys_foreach(ثابت حرف *path,
    hostkeys_foreach_fn *callback, فراغ *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note);
صحيح hostkeys_foreach_file(ثابت حرف *path, FILE *f,
    hostkeys_foreach_fn *callback, فراغ *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note);

فراغ hostfile_create_user_ssh_dir(ثابت حرف *, صحيح);

#endif
