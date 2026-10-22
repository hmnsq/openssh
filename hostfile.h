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

प्रकारव्याख्या गणना {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

प्रकारव्याख्या गणना {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

संरचना hostkey_entry {
	अक्षर *host;
	अक्षर *file;
	u_long ओळ;
	संरचना sshkey *किल्ली;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
संरचना hostkeys {
	संरचना hostkey_entry *entries;
	u_int अंक_entries;
};

संरचना hostkeys *init_hostkeys(शून्य);
शून्य	 load_hostkeys(संरचना hostkeys *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, u_int);
शून्य	 load_hostkeys_file(संरचना hostkeys *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, खाता *, u_int note);
शून्य	 free_hostkeys(संरचना hostkeys *);

HostStatus check_किल्ली_in_hostkeys(संरचना hostkeys *, संरचना sshkey *,
    स्थिरांक संरचना hostkey_entry **);
पूर्णांक	 lookup_किल्ली_in_hostkeys_by_type(संरचना hostkeys *, पूर्णांक, पूर्णांक,
    स्थिरांक संरचना hostkey_entry **);
पूर्णांक	 lookup_marker_in_hostkeys(संरचना hostkeys *, पूर्णांक);

पूर्णांक	 hostfile_read_किल्ली(अक्षर **, u_int *, संरचना sshkey *);
पूर्णांक	 add_host_to_hostfile(स्थिरांक अक्षर *, स्थिरांक अक्षर *,
    स्थिरांक संरचना sshkey *, पूर्णांक);

पूर्णांक	 hostfile_replace_entries(स्थिरांक अक्षर *filename,
    स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip, संरचना sshkey **किल्ल्या, माप_प्रकार nkeys,
    पूर्णांक store_hash, पूर्णांक quiet, पूर्णांक hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

अक्षर	*host_hash(स्थिरांक अक्षर *, स्थिरांक अक्षर *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_किल्ली	(1<<1)	/* need key parsed */

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
संरचना hostkey_foreach_ओळ {
	स्थिरांक अक्षर *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	अक्षर *ओळ;	/* Entire key line; mutable by callback */
	पूर्णांक marker;	/* CA/revocation markers; indicated by MRK_* value */
	स्थिरांक अक्षर *hosts; /* Raw hosts text, may be hashed or list multiple */
	स्थिरांक अक्षर *rawkey; /* Text of key and any comment following it */
	पूर्णांक keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	संरचना sshkey *किल्ली; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	स्थिरांक अक्षर *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
प्रकारव्याख्या पूर्णांक hostkeys_foreach_fn(संरचना hostkey_foreach_ओळ *l, शून्य *ctx);

/* Iterate over a hostkeys file */
पूर्णांक hostkeys_foreach(स्थिरांक अक्षर *path,
    hostkeys_foreach_fn *callback, शून्य *ctx,
    स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip, u_int options, u_int note);
पूर्णांक hostkeys_foreach_file(स्थिरांक अक्षर *path, खाता *f,
    hostkeys_foreach_fn *callback, शून्य *ctx,
    स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip, u_int options, u_int note);

शून्य hostfile_create_user_ssh_dir(स्थिरांक अक्षर *, पूर्णांक);

#endif
