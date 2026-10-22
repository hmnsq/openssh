/*
 * Public domain, 2008, Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * $OpenBSD: charclass.h,v 1.1 2008/10/01 23:04:13 millert Exp $
 */

/* OPENBSD ORIGINAL: lib/libc/gen/charclass.h */

/*
 * POSIX character class support for fnmatch() and glob().
 */
ਸਥਿਰ ਬਣਤਰ cclass {
	ਅਚਲ ਅੱਖਰ *name;
	ਪੂਰਨ (*isctype)(ਪੂਰਨ);
} cclasses[] = {
	{ "alnum",	ਅੱਖਰ_ਜਾਂ_ਅੰਕ },
	{ "alpha",	ਅੱਖਰ_ਹੈ },
	{ "blank",	isblank },
	{ "cntrl",	iscntrl },
	{ "digit",	ਅੰਕ_ਹੈ },
	{ "graph",	isgraph },
	{ "lower",	islower },
	{ "print",	isprint },
	{ "punct",	ispunct },
	{ "space",	ਖਾਲੀ_ਥਾਂ_ਹੈ },
	{ "upper",	isupper },
	{ "xdigit",	isxdigit },
	{ ਨਿਰਾ,		ਨਿਰਾ }
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NCCLASSES	(ਆਕਾਰ(cclasses) / ਆਕਾਰ(cclasses[0]) - 1)
