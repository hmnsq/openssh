/*
 * Public domain, 2008, Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * $OpenBSD: charclass.h,v 1.1 2008/10/01 23:04:13 millert Exp $
 */

/* OPENBSD ORIGINAL: lib/libc/gen/charclass.h */

/*
 * POSIX character class support for fnmatch() and glob().
 */
స్థిర నిర్మాణం cclass {
	స్థిరరాశి అక్షరం *name;
	పూర్ణాంకం (*isctype)(పూర్ణాంకం);
} cclasses[] = {
	{ "alnum",	అక్షరమా_అంకెనా },
	{ "alpha",	అక్షరమా },
	{ "blank",	isblank },
	{ "cntrl",	iscntrl },
	{ "digit",	అంకెనా },
	{ "graph",	isgraph },
	{ "lower",	islower },
	{ "print",	isprint },
	{ "punct",	ispunct },
	{ "space",	ఖాళీనా },
	{ "upper",	isupper },
	{ "xdigit",	isxdigit },
	{ ఖాళీ,		ఖాళీ }
};

#నిర్వచించు NCCLASSES	(పరిమాణం(cclasses) / పరిమాణం(cclasses[0]) - 1)
