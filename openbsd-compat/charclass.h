/*
 * Public domain, 2008, Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * $OpenBSD: charclass.h,v 1.1 2008/10/01 23:04:13 millert Exp $
 */

/* OPENBSD ORIGINAL: lib/libc/gen/charclass.h */

/*
 * POSIX character class support for fnmatch() and glob().
 */
स्थिर संरचना cclass {
	ध्रुव वर्ण *name;
	पूर्णाङ्क (*isctype)(पूर्णाङ्क);
} cclasses[] = {
	{ "alnum",	अक्षरम्_अङ्कः_वा },
	{ "alpha",	अक्षरम्_वा },
	{ "blank",	isblank },
	{ "cntrl",	iscntrl },
	{ "digit",	अङ्कः_वा },
	{ "graph",	isgraph },
	{ "lower",	islower },
	{ "print",	isprint },
	{ "punct",	ispunct },
	{ "space",	रिक्तम्_वा },
	{ "upper",	isupper },
	{ "xdigit",	isxdigit },
	{ रिक्त,		रिक्त }
};

#परिभाषय NCCLASSES	(परिमाण(cclasses) / परिमाण(cclasses[0]) - 1)
