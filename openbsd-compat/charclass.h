/*
 * Public domain, 2008, Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * $OpenBSD: charclass.h,v 1.1 2008/10/01 23:04:13 millert Exp $
 */

/* OPENBSD ORIGINAL: lib/libc/gen/charclass.h */

/*
 * POSIX character class support for fnmatch() and glob().
 */
ಸ್ಥಿರ ಸಂರಚನಾ cclass {
	ಧ್ರುವ ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ (*isctype)(ಪೂರ್ಣಾಙ್ಕ);
} cclasses[] = {
	{ "alnum",	isalnum },
	{ "alpha",	isalpha },
	{ "blank",	isblank },
	{ "cntrl",	iscntrl },
	{ "digit",	isdigit },
	{ "graph",	isgraph },
	{ "lower",	islower },
	{ "print",	isprint },
	{ "punct",	ispunct },
	{ "space",	isspace },
	{ "upper",	isupper },
	{ "xdigit",	isxdigit },
	{ ರಿಕ್ತ,		ರಿಕ್ತ }
};

#define NCCLASSES	(ಪರಿಮಾಣ(cclasses) / ಪರಿಮಾಣ(cclasses[0]) - 1)
