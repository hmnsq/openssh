/*
 * Public domain, 2008, Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * $OpenBSD: charclass.h,v 1.1 2008/10/01 23:04:13 millert Exp $
 */

/* OPENBSD ORIGINAL: lib/libc/gen/charclass.h */

/*
 * POSIX character class support for fnmatch() and glob().
 */
ಸ್ಥಿರ ರಚನೆ cclass {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ (*isctype)(ಪೂರ್ಣಾಂಕ);
} cclasses[] = {
	{ "alnum",	ಅಕ್ಷರವೇ_ಅಂಕಿಯೇ },
	{ "alpha",	ಅಕ್ಷರವೇ },
	{ "blank",	isblank },
	{ "cntrl",	iscntrl },
	{ "digit",	ಅಂಕಿಯೇ },
	{ "graph",	isgraph },
	{ "lower",	islower },
	{ "print",	isprint },
	{ "punct",	ispunct },
	{ "space",	ಖಾಲಿಯೇ },
	{ "upper",	isupper },
	{ "xdigit",	isxdigit },
	{ ಖಾಲಿ,		ಖಾಲಿ }
};

#ವ್ಯಾಖ್ಯಾನಿಸು NCCLASSES	(ಗಾತ್ರ(cclasses) / ಗಾತ್ರ(cclasses[0]) - 1)
