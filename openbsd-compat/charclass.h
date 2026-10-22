/*
 * Public domain, 2008, Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * $OpenBSD: charclass.h,v 1.1 2008/10/01 23:04:13 millert Exp $
 */

/* OPENBSD ORIGINAL: lib/libc/gen/charclass.h */

/*
 * POSIX character class support for fnmatch() and glob().
 */
ساكن بنية cclass {
	ثابت حرف *name;
	صحيح (*isctype)(صحيح);
} cclasses[] = {
	{ "alnum",	اکر_يا_انگ },
	{ "alpha",	اکر_آهي },
	{ "blank",	isblank },
	{ "cntrl",	iscntrl },
	{ "digit",	انگ_آهي },
	{ "graph",	isgraph },
	{ "lower",	islower },
	{ "print",	isprint },
	{ "punct",	ispunct },
	{ "space",	خال_آهي },
	{ "upper",	isupper },
	{ "xdigit",	isxdigit },
	{ عدم,		عدم }
};

#وصف_ڪريو NCCLASSES	(حجم(cclasses) / حجم(cclasses[0]) - 1)
