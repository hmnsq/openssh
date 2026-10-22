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
	{ "alnum",	که_توری_یا_عدد },
	{ "alpha",	که_توری },
	{ "blank",	isblank },
	{ "cntrl",	iscntrl },
	{ "digit",	که_عدد },
	{ "graph",	isgraph },
	{ "lower",	islower },
	{ "print",	isprint },
	{ "punct",	ispunct },
	{ "space",	که_تشه },
	{ "upper",	isupper },
	{ "xdigit",	isxdigit },
	{ عدم,		عدم }
};

#تعریف_کړه NCCLASSES	(حجم(cclasses) / حجم(cclasses[0]) - 1)
