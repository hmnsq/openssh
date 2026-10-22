/*
 * Public domain, 2008, Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * $OpenBSD: charclass.h,v 1.1 2008/10/01 23:04:13 millert Exp $
 */

/* OPENBSD ORIGINAL: lib/libc/gen/charclass.h */

/*
 * POSIX character class support for fnmatch() and glob().
 */
अटल काष्ठा cclass {
	स्थिर अक्षर *name;
	पूर्णांक (*isctype)(पूर्णांक);
} cclasses[] = {
	{ "alnum",	है_अक्षर_अंक },
	{ "alpha",	है_अक्षर },
	{ "blank",	isblank },
	{ "cntrl",	है_नियंत्रण },
	{ "digit",	है_अंक },
	{ "graph",	है_चित्र },
	{ "lower",	है_छोटा },
	{ "print",	है_छाप },
	{ "punct",	है_विराम },
	{ "space",	है_खाली },
	{ "upper",	है_बड़ा },
	{ "xdigit",	है_षष्ठादशक },
	{ शून्य,		शून्य }
};

#घोषणा NCCLASSES	(माप(cclasses) / माप(cclasses[0]) - 1)
