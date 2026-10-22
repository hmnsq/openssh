/*	$OpenBSD: tree.h,v 1.13 2011/07/09 00:19:45 pirofti Exp $	*/
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: sys/sys/tree.h */

#अन्तर्भाव "config.h"
#यदि_परिभाषितम् NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#यदि_अन्तः

#यदि_अपरिभाषितम्	SYS_वृक्षः_H
#परिभाषय	SYS_वृक्षः_H

/*
 * This file defines data structures for different types of trees:
 * splay trees and red-black trees.
 *
 * A splay tree is a self-organizing data structure.  Every operation
 * on the tree causes a splay to happen.  The splay moves the requested
 * node to the root of the tree and partly rebalances it.
 *
 * This has the benefit that request locality causes faster lookups as
 * the requested nodes move to the top of the tree.  On the other hand,
 * every lookup causes memory writes.
 *
 * The Balance Theorem bounds the total access time for m operations
 * and n inserts on an initially empty tree as O((m + n)lg n).  The
 * amortized cost for a sequence of m accesses to a splay tree is O(lg n);
 *
 * A red-black tree is a binary search tree with the node color as an
 * extra attribute.  It fulfills a set of conditions:
 *	- every search path from the root to a leaf consists of the
 *	  same number of black nodes,
 *	- each red node (except for the root) has a black parent,
 *	- each leaf node is black.
 *
 * Every operation on a red-black tree is bounded as O(lg n).
 * The maximum height of a red-black tree is 2lg (n+1).
 */

#परिभाषय SPLAY_शीर्ष(name, type)						\
संरचना name {								\
	संरचना type *sph_मूलम्; /* root of the tree */			\
}

#परिभाषय SPLAY_INITIALIZER(मूलम्)						\
	{ रिक्त }

#परिभाषय SPLAY_INIT(मूलम्) कुरु {						\
	(मूलम्)->sph_मूलम् = रिक्त;					\
} यावत् (0)

#परिभाषय SPLAY_प्रविष्टिः(type)						\
संरचना {								\
	संरचना type *spe_वामः; /* left element */			\
	संरचना type *spe_दक्षिणः; /* right element */			\
}

#परिभाषय SPLAY_वामः(elm, क्षेत्रम्)		(elm)->क्षेत्रम्.spe_वामः
#परिभाषय SPLAY_दक्षिणः(elm, क्षेत्रम्)		(elm)->क्षेत्रम्.spe_दक्षिणः
#परिभाषय SPLAY_मूलम्(शीर्ष)		(शीर्ष)->sph_मूलम्
#परिभाषय SPLAY_रिक्तानि(शीर्ष)		(SPLAY_मूलम्(शीर्ष) == रिक्त)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#परिभाषय SPLAY_ROTATE_दक्षिणः(शीर्ष, tmp, क्षेत्रम्) कुरु {			\
	SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्) = SPLAY_दक्षिणः(tmp, क्षेत्रम्);	\
	SPLAY_दक्षिणः(tmp, क्षेत्रम्) = (शीर्ष)->sph_मूलम्;			\
	(शीर्ष)->sph_मूलम् = tmp;						\
} यावत् (0)
	
#परिभाषय SPLAY_ROTATE_वामः(शीर्ष, tmp, क्षेत्रम्) कुरु {			\
	SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्) = SPLAY_वामः(tmp, क्षेत्रम्);	\
	SPLAY_वामः(tmp, क्षेत्रम्) = (शीर्ष)->sph_मूलम्;			\
	(शीर्ष)->sph_मूलम् = tmp;						\
} यावत् (0)

#परिभाषय SPLAY_LINKLEFT(शीर्ष, tmp, क्षेत्रम्) कुरु {				\
	SPLAY_वामः(tmp, क्षेत्रम्) = (शीर्ष)->sph_मूलम्;			\
	tmp = (शीर्ष)->sph_मूलम्;						\
	(शीर्ष)->sph_मूलम् = SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्);		\
} यावत् (0)

#परिभाषय SPLAY_LINKRIGHT(शीर्ष, tmp, क्षेत्रम्) कुरु {				\
	SPLAY_दक्षिणः(tmp, क्षेत्रम्) = (शीर्ष)->sph_मूलम्;			\
	tmp = (शीर्ष)->sph_मूलम्;						\
	(शीर्ष)->sph_मूलम् = SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्);	\
} यावत् (0)

#परिभाषय SPLAY_ASSEMBLE(शीर्ष, ग्रन्थिः, वामः, दक्षिणः, क्षेत्रम्) कुरु {		\
	SPLAY_दक्षिणः(वामः, क्षेत्रम्) = SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्);	\
	SPLAY_वामः(दक्षिणः, क्षेत्रम्) = SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्);\
	SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्) = SPLAY_दक्षिणः(ग्रन्थिः, क्षेत्रम्);	\
	SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्) = SPLAY_वामः(ग्रन्थिः, क्षेत्रम्);	\
} यावत् (0)

/* Generates prototypes and inline functions */

#परिभाषय SPLAY_PROTOTYPE(name, type, क्षेत्रम्, cmp)				\
शून्य name##_SPLAY(संरचना name *, संरचना type *);			\
शून्य name##_SPLAY_MINMAX(संरचना name *, पूर्णाङ्क);				\
संरचना type *name##_SPLAY_INSERT(संरचना name *, संरचना type *);		\
संरचना type *name##_SPLAY_REMOVE(संरचना name *, संरचना type *);		\
									\
/* Finds the node with the same key as elm */				\
स्थिर __inline संरचना type *						\
name##_SPLAY_FIND(संरचना name *शीर्ष, संरचना type *elm)			\
{									\
	यदि (SPLAY_रिक्तानि(शीर्ष))						\
		प्रत्यागम(रिक्त);						\
	name##_SPLAY(शीर्ष, elm);					\
	यदि ((cmp)(elm, (शीर्ष)->sph_मूलम्) == 0)				\
		प्रत्यागम (शीर्ष->sph_मूलम्);				\
	प्रत्यागम (रिक्त);							\
}									\
									\
स्थिर __inline संरचना type *						\
name##_SPLAY_NEXT(संरचना name *शीर्ष, संरचना type *elm)			\
{									\
	name##_SPLAY(शीर्ष, elm);					\
	यदि (SPLAY_दक्षिणः(elm, क्षेत्रम्) != रिक्त) {				\
		elm = SPLAY_दक्षिणः(elm, क्षेत्रम्);				\
		यावत् (SPLAY_वामः(elm, क्षेत्रम्) != रिक्त) {		\
			elm = SPLAY_वामः(elm, क्षेत्रम्);			\
		}							\
	} अन्यथा								\
		elm = रिक्त;						\
	प्रत्यागम (elm);							\
}									\
									\
स्थिर __inline संरचना type *						\
name##_SPLAY_MIN_MAX(संरचना name *शीर्ष, पूर्णाङ्क val)			\
{									\
	name##_SPLAY_MINMAX(शीर्ष, val);					\
        प्रत्यागम (SPLAY_मूलम्(शीर्ष));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#परिभाषय SPLAY_GENERATE(name, type, क्षेत्रम्, cmp)				\
संरचना type *								\
name##_SPLAY_INSERT(संरचना name *शीर्ष, संरचना type *elm)		\
{									\
    यदि (SPLAY_रिक्तानि(शीर्ष)) {						\
	    SPLAY_वामः(elm, क्षेत्रम्) = SPLAY_दक्षिणः(elm, क्षेत्रम्) = रिक्त;	\
    } अन्यथा {								\
	    पूर्णाङ्क __comp;							\
	    name##_SPLAY(शीर्ष, elm);					\
	    __comp = (cmp)(elm, (शीर्ष)->sph_मूलम्);			\
	    यदि(__comp < 0) {						\
		    SPLAY_वामः(elm, क्षेत्रम्) = SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्);\
		    SPLAY_दक्षिणः(elm, क्षेत्रम्) = (शीर्ष)->sph_मूलम्;		\
		    SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्) = रिक्त;		\
	    } अन्यथा यदि (__comp > 0) {					\
		    SPLAY_दक्षिणः(elm, क्षेत्रम्) = SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्);\
		    SPLAY_वामः(elm, क्षेत्रम्) = (शीर्ष)->sph_मूलम्;		\
		    SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्) = रिक्त;	\
	    } अन्यथा							\
		    प्रत्यागम ((शीर्ष)->sph_मूलम्);				\
    }									\
    (शीर्ष)->sph_मूलम् = (elm);						\
    प्रत्यागम (रिक्त);							\
}									\
									\
संरचना type *								\
name##_SPLAY_REMOVE(संरचना name *शीर्ष, संरचना type *elm)		\
{									\
	संरचना type *__tmp;						\
	यदि (SPLAY_रिक्तानि(शीर्ष))						\
		प्रत्यागम (रिक्त);						\
	name##_SPLAY(शीर्ष, elm);					\
	यदि ((cmp)(elm, (शीर्ष)->sph_मूलम्) == 0) {			\
		यदि (SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्) == रिक्त) {	\
			(शीर्ष)->sph_मूलम् = SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्);\
		} अन्यथा {						\
			__tmp = SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्);	\
			(शीर्ष)->sph_मूलम् = SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्);\
			name##_SPLAY(शीर्ष, elm);			\
			SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्) = __tmp;	\
		}							\
		प्रत्यागम (elm);						\
	}								\
	प्रत्यागम (रिक्त);							\
}									\
									\
शून्य									\
name##_SPLAY(संरचना name *शीर्ष, संरचना type *elm)			\
{									\
	संरचना type __node, *__left, *__right, *__tmp;			\
	पूर्णाङ्क __comp;							\
\
	SPLAY_वामः(&__node, क्षेत्रम्) = SPLAY_दक्षिणः(&__node, क्षेत्रम्) = रिक्त;\
	__left = __right = &__node;					\
\
	यावत् ((__comp = (cmp)(elm, (शीर्ष)->sph_मूलम्))) {		\
		यदि (__comp < 0) {					\
			__tmp = SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्);	\
			यदि (__tmp == रिक्त)				\
				भङ्ग;					\
			यदि ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_दक्षिणः(शीर्ष, __tmp, क्षेत्रम्);	\
				यदि (SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्) == रिक्त)\
					भङ्ग;				\
			}						\
			SPLAY_LINKLEFT(शीर्ष, __right, क्षेत्रम्);		\
		} अन्यथा यदि (__comp > 0) {				\
			__tmp = SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्);	\
			यदि (__tmp == रिक्त)				\
				भङ्ग;					\
			यदि ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_वामः(शीर्ष, __tmp, क्षेत्रम्);	\
				यदि (SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्) == रिक्त)\
					भङ्ग;				\
			}						\
			SPLAY_LINKRIGHT(शीर्ष, __left, क्षेत्रम्);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(शीर्ष, &__node, __left, __right, क्षेत्रम्);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
शून्य name##_SPLAY_MINMAX(संरचना name *शीर्ष, पूर्णाङ्क __comp) \
{									\
	संरचना type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_वामः(&__node, क्षेत्रम्) = SPLAY_दक्षिणः(&__node, क्षेत्रम्) = रिक्त;\
	__left = __right = &__node;					\
\
	यावत् (1) {							\
		यदि (__comp < 0) {					\
			__tmp = SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्);	\
			यदि (__tmp == रिक्त)				\
				भङ्ग;					\
			यदि (__comp < 0){				\
				SPLAY_ROTATE_दक्षिणः(शीर्ष, __tmp, क्षेत्रम्);	\
				यदि (SPLAY_वामः((शीर्ष)->sph_मूलम्, क्षेत्रम्) == रिक्त)\
					भङ्ग;				\
			}						\
			SPLAY_LINKLEFT(शीर्ष, __right, क्षेत्रम्);		\
		} अन्यथा यदि (__comp > 0) {				\
			__tmp = SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्);	\
			यदि (__tmp == रिक्त)				\
				भङ्ग;					\
			यदि (__comp > 0) {				\
				SPLAY_ROTATE_वामः(शीर्ष, __tmp, क्षेत्रम्);	\
				यदि (SPLAY_दक्षिणः((शीर्ष)->sph_मूलम्, क्षेत्रम्) == रिक्त)\
					भङ्ग;				\
			}						\
			SPLAY_LINKRIGHT(शीर्ष, __left, क्षेत्रम्);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(शीर्ष, &__node, __left, __right, क्षेत्रम्);		\
}

#परिभाषय SPLAY_NEGINF	-1
#परिभाषय SPLAY_INF	1

#परिभाषय SPLAY_निवेशय(name, x, y)	name##_SPLAY_INSERT(x, y)
#परिभाषय SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#परिभाषय SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#परिभाषय SPLAY_अग्र(name, x, y)		name##_SPLAY_NEXT(x, y)
#परिभाषय SPLAY_MIN(name, x)		(SPLAY_रिक्तानि(x) ? रिक्त	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#परिभाषय SPLAY_MAX(name, x)		(SPLAY_रिक्तानि(x) ? रिक्त	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#परिभाषय SPLAY_FOREACH(x, name, शीर्ष)					\
	प्रति ((x) = SPLAY_MIN(name, शीर्ष);				\
	     (x) != रिक्त;						\
	     (x) = SPLAY_अग्र(name, शीर्ष, x))

/* Macros that define a red-black tree */
#परिभाषय RB_शीर्ष(name, type)						\
संरचना name {								\
	संरचना type *rbh_मूलम्; /* root of the tree */			\
}

#परिभाषय RB_INITIALIZER(मूलम्)						\
	{ रिक्त }

#परिभाषय RB_INIT(मूलम्) कुरु {						\
	(मूलम्)->rbh_मूलम् = रिक्त;					\
} यावत् (0)

#परिभाषय RB_BLACK	0
#परिभाषय RB_RED		1
#परिभाषय RB_प्रविष्टिः(type)							\
संरचना {								\
	संरचना type *rbe_वामः;		/* left element */		\
	संरचना type *rbe_दक्षिणः;		/* right element */		\
	संरचना type *rbe_parent;	/* parent element */		\
	पूर्णाङ्क rbe_color;			/* node color */		\
}

#परिभाषय RB_वामः(elm, क्षेत्रम्)		(elm)->क्षेत्रम्.rbe_वामः
#परिभाषय RB_दक्षिणः(elm, क्षेत्रम्)		(elm)->क्षेत्रम्.rbe_दक्षिणः
#परिभाषय RB_PARENT(elm, क्षेत्रम्)		(elm)->क्षेत्रम्.rbe_parent
#परिभाषय RB_COLOR(elm, क्षेत्रम्)		(elm)->क्षेत्रम्.rbe_color
#परिभाषय RB_मूलम्(शीर्ष)			(शीर्ष)->rbh_मूलम्
#परिभाषय RB_रिक्तानि(शीर्ष)			(RB_मूलम्(शीर्ष) == रिक्त)

#परिभाषय RB_समुच्चयः(elm, parent, क्षेत्रम्) कुरु {					\
	RB_PARENT(elm, क्षेत्रम्) = parent;					\
	RB_वामः(elm, क्षेत्रम्) = RB_दक्षिणः(elm, क्षेत्रम्) = रिक्त;		\
	RB_COLOR(elm, क्षेत्रम्) = RB_RED;					\
} यावत् (0)

#परिभाषय RB_समुच्चयः_BLACKRED(black, red, क्षेत्रम्) कुरु {				\
	RB_COLOR(black, क्षेत्रम्) = RB_BLACK;				\
	RB_COLOR(red, क्षेत्रम्) = RB_RED;					\
} यावत् (0)

#यदि_अपरिभाषितम् RB_AUGMENT
#परिभाषय RB_AUGMENT(x)	कुरु {} यावत् (0)
#यदि_अन्तः

#परिभाषय RB_ROTATE_वामः(शीर्ष, elm, tmp, क्षेत्रम्) कुरु {			\
	(tmp) = RB_दक्षिणः(elm, क्षेत्रम्);					\
	यदि ((RB_दक्षिणः(elm, क्षेत्रम्) = RB_वामः(tmp, क्षेत्रम्))) {		\
		RB_PARENT(RB_वामः(tmp, क्षेत्रम्), क्षेत्रम्) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	यदि ((RB_PARENT(tmp, क्षेत्रम्) = RB_PARENT(elm, क्षेत्रम्))) {		\
		यदि ((elm) == RB_वामः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्))	\
			RB_वामः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्) = (tmp);	\
		अन्यथा							\
			RB_दक्षिणः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्) = (tmp);	\
	} अन्यथा								\
		(शीर्ष)->rbh_मूलम् = (tmp);				\
	RB_वामः(tmp, क्षेत्रम्) = (elm);					\
	RB_PARENT(elm, क्षेत्रम्) = (tmp);					\
	RB_AUGMENT(tmp);						\
	यदि ((RB_PARENT(tmp, क्षेत्रम्)))					\
		RB_AUGMENT(RB_PARENT(tmp, क्षेत्रम्));			\
} यावत् (0)

#परिभाषय RB_ROTATE_दक्षिणः(शीर्ष, elm, tmp, क्षेत्रम्) कुरु {			\
	(tmp) = RB_वामः(elm, क्षेत्रम्);					\
	यदि ((RB_वामः(elm, क्षेत्रम्) = RB_दक्षिणः(tmp, क्षेत्रम्))) {		\
		RB_PARENT(RB_दक्षिणः(tmp, क्षेत्रम्), क्षेत्रम्) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	यदि ((RB_PARENT(tmp, क्षेत्रम्) = RB_PARENT(elm, क्षेत्रम्))) {		\
		यदि ((elm) == RB_वामः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्))	\
			RB_वामः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्) = (tmp);	\
		अन्यथा							\
			RB_दक्षिणः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्) = (tmp);	\
	} अन्यथा								\
		(शीर्ष)->rbh_मूलम् = (tmp);				\
	RB_दक्षिणः(tmp, क्षेत्रम्) = (elm);					\
	RB_PARENT(elm, क्षेत्रम्) = (tmp);					\
	RB_AUGMENT(tmp);						\
	यदि ((RB_PARENT(tmp, क्षेत्रम्)))					\
		RB_AUGMENT(RB_PARENT(tmp, क्षेत्रम्));			\
} यावत् (0)

/* Generates prototypes and inline functions */
#परिभाषय	RB_PROTOTYPE(name, type, क्षेत्रम्, cmp)				\
	RB_PROTOTYPE_आन्तरिकम्(name, type, क्षेत्रम्, cmp,)
#परिभाषय	RB_PROTOTYPE_STATIC(name, type, क्षेत्रम्, cmp)			\
	RB_PROTOTYPE_आन्तरिकम्(name, type, क्षेत्रम्, cmp, __attribute__((__unused__)) स्थिर)
#परिभाषय RB_PROTOTYPE_आन्तरिकम्(name, type, क्षेत्रम्, cmp, attr)		\
attr शून्य name##_RB_INSERT_COLOR(संरचना name *, संरचना type *);		\
attr शून्य name##_RB_REMOVE_COLOR(संरचना name *, संरचना type *, संरचना type *);\
attr संरचना type *name##_RB_REMOVE(संरचना name *, संरचना type *);	\
attr संरचना type *name##_RB_INSERT(संरचना name *, संरचना type *);	\
attr संरचना type *name##_RB_FIND(संरचना name *, संरचना type *);		\
attr संरचना type *name##_RB_NFIND(संरचना name *, संरचना type *);	\
attr संरचना type *name##_RB_NEXT(संरचना type *);			\
attr संरचना type *name##_RB_PREV(संरचना type *);			\
attr संरचना type *name##_RB_MINMAX(संरचना name *, पूर्णाङ्क);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#परिभाषय	RB_GENERATE(name, type, क्षेत्रम्, cmp)				\
	RB_GENERATE_आन्तरिकम्(name, type, क्षेत्रम्, cmp,)
#परिभाषय	RB_GENERATE_STATIC(name, type, क्षेत्रम्, cmp)			\
	RB_GENERATE_आन्तरिकम्(name, type, क्षेत्रम्, cmp, __attribute__((__unused__)) स्थिर)
#परिभाषय RB_GENERATE_आन्तरिकम्(name, type, क्षेत्रम्, cmp, attr)		\
attr शून्य								\
name##_RB_INSERT_COLOR(संरचना name *शीर्ष, संरचना type *elm)		\
{									\
	संरचना type *parent, *gparent, *tmp;				\
	यावत् ((parent = RB_PARENT(elm, क्षेत्रम्)) &&			\
	    RB_COLOR(parent, क्षेत्रम्) == RB_RED) {			\
		gparent = RB_PARENT(parent, क्षेत्रम्);			\
		यदि (parent == RB_वामः(gparent, क्षेत्रम्)) {		\
			tmp = RB_दक्षिणः(gparent, क्षेत्रम्);			\
			यदि (tmp && RB_COLOR(tmp, क्षेत्रम्) == RB_RED) {	\
				RB_COLOR(tmp, क्षेत्रम्) = RB_BLACK;	\
				RB_समुच्चयः_BLACKRED(parent, gparent, क्षेत्रम्);\
				elm = gparent;				\
				अनुवर्त;				\
			}						\
			यदि (RB_दक्षिणः(parent, क्षेत्रम्) == elm) {		\
				RB_ROTATE_वामः(शीर्ष, parent, tmp, क्षेत्रम्);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_समुच्चयः_BLACKRED(parent, gparent, क्षेत्रम्);	\
			RB_ROTATE_दक्षिणः(शीर्ष, gparent, tmp, क्षेत्रम्);	\
		} अन्यथा {						\
			tmp = RB_वामः(gparent, क्षेत्रम्);			\
			यदि (tmp && RB_COLOR(tmp, क्षेत्रम्) == RB_RED) {	\
				RB_COLOR(tmp, क्षेत्रम्) = RB_BLACK;	\
				RB_समुच्चयः_BLACKRED(parent, gparent, क्षेत्रम्);\
				elm = gparent;				\
				अनुवर्त;				\
			}						\
			यदि (RB_वामः(parent, क्षेत्रम्) == elm) {		\
				RB_ROTATE_दक्षिणः(शीर्ष, parent, tmp, क्षेत्रम्);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_समुच्चयः_BLACKRED(parent, gparent, क्षेत्रम्);	\
			RB_ROTATE_वामः(शीर्ष, gparent, tmp, क्षेत्रम्);	\
		}							\
	}								\
	RB_COLOR(शीर्ष->rbh_मूलम्, क्षेत्रम्) = RB_BLACK;			\
}									\
									\
attr शून्य								\
name##_RB_REMOVE_COLOR(संरचना name *शीर्ष, संरचना type *parent, संरचना type *elm) \
{									\
	संरचना type *tmp;						\
	यावत् ((elm == रिक्त || RB_COLOR(elm, क्षेत्रम्) == RB_BLACK) &&	\
	    elm != RB_मूलम्(शीर्ष)) {					\
		यदि (RB_वामः(parent, क्षेत्रम्) == elm) {			\
			tmp = RB_दक्षिणः(parent, क्षेत्रम्);			\
			यदि (RB_COLOR(tmp, क्षेत्रम्) == RB_RED) {		\
				RB_समुच्चयः_BLACKRED(tmp, parent, क्षेत्रम्);	\
				RB_ROTATE_वामः(शीर्ष, parent, tmp, क्षेत्रम्);\
				tmp = RB_दक्षिणः(parent, क्षेत्रम्);		\
			}						\
			यदि ((RB_वामः(tmp, क्षेत्रम्) == रिक्त ||		\
			    RB_COLOR(RB_वामः(tmp, क्षेत्रम्), क्षेत्रम्) == RB_BLACK) &&\
			    (RB_दक्षिणः(tmp, क्षेत्रम्) == रिक्त ||		\
			    RB_COLOR(RB_दक्षिणः(tmp, क्षेत्रम्), क्षेत्रम्) == RB_BLACK)) {\
				RB_COLOR(tmp, क्षेत्रम्) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, क्षेत्रम्);		\
			} अन्यथा {					\
				यदि (RB_दक्षिणः(tmp, क्षेत्रम्) == रिक्त ||	\
				    RB_COLOR(RB_दक्षिणः(tmp, क्षेत्रम्), क्षेत्रम्) == RB_BLACK) {\
					संरचना type *oleft;		\
					यदि ((oleft = RB_वामः(tmp, क्षेत्रम्)))\
						RB_COLOR(oleft, क्षेत्रम्) = RB_BLACK;\
					RB_COLOR(tmp, क्षेत्रम्) = RB_RED;	\
					RB_ROTATE_दक्षिणः(शीर्ष, tmp, oleft, क्षेत्रम्);\
					tmp = RB_दक्षिणः(parent, क्षेत्रम्);	\
				}					\
				RB_COLOR(tmp, क्षेत्रम्) = RB_COLOR(parent, क्षेत्रम्);\
				RB_COLOR(parent, क्षेत्रम्) = RB_BLACK;	\
				यदि (RB_दक्षिणः(tmp, क्षेत्रम्))		\
					RB_COLOR(RB_दक्षिणः(tmp, क्षेत्रम्), क्षेत्रम्) = RB_BLACK;\
				RB_ROTATE_वामः(शीर्ष, parent, tmp, क्षेत्रम्);\
				elm = RB_मूलम्(शीर्ष);			\
				भङ्ग;					\
			}						\
		} अन्यथा {						\
			tmp = RB_वामः(parent, क्षेत्रम्);			\
			यदि (RB_COLOR(tmp, क्षेत्रम्) == RB_RED) {		\
				RB_समुच्चयः_BLACKRED(tmp, parent, क्षेत्रम्);	\
				RB_ROTATE_दक्षिणः(शीर्ष, parent, tmp, क्षेत्रम्);\
				tmp = RB_वामः(parent, क्षेत्रम्);		\
			}						\
			यदि ((RB_वामः(tmp, क्षेत्रम्) == रिक्त ||		\
			    RB_COLOR(RB_वामः(tmp, क्षेत्रम्), क्षेत्रम्) == RB_BLACK) &&\
			    (RB_दक्षिणः(tmp, क्षेत्रम्) == रिक्त ||		\
			    RB_COLOR(RB_दक्षिणः(tmp, क्षेत्रम्), क्षेत्रम्) == RB_BLACK)) {\
				RB_COLOR(tmp, क्षेत्रम्) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, क्षेत्रम्);		\
			} अन्यथा {					\
				यदि (RB_वामः(tmp, क्षेत्रम्) == रिक्त ||	\
				    RB_COLOR(RB_वामः(tmp, क्षेत्रम्), क्षेत्रम्) == RB_BLACK) {\
					संरचना type *oright;		\
					यदि ((oright = RB_दक्षिणः(tmp, क्षेत्रम्)))\
						RB_COLOR(oright, क्षेत्रम्) = RB_BLACK;\
					RB_COLOR(tmp, क्षेत्रम्) = RB_RED;	\
					RB_ROTATE_वामः(शीर्ष, tmp, oright, क्षेत्रम्);\
					tmp = RB_वामः(parent, क्षेत्रम्);	\
				}					\
				RB_COLOR(tmp, क्षेत्रम्) = RB_COLOR(parent, क्षेत्रम्);\
				RB_COLOR(parent, क्षेत्रम्) = RB_BLACK;	\
				यदि (RB_वामः(tmp, क्षेत्रम्))		\
					RB_COLOR(RB_वामः(tmp, क्षेत्रम्), क्षेत्रम्) = RB_BLACK;\
				RB_ROTATE_दक्षिणः(शीर्ष, parent, tmp, क्षेत्रम्);\
				elm = RB_मूलम्(शीर्ष);			\
				भङ्ग;					\
			}						\
		}							\
	}								\
	यदि (elm)							\
		RB_COLOR(elm, क्षेत्रम्) = RB_BLACK;			\
}									\
									\
attr संरचना type *							\
name##_RB_REMOVE(संरचना name *शीर्ष, संरचना type *elm)			\
{									\
	संरचना type *child, *parent, *old = elm;			\
	पूर्णाङ्क color;							\
	यदि (RB_वामः(elm, क्षेत्रम्) == रिक्त)				\
		child = RB_दक्षिणः(elm, क्षेत्रम्);				\
	अन्यथा यदि (RB_दक्षिणः(elm, क्षेत्रम्) == रिक्त)				\
		child = RB_वामः(elm, क्षेत्रम्);				\
	अन्यथा {								\
		संरचना type *वामः;					\
		elm = RB_दक्षिणः(elm, क्षेत्रम्);				\
		यावत् ((वामः = RB_वामः(elm, क्षेत्रम्)))			\
			elm = वामः;					\
		child = RB_दक्षिणः(elm, क्षेत्रम्);				\
		parent = RB_PARENT(elm, क्षेत्रम्);				\
		color = RB_COLOR(elm, क्षेत्रम्);				\
		यदि (child)						\
			RB_PARENT(child, क्षेत्रम्) = parent;		\
		यदि (parent) {						\
			यदि (RB_वामः(parent, क्षेत्रम्) == elm)		\
				RB_वामः(parent, क्षेत्रम्) = child;		\
			अन्यथा						\
				RB_दक्षिणः(parent, क्षेत्रम्) = child;	\
			RB_AUGMENT(parent);				\
		} अन्यथा							\
			RB_मूलम्(शीर्ष) = child;				\
		यदि (RB_PARENT(elm, क्षेत्रम्) == old)			\
			parent = elm;					\
		(elm)->क्षेत्रम् = (old)->क्षेत्रम्;				\
		यदि (RB_PARENT(old, क्षेत्रम्)) {				\
			यदि (RB_वामः(RB_PARENT(old, क्षेत्रम्), क्षेत्रम्) == old)\
				RB_वामः(RB_PARENT(old, क्षेत्रम्), क्षेत्रम्) = elm;\
			अन्यथा						\
				RB_दक्षिणः(RB_PARENT(old, क्षेत्रम्), क्षेत्रम्) = elm;\
			RB_AUGMENT(RB_PARENT(old, क्षेत्रम्));		\
		} अन्यथा							\
			RB_मूलम्(शीर्ष) = elm;				\
		RB_PARENT(RB_वामः(old, क्षेत्रम्), क्षेत्रम्) = elm;		\
		यदि (RB_दक्षिणः(old, क्षेत्रम्))				\
			RB_PARENT(RB_दक्षिणः(old, क्षेत्रम्), क्षेत्रम्) = elm;	\
		यदि (parent) {						\
			वामः = parent;					\
			कुरु {						\
				RB_AUGMENT(वामः);			\
			} यावत् ((वामः = RB_PARENT(वामः, क्षेत्रम्)));	\
		}							\
		गच्छ color;						\
	}								\
	parent = RB_PARENT(elm, क्षेत्रम्);					\
	color = RB_COLOR(elm, क्षेत्रम्);					\
	यदि (child)							\
		RB_PARENT(child, क्षेत्रम्) = parent;			\
	यदि (parent) {							\
		यदि (RB_वामः(parent, क्षेत्रम्) == elm)			\
			RB_वामः(parent, क्षेत्रम्) = child;			\
		अन्यथा							\
			RB_दक्षिणः(parent, क्षेत्रम्) = child;		\
		RB_AUGMENT(parent);					\
	} अन्यथा								\
		RB_मूलम्(शीर्ष) = child;					\
color:									\
	यदि (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(शीर्ष, parent, child);		\
	प्रत्यागम (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr संरचना type *							\
name##_RB_INSERT(संरचना name *शीर्ष, संरचना type *elm)			\
{									\
	संरचना type *tmp;						\
	संरचना type *parent = रिक्त;					\
	पूर्णाङ्क comp = 0;							\
	tmp = RB_मूलम्(शीर्ष);						\
	यावत् (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		यदि (comp < 0)						\
			tmp = RB_वामः(tmp, क्षेत्रम्);			\
		अन्यथा यदि (comp > 0)					\
			tmp = RB_दक्षिणः(tmp, क्षेत्रम्);			\
		अन्यथा							\
			प्रत्यागम (tmp);					\
	}								\
	RB_समुच्चयः(elm, parent, क्षेत्रम्);					\
	यदि (parent != रिक्त) {						\
		यदि (comp < 0)						\
			RB_वामः(parent, क्षेत्रम्) = elm;			\
		अन्यथा							\
			RB_दक्षिणः(parent, क्षेत्रम्) = elm;			\
		RB_AUGMENT(parent);					\
	} अन्यथा								\
		RB_मूलम्(शीर्ष) = elm;					\
	name##_RB_INSERT_COLOR(शीर्ष, elm);				\
	प्रत्यागम (रिक्त);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr संरचना type *							\
name##_RB_FIND(संरचना name *शीर्ष, संरचना type *elm)			\
{									\
	संरचना type *tmp = RB_मूलम्(शीर्ष);				\
	पूर्णाङ्क comp;							\
	यावत् (tmp) {							\
		comp = cmp(elm, tmp);					\
		यदि (comp < 0)						\
			tmp = RB_वामः(tmp, क्षेत्रम्);			\
		अन्यथा यदि (comp > 0)					\
			tmp = RB_दक्षिणः(tmp, क्षेत्रम्);			\
		अन्यथा							\
			प्रत्यागम (tmp);					\
	}								\
	प्रत्यागम (रिक्त);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr संरचना type *							\
name##_RB_NFIND(संरचना name *शीर्ष, संरचना type *elm)			\
{									\
	संरचना type *tmp = RB_मूलम्(शीर्ष);				\
	संरचना type *res = रिक्त;					\
	पूर्णाङ्क comp;							\
	यावत् (tmp) {							\
		comp = cmp(elm, tmp);					\
		यदि (comp < 0) {						\
			res = tmp;					\
			tmp = RB_वामः(tmp, क्षेत्रम्);			\
		}							\
		अन्यथा यदि (comp > 0)					\
			tmp = RB_दक्षिणः(tmp, क्षेत्रम्);			\
		अन्यथा							\
			प्रत्यागम (tmp);					\
	}								\
	प्रत्यागम (res);							\
}									\
									\
/* ARGSUSED */								\
attr संरचना type *							\
name##_RB_NEXT(संरचना type *elm)					\
{									\
	यदि (RB_दक्षिणः(elm, क्षेत्रम्)) {					\
		elm = RB_दक्षिणः(elm, क्षेत्रम्);				\
		यावत् (RB_वामः(elm, क्षेत्रम्))				\
			elm = RB_वामः(elm, क्षेत्रम्);			\
	} अन्यथा {							\
		यदि (RB_PARENT(elm, क्षेत्रम्) &&				\
		    (elm == RB_वामः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्)))	\
			elm = RB_PARENT(elm, क्षेत्रम्);			\
		अन्यथा {							\
			यावत् (RB_PARENT(elm, क्षेत्रम्) &&			\
			    (elm == RB_दक्षिणः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्)))\
				elm = RB_PARENT(elm, क्षेत्रम्);		\
			elm = RB_PARENT(elm, क्षेत्रम्);			\
		}							\
	}								\
	प्रत्यागम (elm);							\
}									\
									\
/* ARGSUSED */								\
attr संरचना type *							\
name##_RB_PREV(संरचना type *elm)					\
{									\
	यदि (RB_वामः(elm, क्षेत्रम्)) {					\
		elm = RB_वामः(elm, क्षेत्रम्);				\
		यावत् (RB_दक्षिणः(elm, क्षेत्रम्))				\
			elm = RB_दक्षिणः(elm, क्षेत्रम्);			\
	} अन्यथा {							\
		यदि (RB_PARENT(elm, क्षेत्रम्) &&				\
		    (elm == RB_दक्षिणः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्)))	\
			elm = RB_PARENT(elm, क्षेत्रम्);			\
		अन्यथा {							\
			यावत् (RB_PARENT(elm, क्षेत्रम्) &&			\
			    (elm == RB_वामः(RB_PARENT(elm, क्षेत्रम्), क्षेत्रम्)))\
				elm = RB_PARENT(elm, क्षेत्रम्);		\
			elm = RB_PARENT(elm, क्षेत्रम्);			\
		}							\
	}								\
	प्रत्यागम (elm);							\
}									\
									\
attr संरचना type *							\
name##_RB_MINMAX(संरचना name *शीर्ष, पूर्णाङ्क val)				\
{									\
	संरचना type *tmp = RB_मूलम्(शीर्ष);				\
	संरचना type *parent = रिक्त;					\
	यावत् (tmp) {							\
		parent = tmp;						\
		यदि (val < 0)						\
			tmp = RB_वामः(tmp, क्षेत्रम्);			\
		अन्यथा							\
			tmp = RB_दक्षिणः(tmp, क्षेत्रम्);			\
	}								\
	प्रत्यागम (parent);						\
}

#परिभाषय RB_NEGINF	-1
#परिभाषय RB_INF	1

#परिभाषय RB_निवेशय(name, x, y)	name##_RB_INSERT(x, y)
#परिभाषय RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#परिभाषय RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#परिभाषय RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#परिभाषय RB_अग्र(name, x, y)	name##_RB_NEXT(y)
#परिभाषय RB_पूर्व(name, x, y)	name##_RB_PREV(y)
#परिभाषय RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#परिभाषय RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#परिभाषय RB_FOREACH(x, name, शीर्ष)					\
	प्रति ((x) = RB_MIN(name, शीर्ष);					\
	     (x) != रिक्त;						\
	     (x) = name##_RB_NEXT(x))

#परिभाषय RB_FOREACH_SAFE(x, name, शीर्ष, y)				\
	प्रति ((x) = RB_MIN(name, शीर्ष);					\
	    ((x) != रिक्त) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#परिभाषय RB_FOREACH_REVERSE(x, name, शीर्ष)				\
	प्रति ((x) = RB_MAX(name, शीर्ष);					\
	     (x) != रिक्त;						\
	     (x) = name##_RB_PREV(x))

#परिभाषय RB_FOREACH_REVERSE_SAFE(x, name, शीर्ष, y)			\
	प्रति ((x) = RB_MAX(name, शीर्ष);					\
	    ((x) != रिक्त) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#यदि_अन्तः	/* _SYS_TREE_H_ */
