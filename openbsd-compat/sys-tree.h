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

#ضمن "config.h"
#که_تعریف_شوی NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#د_که_پای

#که_نه_تعریف_شوی	SYS_ونه_H
#تعریف_کړه	SYS_ونه_H

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

#تعریف_کړه SPLAY_سر(name, type)						\
بنية name {								\
	بنية type *sph_ریښه; /* root of the tree */			\
}

#تعریف_کړه SPLAY_INITIALIZER(ریښه)						\
	{ عدم }

#تعریف_کړه SPLAY_INIT(ریښه) افعل {						\
	(ریښه)->sph_ریښه = عدم;					\
} طالما (0)

#تعریف_کړه SPLAY_ثبت(type)						\
بنية {								\
	بنية type *spe_کیڼ; /* left element */			\
	بنية type *spe_ښی; /* right element */			\
}

#تعریف_کړه SPLAY_کیڼ(elm, ډګر)		(elm)->ډګر.spe_کیڼ
#تعریف_کړه SPLAY_ښی(elm, ډګر)		(elm)->ډګر.spe_ښی
#تعریف_کړه SPLAY_ریښه(سر_2)		(سر_2)->sph_ریښه
#تعریف_کړه SPLAY_تشه(سر_2)		(SPLAY_ریښه(سر_2) == عدم)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#تعریف_کړه SPLAY_ROTATE_ښی(سر_2, tmp, ډګر) افعل {			\
	SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر) = SPLAY_ښی(tmp, ډګر);	\
	SPLAY_ښی(tmp, ډګر) = (سر_2)->sph_ریښه;			\
	(سر_2)->sph_ریښه = tmp;						\
} طالما (0)
	
#تعریف_کړه SPLAY_ROTATE_کیڼ(سر_2, tmp, ډګر) افعل {			\
	SPLAY_ښی((سر_2)->sph_ریښه, ډګر) = SPLAY_کیڼ(tmp, ډګر);	\
	SPLAY_کیڼ(tmp, ډګر) = (سر_2)->sph_ریښه;			\
	(سر_2)->sph_ریښه = tmp;						\
} طالما (0)

#تعریف_کړه SPLAY_LINKLEFT(سر_2, tmp, ډګر) افعل {				\
	SPLAY_کیڼ(tmp, ډګر) = (سر_2)->sph_ریښه;			\
	tmp = (سر_2)->sph_ریښه;						\
	(سر_2)->sph_ریښه = SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر);		\
} طالما (0)

#تعریف_کړه SPLAY_LINKRIGHT(سر_2, tmp, ډګر) افعل {				\
	SPLAY_ښی(tmp, ډګر) = (سر_2)->sph_ریښه;			\
	tmp = (سر_2)->sph_ریښه;						\
	(سر_2)->sph_ریښه = SPLAY_ښی((سر_2)->sph_ریښه, ډګر);	\
} طالما (0)

#تعریف_کړه SPLAY_ASSEMBLE(سر_2, غوټه, کیڼ, ښی, ډګر) افعل {		\
	SPLAY_ښی(کیڼ, ډګر) = SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر);	\
	SPLAY_کیڼ(ښی, ډګر) = SPLAY_ښی((سر_2)->sph_ریښه, ډګر);\
	SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر) = SPLAY_ښی(غوټه, ډګر);	\
	SPLAY_ښی((سر_2)->sph_ریښه, ډګر) = SPLAY_کیڼ(غوټه, ډګر);	\
} طالما (0)

/* Generates prototypes and inline functions */

#تعریف_کړه SPLAY_PROTOTYPE(name, type, ډګر, cmp)				\
فراغ name##_SPLAY(بنية name *, بنية type *);			\
فراغ name##_SPLAY_MINMAX(بنية name *, صحيح);				\
بنية type *name##_SPLAY_INSERT(بنية name *, بنية type *);		\
بنية type *name##_SPLAY_REMOVE(بنية name *, بنية type *);		\
									\
/* Finds the node with the same key as elm */				\
ساكن __inline بنية type *						\
name##_SPLAY_FIND(بنية name *سر_2, بنية type *elm)			\
{									\
	إذا (SPLAY_تشه(سر_2))						\
		أرجع(عدم);						\
	name##_SPLAY(سر_2, elm);					\
	إذا ((cmp)(elm, (سر_2)->sph_ریښه) == 0)				\
		أرجع (سر_2->sph_ریښه);				\
	أرجع (عدم);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_NEXT(بنية name *سر_2, بنية type *elm)			\
{									\
	name##_SPLAY(سر_2, elm);					\
	إذا (SPLAY_ښی(elm, ډګر) != عدم) {				\
		elm = SPLAY_ښی(elm, ډګر);				\
		طالما (SPLAY_کیڼ(elm, ډګر) != عدم) {		\
			elm = SPLAY_کیڼ(elm, ډګر);			\
		}							\
	} وإلا								\
		elm = عدم;						\
	أرجع (elm);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_MIN_MAX(بنية name *سر_2, صحيح val)			\
{									\
	name##_SPLAY_MINMAX(سر_2, val);					\
        أرجع (SPLAY_ریښه(سر_2));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#تعریف_کړه SPLAY_GENERATE(name, type, ډګر, cmp)				\
بنية type *								\
name##_SPLAY_INSERT(بنية name *سر_2, بنية type *elm)		\
{									\
    إذا (SPLAY_تشه(سر_2)) {						\
	    SPLAY_کیڼ(elm, ډګر) = SPLAY_ښی(elm, ډګر) = عدم;	\
    } وإلا {								\
	    صحيح __comp;							\
	    name##_SPLAY(سر_2, elm);					\
	    __comp = (cmp)(elm, (سر_2)->sph_ریښه);			\
	    إذا(__comp < 0) {						\
		    SPLAY_کیڼ(elm, ډګر) = SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر);\
		    SPLAY_ښی(elm, ډګر) = (سر_2)->sph_ریښه;		\
		    SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر) = عدم;		\
	    } وإلا إذا (__comp > 0) {					\
		    SPLAY_ښی(elm, ډګر) = SPLAY_ښی((سر_2)->sph_ریښه, ډګر);\
		    SPLAY_کیڼ(elm, ډګر) = (سر_2)->sph_ریښه;		\
		    SPLAY_ښی((سر_2)->sph_ریښه, ډګر) = عدم;	\
	    } وإلا							\
		    أرجع ((سر_2)->sph_ریښه);				\
    }									\
    (سر_2)->sph_ریښه = (elm);						\
    أرجع (عدم);							\
}									\
									\
بنية type *								\
name##_SPLAY_REMOVE(بنية name *سر_2, بنية type *elm)		\
{									\
	بنية type *__tmp;						\
	إذا (SPLAY_تشه(سر_2))						\
		أرجع (عدم);						\
	name##_SPLAY(سر_2, elm);					\
	إذا ((cmp)(elm, (سر_2)->sph_ریښه) == 0) {			\
		إذا (SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر) == عدم) {	\
			(سر_2)->sph_ریښه = SPLAY_ښی((سر_2)->sph_ریښه, ډګر);\
		} وإلا {						\
			__tmp = SPLAY_ښی((سر_2)->sph_ریښه, ډګر);	\
			(سر_2)->sph_ریښه = SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر);\
			name##_SPLAY(سر_2, elm);			\
			SPLAY_ښی((سر_2)->sph_ریښه, ډګر) = __tmp;	\
		}							\
		أرجع (elm);						\
	}								\
	أرجع (عدم);							\
}									\
									\
فراغ									\
name##_SPLAY(بنية name *سر_2, بنية type *elm)			\
{									\
	بنية type __node, *__left, *__right, *__tmp;			\
	صحيح __comp;							\
\
	SPLAY_کیڼ(&__node, ډګر) = SPLAY_ښی(&__node, ډګر) = عدم;\
	__left = __right = &__node;					\
\
	طالما ((__comp = (cmp)(elm, (سر_2)->sph_ریښه))) {		\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_ښی(سر_2, __tmp, ډګر);	\
				إذا (SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(سر_2, __right, ډګر);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_ښی((سر_2)->sph_ریښه, ډګر);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_کیڼ(سر_2, __tmp, ډګر);	\
				إذا (SPLAY_ښی((سر_2)->sph_ریښه, ډګر) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(سر_2, __left, ډګر);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(سر_2, &__node, __left, __right, ډګر);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
فراغ name##_SPLAY_MINMAX(بنية name *سر_2, صحيح __comp) \
{									\
	بنية type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_کیڼ(&__node, ډګر) = SPLAY_ښی(&__node, ډګر) = عدم;\
	__left = __right = &__node;					\
\
	طالما (1) {							\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp < 0){				\
				SPLAY_ROTATE_ښی(سر_2, __tmp, ډګر);	\
				إذا (SPLAY_کیڼ((سر_2)->sph_ریښه, ډګر) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(سر_2, __right, ډګر);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_ښی((سر_2)->sph_ریښه, ډګر);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp > 0) {				\
				SPLAY_ROTATE_کیڼ(سر_2, __tmp, ډګر);	\
				إذا (SPLAY_ښی((سر_2)->sph_ریښه, ډګر) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(سر_2, __left, ډګر);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(سر_2, &__node, __left, __right, ډګر);		\
}

#تعریف_کړه SPLAY_NEGINF	-1
#تعریف_کړه SPLAY_INF	1

#تعریف_کړه SPLAY_ورننباسه(name, x, y)	name##_SPLAY_INSERT(x, y)
#تعریف_کړه SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#تعریف_کړه SPLAY_پیدا_کړه(name, x, y)		name##_SPLAY_FIND(x, y)
#تعریف_کړه SPLAY_بل(name, x, y)		name##_SPLAY_NEXT(x, y)
#تعریف_کړه SPLAY_MIN(name, x)		(SPLAY_تشه(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#تعریف_کړه SPLAY_MAX(name, x)		(SPLAY_تشه(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#تعریف_کړه SPLAY_FOREACH(x, name, سر_2)					\
	لكل ((x) = SPLAY_MIN(name, سر_2);				\
	     (x) != عدم;						\
	     (x) = SPLAY_بل(name, سر_2, x))

/* Macros that define a red-black tree */
#تعریف_کړه RB_سر(name, type)						\
بنية name {								\
	بنية type *rbh_ریښه; /* root of the tree */			\
}

#تعریف_کړه RB_INITIALIZER(ریښه)						\
	{ عدم }

#تعریف_کړه RB_INIT(ریښه) افعل {						\
	(ریښه)->rbh_ریښه = عدم;					\
} طالما (0)

#تعریف_کړه RB_BLACK	0
#تعریف_کړه RB_RED		1
#تعریف_کړه RB_ثبت(type)							\
بنية {								\
	بنية type *rbe_کیڼ;		/* left element */		\
	بنية type *rbe_ښی;		/* right element */		\
	بنية type *rbe_پلار;	/* parent element */		\
	صحيح rbe_color;			/* node color */		\
}

#تعریف_کړه RB_کیڼ(elm, ډګر)		(elm)->ډګر.rbe_کیڼ
#تعریف_کړه RB_ښی(elm, ډګر)		(elm)->ډګر.rbe_ښی
#تعریف_کړه RB_پلار(elm, ډګر)		(elm)->ډګر.rbe_پلار
#تعریف_کړه RB_COLOR(elm, ډګر)		(elm)->ډګر.rbe_color
#تعریف_کړه RB_ریښه(سر_2)			(سر_2)->rbh_ریښه
#تعریف_کړه RB_تشه(سر_2)			(RB_ریښه(سر_2) == عدم)

#تعریف_کړه RB_سېټ(elm, پلار, ډګر) افعل {					\
	RB_پلار(elm, ډګر) = پلار;					\
	RB_کیڼ(elm, ډګر) = RB_ښی(elm, ډګر) = عدم;		\
	RB_COLOR(elm, ډګر) = RB_RED;					\
} طالما (0)

#تعریف_کړه RB_سېټ_BLACKRED(black, red, ډګر) افعل {				\
	RB_COLOR(black, ډګر) = RB_BLACK;				\
	RB_COLOR(red, ډګر) = RB_RED;					\
} طالما (0)

#که_نه_تعریف_شوی RB_AUGMENT
#تعریف_کړه RB_AUGMENT(x)	افعل {} طالما (0)
#د_که_پای

#تعریف_کړه RB_ROTATE_کیڼ(سر_2, elm, tmp, ډګر) افعل {			\
	(tmp) = RB_ښی(elm, ډګر);					\
	إذا ((RB_ښی(elm, ډګر) = RB_کیڼ(tmp, ډګر))) {		\
		RB_پلار(RB_کیڼ(tmp, ډګر), ډګر) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_پلار(tmp, ډګر) = RB_پلار(elm, ډګر))) {		\
		إذا ((elm) == RB_کیڼ(RB_پلار(elm, ډګر), ډګر))	\
			RB_کیڼ(RB_پلار(elm, ډګر), ډګر) = (tmp);	\
		وإلا							\
			RB_ښی(RB_پلار(elm, ډګر), ډګر) = (tmp);	\
	} وإلا								\
		(سر_2)->rbh_ریښه = (tmp);				\
	RB_کیڼ(tmp, ډګر) = (elm);					\
	RB_پلار(elm, ډګر) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_پلار(tmp, ډګر)))					\
		RB_AUGMENT(RB_پلار(tmp, ډګر));			\
} طالما (0)

#تعریف_کړه RB_ROTATE_ښی(سر_2, elm, tmp, ډګر) افعل {			\
	(tmp) = RB_کیڼ(elm, ډګر);					\
	إذا ((RB_کیڼ(elm, ډګر) = RB_ښی(tmp, ډګر))) {		\
		RB_پلار(RB_ښی(tmp, ډګر), ډګر) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_پلار(tmp, ډګر) = RB_پلار(elm, ډګر))) {		\
		إذا ((elm) == RB_کیڼ(RB_پلار(elm, ډګر), ډګر))	\
			RB_کیڼ(RB_پلار(elm, ډګر), ډګر) = (tmp);	\
		وإلا							\
			RB_ښی(RB_پلار(elm, ډګر), ډګر) = (tmp);	\
	} وإلا								\
		(سر_2)->rbh_ریښه = (tmp);				\
	RB_ښی(tmp, ډګر) = (elm);					\
	RB_پلار(elm, ډګر) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_پلار(tmp, ډګر)))					\
		RB_AUGMENT(RB_پلار(tmp, ډګر));			\
} طالما (0)

/* Generates prototypes and inline functions */
#تعریف_کړه	RB_PROTOTYPE(name, type, ډګر, cmp)				\
	RB_PROTOTYPE_دننی(name, type, ډګر, cmp,)
#تعریف_کړه	RB_PROTOTYPE_STATIC(name, type, ډګر, cmp)			\
	RB_PROTOTYPE_دننی(name, type, ډګر, cmp, __attribute__((__unused__)) ساكن)
#تعریف_کړه RB_PROTOTYPE_دننی(name, type, ډګر, cmp, attr)		\
attr فراغ name##_RB_INSERT_COLOR(بنية name *, بنية type *);		\
attr فراغ name##_RB_REMOVE_COLOR(بنية name *, بنية type *, بنية type *);\
attr بنية type *name##_RB_REMOVE(بنية name *, بنية type *);	\
attr بنية type *name##_RB_INSERT(بنية name *, بنية type *);	\
attr بنية type *name##_RB_FIND(بنية name *, بنية type *);		\
attr بنية type *name##_RB_NFIND(بنية name *, بنية type *);	\
attr بنية type *name##_RB_NEXT(بنية type *);			\
attr بنية type *name##_RB_PREV(بنية type *);			\
attr بنية type *name##_RB_MINMAX(بنية name *, صحيح);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#تعریف_کړه	RB_GENERATE(name, type, ډګر, cmp)				\
	RB_GENERATE_دننی(name, type, ډګر, cmp,)
#تعریف_کړه	RB_GENERATE_STATIC(name, type, ډګر, cmp)			\
	RB_GENERATE_دننی(name, type, ډګر, cmp, __attribute__((__unused__)) ساكن)
#تعریف_کړه RB_GENERATE_دننی(name, type, ډګر, cmp, attr)		\
attr فراغ								\
name##_RB_INSERT_COLOR(بنية name *سر_2, بنية type *elm)		\
{									\
	بنية type *پلار, *gparent, *tmp;				\
	طالما ((پلار = RB_پلار(elm, ډګر)) &&			\
	    RB_COLOR(پلار, ډګر) == RB_RED) {			\
		gparent = RB_پلار(پلار, ډګر);			\
		إذا (پلار == RB_کیڼ(gparent, ډګر)) {		\
			tmp = RB_ښی(gparent, ډګر);			\
			إذا (tmp && RB_COLOR(tmp, ډګر) == RB_RED) {	\
				RB_COLOR(tmp, ډګر) = RB_BLACK;	\
				RB_سېټ_BLACKRED(پلار, gparent, ډګر);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_ښی(پلار, ډګر) == elm) {		\
				RB_ROTATE_کیڼ(سر_2, پلار, tmp, ډګر);\
				tmp = پلار;				\
				پلار = elm;				\
				elm = tmp;				\
			}						\
			RB_سېټ_BLACKRED(پلار, gparent, ډګر);	\
			RB_ROTATE_ښی(سر_2, gparent, tmp, ډګر);	\
		} وإلا {						\
			tmp = RB_کیڼ(gparent, ډګر);			\
			إذا (tmp && RB_COLOR(tmp, ډګر) == RB_RED) {	\
				RB_COLOR(tmp, ډګر) = RB_BLACK;	\
				RB_سېټ_BLACKRED(پلار, gparent, ډګر);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_کیڼ(پلار, ډګر) == elm) {		\
				RB_ROTATE_ښی(سر_2, پلار, tmp, ډګر);\
				tmp = پلار;				\
				پلار = elm;				\
				elm = tmp;				\
			}						\
			RB_سېټ_BLACKRED(پلار, gparent, ډګر);	\
			RB_ROTATE_کیڼ(سر_2, gparent, tmp, ډګر);	\
		}							\
	}								\
	RB_COLOR(سر_2->rbh_ریښه, ډګر) = RB_BLACK;			\
}									\
									\
attr فراغ								\
name##_RB_REMOVE_COLOR(بنية name *سر_2, بنية type *پلار, بنية type *elm) \
{									\
	بنية type *tmp;						\
	طالما ((elm == عدم || RB_COLOR(elm, ډګر) == RB_BLACK) &&	\
	    elm != RB_ریښه(سر_2)) {					\
		إذا (RB_کیڼ(پلار, ډګر) == elm) {			\
			tmp = RB_ښی(پلار, ډګر);			\
			إذا (RB_COLOR(tmp, ډګر) == RB_RED) {		\
				RB_سېټ_BLACKRED(tmp, پلار, ډګر);	\
				RB_ROTATE_کیڼ(سر_2, پلار, tmp, ډګر);\
				tmp = RB_ښی(پلار, ډګر);		\
			}						\
			إذا ((RB_کیڼ(tmp, ډګر) == عدم ||		\
			    RB_COLOR(RB_کیڼ(tmp, ډګر), ډګر) == RB_BLACK) &&\
			    (RB_ښی(tmp, ډګر) == عدم ||		\
			    RB_COLOR(RB_ښی(tmp, ډګر), ډګر) == RB_BLACK)) {\
				RB_COLOR(tmp, ډګر) = RB_RED;		\
				elm = پلار;				\
				پلار = RB_پلار(elm, ډګر);		\
			} وإلا {					\
				إذا (RB_ښی(tmp, ډګر) == عدم ||	\
				    RB_COLOR(RB_ښی(tmp, ډګر), ډګر) == RB_BLACK) {\
					بنية type *oleft;		\
					إذا ((oleft = RB_کیڼ(tmp, ډګر)))\
						RB_COLOR(oleft, ډګر) = RB_BLACK;\
					RB_COLOR(tmp, ډګر) = RB_RED;	\
					RB_ROTATE_ښی(سر_2, tmp, oleft, ډګر);\
					tmp = RB_ښی(پلار, ډګر);	\
				}					\
				RB_COLOR(tmp, ډګر) = RB_COLOR(پلار, ډګر);\
				RB_COLOR(پلار, ډګر) = RB_BLACK;	\
				إذا (RB_ښی(tmp, ډګر))		\
					RB_COLOR(RB_ښی(tmp, ډګر), ډګر) = RB_BLACK;\
				RB_ROTATE_کیڼ(سر_2, پلار, tmp, ډګر);\
				elm = RB_ریښه(سر_2);			\
				اكسر;					\
			}						\
		} وإلا {						\
			tmp = RB_کیڼ(پلار, ډګر);			\
			إذا (RB_COLOR(tmp, ډګر) == RB_RED) {		\
				RB_سېټ_BLACKRED(tmp, پلار, ډګر);	\
				RB_ROTATE_ښی(سر_2, پلار, tmp, ډګر);\
				tmp = RB_کیڼ(پلار, ډګر);		\
			}						\
			إذا ((RB_کیڼ(tmp, ډګر) == عدم ||		\
			    RB_COLOR(RB_کیڼ(tmp, ډګر), ډګر) == RB_BLACK) &&\
			    (RB_ښی(tmp, ډګر) == عدم ||		\
			    RB_COLOR(RB_ښی(tmp, ډګر), ډګر) == RB_BLACK)) {\
				RB_COLOR(tmp, ډګر) = RB_RED;		\
				elm = پلار;				\
				پلار = RB_پلار(elm, ډګر);		\
			} وإلا {					\
				إذا (RB_کیڼ(tmp, ډګر) == عدم ||	\
				    RB_COLOR(RB_کیڼ(tmp, ډګر), ډګر) == RB_BLACK) {\
					بنية type *oright;		\
					إذا ((oright = RB_ښی(tmp, ډګر)))\
						RB_COLOR(oright, ډګر) = RB_BLACK;\
					RB_COLOR(tmp, ډګر) = RB_RED;	\
					RB_ROTATE_کیڼ(سر_2, tmp, oright, ډګر);\
					tmp = RB_کیڼ(پلار, ډګر);	\
				}					\
				RB_COLOR(tmp, ډګر) = RB_COLOR(پلار, ډګر);\
				RB_COLOR(پلار, ډګر) = RB_BLACK;	\
				إذا (RB_کیڼ(tmp, ډګر))		\
					RB_COLOR(RB_کیڼ(tmp, ډګر), ډګر) = RB_BLACK;\
				RB_ROTATE_ښی(سر_2, پلار, tmp, ډګر);\
				elm = RB_ریښه(سر_2);			\
				اكسر;					\
			}						\
		}							\
	}								\
	إذا (elm)							\
		RB_COLOR(elm, ډګر) = RB_BLACK;			\
}									\
									\
attr بنية type *							\
name##_RB_REMOVE(بنية name *سر_2, بنية type *elm)			\
{									\
	بنية type *ماشوم, *پلار, *old = elm;			\
	صحيح color;							\
	إذا (RB_کیڼ(elm, ډګر) == عدم)				\
		ماشوم = RB_ښی(elm, ډګر);				\
	وإلا إذا (RB_ښی(elm, ډګر) == عدم)				\
		ماشوم = RB_کیڼ(elm, ډګر);				\
	وإلا {								\
		بنية type *کیڼ;					\
		elm = RB_ښی(elm, ډګر);				\
		طالما ((کیڼ = RB_کیڼ(elm, ډګر)))			\
			elm = کیڼ;					\
		ماشوم = RB_ښی(elm, ډګر);				\
		پلار = RB_پلار(elm, ډګر);				\
		color = RB_COLOR(elm, ډګر);				\
		إذا (ماشوم)						\
			RB_پلار(ماشوم, ډګر) = پلار;		\
		إذا (پلار) {						\
			إذا (RB_کیڼ(پلار, ډګر) == elm)		\
				RB_کیڼ(پلار, ډګر) = ماشوم;		\
			وإلا						\
				RB_ښی(پلار, ډګر) = ماشوم;	\
			RB_AUGMENT(پلار);				\
		} وإلا							\
			RB_ریښه(سر_2) = ماشوم;				\
		إذا (RB_پلار(elm, ډګر) == old)			\
			پلار = elm;					\
		(elm)->ډګر = (old)->ډګر;				\
		إذا (RB_پلار(old, ډګر)) {				\
			إذا (RB_کیڼ(RB_پلار(old, ډګر), ډګر) == old)\
				RB_کیڼ(RB_پلار(old, ډګر), ډګر) = elm;\
			وإلا						\
				RB_ښی(RB_پلار(old, ډګر), ډګر) = elm;\
			RB_AUGMENT(RB_پلار(old, ډګر));		\
		} وإلا							\
			RB_ریښه(سر_2) = elm;				\
		RB_پلار(RB_کیڼ(old, ډګر), ډګر) = elm;		\
		إذا (RB_ښی(old, ډګر))				\
			RB_پلار(RB_ښی(old, ډګر), ډګر) = elm;	\
		إذا (پلار) {						\
			کیڼ = پلار;					\
			افعل {						\
				RB_AUGMENT(کیڼ);			\
			} طالما ((کیڼ = RB_پلار(کیڼ, ډګر)));	\
		}							\
		اذهب color;						\
	}								\
	پلار = RB_پلار(elm, ډګر);					\
	color = RB_COLOR(elm, ډګر);					\
	إذا (ماشوم)							\
		RB_پلار(ماشوم, ډګر) = پلار;			\
	إذا (پلار) {							\
		إذا (RB_کیڼ(پلار, ډګر) == elm)			\
			RB_کیڼ(پلار, ډګر) = ماشوم;			\
		وإلا							\
			RB_ښی(پلار, ډګر) = ماشوم;		\
		RB_AUGMENT(پلار);					\
	} وإلا								\
		RB_ریښه(سر_2) = ماشوم;					\
color:									\
	إذا (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(سر_2, پلار, ماشوم);		\
	أرجع (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr بنية type *							\
name##_RB_INSERT(بنية name *سر_2, بنية type *elm)			\
{									\
	بنية type *tmp;						\
	بنية type *پلار = عدم;					\
	صحيح comp = 0;							\
	tmp = RB_ریښه(سر_2);						\
	طالما (tmp) {							\
		پلار = tmp;						\
		comp = (cmp)(elm, پلار);				\
		إذا (comp < 0)						\
			tmp = RB_کیڼ(tmp, ډګر);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_ښی(tmp, ډګر);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	RB_سېټ(elm, پلار, ډګر);					\
	إذا (پلار != عدم) {						\
		إذا (comp < 0)						\
			RB_کیڼ(پلار, ډګر) = elm;			\
		وإلا							\
			RB_ښی(پلار, ډګر) = elm;			\
		RB_AUGMENT(پلار);					\
	} وإلا								\
		RB_ریښه(سر_2) = elm;					\
	name##_RB_INSERT_COLOR(سر_2, elm);				\
	أرجع (عدم);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr بنية type *							\
name##_RB_FIND(بنية name *سر_2, بنية type *elm)			\
{									\
	بنية type *tmp = RB_ریښه(سر_2);				\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0)						\
			tmp = RB_کیڼ(tmp, ډګر);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_ښی(tmp, ډګر);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	أرجع (عدم);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr بنية type *							\
name##_RB_NFIND(بنية name *سر_2, بنية type *elm)			\
{									\
	بنية type *tmp = RB_ریښه(سر_2);				\
	بنية type *res = عدم;					\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0) {						\
			res = tmp;					\
			tmp = RB_کیڼ(tmp, ډګر);			\
		}							\
		وإلا إذا (comp > 0)					\
			tmp = RB_ښی(tmp, ډګر);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	أرجع (res);							\
}									\
									\
/* ARGSUSED */								\
attr بنية type *							\
name##_RB_NEXT(بنية type *elm)					\
{									\
	إذا (RB_ښی(elm, ډګر)) {					\
		elm = RB_ښی(elm, ډګر);				\
		طالما (RB_کیڼ(elm, ډګر))				\
			elm = RB_کیڼ(elm, ډګر);			\
	} وإلا {							\
		إذا (RB_پلار(elm, ډګر) &&				\
		    (elm == RB_کیڼ(RB_پلار(elm, ډګر), ډګر)))	\
			elm = RB_پلار(elm, ډګر);			\
		وإلا {							\
			طالما (RB_پلار(elm, ډګر) &&			\
			    (elm == RB_ښی(RB_پلار(elm, ډګر), ډګر)))\
				elm = RB_پلار(elm, ډګر);		\
			elm = RB_پلار(elm, ډګر);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
/* ARGSUSED */								\
attr بنية type *							\
name##_RB_PREV(بنية type *elm)					\
{									\
	إذا (RB_کیڼ(elm, ډګر)) {					\
		elm = RB_کیڼ(elm, ډګر);				\
		طالما (RB_ښی(elm, ډګر))				\
			elm = RB_ښی(elm, ډګر);			\
	} وإلا {							\
		إذا (RB_پلار(elm, ډګر) &&				\
		    (elm == RB_ښی(RB_پلار(elm, ډګر), ډګر)))	\
			elm = RB_پلار(elm, ډګر);			\
		وإلا {							\
			طالما (RB_پلار(elm, ډګر) &&			\
			    (elm == RB_کیڼ(RB_پلار(elm, ډګر), ډګر)))\
				elm = RB_پلار(elm, ډګر);		\
			elm = RB_پلار(elm, ډګر);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
attr بنية type *							\
name##_RB_MINMAX(بنية name *سر_2, صحيح val)				\
{									\
	بنية type *tmp = RB_ریښه(سر_2);				\
	بنية type *پلار = عدم;					\
	طالما (tmp) {							\
		پلار = tmp;						\
		إذا (val < 0)						\
			tmp = RB_کیڼ(tmp, ډګر);			\
		وإلا							\
			tmp = RB_ښی(tmp, ډګر);			\
	}								\
	أرجع (پلار);						\
}

#تعریف_کړه RB_NEGINF	-1
#تعریف_کړه RB_INF	1

#تعریف_کړه RB_ورننباسه(name, x, y)	name##_RB_INSERT(x, y)
#تعریف_کړه RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#تعریف_کړه RB_پیدا_کړه(name, x, y)	name##_RB_FIND(x, y)
#تعریف_کړه RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#تعریف_کړه RB_بل(name, x, y)	name##_RB_NEXT(y)
#تعریف_کړه RB_PREV(name, x, y)	name##_RB_PREV(y)
#تعریف_کړه RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#تعریف_کړه RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#تعریف_کړه RB_FOREACH(x, name, سر_2)					\
	لكل ((x) = RB_MIN(name, سر_2);					\
	     (x) != عدم;						\
	     (x) = name##_RB_NEXT(x))

#تعریف_کړه RB_FOREACH_خوندي(x, name, سر_2, y)				\
	لكل ((x) = RB_MIN(name, سر_2);					\
	    ((x) != عدم) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#تعریف_کړه RB_FOREACH_سرچپه(x, name, سر_2)				\
	لكل ((x) = RB_MAX(name, سر_2);					\
	     (x) != عدم;						\
	     (x) = name##_RB_PREV(x))

#تعریف_کړه RB_FOREACH_سرچپه_خوندي(x, name, سر_2, y)			\
	لكل ((x) = RB_MAX(name, سر_2);					\
	    ((x) != عدم) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#د_که_پای	/* _SYS_TREE_H_ */
