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
#جے_تعریف_شدہ NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#جے_انت

#جے_بنا_تعریف	SYS_درخت_H
#تعریف_کرو	SYS_درخت_H

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

#تعریف_کرو SPLAY_سر(name, type)						\
بنية name {								\
	بنية type *sph_جڑ; /* root of the tree */			\
}

#تعریف_کرو SPLAY_INITIALIZER(جڑ)						\
	{ عدم }

#تعریف_کرو SPLAY_INIT(جڑ) افعل {						\
	(جڑ)->sph_جڑ = عدم;					\
} طالما (0)

#تعریف_کرو SPLAY_اندراج(type)						\
بنية {								\
	بنية type *spe_بایاں; /* left element */			\
	بنية type *spe_دایاں; /* right element */			\
}

#تعریف_کرو SPLAY_بایاں(elm, میدان)		(elm)->میدان.spe_بایاں
#تعریف_کرو SPLAY_دایاں(elm, میدان)		(elm)->میدان.spe_دایاں
#تعریف_کرو SPLAY_جڑ(سر)		(سر)->sph_جڑ
#تعریف_کرو SPLAY_خالی_تھاواں(سر)		(SPLAY_جڑ(سر) == عدم)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#تعریف_کرو SPLAY_ROTATE_دایاں(سر, tmp, میدان) افعل {			\
	SPLAY_بایاں((سر)->sph_جڑ, میدان) = SPLAY_دایاں(tmp, میدان);	\
	SPLAY_دایاں(tmp, میدان) = (سر)->sph_جڑ;			\
	(سر)->sph_جڑ = tmp;						\
} طالما (0)
	
#تعریف_کرو SPLAY_ROTATE_بایاں(سر, tmp, میدان) افعل {			\
	SPLAY_دایاں((سر)->sph_جڑ, میدان) = SPLAY_بایاں(tmp, میدان);	\
	SPLAY_بایاں(tmp, میدان) = (سر)->sph_جڑ;			\
	(سر)->sph_جڑ = tmp;						\
} طالما (0)

#تعریف_کرو SPLAY_LINKLEFT(سر, tmp, میدان) افعل {				\
	SPLAY_بایاں(tmp, میدان) = (سر)->sph_جڑ;			\
	tmp = (سر)->sph_جڑ;						\
	(سر)->sph_جڑ = SPLAY_بایاں((سر)->sph_جڑ, میدان);		\
} طالما (0)

#تعریف_کرو SPLAY_LINKRIGHT(سر, tmp, میدان) افعل {				\
	SPLAY_دایاں(tmp, میدان) = (سر)->sph_جڑ;			\
	tmp = (سر)->sph_جڑ;						\
	(سر)->sph_جڑ = SPLAY_دایاں((سر)->sph_جڑ, میدان);	\
} طالما (0)

#تعریف_کرو SPLAY_ASSEMBLE(سر, گرہ, بایاں, دایاں, میدان) افعل {		\
	SPLAY_دایاں(بایاں, میدان) = SPLAY_بایاں((سر)->sph_جڑ, میدان);	\
	SPLAY_بایاں(دایاں, میدان) = SPLAY_دایاں((سر)->sph_جڑ, میدان);\
	SPLAY_بایاں((سر)->sph_جڑ, میدان) = SPLAY_دایاں(گرہ, میدان);	\
	SPLAY_دایاں((سر)->sph_جڑ, میدان) = SPLAY_بایاں(گرہ, میدان);	\
} طالما (0)

/* Generates prototypes and inline functions */

#تعریف_کرو SPLAY_PROTOTYPE(name, type, میدان, cmp)				\
فراغ name##_SPLAY(بنية name *, بنية type *);			\
فراغ name##_SPLAY_MINMAX(بنية name *, صحيح);				\
بنية type *name##_SPLAY_INSERT(بنية name *, بنية type *);		\
بنية type *name##_SPLAY_REMOVE(بنية name *, بنية type *);		\
									\
/* Finds the node with the same key as elm */				\
ساكن __inline بنية type *						\
name##_SPLAY_FIND(بنية name *سر, بنية type *elm)			\
{									\
	إذا (SPLAY_خالی_تھاواں(سر))						\
		أرجع(عدم);						\
	name##_SPLAY(سر, elm);					\
	إذا ((cmp)(elm, (سر)->sph_جڑ) == 0)				\
		أرجع (سر->sph_جڑ);				\
	أرجع (عدم);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_NEXT(بنية name *سر, بنية type *elm)			\
{									\
	name##_SPLAY(سر, elm);					\
	إذا (SPLAY_دایاں(elm, میدان) != عدم) {				\
		elm = SPLAY_دایاں(elm, میدان);				\
		طالما (SPLAY_بایاں(elm, میدان) != عدم) {		\
			elm = SPLAY_بایاں(elm, میدان);			\
		}							\
	} وإلا								\
		elm = عدم;						\
	أرجع (elm);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_MIN_MAX(بنية name *سر, صحيح val)			\
{									\
	name##_SPLAY_MINMAX(سر, val);					\
        أرجع (SPLAY_جڑ(سر));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#تعریف_کرو SPLAY_GENERATE(name, type, میدان, cmp)				\
بنية type *								\
name##_SPLAY_INSERT(بنية name *سر, بنية type *elm)		\
{									\
    إذا (SPLAY_خالی_تھاواں(سر)) {						\
	    SPLAY_بایاں(elm, میدان) = SPLAY_دایاں(elm, میدان) = عدم;	\
    } وإلا {								\
	    صحيح __comp;							\
	    name##_SPLAY(سر, elm);					\
	    __comp = (cmp)(elm, (سر)->sph_جڑ);			\
	    إذا(__comp < 0) {						\
		    SPLAY_بایاں(elm, میدان) = SPLAY_بایاں((سر)->sph_جڑ, میدان);\
		    SPLAY_دایاں(elm, میدان) = (سر)->sph_جڑ;		\
		    SPLAY_بایاں((سر)->sph_جڑ, میدان) = عدم;		\
	    } وإلا إذا (__comp > 0) {					\
		    SPLAY_دایاں(elm, میدان) = SPLAY_دایاں((سر)->sph_جڑ, میدان);\
		    SPLAY_بایاں(elm, میدان) = (سر)->sph_جڑ;		\
		    SPLAY_دایاں((سر)->sph_جڑ, میدان) = عدم;	\
	    } وإلا							\
		    أرجع ((سر)->sph_جڑ);				\
    }									\
    (سر)->sph_جڑ = (elm);						\
    أرجع (عدم);							\
}									\
									\
بنية type *								\
name##_SPLAY_REMOVE(بنية name *سر, بنية type *elm)		\
{									\
	بنية type *__tmp;						\
	إذا (SPLAY_خالی_تھاواں(سر))						\
		أرجع (عدم);						\
	name##_SPLAY(سر, elm);					\
	إذا ((cmp)(elm, (سر)->sph_جڑ) == 0) {			\
		إذا (SPLAY_بایاں((سر)->sph_جڑ, میدان) == عدم) {	\
			(سر)->sph_جڑ = SPLAY_دایاں((سر)->sph_جڑ, میدان);\
		} وإلا {						\
			__tmp = SPLAY_دایاں((سر)->sph_جڑ, میدان);	\
			(سر)->sph_جڑ = SPLAY_بایاں((سر)->sph_جڑ, میدان);\
			name##_SPLAY(سر, elm);			\
			SPLAY_دایاں((سر)->sph_جڑ, میدان) = __tmp;	\
		}							\
		أرجع (elm);						\
	}								\
	أرجع (عدم);							\
}									\
									\
فراغ									\
name##_SPLAY(بنية name *سر, بنية type *elm)			\
{									\
	بنية type __node, *__left, *__right, *__tmp;			\
	صحيح __comp;							\
\
	SPLAY_بایاں(&__node, میدان) = SPLAY_دایاں(&__node, میدان) = عدم;\
	__left = __right = &__node;					\
\
	طالما ((__comp = (cmp)(elm, (سر)->sph_جڑ))) {		\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_بایاں((سر)->sph_جڑ, میدان);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_دایاں(سر, __tmp, میدان);	\
				إذا (SPLAY_بایاں((سر)->sph_جڑ, میدان) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(سر, __right, میدان);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_دایاں((سر)->sph_جڑ, میدان);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_بایاں(سر, __tmp, میدان);	\
				إذا (SPLAY_دایاں((سر)->sph_جڑ, میدان) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(سر, __left, میدان);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(سر, &__node, __left, __right, میدان);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
فراغ name##_SPLAY_MINMAX(بنية name *سر, صحيح __comp) \
{									\
	بنية type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_بایاں(&__node, میدان) = SPLAY_دایاں(&__node, میدان) = عدم;\
	__left = __right = &__node;					\
\
	طالما (1) {							\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_بایاں((سر)->sph_جڑ, میدان);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp < 0){				\
				SPLAY_ROTATE_دایاں(سر, __tmp, میدان);	\
				إذا (SPLAY_بایاں((سر)->sph_جڑ, میدان) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(سر, __right, میدان);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_دایاں((سر)->sph_جڑ, میدان);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp > 0) {				\
				SPLAY_ROTATE_بایاں(سر, __tmp, میدان);	\
				إذا (SPLAY_دایاں((سر)->sph_جڑ, میدان) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(سر, __left, میدان);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(سر, &__node, __left, __right, میدان);		\
}

#تعریف_کرو SPLAY_NEGINF	-1
#تعریف_کرو SPLAY_INF	1

#تعریف_کرو SPLAY_داخل_کرو(name, x, y)	name##_SPLAY_INSERT(x, y)
#تعریف_کرو SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#تعریف_کرو SPLAY_لبھو(name, x, y)		name##_SPLAY_FIND(x, y)
#تعریف_کرو SPLAY_اگلا(name, x, y)		name##_SPLAY_NEXT(x, y)
#تعریف_کرو SPLAY_MIN(name, x)		(SPLAY_خالی_تھاواں(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#تعریف_کرو SPLAY_MAX(name, x)		(SPLAY_خالی_تھاواں(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#تعریف_کرو SPLAY_FOREACH(x, name, سر)					\
	لكل ((x) = SPLAY_MIN(name, سر);				\
	     (x) != عدم;						\
	     (x) = SPLAY_اگلا(name, سر, x))

/* Macros that define a red-black tree */
#تعریف_کرو RB_سر(name, type)						\
بنية name {								\
	بنية type *rbh_جڑ; /* root of the tree */			\
}

#تعریف_کرو RB_INITIALIZER(جڑ)						\
	{ عدم }

#تعریف_کرو RB_INIT(جڑ) افعل {						\
	(جڑ)->rbh_جڑ = عدم;					\
} طالما (0)

#تعریف_کرو RB_BLACK	0
#تعریف_کرو RB_RED		1
#تعریف_کرو RB_اندراج(type)							\
بنية {								\
	بنية type *rbe_بایاں;		/* left element */		\
	بنية type *rbe_دایاں;		/* right element */		\
	بنية type *rbe_ماپا;	/* parent element */		\
	صحيح rbe_color;			/* node color */		\
}

#تعریف_کرو RB_بایاں(elm, میدان)		(elm)->میدان.rbe_بایاں
#تعریف_کرو RB_دایاں(elm, میدان)		(elm)->میدان.rbe_دایاں
#تعریف_کرو RB_ماپا(elm, میدان)		(elm)->میدان.rbe_ماپا
#تعریف_کرو RB_COLOR(elm, میدان)		(elm)->میدان.rbe_color
#تعریف_کرو RB_جڑ(سر)			(سر)->rbh_جڑ
#تعریف_کرو RB_خالی_تھاواں(سر)			(RB_جڑ(سر) == عدم)

#تعریف_کرو RB_سیٹ(elm, ماپا, میدان) افعل {					\
	RB_ماپا(elm, میدان) = ماپا;					\
	RB_بایاں(elm, میدان) = RB_دایاں(elm, میدان) = عدم;		\
	RB_COLOR(elm, میدان) = RB_RED;					\
} طالما (0)

#تعریف_کرو RB_سیٹ_BLACKRED(black, red, میدان) افعل {				\
	RB_COLOR(black, میدان) = RB_BLACK;				\
	RB_COLOR(red, میدان) = RB_RED;					\
} طالما (0)

#جے_بنا_تعریف RB_AUGMENT
#تعریف_کرو RB_AUGMENT(x)	افعل {} طالما (0)
#جے_انت

#تعریف_کرو RB_ROTATE_بایاں(سر, elm, tmp, میدان) افعل {			\
	(tmp) = RB_دایاں(elm, میدان);					\
	إذا ((RB_دایاں(elm, میدان) = RB_بایاں(tmp, میدان))) {		\
		RB_ماپا(RB_بایاں(tmp, میدان), میدان) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_ماپا(tmp, میدان) = RB_ماپا(elm, میدان))) {		\
		إذا ((elm) == RB_بایاں(RB_ماپا(elm, میدان), میدان))	\
			RB_بایاں(RB_ماپا(elm, میدان), میدان) = (tmp);	\
		وإلا							\
			RB_دایاں(RB_ماپا(elm, میدان), میدان) = (tmp);	\
	} وإلا								\
		(سر)->rbh_جڑ = (tmp);				\
	RB_بایاں(tmp, میدان) = (elm);					\
	RB_ماپا(elm, میدان) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_ماپا(tmp, میدان)))					\
		RB_AUGMENT(RB_ماپا(tmp, میدان));			\
} طالما (0)

#تعریف_کرو RB_ROTATE_دایاں(سر, elm, tmp, میدان) افعل {			\
	(tmp) = RB_بایاں(elm, میدان);					\
	إذا ((RB_بایاں(elm, میدان) = RB_دایاں(tmp, میدان))) {		\
		RB_ماپا(RB_دایاں(tmp, میدان), میدان) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_ماپا(tmp, میدان) = RB_ماپا(elm, میدان))) {		\
		إذا ((elm) == RB_بایاں(RB_ماپا(elm, میدان), میدان))	\
			RB_بایاں(RB_ماپا(elm, میدان), میدان) = (tmp);	\
		وإلا							\
			RB_دایاں(RB_ماپا(elm, میدان), میدان) = (tmp);	\
	} وإلا								\
		(سر)->rbh_جڑ = (tmp);				\
	RB_دایاں(tmp, میدان) = (elm);					\
	RB_ماپا(elm, میدان) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_ماپا(tmp, میدان)))					\
		RB_AUGMENT(RB_ماپا(tmp, میدان));			\
} طالما (0)

/* Generates prototypes and inline functions */
#تعریف_کرو	RB_PROTOTYPE(name, type, میدان, cmp)				\
	RB_PROTOTYPE_اندرونی(name, type, میدان, cmp,)
#تعریف_کرو	RB_PROTOTYPE_STATIC(name, type, میدان, cmp)			\
	RB_PROTOTYPE_اندرونی(name, type, میدان, cmp, __attribute__((__unused__)) ساكن)
#تعریف_کرو RB_PROTOTYPE_اندرونی(name, type, میدان, cmp, attr)		\
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
#تعریف_کرو	RB_GENERATE(name, type, میدان, cmp)				\
	RB_GENERATE_اندرونی(name, type, میدان, cmp,)
#تعریف_کرو	RB_GENERATE_STATIC(name, type, میدان, cmp)			\
	RB_GENERATE_اندرونی(name, type, میدان, cmp, __attribute__((__unused__)) ساكن)
#تعریف_کرو RB_GENERATE_اندرونی(name, type, میدان, cmp, attr)		\
attr فراغ								\
name##_RB_INSERT_COLOR(بنية name *سر, بنية type *elm)		\
{									\
	بنية type *ماپا, *gparent, *tmp;				\
	طالما ((ماپا = RB_ماپا(elm, میدان)) &&			\
	    RB_COLOR(ماپا, میدان) == RB_RED) {			\
		gparent = RB_ماپا(ماپا, میدان);			\
		إذا (ماپا == RB_بایاں(gparent, میدان)) {		\
			tmp = RB_دایاں(gparent, میدان);			\
			إذا (tmp && RB_COLOR(tmp, میدان) == RB_RED) {	\
				RB_COLOR(tmp, میدان) = RB_BLACK;	\
				RB_سیٹ_BLACKRED(ماپا, gparent, میدان);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_دایاں(ماپا, میدان) == elm) {		\
				RB_ROTATE_بایاں(سر, ماپا, tmp, میدان);\
				tmp = ماپا;				\
				ماپا = elm;				\
				elm = tmp;				\
			}						\
			RB_سیٹ_BLACKRED(ماپا, gparent, میدان);	\
			RB_ROTATE_دایاں(سر, gparent, tmp, میدان);	\
		} وإلا {						\
			tmp = RB_بایاں(gparent, میدان);			\
			إذا (tmp && RB_COLOR(tmp, میدان) == RB_RED) {	\
				RB_COLOR(tmp, میدان) = RB_BLACK;	\
				RB_سیٹ_BLACKRED(ماپا, gparent, میدان);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_بایاں(ماپا, میدان) == elm) {		\
				RB_ROTATE_دایاں(سر, ماپا, tmp, میدان);\
				tmp = ماپا;				\
				ماپا = elm;				\
				elm = tmp;				\
			}						\
			RB_سیٹ_BLACKRED(ماپا, gparent, میدان);	\
			RB_ROTATE_بایاں(سر, gparent, tmp, میدان);	\
		}							\
	}								\
	RB_COLOR(سر->rbh_جڑ, میدان) = RB_BLACK;			\
}									\
									\
attr فراغ								\
name##_RB_REMOVE_COLOR(بنية name *سر, بنية type *ماپا, بنية type *elm) \
{									\
	بنية type *tmp;						\
	طالما ((elm == عدم || RB_COLOR(elm, میدان) == RB_BLACK) &&	\
	    elm != RB_جڑ(سر)) {					\
		إذا (RB_بایاں(ماپا, میدان) == elm) {			\
			tmp = RB_دایاں(ماپا, میدان);			\
			إذا (RB_COLOR(tmp, میدان) == RB_RED) {		\
				RB_سیٹ_BLACKRED(tmp, ماپا, میدان);	\
				RB_ROTATE_بایاں(سر, ماپا, tmp, میدان);\
				tmp = RB_دایاں(ماپا, میدان);		\
			}						\
			إذا ((RB_بایاں(tmp, میدان) == عدم ||		\
			    RB_COLOR(RB_بایاں(tmp, میدان), میدان) == RB_BLACK) &&\
			    (RB_دایاں(tmp, میدان) == عدم ||		\
			    RB_COLOR(RB_دایاں(tmp, میدان), میدان) == RB_BLACK)) {\
				RB_COLOR(tmp, میدان) = RB_RED;		\
				elm = ماپا;				\
				ماپا = RB_ماپا(elm, میدان);		\
			} وإلا {					\
				إذا (RB_دایاں(tmp, میدان) == عدم ||	\
				    RB_COLOR(RB_دایاں(tmp, میدان), میدان) == RB_BLACK) {\
					بنية type *oleft;		\
					إذا ((oleft = RB_بایاں(tmp, میدان)))\
						RB_COLOR(oleft, میدان) = RB_BLACK;\
					RB_COLOR(tmp, میدان) = RB_RED;	\
					RB_ROTATE_دایاں(سر, tmp, oleft, میدان);\
					tmp = RB_دایاں(ماپا, میدان);	\
				}					\
				RB_COLOR(tmp, میدان) = RB_COLOR(ماپا, میدان);\
				RB_COLOR(ماپا, میدان) = RB_BLACK;	\
				إذا (RB_دایاں(tmp, میدان))		\
					RB_COLOR(RB_دایاں(tmp, میدان), میدان) = RB_BLACK;\
				RB_ROTATE_بایاں(سر, ماپا, tmp, میدان);\
				elm = RB_جڑ(سر);			\
				اكسر;					\
			}						\
		} وإلا {						\
			tmp = RB_بایاں(ماپا, میدان);			\
			إذا (RB_COLOR(tmp, میدان) == RB_RED) {		\
				RB_سیٹ_BLACKRED(tmp, ماپا, میدان);	\
				RB_ROTATE_دایاں(سر, ماپا, tmp, میدان);\
				tmp = RB_بایاں(ماپا, میدان);		\
			}						\
			إذا ((RB_بایاں(tmp, میدان) == عدم ||		\
			    RB_COLOR(RB_بایاں(tmp, میدان), میدان) == RB_BLACK) &&\
			    (RB_دایاں(tmp, میدان) == عدم ||		\
			    RB_COLOR(RB_دایاں(tmp, میدان), میدان) == RB_BLACK)) {\
				RB_COLOR(tmp, میدان) = RB_RED;		\
				elm = ماپا;				\
				ماپا = RB_ماپا(elm, میدان);		\
			} وإلا {					\
				إذا (RB_بایاں(tmp, میدان) == عدم ||	\
				    RB_COLOR(RB_بایاں(tmp, میدان), میدان) == RB_BLACK) {\
					بنية type *oright;		\
					إذا ((oright = RB_دایاں(tmp, میدان)))\
						RB_COLOR(oright, میدان) = RB_BLACK;\
					RB_COLOR(tmp, میدان) = RB_RED;	\
					RB_ROTATE_بایاں(سر, tmp, oright, میدان);\
					tmp = RB_بایاں(ماپا, میدان);	\
				}					\
				RB_COLOR(tmp, میدان) = RB_COLOR(ماپا, میدان);\
				RB_COLOR(ماپا, میدان) = RB_BLACK;	\
				إذا (RB_بایاں(tmp, میدان))		\
					RB_COLOR(RB_بایاں(tmp, میدان), میدان) = RB_BLACK;\
				RB_ROTATE_دایاں(سر, ماپا, tmp, میدان);\
				elm = RB_جڑ(سر);			\
				اكسر;					\
			}						\
		}							\
	}								\
	إذا (elm)							\
		RB_COLOR(elm, میدان) = RB_BLACK;			\
}									\
									\
attr بنية type *							\
name##_RB_REMOVE(بنية name *سر, بنية type *elm)			\
{									\
	بنية type *بچہ, *ماپا, *old = elm;			\
	صحيح color;							\
	إذا (RB_بایاں(elm, میدان) == عدم)				\
		بچہ = RB_دایاں(elm, میدان);				\
	وإلا إذا (RB_دایاں(elm, میدان) == عدم)				\
		بچہ = RB_بایاں(elm, میدان);				\
	وإلا {								\
		بنية type *بایاں;					\
		elm = RB_دایاں(elm, میدان);				\
		طالما ((بایاں = RB_بایاں(elm, میدان)))			\
			elm = بایاں;					\
		بچہ = RB_دایاں(elm, میدان);				\
		ماپا = RB_ماپا(elm, میدان);				\
		color = RB_COLOR(elm, میدان);				\
		إذا (بچہ)						\
			RB_ماپا(بچہ, میدان) = ماپا;		\
		إذا (ماپا) {						\
			إذا (RB_بایاں(ماپا, میدان) == elm)		\
				RB_بایاں(ماپا, میدان) = بچہ;		\
			وإلا						\
				RB_دایاں(ماپا, میدان) = بچہ;	\
			RB_AUGMENT(ماپا);				\
		} وإلا							\
			RB_جڑ(سر) = بچہ;				\
		إذا (RB_ماپا(elm, میدان) == old)			\
			ماپا = elm;					\
		(elm)->میدان = (old)->میدان;				\
		إذا (RB_ماپا(old, میدان)) {				\
			إذا (RB_بایاں(RB_ماپا(old, میدان), میدان) == old)\
				RB_بایاں(RB_ماپا(old, میدان), میدان) = elm;\
			وإلا						\
				RB_دایاں(RB_ماپا(old, میدان), میدان) = elm;\
			RB_AUGMENT(RB_ماپا(old, میدان));		\
		} وإلا							\
			RB_جڑ(سر) = elm;				\
		RB_ماپا(RB_بایاں(old, میدان), میدان) = elm;		\
		إذا (RB_دایاں(old, میدان))				\
			RB_ماپا(RB_دایاں(old, میدان), میدان) = elm;	\
		إذا (ماپا) {						\
			بایاں = ماپا;					\
			افعل {						\
				RB_AUGMENT(بایاں);			\
			} طالما ((بایاں = RB_ماپا(بایاں, میدان)));	\
		}							\
		اذهب color;						\
	}								\
	ماپا = RB_ماپا(elm, میدان);					\
	color = RB_COLOR(elm, میدان);					\
	إذا (بچہ)							\
		RB_ماپا(بچہ, میدان) = ماپا;			\
	إذا (ماپا) {							\
		إذا (RB_بایاں(ماپا, میدان) == elm)			\
			RB_بایاں(ماپا, میدان) = بچہ;			\
		وإلا							\
			RB_دایاں(ماپا, میدان) = بچہ;		\
		RB_AUGMENT(ماپا);					\
	} وإلا								\
		RB_جڑ(سر) = بچہ;					\
color:									\
	إذا (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(سر, ماپا, بچہ);		\
	أرجع (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr بنية type *							\
name##_RB_INSERT(بنية name *سر, بنية type *elm)			\
{									\
	بنية type *tmp;						\
	بنية type *ماپا = عدم;					\
	صحيح comp = 0;							\
	tmp = RB_جڑ(سر);						\
	طالما (tmp) {							\
		ماپا = tmp;						\
		comp = (cmp)(elm, ماپا);				\
		إذا (comp < 0)						\
			tmp = RB_بایاں(tmp, میدان);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_دایاں(tmp, میدان);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	RB_سیٹ(elm, ماپا, میدان);					\
	إذا (ماپا != عدم) {						\
		إذا (comp < 0)						\
			RB_بایاں(ماپا, میدان) = elm;			\
		وإلا							\
			RB_دایاں(ماپا, میدان) = elm;			\
		RB_AUGMENT(ماپا);					\
	} وإلا								\
		RB_جڑ(سر) = elm;					\
	name##_RB_INSERT_COLOR(سر, elm);				\
	أرجع (عدم);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr بنية type *							\
name##_RB_FIND(بنية name *سر, بنية type *elm)			\
{									\
	بنية type *tmp = RB_جڑ(سر);				\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0)						\
			tmp = RB_بایاں(tmp, میدان);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_دایاں(tmp, میدان);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	أرجع (عدم);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr بنية type *							\
name##_RB_NFIND(بنية name *سر, بنية type *elm)			\
{									\
	بنية type *tmp = RB_جڑ(سر);				\
	بنية type *res = عدم;					\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0) {						\
			res = tmp;					\
			tmp = RB_بایاں(tmp, میدان);			\
		}							\
		وإلا إذا (comp > 0)					\
			tmp = RB_دایاں(tmp, میدان);			\
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
	إذا (RB_دایاں(elm, میدان)) {					\
		elm = RB_دایاں(elm, میدان);				\
		طالما (RB_بایاں(elm, میدان))				\
			elm = RB_بایاں(elm, میدان);			\
	} وإلا {							\
		إذا (RB_ماپا(elm, میدان) &&				\
		    (elm == RB_بایاں(RB_ماپا(elm, میدان), میدان)))	\
			elm = RB_ماپا(elm, میدان);			\
		وإلا {							\
			طالما (RB_ماپا(elm, میدان) &&			\
			    (elm == RB_دایاں(RB_ماپا(elm, میدان), میدان)))\
				elm = RB_ماپا(elm, میدان);		\
			elm = RB_ماپا(elm, میدان);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
/* ARGSUSED */								\
attr بنية type *							\
name##_RB_PREV(بنية type *elm)					\
{									\
	إذا (RB_بایاں(elm, میدان)) {					\
		elm = RB_بایاں(elm, میدان);				\
		طالما (RB_دایاں(elm, میدان))				\
			elm = RB_دایاں(elm, میدان);			\
	} وإلا {							\
		إذا (RB_ماپا(elm, میدان) &&				\
		    (elm == RB_دایاں(RB_ماپا(elm, میدان), میدان)))	\
			elm = RB_ماپا(elm, میدان);			\
		وإلا {							\
			طالما (RB_ماپا(elm, میدان) &&			\
			    (elm == RB_بایاں(RB_ماپا(elm, میدان), میدان)))\
				elm = RB_ماپا(elm, میدان);		\
			elm = RB_ماپا(elm, میدان);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
attr بنية type *							\
name##_RB_MINMAX(بنية name *سر, صحيح val)				\
{									\
	بنية type *tmp = RB_جڑ(سر);				\
	بنية type *ماپا = عدم;					\
	طالما (tmp) {							\
		ماپا = tmp;						\
		إذا (val < 0)						\
			tmp = RB_بایاں(tmp, میدان);			\
		وإلا							\
			tmp = RB_دایاں(tmp, میدان);			\
	}								\
	أرجع (ماپا);						\
}

#تعریف_کرو RB_NEGINF	-1
#تعریف_کرو RB_INF	1

#تعریف_کرو RB_داخل_کرو(name, x, y)	name##_RB_INSERT(x, y)
#تعریف_کرو RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#تعریف_کرو RB_لبھو(name, x, y)	name##_RB_FIND(x, y)
#تعریف_کرو RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#تعریف_کرو RB_اگلا(name, x, y)	name##_RB_NEXT(y)
#تعریف_کرو RB_PREV(name, x, y)	name##_RB_PREV(y)
#تعریف_کرو RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#تعریف_کرو RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#تعریف_کرو RB_FOREACH(x, name, سر)					\
	لكل ((x) = RB_MIN(name, سر);					\
	     (x) != عدم;						\
	     (x) = name##_RB_NEXT(x))

#تعریف_کرو RB_FOREACH_محفوظ(x, name, سر, y)				\
	لكل ((x) = RB_MIN(name, سر);					\
	    ((x) != عدم) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#تعریف_کرو RB_FOREACH_الٹ(x, name, سر)				\
	لكل ((x) = RB_MAX(name, سر);					\
	     (x) != عدم;						\
	     (x) = name##_RB_PREV(x))

#تعریف_کرو RB_FOREACH_الٹ_محفوظ(x, name, سر, y)			\
	لكل ((x) = RB_MAX(name, سر);					\
	    ((x) != عدم) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#جے_انت	/* _SYS_TREE_H_ */
