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
#جيڪڏهن_وصف_ٿيل NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل	SYS_وڻ_H
#وصف_ڪريو	SYS_وڻ_H

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

#وصف_ڪريو SPLAY_سر(name, type)						\
بنية name {								\
	بنية type *sph_پاڙ; /* root of the tree */			\
}

#وصف_ڪريو SPLAY_INITIALIZER(پاڙ)						\
	{ عدم }

#وصف_ڪريو SPLAY_INIT(پاڙ) افعل {						\
	(پاڙ)->sph_پاڙ = عدم;					\
} طالما (0)

#وصف_ڪريو SPLAY_داخلا(type)						\
بنية {								\
	بنية type *spe_کاٻو; /* left element */			\
	بنية type *spe_ساڄو; /* right element */			\
}

#وصف_ڪريو SPLAY_کاٻو(elm, ميدان)		(elm)->ميدان.spe_کاٻو
#وصف_ڪريو SPLAY_ساڄو(elm, ميدان)		(elm)->ميدان.spe_ساڄو
#وصف_ڪريو SPLAY_پاڙ(سر)		(سر)->sph_پاڙ
#وصف_ڪريو SPLAY_خالي_جايون(سر)		(SPLAY_پاڙ(سر) == عدم)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#وصف_ڪريو SPLAY_ROTATE_ساڄو(سر, tmp, ميدان) افعل {			\
	SPLAY_کاٻو((سر)->sph_پاڙ, ميدان) = SPLAY_ساڄو(tmp, ميدان);	\
	SPLAY_ساڄو(tmp, ميدان) = (سر)->sph_پاڙ;			\
	(سر)->sph_پاڙ = tmp;						\
} طالما (0)
	
#وصف_ڪريو SPLAY_ROTATE_کاٻو(سر, tmp, ميدان) افعل {			\
	SPLAY_ساڄو((سر)->sph_پاڙ, ميدان) = SPLAY_کاٻو(tmp, ميدان);	\
	SPLAY_کاٻو(tmp, ميدان) = (سر)->sph_پاڙ;			\
	(سر)->sph_پاڙ = tmp;						\
} طالما (0)

#وصف_ڪريو SPLAY_LINKLEFT(سر, tmp, ميدان) افعل {				\
	SPLAY_کاٻو(tmp, ميدان) = (سر)->sph_پاڙ;			\
	tmp = (سر)->sph_پاڙ;						\
	(سر)->sph_پاڙ = SPLAY_کاٻو((سر)->sph_پاڙ, ميدان);		\
} طالما (0)

#وصف_ڪريو SPLAY_LINKRIGHT(سر, tmp, ميدان) افعل {				\
	SPLAY_ساڄو(tmp, ميدان) = (سر)->sph_پاڙ;			\
	tmp = (سر)->sph_پاڙ;						\
	(سر)->sph_پاڙ = SPLAY_ساڄو((سر)->sph_پاڙ, ميدان);	\
} طالما (0)

#وصف_ڪريو SPLAY_ASSEMBLE(سر, ڳنڍ, کاٻو, ساڄو, ميدان) افعل {		\
	SPLAY_ساڄو(کاٻو, ميدان) = SPLAY_کاٻو((سر)->sph_پاڙ, ميدان);	\
	SPLAY_کاٻو(ساڄو, ميدان) = SPLAY_ساڄو((سر)->sph_پاڙ, ميدان);\
	SPLAY_کاٻو((سر)->sph_پاڙ, ميدان) = SPLAY_ساڄو(ڳنڍ, ميدان);	\
	SPLAY_ساڄو((سر)->sph_پاڙ, ميدان) = SPLAY_کاٻو(ڳنڍ, ميدان);	\
} طالما (0)

/* Generates prototypes and inline functions */

#وصف_ڪريو SPLAY_PROTOTYPE(name, type, ميدان, cmp)				\
فراغ name##_SPLAY(بنية name *, بنية type *);			\
فراغ name##_SPLAY_MINMAX(بنية name *, صحيح);				\
بنية type *name##_SPLAY_INSERT(بنية name *, بنية type *);		\
بنية type *name##_SPLAY_REMOVE(بنية name *, بنية type *);		\
									\
/* Finds the node with the same key as elm */				\
ساكن __inline بنية type *						\
name##_SPLAY_FIND(بنية name *سر, بنية type *elm)			\
{									\
	إذا (SPLAY_خالي_جايون(سر))						\
		أرجع(عدم);						\
	name##_SPLAY(سر, elm);					\
	إذا ((cmp)(elm, (سر)->sph_پاڙ) == 0)				\
		أرجع (سر->sph_پاڙ);				\
	أرجع (عدم);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_NEXT(بنية name *سر, بنية type *elm)			\
{									\
	name##_SPLAY(سر, elm);					\
	إذا (SPLAY_ساڄو(elm, ميدان) != عدم) {				\
		elm = SPLAY_ساڄو(elm, ميدان);				\
		طالما (SPLAY_کاٻو(elm, ميدان) != عدم) {		\
			elm = SPLAY_کاٻو(elm, ميدان);			\
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
        أرجع (SPLAY_پاڙ(سر));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#وصف_ڪريو SPLAY_GENERATE(name, type, ميدان, cmp)				\
بنية type *								\
name##_SPLAY_INSERT(بنية name *سر, بنية type *elm)		\
{									\
    إذا (SPLAY_خالي_جايون(سر)) {						\
	    SPLAY_کاٻو(elm, ميدان) = SPLAY_ساڄو(elm, ميدان) = عدم;	\
    } وإلا {								\
	    صحيح __comp;							\
	    name##_SPLAY(سر, elm);					\
	    __comp = (cmp)(elm, (سر)->sph_پاڙ);			\
	    إذا(__comp < 0) {						\
		    SPLAY_کاٻو(elm, ميدان) = SPLAY_کاٻو((سر)->sph_پاڙ, ميدان);\
		    SPLAY_ساڄو(elm, ميدان) = (سر)->sph_پاڙ;		\
		    SPLAY_کاٻو((سر)->sph_پاڙ, ميدان) = عدم;		\
	    } وإلا إذا (__comp > 0) {					\
		    SPLAY_ساڄو(elm, ميدان) = SPLAY_ساڄو((سر)->sph_پاڙ, ميدان);\
		    SPLAY_کاٻو(elm, ميدان) = (سر)->sph_پاڙ;		\
		    SPLAY_ساڄو((سر)->sph_پاڙ, ميدان) = عدم;	\
	    } وإلا							\
		    أرجع ((سر)->sph_پاڙ);				\
    }									\
    (سر)->sph_پاڙ = (elm);						\
    أرجع (عدم);							\
}									\
									\
بنية type *								\
name##_SPLAY_REMOVE(بنية name *سر, بنية type *elm)		\
{									\
	بنية type *__tmp;						\
	إذا (SPLAY_خالي_جايون(سر))						\
		أرجع (عدم);						\
	name##_SPLAY(سر, elm);					\
	إذا ((cmp)(elm, (سر)->sph_پاڙ) == 0) {			\
		إذا (SPLAY_کاٻو((سر)->sph_پاڙ, ميدان) == عدم) {	\
			(سر)->sph_پاڙ = SPLAY_ساڄو((سر)->sph_پاڙ, ميدان);\
		} وإلا {						\
			__tmp = SPLAY_ساڄو((سر)->sph_پاڙ, ميدان);	\
			(سر)->sph_پاڙ = SPLAY_کاٻو((سر)->sph_پاڙ, ميدان);\
			name##_SPLAY(سر, elm);			\
			SPLAY_ساڄو((سر)->sph_پاڙ, ميدان) = __tmp;	\
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
	SPLAY_کاٻو(&__node, ميدان) = SPLAY_ساڄو(&__node, ميدان) = عدم;\
	__left = __right = &__node;					\
\
	طالما ((__comp = (cmp)(elm, (سر)->sph_پاڙ))) {		\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_کاٻو((سر)->sph_پاڙ, ميدان);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_ساڄو(سر, __tmp, ميدان);	\
				إذا (SPLAY_کاٻو((سر)->sph_پاڙ, ميدان) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(سر, __right, ميدان);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_ساڄو((سر)->sph_پاڙ, ميدان);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_کاٻو(سر, __tmp, ميدان);	\
				إذا (SPLAY_ساڄو((سر)->sph_پاڙ, ميدان) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(سر, __left, ميدان);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(سر, &__node, __left, __right, ميدان);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
فراغ name##_SPLAY_MINMAX(بنية name *سر, صحيح __comp) \
{									\
	بنية type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_کاٻو(&__node, ميدان) = SPLAY_ساڄو(&__node, ميدان) = عدم;\
	__left = __right = &__node;					\
\
	طالما (1) {							\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_کاٻو((سر)->sph_پاڙ, ميدان);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp < 0){				\
				SPLAY_ROTATE_ساڄو(سر, __tmp, ميدان);	\
				إذا (SPLAY_کاٻو((سر)->sph_پاڙ, ميدان) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(سر, __right, ميدان);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_ساڄو((سر)->sph_پاڙ, ميدان);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp > 0) {				\
				SPLAY_ROTATE_کاٻو(سر, __tmp, ميدان);	\
				إذا (SPLAY_ساڄو((سر)->sph_پاڙ, ميدان) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(سر, __left, ميدان);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(سر, &__node, __left, __right, ميدان);		\
}

#وصف_ڪريو SPLAY_NEGINF	-1
#وصف_ڪريو SPLAY_INF	1

#وصف_ڪريو SPLAY_وجهو(name, x, y)	name##_SPLAY_INSERT(x, y)
#وصف_ڪريو SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#وصف_ڪريو SPLAY_ڳوليو(name, x, y)		name##_SPLAY_FIND(x, y)
#وصف_ڪريو SPLAY_ايندڙ(name, x, y)		name##_SPLAY_NEXT(x, y)
#وصف_ڪريو SPLAY_MIN(name, x)		(SPLAY_خالي_جايون(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#وصف_ڪريو SPLAY_MAX(name, x)		(SPLAY_خالي_جايون(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#وصف_ڪريو SPLAY_FOREACH(x, name, سر)					\
	لكل ((x) = SPLAY_MIN(name, سر);				\
	     (x) != عدم;						\
	     (x) = SPLAY_ايندڙ(name, سر, x))

/* Macros that define a red-black tree */
#وصف_ڪريو RB_سر(name, type)						\
بنية name {								\
	بنية type *rbh_پاڙ; /* root of the tree */			\
}

#وصف_ڪريو RB_INITIALIZER(پاڙ)						\
	{ عدم }

#وصف_ڪريو RB_INIT(پاڙ) افعل {						\
	(پاڙ)->rbh_پاڙ = عدم;					\
} طالما (0)

#وصف_ڪريو RB_BLACK	0
#وصف_ڪريو RB_RED		1
#وصف_ڪريو RB_داخلا(type)							\
بنية {								\
	بنية type *rbe_کاٻو;		/* left element */		\
	بنية type *rbe_ساڄو;		/* right element */		\
	بنية type *rbe_والد;	/* parent element */		\
	صحيح rbe_color;			/* node color */		\
}

#وصف_ڪريو RB_کاٻو(elm, ميدان)		(elm)->ميدان.rbe_کاٻو
#وصف_ڪريو RB_ساڄو(elm, ميدان)		(elm)->ميدان.rbe_ساڄو
#وصف_ڪريو RB_والد(elm, ميدان)		(elm)->ميدان.rbe_والد
#وصف_ڪريو RB_COLOR(elm, ميدان)		(elm)->ميدان.rbe_color
#وصف_ڪريو RB_پاڙ(سر)			(سر)->rbh_پاڙ
#وصف_ڪريو RB_خالي_جايون(سر)			(RB_پاڙ(سر) == عدم)

#وصف_ڪريو RB_سيٽ(elm, والد, ميدان) افعل {					\
	RB_والد(elm, ميدان) = والد;					\
	RB_کاٻو(elm, ميدان) = RB_ساڄو(elm, ميدان) = عدم;		\
	RB_COLOR(elm, ميدان) = RB_RED;					\
} طالما (0)

#وصف_ڪريو RB_سيٽ_BLACKRED(black, red, ميدان) افعل {				\
	RB_COLOR(black, ميدان) = RB_BLACK;				\
	RB_COLOR(red, ميدان) = RB_RED;					\
} طالما (0)

#جيڪڏهن_وصف_نه_ٿيل RB_AUGMENT
#وصف_ڪريو RB_AUGMENT(x)	افعل {} طالما (0)
#جيڪڏهن_پورو

#وصف_ڪريو RB_ROTATE_کاٻو(سر, elm, tmp, ميدان) افعل {			\
	(tmp) = RB_ساڄو(elm, ميدان);					\
	إذا ((RB_ساڄو(elm, ميدان) = RB_کاٻو(tmp, ميدان))) {		\
		RB_والد(RB_کاٻو(tmp, ميدان), ميدان) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_والد(tmp, ميدان) = RB_والد(elm, ميدان))) {		\
		إذا ((elm) == RB_کاٻو(RB_والد(elm, ميدان), ميدان))	\
			RB_کاٻو(RB_والد(elm, ميدان), ميدان) = (tmp);	\
		وإلا							\
			RB_ساڄو(RB_والد(elm, ميدان), ميدان) = (tmp);	\
	} وإلا								\
		(سر)->rbh_پاڙ = (tmp);				\
	RB_کاٻو(tmp, ميدان) = (elm);					\
	RB_والد(elm, ميدان) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_والد(tmp, ميدان)))					\
		RB_AUGMENT(RB_والد(tmp, ميدان));			\
} طالما (0)

#وصف_ڪريو RB_ROTATE_ساڄو(سر, elm, tmp, ميدان) افعل {			\
	(tmp) = RB_کاٻو(elm, ميدان);					\
	إذا ((RB_کاٻو(elm, ميدان) = RB_ساڄو(tmp, ميدان))) {		\
		RB_والد(RB_ساڄو(tmp, ميدان), ميدان) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_والد(tmp, ميدان) = RB_والد(elm, ميدان))) {		\
		إذا ((elm) == RB_کاٻو(RB_والد(elm, ميدان), ميدان))	\
			RB_کاٻو(RB_والد(elm, ميدان), ميدان) = (tmp);	\
		وإلا							\
			RB_ساڄو(RB_والد(elm, ميدان), ميدان) = (tmp);	\
	} وإلا								\
		(سر)->rbh_پاڙ = (tmp);				\
	RB_ساڄو(tmp, ميدان) = (elm);					\
	RB_والد(elm, ميدان) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_والد(tmp, ميدان)))					\
		RB_AUGMENT(RB_والد(tmp, ميدان));			\
} طالما (0)

/* Generates prototypes and inline functions */
#وصف_ڪريو	RB_PROTOTYPE(name, type, ميدان, cmp)				\
	RB_PROTOTYPE_اندروني(name, type, ميدان, cmp,)
#وصف_ڪريو	RB_PROTOTYPE_STATIC(name, type, ميدان, cmp)			\
	RB_PROTOTYPE_اندروني(name, type, ميدان, cmp, __attribute__((__unused__)) ساكن)
#وصف_ڪريو RB_PROTOTYPE_اندروني(name, type, ميدان, cmp, attr)		\
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
#وصف_ڪريو	RB_GENERATE(name, type, ميدان, cmp)				\
	RB_GENERATE_اندروني(name, type, ميدان, cmp,)
#وصف_ڪريو	RB_GENERATE_STATIC(name, type, ميدان, cmp)			\
	RB_GENERATE_اندروني(name, type, ميدان, cmp, __attribute__((__unused__)) ساكن)
#وصف_ڪريو RB_GENERATE_اندروني(name, type, ميدان, cmp, attr)		\
attr فراغ								\
name##_RB_INSERT_COLOR(بنية name *سر, بنية type *elm)		\
{									\
	بنية type *والد, *gparent, *tmp;				\
	طالما ((والد = RB_والد(elm, ميدان)) &&			\
	    RB_COLOR(والد, ميدان) == RB_RED) {			\
		gparent = RB_والد(والد, ميدان);			\
		إذا (والد == RB_کاٻو(gparent, ميدان)) {		\
			tmp = RB_ساڄو(gparent, ميدان);			\
			إذا (tmp && RB_COLOR(tmp, ميدان) == RB_RED) {	\
				RB_COLOR(tmp, ميدان) = RB_BLACK;	\
				RB_سيٽ_BLACKRED(والد, gparent, ميدان);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_ساڄو(والد, ميدان) == elm) {		\
				RB_ROTATE_کاٻو(سر, والد, tmp, ميدان);\
				tmp = والد;				\
				والد = elm;				\
				elm = tmp;				\
			}						\
			RB_سيٽ_BLACKRED(والد, gparent, ميدان);	\
			RB_ROTATE_ساڄو(سر, gparent, tmp, ميدان);	\
		} وإلا {						\
			tmp = RB_کاٻو(gparent, ميدان);			\
			إذا (tmp && RB_COLOR(tmp, ميدان) == RB_RED) {	\
				RB_COLOR(tmp, ميدان) = RB_BLACK;	\
				RB_سيٽ_BLACKRED(والد, gparent, ميدان);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_کاٻو(والد, ميدان) == elm) {		\
				RB_ROTATE_ساڄو(سر, والد, tmp, ميدان);\
				tmp = والد;				\
				والد = elm;				\
				elm = tmp;				\
			}						\
			RB_سيٽ_BLACKRED(والد, gparent, ميدان);	\
			RB_ROTATE_کاٻو(سر, gparent, tmp, ميدان);	\
		}							\
	}								\
	RB_COLOR(سر->rbh_پاڙ, ميدان) = RB_BLACK;			\
}									\
									\
attr فراغ								\
name##_RB_REMOVE_COLOR(بنية name *سر, بنية type *والد, بنية type *elm) \
{									\
	بنية type *tmp;						\
	طالما ((elm == عدم || RB_COLOR(elm, ميدان) == RB_BLACK) &&	\
	    elm != RB_پاڙ(سر)) {					\
		إذا (RB_کاٻو(والد, ميدان) == elm) {			\
			tmp = RB_ساڄو(والد, ميدان);			\
			إذا (RB_COLOR(tmp, ميدان) == RB_RED) {		\
				RB_سيٽ_BLACKRED(tmp, والد, ميدان);	\
				RB_ROTATE_کاٻو(سر, والد, tmp, ميدان);\
				tmp = RB_ساڄو(والد, ميدان);		\
			}						\
			إذا ((RB_کاٻو(tmp, ميدان) == عدم ||		\
			    RB_COLOR(RB_کاٻو(tmp, ميدان), ميدان) == RB_BLACK) &&\
			    (RB_ساڄو(tmp, ميدان) == عدم ||		\
			    RB_COLOR(RB_ساڄو(tmp, ميدان), ميدان) == RB_BLACK)) {\
				RB_COLOR(tmp, ميدان) = RB_RED;		\
				elm = والد;				\
				والد = RB_والد(elm, ميدان);		\
			} وإلا {					\
				إذا (RB_ساڄو(tmp, ميدان) == عدم ||	\
				    RB_COLOR(RB_ساڄو(tmp, ميدان), ميدان) == RB_BLACK) {\
					بنية type *oleft;		\
					إذا ((oleft = RB_کاٻو(tmp, ميدان)))\
						RB_COLOR(oleft, ميدان) = RB_BLACK;\
					RB_COLOR(tmp, ميدان) = RB_RED;	\
					RB_ROTATE_ساڄو(سر, tmp, oleft, ميدان);\
					tmp = RB_ساڄو(والد, ميدان);	\
				}					\
				RB_COLOR(tmp, ميدان) = RB_COLOR(والد, ميدان);\
				RB_COLOR(والد, ميدان) = RB_BLACK;	\
				إذا (RB_ساڄو(tmp, ميدان))		\
					RB_COLOR(RB_ساڄو(tmp, ميدان), ميدان) = RB_BLACK;\
				RB_ROTATE_کاٻو(سر, والد, tmp, ميدان);\
				elm = RB_پاڙ(سر);			\
				اكسر;					\
			}						\
		} وإلا {						\
			tmp = RB_کاٻو(والد, ميدان);			\
			إذا (RB_COLOR(tmp, ميدان) == RB_RED) {		\
				RB_سيٽ_BLACKRED(tmp, والد, ميدان);	\
				RB_ROTATE_ساڄو(سر, والد, tmp, ميدان);\
				tmp = RB_کاٻو(والد, ميدان);		\
			}						\
			إذا ((RB_کاٻو(tmp, ميدان) == عدم ||		\
			    RB_COLOR(RB_کاٻو(tmp, ميدان), ميدان) == RB_BLACK) &&\
			    (RB_ساڄو(tmp, ميدان) == عدم ||		\
			    RB_COLOR(RB_ساڄو(tmp, ميدان), ميدان) == RB_BLACK)) {\
				RB_COLOR(tmp, ميدان) = RB_RED;		\
				elm = والد;				\
				والد = RB_والد(elm, ميدان);		\
			} وإلا {					\
				إذا (RB_کاٻو(tmp, ميدان) == عدم ||	\
				    RB_COLOR(RB_کاٻو(tmp, ميدان), ميدان) == RB_BLACK) {\
					بنية type *oright;		\
					إذا ((oright = RB_ساڄو(tmp, ميدان)))\
						RB_COLOR(oright, ميدان) = RB_BLACK;\
					RB_COLOR(tmp, ميدان) = RB_RED;	\
					RB_ROTATE_کاٻو(سر, tmp, oright, ميدان);\
					tmp = RB_کاٻو(والد, ميدان);	\
				}					\
				RB_COLOR(tmp, ميدان) = RB_COLOR(والد, ميدان);\
				RB_COLOR(والد, ميدان) = RB_BLACK;	\
				إذا (RB_کاٻو(tmp, ميدان))		\
					RB_COLOR(RB_کاٻو(tmp, ميدان), ميدان) = RB_BLACK;\
				RB_ROTATE_ساڄو(سر, والد, tmp, ميدان);\
				elm = RB_پاڙ(سر);			\
				اكسر;					\
			}						\
		}							\
	}								\
	إذا (elm)							\
		RB_COLOR(elm, ميدان) = RB_BLACK;			\
}									\
									\
attr بنية type *							\
name##_RB_REMOVE(بنية name *سر, بنية type *elm)			\
{									\
	بنية type *ٻار, *والد, *old = elm;			\
	صحيح color;							\
	إذا (RB_کاٻو(elm, ميدان) == عدم)				\
		ٻار = RB_ساڄو(elm, ميدان);				\
	وإلا إذا (RB_ساڄو(elm, ميدان) == عدم)				\
		ٻار = RB_کاٻو(elm, ميدان);				\
	وإلا {								\
		بنية type *کاٻو;					\
		elm = RB_ساڄو(elm, ميدان);				\
		طالما ((کاٻو = RB_کاٻو(elm, ميدان)))			\
			elm = کاٻو;					\
		ٻار = RB_ساڄو(elm, ميدان);				\
		والد = RB_والد(elm, ميدان);				\
		color = RB_COLOR(elm, ميدان);				\
		إذا (ٻار)						\
			RB_والد(ٻار, ميدان) = والد;		\
		إذا (والد) {						\
			إذا (RB_کاٻو(والد, ميدان) == elm)		\
				RB_کاٻو(والد, ميدان) = ٻار;		\
			وإلا						\
				RB_ساڄو(والد, ميدان) = ٻار;	\
			RB_AUGMENT(والد);				\
		} وإلا							\
			RB_پاڙ(سر) = ٻار;				\
		إذا (RB_والد(elm, ميدان) == old)			\
			والد = elm;					\
		(elm)->ميدان = (old)->ميدان;				\
		إذا (RB_والد(old, ميدان)) {				\
			إذا (RB_کاٻو(RB_والد(old, ميدان), ميدان) == old)\
				RB_کاٻو(RB_والد(old, ميدان), ميدان) = elm;\
			وإلا						\
				RB_ساڄو(RB_والد(old, ميدان), ميدان) = elm;\
			RB_AUGMENT(RB_والد(old, ميدان));		\
		} وإلا							\
			RB_پاڙ(سر) = elm;				\
		RB_والد(RB_کاٻو(old, ميدان), ميدان) = elm;		\
		إذا (RB_ساڄو(old, ميدان))				\
			RB_والد(RB_ساڄو(old, ميدان), ميدان) = elm;	\
		إذا (والد) {						\
			کاٻو = والد;					\
			افعل {						\
				RB_AUGMENT(کاٻو);			\
			} طالما ((کاٻو = RB_والد(کاٻو, ميدان)));	\
		}							\
		اذهب color;						\
	}								\
	والد = RB_والد(elm, ميدان);					\
	color = RB_COLOR(elm, ميدان);					\
	إذا (ٻار)							\
		RB_والد(ٻار, ميدان) = والد;			\
	إذا (والد) {							\
		إذا (RB_کاٻو(والد, ميدان) == elm)			\
			RB_کاٻو(والد, ميدان) = ٻار;			\
		وإلا							\
			RB_ساڄو(والد, ميدان) = ٻار;		\
		RB_AUGMENT(والد);					\
	} وإلا								\
		RB_پاڙ(سر) = ٻار;					\
color:									\
	إذا (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(سر, والد, ٻار);		\
	أرجع (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr بنية type *							\
name##_RB_INSERT(بنية name *سر, بنية type *elm)			\
{									\
	بنية type *tmp;						\
	بنية type *والد = عدم;					\
	صحيح comp = 0;							\
	tmp = RB_پاڙ(سر);						\
	طالما (tmp) {							\
		والد = tmp;						\
		comp = (cmp)(elm, والد);				\
		إذا (comp < 0)						\
			tmp = RB_کاٻو(tmp, ميدان);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_ساڄو(tmp, ميدان);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	RB_سيٽ(elm, والد, ميدان);					\
	إذا (والد != عدم) {						\
		إذا (comp < 0)						\
			RB_کاٻو(والد, ميدان) = elm;			\
		وإلا							\
			RB_ساڄو(والد, ميدان) = elm;			\
		RB_AUGMENT(والد);					\
	} وإلا								\
		RB_پاڙ(سر) = elm;					\
	name##_RB_INSERT_COLOR(سر, elm);				\
	أرجع (عدم);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr بنية type *							\
name##_RB_FIND(بنية name *سر, بنية type *elm)			\
{									\
	بنية type *tmp = RB_پاڙ(سر);				\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0)						\
			tmp = RB_کاٻو(tmp, ميدان);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_ساڄو(tmp, ميدان);			\
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
	بنية type *tmp = RB_پاڙ(سر);				\
	بنية type *res = عدم;					\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0) {						\
			res = tmp;					\
			tmp = RB_کاٻو(tmp, ميدان);			\
		}							\
		وإلا إذا (comp > 0)					\
			tmp = RB_ساڄو(tmp, ميدان);			\
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
	إذا (RB_ساڄو(elm, ميدان)) {					\
		elm = RB_ساڄو(elm, ميدان);				\
		طالما (RB_کاٻو(elm, ميدان))				\
			elm = RB_کاٻو(elm, ميدان);			\
	} وإلا {							\
		إذا (RB_والد(elm, ميدان) &&				\
		    (elm == RB_کاٻو(RB_والد(elm, ميدان), ميدان)))	\
			elm = RB_والد(elm, ميدان);			\
		وإلا {							\
			طالما (RB_والد(elm, ميدان) &&			\
			    (elm == RB_ساڄو(RB_والد(elm, ميدان), ميدان)))\
				elm = RB_والد(elm, ميدان);		\
			elm = RB_والد(elm, ميدان);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
/* ARGSUSED */								\
attr بنية type *							\
name##_RB_PREV(بنية type *elm)					\
{									\
	إذا (RB_کاٻو(elm, ميدان)) {					\
		elm = RB_کاٻو(elm, ميدان);				\
		طالما (RB_ساڄو(elm, ميدان))				\
			elm = RB_ساڄو(elm, ميدان);			\
	} وإلا {							\
		إذا (RB_والد(elm, ميدان) &&				\
		    (elm == RB_ساڄو(RB_والد(elm, ميدان), ميدان)))	\
			elm = RB_والد(elm, ميدان);			\
		وإلا {							\
			طالما (RB_والد(elm, ميدان) &&			\
			    (elm == RB_کاٻو(RB_والد(elm, ميدان), ميدان)))\
				elm = RB_والد(elm, ميدان);		\
			elm = RB_والد(elm, ميدان);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
attr بنية type *							\
name##_RB_MINMAX(بنية name *سر, صحيح val)				\
{									\
	بنية type *tmp = RB_پاڙ(سر);				\
	بنية type *والد = عدم;					\
	طالما (tmp) {							\
		والد = tmp;						\
		إذا (val < 0)						\
			tmp = RB_کاٻو(tmp, ميدان);			\
		وإلا							\
			tmp = RB_ساڄو(tmp, ميدان);			\
	}								\
	أرجع (والد);						\
}

#وصف_ڪريو RB_NEGINF	-1
#وصف_ڪريو RB_INF	1

#وصف_ڪريو RB_وجهو(name, x, y)	name##_RB_INSERT(x, y)
#وصف_ڪريو RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#وصف_ڪريو RB_ڳوليو(name, x, y)	name##_RB_FIND(x, y)
#وصف_ڪريو RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#وصف_ڪريو RB_ايندڙ(name, x, y)	name##_RB_NEXT(y)
#وصف_ڪريو RB_PREV(name, x, y)	name##_RB_PREV(y)
#وصف_ڪريو RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#وصف_ڪريو RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#وصف_ڪريو RB_FOREACH(x, name, سر)					\
	لكل ((x) = RB_MIN(name, سر);					\
	     (x) != عدم;						\
	     (x) = name##_RB_NEXT(x))

#وصف_ڪريو RB_FOREACH_محفوظ(x, name, سر, y)				\
	لكل ((x) = RB_MIN(name, سر);					\
	    ((x) != عدم) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#وصف_ڪريو RB_FOREACH_ابتو(x, name, سر)				\
	لكل ((x) = RB_MAX(name, سر);					\
	     (x) != عدم;						\
	     (x) = name##_RB_PREV(x))

#وصف_ڪريو RB_FOREACH_ابتو_محفوظ(x, name, سر, y)			\
	لكل ((x) = RB_MAX(name, سر);					\
	    ((x) != عدم) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#جيڪڏهن_پورو	/* _SYS_TREE_H_ */
