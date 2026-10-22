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
#اگر_تعریف_شده NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#پایان_اگر

#اگر_تعریف_نشده	SYS_درخت_H
#تعریف_کن	SYS_درخت_H

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

#تعریف_کن SPLAY_سر(name, type)						\
بنية name {								\
	بنية type *sph_ریشه; /* root of the tree */			\
}

#تعریف_کن SPLAY_INITIALIZER(ریشه)						\
	{ عدم }

#تعریف_کن SPLAY_INIT(ریشه) افعل {						\
	(ریشه)->sph_ریشه = عدم;					\
} طالما (0)

#تعریف_کن SPLAY_مدخل(type)						\
بنية {								\
	بنية type *spe_چپ; /* left element */			\
	بنية type *spe_راست; /* right element */			\
}

#تعریف_کن SPLAY_چپ(elm, فیلد)		(elm)->فیلد.spe_چپ
#تعریف_کن SPLAY_راست(elm, فیلد)		(elm)->فیلد.spe_راست
#تعریف_کن SPLAY_ریشه(سر)		(سر)->sph_ریشه
#تعریف_کن SPLAY_خالی(سر)		(SPLAY_ریشه(سر) == عدم)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#تعریف_کن SPLAY_ROTATE_راست(سر, tmp, فیلد) افعل {			\
	SPLAY_چپ((سر)->sph_ریشه, فیلد) = SPLAY_راست(tmp, فیلد);	\
	SPLAY_راست(tmp, فیلد) = (سر)->sph_ریشه;			\
	(سر)->sph_ریشه = tmp;						\
} طالما (0)
	
#تعریف_کن SPLAY_ROTATE_چپ(سر, tmp, فیلد) افعل {			\
	SPLAY_راست((سر)->sph_ریشه, فیلد) = SPLAY_چپ(tmp, فیلد);	\
	SPLAY_چپ(tmp, فیلد) = (سر)->sph_ریشه;			\
	(سر)->sph_ریشه = tmp;						\
} طالما (0)

#تعریف_کن SPLAY_LINKLEFT(سر, tmp, فیلد) افعل {				\
	SPLAY_چپ(tmp, فیلد) = (سر)->sph_ریشه;			\
	tmp = (سر)->sph_ریشه;						\
	(سر)->sph_ریشه = SPLAY_چپ((سر)->sph_ریشه, فیلد);		\
} طالما (0)

#تعریف_کن SPLAY_LINKRIGHT(سر, tmp, فیلد) افعل {				\
	SPLAY_راست(tmp, فیلد) = (سر)->sph_ریشه;			\
	tmp = (سر)->sph_ریشه;						\
	(سر)->sph_ریشه = SPLAY_راست((سر)->sph_ریشه, فیلد);	\
} طالما (0)

#تعریف_کن SPLAY_ASSEMBLE(سر, گره, چپ, راست, فیلد) افعل {		\
	SPLAY_راست(چپ, فیلد) = SPLAY_چپ((سر)->sph_ریشه, فیلد);	\
	SPLAY_چپ(راست, فیلد) = SPLAY_راست((سر)->sph_ریشه, فیلد);\
	SPLAY_چپ((سر)->sph_ریشه, فیلد) = SPLAY_راست(گره, فیلد);	\
	SPLAY_راست((سر)->sph_ریشه, فیلد) = SPLAY_چپ(گره, فیلد);	\
} طالما (0)

/* Generates prototypes and inline functions */

#تعریف_کن SPLAY_PROTOTYPE(name, type, فیلد, cmp)				\
فراغ name##_SPLAY(بنية name *, بنية type *);			\
فراغ name##_SPLAY_MINMAX(بنية name *, صحيح);				\
بنية type *name##_SPLAY_INSERT(بنية name *, بنية type *);		\
بنية type *name##_SPLAY_REMOVE(بنية name *, بنية type *);		\
									\
/* Finds the node with the same key as elm */				\
ساكن __inline بنية type *						\
name##_SPLAY_FIND(بنية name *سر, بنية type *elm)			\
{									\
	إذا (SPLAY_خالی(سر))						\
		أرجع(عدم);						\
	name##_SPLAY(سر, elm);					\
	إذا ((cmp)(elm, (سر)->sph_ریشه) == 0)				\
		أرجع (سر->sph_ریشه);				\
	أرجع (عدم);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_NEXT(بنية name *سر, بنية type *elm)			\
{									\
	name##_SPLAY(سر, elm);					\
	إذا (SPLAY_راست(elm, فیلد) != عدم) {				\
		elm = SPLAY_راست(elm, فیلد);				\
		طالما (SPLAY_چپ(elm, فیلد) != عدم) {		\
			elm = SPLAY_چپ(elm, فیلد);			\
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
        أرجع (SPLAY_ریشه(سر));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#تعریف_کن SPLAY_GENERATE(name, type, فیلد, cmp)				\
بنية type *								\
name##_SPLAY_INSERT(بنية name *سر, بنية type *elm)		\
{									\
    إذا (SPLAY_خالی(سر)) {						\
	    SPLAY_چپ(elm, فیلد) = SPLAY_راست(elm, فیلد) = عدم;	\
    } وإلا {								\
	    صحيح __comp;							\
	    name##_SPLAY(سر, elm);					\
	    __comp = (cmp)(elm, (سر)->sph_ریشه);			\
	    إذا(__comp < 0) {						\
		    SPLAY_چپ(elm, فیلد) = SPLAY_چپ((سر)->sph_ریشه, فیلد);\
		    SPLAY_راست(elm, فیلد) = (سر)->sph_ریشه;		\
		    SPLAY_چپ((سر)->sph_ریشه, فیلد) = عدم;		\
	    } وإلا إذا (__comp > 0) {					\
		    SPLAY_راست(elm, فیلد) = SPLAY_راست((سر)->sph_ریشه, فیلد);\
		    SPLAY_چپ(elm, فیلد) = (سر)->sph_ریشه;		\
		    SPLAY_راست((سر)->sph_ریشه, فیلد) = عدم;	\
	    } وإلا							\
		    أرجع ((سر)->sph_ریشه);				\
    }									\
    (سر)->sph_ریشه = (elm);						\
    أرجع (عدم);							\
}									\
									\
بنية type *								\
name##_SPLAY_REMOVE(بنية name *سر, بنية type *elm)		\
{									\
	بنية type *__tmp;						\
	إذا (SPLAY_خالی(سر))						\
		أرجع (عدم);						\
	name##_SPLAY(سر, elm);					\
	إذا ((cmp)(elm, (سر)->sph_ریشه) == 0) {			\
		إذا (SPLAY_چپ((سر)->sph_ریشه, فیلد) == عدم) {	\
			(سر)->sph_ریشه = SPLAY_راست((سر)->sph_ریشه, فیلد);\
		} وإلا {						\
			__tmp = SPLAY_راست((سر)->sph_ریشه, فیلد);	\
			(سر)->sph_ریشه = SPLAY_چپ((سر)->sph_ریشه, فیلد);\
			name##_SPLAY(سر, elm);			\
			SPLAY_راست((سر)->sph_ریشه, فیلد) = __tmp;	\
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
	SPLAY_چپ(&__node, فیلد) = SPLAY_راست(&__node, فیلد) = عدم;\
	__left = __right = &__node;					\
\
	طالما ((__comp = (cmp)(elm, (سر)->sph_ریشه))) {		\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_چپ((سر)->sph_ریشه, فیلد);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_راست(سر, __tmp, فیلد);	\
				إذا (SPLAY_چپ((سر)->sph_ریشه, فیلد) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(سر, __right, فیلد);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_راست((سر)->sph_ریشه, فیلد);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_چپ(سر, __tmp, فیلد);	\
				إذا (SPLAY_راست((سر)->sph_ریشه, فیلد) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(سر, __left, فیلد);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(سر, &__node, __left, __right, فیلد);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
فراغ name##_SPLAY_MINMAX(بنية name *سر, صحيح __comp) \
{									\
	بنية type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_چپ(&__node, فیلد) = SPLAY_راست(&__node, فیلد) = عدم;\
	__left = __right = &__node;					\
\
	طالما (1) {							\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_چپ((سر)->sph_ریشه, فیلد);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp < 0){				\
				SPLAY_ROTATE_راست(سر, __tmp, فیلد);	\
				إذا (SPLAY_چپ((سر)->sph_ریشه, فیلد) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(سر, __right, فیلد);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_راست((سر)->sph_ریشه, فیلد);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp > 0) {				\
				SPLAY_ROTATE_چپ(سر, __tmp, فیلد);	\
				إذا (SPLAY_راست((سر)->sph_ریشه, فیلد) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(سر, __left, فیلد);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(سر, &__node, __left, __right, فیلد);		\
}

#تعریف_کن SPLAY_NEGINF	-1
#تعریف_کن SPLAY_INF	1

#تعریف_کن SPLAY_درج(name, x, y)	name##_SPLAY_INSERT(x, y)
#تعریف_کن SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#تعریف_کن SPLAY_پیدا_کن(name, x, y)		name##_SPLAY_FIND(x, y)
#تعریف_کن SPLAY_بعدی(name, x, y)		name##_SPLAY_NEXT(x, y)
#تعریف_کن SPLAY_MIN(name, x)		(SPLAY_خالی(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#تعریف_کن SPLAY_MAX(name, x)		(SPLAY_خالی(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#تعریف_کن SPLAY_FOREACH(x, name, سر)					\
	لكل ((x) = SPLAY_MIN(name, سر);				\
	     (x) != عدم;						\
	     (x) = SPLAY_بعدی(name, سر, x))

/* Macros that define a red-black tree */
#تعریف_کن RB_سر(name, type)						\
بنية name {								\
	بنية type *rbh_ریشه; /* root of the tree */			\
}

#تعریف_کن RB_INITIALIZER(ریشه)						\
	{ عدم }

#تعریف_کن RB_INIT(ریشه) افعل {						\
	(ریشه)->rbh_ریشه = عدم;					\
} طالما (0)

#تعریف_کن RB_BLACK	0
#تعریف_کن RB_RED		1
#تعریف_کن RB_مدخل(type)							\
بنية {								\
	بنية type *rbe_چپ;		/* left element */		\
	بنية type *rbe_راست;		/* right element */		\
	بنية type *rbe_والد;	/* parent element */		\
	صحيح rbe_color;			/* node color */		\
}

#تعریف_کن RB_چپ(elm, فیلد)		(elm)->فیلد.rbe_چپ
#تعریف_کن RB_راست(elm, فیلد)		(elm)->فیلد.rbe_راست
#تعریف_کن RB_والد(elm, فیلد)		(elm)->فیلد.rbe_والد
#تعریف_کن RB_COLOR(elm, فیلد)		(elm)->فیلد.rbe_color
#تعریف_کن RB_ریشه(سر)			(سر)->rbh_ریشه
#تعریف_کن RB_خالی(سر)			(RB_ریشه(سر) == عدم)

#تعریف_کن RB_مجموعه(elm, والد, فیلد) افعل {					\
	RB_والد(elm, فیلد) = والد;					\
	RB_چپ(elm, فیلد) = RB_راست(elm, فیلد) = عدم;		\
	RB_COLOR(elm, فیلد) = RB_RED;					\
} طالما (0)

#تعریف_کن RB_مجموعه_BLACKRED(black, red, فیلد) افعل {				\
	RB_COLOR(black, فیلد) = RB_BLACK;				\
	RB_COLOR(red, فیلد) = RB_RED;					\
} طالما (0)

#اگر_تعریف_نشده RB_AUGMENT
#تعریف_کن RB_AUGMENT(x)	افعل {} طالما (0)
#پایان_اگر

#تعریف_کن RB_ROTATE_چپ(سر, elm, tmp, فیلد) افعل {			\
	(tmp) = RB_راست(elm, فیلد);					\
	إذا ((RB_راست(elm, فیلد) = RB_چپ(tmp, فیلد))) {		\
		RB_والد(RB_چپ(tmp, فیلد), فیلد) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_والد(tmp, فیلد) = RB_والد(elm, فیلد))) {		\
		إذا ((elm) == RB_چپ(RB_والد(elm, فیلد), فیلد))	\
			RB_چپ(RB_والد(elm, فیلد), فیلد) = (tmp);	\
		وإلا							\
			RB_راست(RB_والد(elm, فیلد), فیلد) = (tmp);	\
	} وإلا								\
		(سر)->rbh_ریشه = (tmp);				\
	RB_چپ(tmp, فیلد) = (elm);					\
	RB_والد(elm, فیلد) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_والد(tmp, فیلد)))					\
		RB_AUGMENT(RB_والد(tmp, فیلد));			\
} طالما (0)

#تعریف_کن RB_ROTATE_راست(سر, elm, tmp, فیلد) افعل {			\
	(tmp) = RB_چپ(elm, فیلد);					\
	إذا ((RB_چپ(elm, فیلد) = RB_راست(tmp, فیلد))) {		\
		RB_والد(RB_راست(tmp, فیلد), فیلد) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_والد(tmp, فیلد) = RB_والد(elm, فیلد))) {		\
		إذا ((elm) == RB_چپ(RB_والد(elm, فیلد), فیلد))	\
			RB_چپ(RB_والد(elm, فیلد), فیلد) = (tmp);	\
		وإلا							\
			RB_راست(RB_والد(elm, فیلد), فیلد) = (tmp);	\
	} وإلا								\
		(سر)->rbh_ریشه = (tmp);				\
	RB_راست(tmp, فیلد) = (elm);					\
	RB_والد(elm, فیلد) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_والد(tmp, فیلد)))					\
		RB_AUGMENT(RB_والد(tmp, فیلد));			\
} طالما (0)

/* Generates prototypes and inline functions */
#تعریف_کن	RB_PROTOTYPE(name, type, فیلد, cmp)				\
	RB_PROTOTYPE_داخلی(name, type, فیلد, cmp,)
#تعریف_کن	RB_PROTOTYPE_STATIC(name, type, فیلد, cmp)			\
	RB_PROTOTYPE_داخلی(name, type, فیلد, cmp, __attribute__((__unused__)) ساكن)
#تعریف_کن RB_PROTOTYPE_داخلی(name, type, فیلد, cmp, attr)		\
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
#تعریف_کن	RB_GENERATE(name, type, فیلد, cmp)				\
	RB_GENERATE_داخلی(name, type, فیلد, cmp,)
#تعریف_کن	RB_GENERATE_STATIC(name, type, فیلد, cmp)			\
	RB_GENERATE_داخلی(name, type, فیلد, cmp, __attribute__((__unused__)) ساكن)
#تعریف_کن RB_GENERATE_داخلی(name, type, فیلد, cmp, attr)		\
attr فراغ								\
name##_RB_INSERT_COLOR(بنية name *سر, بنية type *elm)		\
{									\
	بنية type *والد, *gparent, *tmp;				\
	طالما ((والد = RB_والد(elm, فیلد)) &&			\
	    RB_COLOR(والد, فیلد) == RB_RED) {			\
		gparent = RB_والد(والد, فیلد);			\
		إذا (والد == RB_چپ(gparent, فیلد)) {		\
			tmp = RB_راست(gparent, فیلد);			\
			إذا (tmp && RB_COLOR(tmp, فیلد) == RB_RED) {	\
				RB_COLOR(tmp, فیلد) = RB_BLACK;	\
				RB_مجموعه_BLACKRED(والد, gparent, فیلد);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_راست(والد, فیلد) == elm) {		\
				RB_ROTATE_چپ(سر, والد, tmp, فیلد);\
				tmp = والد;				\
				والد = elm;				\
				elm = tmp;				\
			}						\
			RB_مجموعه_BLACKRED(والد, gparent, فیلد);	\
			RB_ROTATE_راست(سر, gparent, tmp, فیلد);	\
		} وإلا {						\
			tmp = RB_چپ(gparent, فیلد);			\
			إذا (tmp && RB_COLOR(tmp, فیلد) == RB_RED) {	\
				RB_COLOR(tmp, فیلد) = RB_BLACK;	\
				RB_مجموعه_BLACKRED(والد, gparent, فیلد);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_چپ(والد, فیلد) == elm) {		\
				RB_ROTATE_راست(سر, والد, tmp, فیلد);\
				tmp = والد;				\
				والد = elm;				\
				elm = tmp;				\
			}						\
			RB_مجموعه_BLACKRED(والد, gparent, فیلد);	\
			RB_ROTATE_چپ(سر, gparent, tmp, فیلد);	\
		}							\
	}								\
	RB_COLOR(سر->rbh_ریشه, فیلد) = RB_BLACK;			\
}									\
									\
attr فراغ								\
name##_RB_REMOVE_COLOR(بنية name *سر, بنية type *والد, بنية type *elm) \
{									\
	بنية type *tmp;						\
	طالما ((elm == عدم || RB_COLOR(elm, فیلد) == RB_BLACK) &&	\
	    elm != RB_ریشه(سر)) {					\
		إذا (RB_چپ(والد, فیلد) == elm) {			\
			tmp = RB_راست(والد, فیلد);			\
			إذا (RB_COLOR(tmp, فیلد) == RB_RED) {		\
				RB_مجموعه_BLACKRED(tmp, والد, فیلد);	\
				RB_ROTATE_چپ(سر, والد, tmp, فیلد);\
				tmp = RB_راست(والد, فیلد);		\
			}						\
			إذا ((RB_چپ(tmp, فیلد) == عدم ||		\
			    RB_COLOR(RB_چپ(tmp, فیلد), فیلد) == RB_BLACK) &&\
			    (RB_راست(tmp, فیلد) == عدم ||		\
			    RB_COLOR(RB_راست(tmp, فیلد), فیلد) == RB_BLACK)) {\
				RB_COLOR(tmp, فیلد) = RB_RED;		\
				elm = والد;				\
				والد = RB_والد(elm, فیلد);		\
			} وإلا {					\
				إذا (RB_راست(tmp, فیلد) == عدم ||	\
				    RB_COLOR(RB_راست(tmp, فیلد), فیلد) == RB_BLACK) {\
					بنية type *oleft;		\
					إذا ((oleft = RB_چپ(tmp, فیلد)))\
						RB_COLOR(oleft, فیلد) = RB_BLACK;\
					RB_COLOR(tmp, فیلد) = RB_RED;	\
					RB_ROTATE_راست(سر, tmp, oleft, فیلد);\
					tmp = RB_راست(والد, فیلد);	\
				}					\
				RB_COLOR(tmp, فیلد) = RB_COLOR(والد, فیلد);\
				RB_COLOR(والد, فیلد) = RB_BLACK;	\
				إذا (RB_راست(tmp, فیلد))		\
					RB_COLOR(RB_راست(tmp, فیلد), فیلد) = RB_BLACK;\
				RB_ROTATE_چپ(سر, والد, tmp, فیلد);\
				elm = RB_ریشه(سر);			\
				اكسر;					\
			}						\
		} وإلا {						\
			tmp = RB_چپ(والد, فیلد);			\
			إذا (RB_COLOR(tmp, فیلد) == RB_RED) {		\
				RB_مجموعه_BLACKRED(tmp, والد, فیلد);	\
				RB_ROTATE_راست(سر, والد, tmp, فیلد);\
				tmp = RB_چپ(والد, فیلد);		\
			}						\
			إذا ((RB_چپ(tmp, فیلد) == عدم ||		\
			    RB_COLOR(RB_چپ(tmp, فیلد), فیلد) == RB_BLACK) &&\
			    (RB_راست(tmp, فیلد) == عدم ||		\
			    RB_COLOR(RB_راست(tmp, فیلد), فیلد) == RB_BLACK)) {\
				RB_COLOR(tmp, فیلد) = RB_RED;		\
				elm = والد;				\
				والد = RB_والد(elm, فیلد);		\
			} وإلا {					\
				إذا (RB_چپ(tmp, فیلد) == عدم ||	\
				    RB_COLOR(RB_چپ(tmp, فیلد), فیلد) == RB_BLACK) {\
					بنية type *oright;		\
					إذا ((oright = RB_راست(tmp, فیلد)))\
						RB_COLOR(oright, فیلد) = RB_BLACK;\
					RB_COLOR(tmp, فیلد) = RB_RED;	\
					RB_ROTATE_چپ(سر, tmp, oright, فیلد);\
					tmp = RB_چپ(والد, فیلد);	\
				}					\
				RB_COLOR(tmp, فیلد) = RB_COLOR(والد, فیلد);\
				RB_COLOR(والد, فیلد) = RB_BLACK;	\
				إذا (RB_چپ(tmp, فیلد))		\
					RB_COLOR(RB_چپ(tmp, فیلد), فیلد) = RB_BLACK;\
				RB_ROTATE_راست(سر, والد, tmp, فیلد);\
				elm = RB_ریشه(سر);			\
				اكسر;					\
			}						\
		}							\
	}								\
	إذا (elm)							\
		RB_COLOR(elm, فیلد) = RB_BLACK;			\
}									\
									\
attr بنية type *							\
name##_RB_REMOVE(بنية name *سر, بنية type *elm)			\
{									\
	بنية type *فرزند, *والد, *old = elm;			\
	صحيح color;							\
	إذا (RB_چپ(elm, فیلد) == عدم)				\
		فرزند = RB_راست(elm, فیلد);				\
	وإلا إذا (RB_راست(elm, فیلد) == عدم)				\
		فرزند = RB_چپ(elm, فیلد);				\
	وإلا {								\
		بنية type *چپ;					\
		elm = RB_راست(elm, فیلد);				\
		طالما ((چپ = RB_چپ(elm, فیلد)))			\
			elm = چپ;					\
		فرزند = RB_راست(elm, فیلد);				\
		والد = RB_والد(elm, فیلد);				\
		color = RB_COLOR(elm, فیلد);				\
		إذا (فرزند)						\
			RB_والد(فرزند, فیلد) = والد;		\
		إذا (والد) {						\
			إذا (RB_چپ(والد, فیلد) == elm)		\
				RB_چپ(والد, فیلد) = فرزند;		\
			وإلا						\
				RB_راست(والد, فیلد) = فرزند;	\
			RB_AUGMENT(والد);				\
		} وإلا							\
			RB_ریشه(سر) = فرزند;				\
		إذا (RB_والد(elm, فیلد) == old)			\
			والد = elm;					\
		(elm)->فیلد = (old)->فیلد;				\
		إذا (RB_والد(old, فیلد)) {				\
			إذا (RB_چپ(RB_والد(old, فیلد), فیلد) == old)\
				RB_چپ(RB_والد(old, فیلد), فیلد) = elm;\
			وإلا						\
				RB_راست(RB_والد(old, فیلد), فیلد) = elm;\
			RB_AUGMENT(RB_والد(old, فیلد));		\
		} وإلا							\
			RB_ریشه(سر) = elm;				\
		RB_والد(RB_چپ(old, فیلد), فیلد) = elm;		\
		إذا (RB_راست(old, فیلد))				\
			RB_والد(RB_راست(old, فیلد), فیلد) = elm;	\
		إذا (والد) {						\
			چپ = والد;					\
			افعل {						\
				RB_AUGMENT(چپ);			\
			} طالما ((چپ = RB_والد(چپ, فیلد)));	\
		}							\
		اذهب color;						\
	}								\
	والد = RB_والد(elm, فیلد);					\
	color = RB_COLOR(elm, فیلد);					\
	إذا (فرزند)							\
		RB_والد(فرزند, فیلد) = والد;			\
	إذا (والد) {							\
		إذا (RB_چپ(والد, فیلد) == elm)			\
			RB_چپ(والد, فیلد) = فرزند;			\
		وإلا							\
			RB_راست(والد, فیلد) = فرزند;		\
		RB_AUGMENT(والد);					\
	} وإلا								\
		RB_ریشه(سر) = فرزند;					\
color:									\
	إذا (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(سر, والد, فرزند);		\
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
	tmp = RB_ریشه(سر);						\
	طالما (tmp) {							\
		والد = tmp;						\
		comp = (cmp)(elm, والد);				\
		إذا (comp < 0)						\
			tmp = RB_چپ(tmp, فیلد);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_راست(tmp, فیلد);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	RB_مجموعه(elm, والد, فیلد);					\
	إذا (والد != عدم) {						\
		إذا (comp < 0)						\
			RB_چپ(والد, فیلد) = elm;			\
		وإلا							\
			RB_راست(والد, فیلد) = elm;			\
		RB_AUGMENT(والد);					\
	} وإلا								\
		RB_ریشه(سر) = elm;					\
	name##_RB_INSERT_COLOR(سر, elm);				\
	أرجع (عدم);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr بنية type *							\
name##_RB_FIND(بنية name *سر, بنية type *elm)			\
{									\
	بنية type *tmp = RB_ریشه(سر);				\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0)						\
			tmp = RB_چپ(tmp, فیلد);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_راست(tmp, فیلد);			\
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
	بنية type *tmp = RB_ریشه(سر);				\
	بنية type *res = عدم;					\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0) {						\
			res = tmp;					\
			tmp = RB_چپ(tmp, فیلد);			\
		}							\
		وإلا إذا (comp > 0)					\
			tmp = RB_راست(tmp, فیلد);			\
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
	إذا (RB_راست(elm, فیلد)) {					\
		elm = RB_راست(elm, فیلد);				\
		طالما (RB_چپ(elm, فیلد))				\
			elm = RB_چپ(elm, فیلد);			\
	} وإلا {							\
		إذا (RB_والد(elm, فیلد) &&				\
		    (elm == RB_چپ(RB_والد(elm, فیلد), فیلد)))	\
			elm = RB_والد(elm, فیلد);			\
		وإلا {							\
			طالما (RB_والد(elm, فیلد) &&			\
			    (elm == RB_راست(RB_والد(elm, فیلد), فیلد)))\
				elm = RB_والد(elm, فیلد);		\
			elm = RB_والد(elm, فیلد);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
/* ARGSUSED */								\
attr بنية type *							\
name##_RB_PREV(بنية type *elm)					\
{									\
	إذا (RB_چپ(elm, فیلد)) {					\
		elm = RB_چپ(elm, فیلد);				\
		طالما (RB_راست(elm, فیلد))				\
			elm = RB_راست(elm, فیلد);			\
	} وإلا {							\
		إذا (RB_والد(elm, فیلد) &&				\
		    (elm == RB_راست(RB_والد(elm, فیلد), فیلد)))	\
			elm = RB_والد(elm, فیلد);			\
		وإلا {							\
			طالما (RB_والد(elm, فیلد) &&			\
			    (elm == RB_چپ(RB_والد(elm, فیلد), فیلد)))\
				elm = RB_والد(elm, فیلد);		\
			elm = RB_والد(elm, فیلد);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
attr بنية type *							\
name##_RB_MINMAX(بنية name *سر, صحيح val)				\
{									\
	بنية type *tmp = RB_ریشه(سر);				\
	بنية type *والد = عدم;					\
	طالما (tmp) {							\
		والد = tmp;						\
		إذا (val < 0)						\
			tmp = RB_چپ(tmp, فیلد);			\
		وإلا							\
			tmp = RB_راست(tmp, فیلد);			\
	}								\
	أرجع (والد);						\
}

#تعریف_کن RB_NEGINF	-1
#تعریف_کن RB_INF	1

#تعریف_کن RB_درج(name, x, y)	name##_RB_INSERT(x, y)
#تعریف_کن RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#تعریف_کن RB_پیدا_کن(name, x, y)	name##_RB_FIND(x, y)
#تعریف_کن RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#تعریف_کن RB_بعدی(name, x, y)	name##_RB_NEXT(y)
#تعریف_کن RB_PREV(name, x, y)	name##_RB_PREV(y)
#تعریف_کن RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#تعریف_کن RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#تعریف_کن RB_FOREACH(x, name, سر)					\
	لكل ((x) = RB_MIN(name, سر);					\
	     (x) != عدم;						\
	     (x) = name##_RB_NEXT(x))

#تعریف_کن RB_FOREACH_امن(x, name, سر, y)				\
	لكل ((x) = RB_MIN(name, سر);					\
	    ((x) != عدم) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#تعریف_کن RB_FOREACH_معکوس(x, name, سر)				\
	لكل ((x) = RB_MAX(name, سر);					\
	     (x) != عدم;						\
	     (x) = name##_RB_PREV(x))

#تعریف_کن RB_FOREACH_معکوس_امن(x, name, سر, y)			\
	لكل ((x) = RB_MAX(name, سر);					\
	    ((x) != عدم) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#پایان_اگر	/* _SYS_TREE_H_ */
