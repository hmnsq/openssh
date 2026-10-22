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

#شامل "config.h"
#اگر_تعریف_شدہ NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#اگر_ختم

#اگر_غیر_تعریف_شدہ	SYS_درخت_H
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
ساخت name {								\
	ساخت type *sph_جڑ; /* root of the tree */			\
}

#تعریف_کرو SPLAY_INITIALIZER(جڑ)						\
	{ تہی }

#تعریف_کرو SPLAY_INIT(جڑ) کرو {						\
	(جڑ)->sph_جڑ = تہی;					\
} جب (0)

#تعریف_کرو SPLAY_اندراج(type)						\
ساخت {								\
	ساخت type *spe_بایاں; /* left element */			\
	ساخت type *spe_دایاں; /* right element */			\
}

#تعریف_کرو SPLAY_بایاں(elm, میدان)		(elm)->میدان.spe_بایاں
#تعریف_کرو SPLAY_دایاں(elm, میدان)		(elm)->میدان.spe_دایاں
#تعریف_کرو SPLAY_جڑ(سر)		(سر)->sph_جڑ
#تعریف_کرو SPLAY_خالی_خانے(سر)		(SPLAY_جڑ(سر) == تہی)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#تعریف_کرو SPLAY_ROTATE_دایاں(سر, tmp, میدان) کرو {			\
	SPLAY_بایاں((سر)->sph_جڑ, میدان) = SPLAY_دایاں(tmp, میدان);	\
	SPLAY_دایاں(tmp, میدان) = (سر)->sph_جڑ;			\
	(سر)->sph_جڑ = tmp;						\
} جب (0)
	
#تعریف_کرو SPLAY_ROTATE_بایاں(سر, tmp, میدان) کرو {			\
	SPLAY_دایاں((سر)->sph_جڑ, میدان) = SPLAY_بایاں(tmp, میدان);	\
	SPLAY_بایاں(tmp, میدان) = (سر)->sph_جڑ;			\
	(سر)->sph_جڑ = tmp;						\
} جب (0)

#تعریف_کرو SPLAY_LINKLEFT(سر, tmp, میدان) کرو {				\
	SPLAY_بایاں(tmp, میدان) = (سر)->sph_جڑ;			\
	tmp = (سر)->sph_جڑ;						\
	(سر)->sph_جڑ = SPLAY_بایاں((سر)->sph_جڑ, میدان);		\
} جب (0)

#تعریف_کرو SPLAY_LINKRIGHT(سر, tmp, میدان) کرو {				\
	SPLAY_دایاں(tmp, میدان) = (سر)->sph_جڑ;			\
	tmp = (سر)->sph_جڑ;						\
	(سر)->sph_جڑ = SPLAY_دایاں((سر)->sph_جڑ, میدان);	\
} جب (0)

#تعریف_کرو SPLAY_ASSEMBLE(سر, گرہ, بایاں, دایاں, میدان) کرو {		\
	SPLAY_دایاں(بایاں, میدان) = SPLAY_بایاں((سر)->sph_جڑ, میدان);	\
	SPLAY_بایاں(دایاں, میدان) = SPLAY_دایاں((سر)->sph_جڑ, میدان);\
	SPLAY_بایاں((سر)->sph_جڑ, میدان) = SPLAY_دایاں(گرہ, میدان);	\
	SPLAY_دایاں((سر)->sph_جڑ, میدان) = SPLAY_بایاں(گرہ, میدان);	\
} جب (0)

/* Generates prototypes and inline functions */

#تعریف_کرو SPLAY_PROTOTYPE(name, type, میدان, cmp)				\
خالی name##_SPLAY(ساخت name *, ساخت type *);			\
خالی name##_SPLAY_MINMAX(ساخت name *, صحیح);				\
ساخت type *name##_SPLAY_INSERT(ساخت name *, ساخت type *);		\
ساخت type *name##_SPLAY_REMOVE(ساخت name *, ساخت type *);		\
									\
/* Finds the node with the same key as elm */				\
ساکن __inline ساخت type *						\
name##_SPLAY_FIND(ساخت name *سر, ساخت type *elm)			\
{									\
	اگر (SPLAY_خالی_خانے(سر))						\
		واپس(تہی);						\
	name##_SPLAY(سر, elm);					\
	اگر ((cmp)(elm, (سر)->sph_جڑ) == 0)				\
		واپس (سر->sph_جڑ);				\
	واپس (تہی);							\
}									\
									\
ساکن __inline ساخت type *						\
name##_SPLAY_NEXT(ساخت name *سر, ساخت type *elm)			\
{									\
	name##_SPLAY(سر, elm);					\
	اگر (SPLAY_دایاں(elm, میدان) != تہی) {				\
		elm = SPLAY_دایاں(elm, میدان);				\
		جب (SPLAY_بایاں(elm, میدان) != تہی) {		\
			elm = SPLAY_بایاں(elm, میدان);			\
		}							\
	} ورنہ								\
		elm = تہی;						\
	واپس (elm);							\
}									\
									\
ساکن __inline ساخت type *						\
name##_SPLAY_MIN_MAX(ساخت name *سر, صحیح val)			\
{									\
	name##_SPLAY_MINMAX(سر, val);					\
        واپس (SPLAY_جڑ(سر));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#تعریف_کرو SPLAY_GENERATE(name, type, میدان, cmp)				\
ساخت type *								\
name##_SPLAY_INSERT(ساخت name *سر, ساخت type *elm)		\
{									\
    اگر (SPLAY_خالی_خانے(سر)) {						\
	    SPLAY_بایاں(elm, میدان) = SPLAY_دایاں(elm, میدان) = تہی;	\
    } ورنہ {								\
	    صحیح __comp;							\
	    name##_SPLAY(سر, elm);					\
	    __comp = (cmp)(elm, (سر)->sph_جڑ);			\
	    اگر(__comp < 0) {						\
		    SPLAY_بایاں(elm, میدان) = SPLAY_بایاں((سر)->sph_جڑ, میدان);\
		    SPLAY_دایاں(elm, میدان) = (سر)->sph_جڑ;		\
		    SPLAY_بایاں((سر)->sph_جڑ, میدان) = تہی;		\
	    } ورنہ اگر (__comp > 0) {					\
		    SPLAY_دایاں(elm, میدان) = SPLAY_دایاں((سر)->sph_جڑ, میدان);\
		    SPLAY_بایاں(elm, میدان) = (سر)->sph_جڑ;		\
		    SPLAY_دایاں((سر)->sph_جڑ, میدان) = تہی;	\
	    } ورنہ							\
		    واپس ((سر)->sph_جڑ);				\
    }									\
    (سر)->sph_جڑ = (elm);						\
    واپس (تہی);							\
}									\
									\
ساخت type *								\
name##_SPLAY_REMOVE(ساخت name *سر, ساخت type *elm)		\
{									\
	ساخت type *__tmp;						\
	اگر (SPLAY_خالی_خانے(سر))						\
		واپس (تہی);						\
	name##_SPLAY(سر, elm);					\
	اگر ((cmp)(elm, (سر)->sph_جڑ) == 0) {			\
		اگر (SPLAY_بایاں((سر)->sph_جڑ, میدان) == تہی) {	\
			(سر)->sph_جڑ = SPLAY_دایاں((سر)->sph_جڑ, میدان);\
		} ورنہ {						\
			__tmp = SPLAY_دایاں((سر)->sph_جڑ, میدان);	\
			(سر)->sph_جڑ = SPLAY_بایاں((سر)->sph_جڑ, میدان);\
			name##_SPLAY(سر, elm);			\
			SPLAY_دایاں((سر)->sph_جڑ, میدان) = __tmp;	\
		}							\
		واپس (elm);						\
	}								\
	واپس (تہی);							\
}									\
									\
خالی									\
name##_SPLAY(ساخت name *سر, ساخت type *elm)			\
{									\
	ساخت type __node, *__left, *__right, *__tmp;			\
	صحیح __comp;							\
\
	SPLAY_بایاں(&__node, میدان) = SPLAY_دایاں(&__node, میدان) = تہی;\
	__left = __right = &__node;					\
\
	جب ((__comp = (cmp)(elm, (سر)->sph_جڑ))) {		\
		اگر (__comp < 0) {					\
			__tmp = SPLAY_بایاں((سر)->sph_جڑ, میدان);	\
			اگر (__tmp == تہی)				\
				توڑو;					\
			اگر ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_دایاں(سر, __tmp, میدان);	\
				اگر (SPLAY_بایاں((سر)->sph_جڑ, میدان) == تہی)\
					توڑو;				\
			}						\
			SPLAY_LINKLEFT(سر, __right, میدان);		\
		} ورنہ اگر (__comp > 0) {				\
			__tmp = SPLAY_دایاں((سر)->sph_جڑ, میدان);	\
			اگر (__tmp == تہی)				\
				توڑو;					\
			اگر ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_بایاں(سر, __tmp, میدان);	\
				اگر (SPLAY_دایاں((سر)->sph_جڑ, میدان) == تہی)\
					توڑو;				\
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
خالی name##_SPLAY_MINMAX(ساخت name *سر, صحیح __comp) \
{									\
	ساخت type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_بایاں(&__node, میدان) = SPLAY_دایاں(&__node, میدان) = تہی;\
	__left = __right = &__node;					\
\
	جب (1) {							\
		اگر (__comp < 0) {					\
			__tmp = SPLAY_بایاں((سر)->sph_جڑ, میدان);	\
			اگر (__tmp == تہی)				\
				توڑو;					\
			اگر (__comp < 0){				\
				SPLAY_ROTATE_دایاں(سر, __tmp, میدان);	\
				اگر (SPLAY_بایاں((سر)->sph_جڑ, میدان) == تہی)\
					توڑو;				\
			}						\
			SPLAY_LINKLEFT(سر, __right, میدان);		\
		} ورنہ اگر (__comp > 0) {				\
			__tmp = SPLAY_دایاں((سر)->sph_جڑ, میدان);	\
			اگر (__tmp == تہی)				\
				توڑو;					\
			اگر (__comp > 0) {				\
				SPLAY_ROTATE_بایاں(سر, __tmp, میدان);	\
				اگر (SPLAY_دایاں((سر)->sph_جڑ, میدان) == تہی)\
					توڑو;				\
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
#تعریف_کرو SPLAY_ڈھونڈو(name, x, y)		name##_SPLAY_FIND(x, y)
#تعریف_کرو SPLAY_اگلا(name, x, y)		name##_SPLAY_NEXT(x, y)
#تعریف_کرو SPLAY_MIN(name, x)		(SPLAY_خالی_خانے(x) ? تہی	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#تعریف_کرو SPLAY_MAX(name, x)		(SPLAY_خالی_خانے(x) ? تہی	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#تعریف_کرو SPLAY_FOREACH(x, name, سر)					\
	برائے ((x) = SPLAY_MIN(name, سر);				\
	     (x) != تہی;						\
	     (x) = SPLAY_اگلا(name, سر, x))

/* Macros that define a red-black tree */
#تعریف_کرو RB_سر(name, type)						\
ساخت name {								\
	ساخت type *rbh_جڑ; /* root of the tree */			\
}

#تعریف_کرو RB_INITIALIZER(جڑ)						\
	{ تہی }

#تعریف_کرو RB_INIT(جڑ) کرو {						\
	(جڑ)->rbh_جڑ = تہی;					\
} جب (0)

#تعریف_کرو RB_BLACK	0
#تعریف_کرو RB_RED		1
#تعریف_کرو RB_اندراج(type)							\
ساخت {								\
	ساخت type *rbe_بایاں;		/* left element */		\
	ساخت type *rbe_دایاں;		/* right element */		\
	ساخت type *rbe_والد;	/* parent element */		\
	صحیح rbe_color;			/* node color */		\
}

#تعریف_کرو RB_بایاں(elm, میدان)		(elm)->میدان.rbe_بایاں
#تعریف_کرو RB_دایاں(elm, میدان)		(elm)->میدان.rbe_دایاں
#تعریف_کرو RB_والد(elm, میدان)		(elm)->میدان.rbe_والد
#تعریف_کرو RB_COLOR(elm, میدان)		(elm)->میدان.rbe_color
#تعریف_کرو RB_جڑ(سر)			(سر)->rbh_جڑ
#تعریف_کرو RB_خالی_خانے(سر)			(RB_جڑ(سر) == تہی)

#تعریف_کرو RB_سیٹ(elm, والد, میدان) کرو {					\
	RB_والد(elm, میدان) = والد;					\
	RB_بایاں(elm, میدان) = RB_دایاں(elm, میدان) = تہی;		\
	RB_COLOR(elm, میدان) = RB_RED;					\
} جب (0)

#تعریف_کرو RB_سیٹ_BLACKRED(black, red, میدان) کرو {				\
	RB_COLOR(black, میدان) = RB_BLACK;				\
	RB_COLOR(red, میدان) = RB_RED;					\
} جب (0)

#اگر_غیر_تعریف_شدہ RB_AUGMENT
#تعریف_کرو RB_AUGMENT(x)	کرو {} جب (0)
#اگر_ختم

#تعریف_کرو RB_ROTATE_بایاں(سر, elm, tmp, میدان) کرو {			\
	(tmp) = RB_دایاں(elm, میدان);					\
	اگر ((RB_دایاں(elm, میدان) = RB_بایاں(tmp, میدان))) {		\
		RB_والد(RB_بایاں(tmp, میدان), میدان) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	اگر ((RB_والد(tmp, میدان) = RB_والد(elm, میدان))) {		\
		اگر ((elm) == RB_بایاں(RB_والد(elm, میدان), میدان))	\
			RB_بایاں(RB_والد(elm, میدان), میدان) = (tmp);	\
		ورنہ							\
			RB_دایاں(RB_والد(elm, میدان), میدان) = (tmp);	\
	} ورنہ								\
		(سر)->rbh_جڑ = (tmp);				\
	RB_بایاں(tmp, میدان) = (elm);					\
	RB_والد(elm, میدان) = (tmp);					\
	RB_AUGMENT(tmp);						\
	اگر ((RB_والد(tmp, میدان)))					\
		RB_AUGMENT(RB_والد(tmp, میدان));			\
} جب (0)

#تعریف_کرو RB_ROTATE_دایاں(سر, elm, tmp, میدان) کرو {			\
	(tmp) = RB_بایاں(elm, میدان);					\
	اگر ((RB_بایاں(elm, میدان) = RB_دایاں(tmp, میدان))) {		\
		RB_والد(RB_دایاں(tmp, میدان), میدان) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	اگر ((RB_والد(tmp, میدان) = RB_والد(elm, میدان))) {		\
		اگر ((elm) == RB_بایاں(RB_والد(elm, میدان), میدان))	\
			RB_بایاں(RB_والد(elm, میدان), میدان) = (tmp);	\
		ورنہ							\
			RB_دایاں(RB_والد(elm, میدان), میدان) = (tmp);	\
	} ورنہ								\
		(سر)->rbh_جڑ = (tmp);				\
	RB_دایاں(tmp, میدان) = (elm);					\
	RB_والد(elm, میدان) = (tmp);					\
	RB_AUGMENT(tmp);						\
	اگر ((RB_والد(tmp, میدان)))					\
		RB_AUGMENT(RB_والد(tmp, میدان));			\
} جب (0)

/* Generates prototypes and inline functions */
#تعریف_کرو	RB_PROTOTYPE(name, type, میدان, cmp)				\
	RB_PROTOTYPE_اندرونی(name, type, میدان, cmp,)
#تعریف_کرو	RB_PROTOTYPE_STATIC(name, type, میدان, cmp)			\
	RB_PROTOTYPE_اندرونی(name, type, میدان, cmp, __attribute__((__unused__)) ساکن)
#تعریف_کرو RB_PROTOTYPE_اندرونی(name, type, میدان, cmp, attr)		\
attr خالی name##_RB_INSERT_COLOR(ساخت name *, ساخت type *);		\
attr خالی name##_RB_REMOVE_COLOR(ساخت name *, ساخت type *, ساخت type *);\
attr ساخت type *name##_RB_REMOVE(ساخت name *, ساخت type *);	\
attr ساخت type *name##_RB_INSERT(ساخت name *, ساخت type *);	\
attr ساخت type *name##_RB_FIND(ساخت name *, ساخت type *);		\
attr ساخت type *name##_RB_NFIND(ساخت name *, ساخت type *);	\
attr ساخت type *name##_RB_NEXT(ساخت type *);			\
attr ساخت type *name##_RB_PREV(ساخت type *);			\
attr ساخت type *name##_RB_MINMAX(ساخت name *, صحیح);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#تعریف_کرو	RB_GENERATE(name, type, میدان, cmp)				\
	RB_GENERATE_اندرونی(name, type, میدان, cmp,)
#تعریف_کرو	RB_GENERATE_STATIC(name, type, میدان, cmp)			\
	RB_GENERATE_اندرونی(name, type, میدان, cmp, __attribute__((__unused__)) ساکن)
#تعریف_کرو RB_GENERATE_اندرونی(name, type, میدان, cmp, attr)		\
attr خالی								\
name##_RB_INSERT_COLOR(ساخت name *سر, ساخت type *elm)		\
{									\
	ساخت type *والد, *gparent, *tmp;				\
	جب ((والد = RB_والد(elm, میدان)) &&			\
	    RB_COLOR(والد, میدان) == RB_RED) {			\
		gparent = RB_والد(والد, میدان);			\
		اگر (والد == RB_بایاں(gparent, میدان)) {		\
			tmp = RB_دایاں(gparent, میدان);			\
			اگر (tmp && RB_COLOR(tmp, میدان) == RB_RED) {	\
				RB_COLOR(tmp, میدان) = RB_BLACK;	\
				RB_سیٹ_BLACKRED(والد, gparent, میدان);\
				elm = gparent;				\
				جاری;				\
			}						\
			اگر (RB_دایاں(والد, میدان) == elm) {		\
				RB_ROTATE_بایاں(سر, والد, tmp, میدان);\
				tmp = والد;				\
				والد = elm;				\
				elm = tmp;				\
			}						\
			RB_سیٹ_BLACKRED(والد, gparent, میدان);	\
			RB_ROTATE_دایاں(سر, gparent, tmp, میدان);	\
		} ورنہ {						\
			tmp = RB_بایاں(gparent, میدان);			\
			اگر (tmp && RB_COLOR(tmp, میدان) == RB_RED) {	\
				RB_COLOR(tmp, میدان) = RB_BLACK;	\
				RB_سیٹ_BLACKRED(والد, gparent, میدان);\
				elm = gparent;				\
				جاری;				\
			}						\
			اگر (RB_بایاں(والد, میدان) == elm) {		\
				RB_ROTATE_دایاں(سر, والد, tmp, میدان);\
				tmp = والد;				\
				والد = elm;				\
				elm = tmp;				\
			}						\
			RB_سیٹ_BLACKRED(والد, gparent, میدان);	\
			RB_ROTATE_بایاں(سر, gparent, tmp, میدان);	\
		}							\
	}								\
	RB_COLOR(سر->rbh_جڑ, میدان) = RB_BLACK;			\
}									\
									\
attr خالی								\
name##_RB_REMOVE_COLOR(ساخت name *سر, ساخت type *والد, ساخت type *elm) \
{									\
	ساخت type *tmp;						\
	جب ((elm == تہی || RB_COLOR(elm, میدان) == RB_BLACK) &&	\
	    elm != RB_جڑ(سر)) {					\
		اگر (RB_بایاں(والد, میدان) == elm) {			\
			tmp = RB_دایاں(والد, میدان);			\
			اگر (RB_COLOR(tmp, میدان) == RB_RED) {		\
				RB_سیٹ_BLACKRED(tmp, والد, میدان);	\
				RB_ROTATE_بایاں(سر, والد, tmp, میدان);\
				tmp = RB_دایاں(والد, میدان);		\
			}						\
			اگر ((RB_بایاں(tmp, میدان) == تہی ||		\
			    RB_COLOR(RB_بایاں(tmp, میدان), میدان) == RB_BLACK) &&\
			    (RB_دایاں(tmp, میدان) == تہی ||		\
			    RB_COLOR(RB_دایاں(tmp, میدان), میدان) == RB_BLACK)) {\
				RB_COLOR(tmp, میدان) = RB_RED;		\
				elm = والد;				\
				والد = RB_والد(elm, میدان);		\
			} ورنہ {					\
				اگر (RB_دایاں(tmp, میدان) == تہی ||	\
				    RB_COLOR(RB_دایاں(tmp, میدان), میدان) == RB_BLACK) {\
					ساخت type *oleft;		\
					اگر ((oleft = RB_بایاں(tmp, میدان)))\
						RB_COLOR(oleft, میدان) = RB_BLACK;\
					RB_COLOR(tmp, میدان) = RB_RED;	\
					RB_ROTATE_دایاں(سر, tmp, oleft, میدان);\
					tmp = RB_دایاں(والد, میدان);	\
				}					\
				RB_COLOR(tmp, میدان) = RB_COLOR(والد, میدان);\
				RB_COLOR(والد, میدان) = RB_BLACK;	\
				اگر (RB_دایاں(tmp, میدان))		\
					RB_COLOR(RB_دایاں(tmp, میدان), میدان) = RB_BLACK;\
				RB_ROTATE_بایاں(سر, والد, tmp, میدان);\
				elm = RB_جڑ(سر);			\
				توڑو;					\
			}						\
		} ورنہ {						\
			tmp = RB_بایاں(والد, میدان);			\
			اگر (RB_COLOR(tmp, میدان) == RB_RED) {		\
				RB_سیٹ_BLACKRED(tmp, والد, میدان);	\
				RB_ROTATE_دایاں(سر, والد, tmp, میدان);\
				tmp = RB_بایاں(والد, میدان);		\
			}						\
			اگر ((RB_بایاں(tmp, میدان) == تہی ||		\
			    RB_COLOR(RB_بایاں(tmp, میدان), میدان) == RB_BLACK) &&\
			    (RB_دایاں(tmp, میدان) == تہی ||		\
			    RB_COLOR(RB_دایاں(tmp, میدان), میدان) == RB_BLACK)) {\
				RB_COLOR(tmp, میدان) = RB_RED;		\
				elm = والد;				\
				والد = RB_والد(elm, میدان);		\
			} ورنہ {					\
				اگر (RB_بایاں(tmp, میدان) == تہی ||	\
				    RB_COLOR(RB_بایاں(tmp, میدان), میدان) == RB_BLACK) {\
					ساخت type *oright;		\
					اگر ((oright = RB_دایاں(tmp, میدان)))\
						RB_COLOR(oright, میدان) = RB_BLACK;\
					RB_COLOR(tmp, میدان) = RB_RED;	\
					RB_ROTATE_بایاں(سر, tmp, oright, میدان);\
					tmp = RB_بایاں(والد, میدان);	\
				}					\
				RB_COLOR(tmp, میدان) = RB_COLOR(والد, میدان);\
				RB_COLOR(والد, میدان) = RB_BLACK;	\
				اگر (RB_بایاں(tmp, میدان))		\
					RB_COLOR(RB_بایاں(tmp, میدان), میدان) = RB_BLACK;\
				RB_ROTATE_دایاں(سر, والد, tmp, میدان);\
				elm = RB_جڑ(سر);			\
				توڑو;					\
			}						\
		}							\
	}								\
	اگر (elm)							\
		RB_COLOR(elm, میدان) = RB_BLACK;			\
}									\
									\
attr ساخت type *							\
name##_RB_REMOVE(ساخت name *سر, ساخت type *elm)			\
{									\
	ساخت type *بچہ, *والد, *old = elm;			\
	صحیح color;							\
	اگر (RB_بایاں(elm, میدان) == تہی)				\
		بچہ = RB_دایاں(elm, میدان);				\
	ورنہ اگر (RB_دایاں(elm, میدان) == تہی)				\
		بچہ = RB_بایاں(elm, میدان);				\
	ورنہ {								\
		ساخت type *بایاں;					\
		elm = RB_دایاں(elm, میدان);				\
		جب ((بایاں = RB_بایاں(elm, میدان)))			\
			elm = بایاں;					\
		بچہ = RB_دایاں(elm, میدان);				\
		والد = RB_والد(elm, میدان);				\
		color = RB_COLOR(elm, میدان);				\
		اگر (بچہ)						\
			RB_والد(بچہ, میدان) = والد;		\
		اگر (والد) {						\
			اگر (RB_بایاں(والد, میدان) == elm)		\
				RB_بایاں(والد, میدان) = بچہ;		\
			ورنہ						\
				RB_دایاں(والد, میدان) = بچہ;	\
			RB_AUGMENT(والد);				\
		} ورنہ							\
			RB_جڑ(سر) = بچہ;				\
		اگر (RB_والد(elm, میدان) == old)			\
			والد = elm;					\
		(elm)->میدان = (old)->میدان;				\
		اگر (RB_والد(old, میدان)) {				\
			اگر (RB_بایاں(RB_والد(old, میدان), میدان) == old)\
				RB_بایاں(RB_والد(old, میدان), میدان) = elm;\
			ورنہ						\
				RB_دایاں(RB_والد(old, میدان), میدان) = elm;\
			RB_AUGMENT(RB_والد(old, میدان));		\
		} ورنہ							\
			RB_جڑ(سر) = elm;				\
		RB_والد(RB_بایاں(old, میدان), میدان) = elm;		\
		اگر (RB_دایاں(old, میدان))				\
			RB_والد(RB_دایاں(old, میدان), میدان) = elm;	\
		اگر (والد) {						\
			بایاں = والد;					\
			کرو {						\
				RB_AUGMENT(بایاں);			\
			} جب ((بایاں = RB_والد(بایاں, میدان)));	\
		}							\
		جاؤ color;						\
	}								\
	والد = RB_والد(elm, میدان);					\
	color = RB_COLOR(elm, میدان);					\
	اگر (بچہ)							\
		RB_والد(بچہ, میدان) = والد;			\
	اگر (والد) {							\
		اگر (RB_بایاں(والد, میدان) == elm)			\
			RB_بایاں(والد, میدان) = بچہ;			\
		ورنہ							\
			RB_دایاں(والد, میدان) = بچہ;		\
		RB_AUGMENT(والد);					\
	} ورنہ								\
		RB_جڑ(سر) = بچہ;					\
color:									\
	اگر (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(سر, والد, بچہ);		\
	واپس (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr ساخت type *							\
name##_RB_INSERT(ساخت name *سر, ساخت type *elm)			\
{									\
	ساخت type *tmp;						\
	ساخت type *والد = تہی;					\
	صحیح comp = 0;							\
	tmp = RB_جڑ(سر);						\
	جب (tmp) {							\
		والد = tmp;						\
		comp = (cmp)(elm, والد);				\
		اگر (comp < 0)						\
			tmp = RB_بایاں(tmp, میدان);			\
		ورنہ اگر (comp > 0)					\
			tmp = RB_دایاں(tmp, میدان);			\
		ورنہ							\
			واپس (tmp);					\
	}								\
	RB_سیٹ(elm, والد, میدان);					\
	اگر (والد != تہی) {						\
		اگر (comp < 0)						\
			RB_بایاں(والد, میدان) = elm;			\
		ورنہ							\
			RB_دایاں(والد, میدان) = elm;			\
		RB_AUGMENT(والد);					\
	} ورنہ								\
		RB_جڑ(سر) = elm;					\
	name##_RB_INSERT_COLOR(سر, elm);				\
	واپس (تہی);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr ساخت type *							\
name##_RB_FIND(ساخت name *سر, ساخت type *elm)			\
{									\
	ساخت type *tmp = RB_جڑ(سر);				\
	صحیح comp;							\
	جب (tmp) {							\
		comp = cmp(elm, tmp);					\
		اگر (comp < 0)						\
			tmp = RB_بایاں(tmp, میدان);			\
		ورنہ اگر (comp > 0)					\
			tmp = RB_دایاں(tmp, میدان);			\
		ورنہ							\
			واپس (tmp);					\
	}								\
	واپس (تہی);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr ساخت type *							\
name##_RB_NFIND(ساخت name *سر, ساخت type *elm)			\
{									\
	ساخت type *tmp = RB_جڑ(سر);				\
	ساخت type *res = تہی;					\
	صحیح comp;							\
	جب (tmp) {							\
		comp = cmp(elm, tmp);					\
		اگر (comp < 0) {						\
			res = tmp;					\
			tmp = RB_بایاں(tmp, میدان);			\
		}							\
		ورنہ اگر (comp > 0)					\
			tmp = RB_دایاں(tmp, میدان);			\
		ورنہ							\
			واپس (tmp);					\
	}								\
	واپس (res);							\
}									\
									\
/* ARGSUSED */								\
attr ساخت type *							\
name##_RB_NEXT(ساخت type *elm)					\
{									\
	اگر (RB_دایاں(elm, میدان)) {					\
		elm = RB_دایاں(elm, میدان);				\
		جب (RB_بایاں(elm, میدان))				\
			elm = RB_بایاں(elm, میدان);			\
	} ورنہ {							\
		اگر (RB_والد(elm, میدان) &&				\
		    (elm == RB_بایاں(RB_والد(elm, میدان), میدان)))	\
			elm = RB_والد(elm, میدان);			\
		ورنہ {							\
			جب (RB_والد(elm, میدان) &&			\
			    (elm == RB_دایاں(RB_والد(elm, میدان), میدان)))\
				elm = RB_والد(elm, میدان);		\
			elm = RB_والد(elm, میدان);			\
		}							\
	}								\
	واپس (elm);							\
}									\
									\
/* ARGSUSED */								\
attr ساخت type *							\
name##_RB_PREV(ساخت type *elm)					\
{									\
	اگر (RB_بایاں(elm, میدان)) {					\
		elm = RB_بایاں(elm, میدان);				\
		جب (RB_دایاں(elm, میدان))				\
			elm = RB_دایاں(elm, میدان);			\
	} ورنہ {							\
		اگر (RB_والد(elm, میدان) &&				\
		    (elm == RB_دایاں(RB_والد(elm, میدان), میدان)))	\
			elm = RB_والد(elm, میدان);			\
		ورنہ {							\
			جب (RB_والد(elm, میدان) &&			\
			    (elm == RB_بایاں(RB_والد(elm, میدان), میدان)))\
				elm = RB_والد(elm, میدان);		\
			elm = RB_والد(elm, میدان);			\
		}							\
	}								\
	واپس (elm);							\
}									\
									\
attr ساخت type *							\
name##_RB_MINMAX(ساخت name *سر, صحیح val)				\
{									\
	ساخت type *tmp = RB_جڑ(سر);				\
	ساخت type *والد = تہی;					\
	جب (tmp) {							\
		والد = tmp;						\
		اگر (val < 0)						\
			tmp = RB_بایاں(tmp, میدان);			\
		ورنہ							\
			tmp = RB_دایاں(tmp, میدان);			\
	}								\
	واپس (والد);						\
}

#تعریف_کرو RB_NEGINF	-1
#تعریف_کرو RB_INF	1

#تعریف_کرو RB_داخل_کرو(name, x, y)	name##_RB_INSERT(x, y)
#تعریف_کرو RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#تعریف_کرو RB_ڈھونڈو(name, x, y)	name##_RB_FIND(x, y)
#تعریف_کرو RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#تعریف_کرو RB_اگلا(name, x, y)	name##_RB_NEXT(y)
#تعریف_کرو RB_پچھلا(name, x, y)	name##_RB_PREV(y)
#تعریف_کرو RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#تعریف_کرو RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#تعریف_کرو RB_FOREACH(x, name, سر)					\
	برائے ((x) = RB_MIN(name, سر);					\
	     (x) != تہی;						\
	     (x) = name##_RB_NEXT(x))

#تعریف_کرو RB_FOREACH_محفوظ(x, name, سر, y)				\
	برائے ((x) = RB_MIN(name, سر);					\
	    ((x) != تہی) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#تعریف_کرو RB_FOREACH_الٹ(x, name, سر)				\
	برائے ((x) = RB_MAX(name, سر);					\
	     (x) != تہی;						\
	     (x) = name##_RB_PREV(x))

#تعریف_کرو RB_FOREACH_الٹ_محفوظ(x, name, سر, y)			\
	برائے ((x) = RB_MAX(name, سر);					\
	    ((x) != تہی) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#اگر_ختم	/* _SYS_TREE_H_ */
