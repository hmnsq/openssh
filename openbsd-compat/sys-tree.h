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

#অন্তর্ভাব "config.h"
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_বৃক্ষ_H
#define	SYS_বৃক্ষ_H

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

#define SPLAY_শীর্ষ(name, type)						\
কাঠামো name {								\
	কাঠামো type *sph_মূল; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(মূল)						\
	{ ফাঁকা }

#define SPLAY_INIT(মূল) করো {						\
	(মূল)->sph_মূল = ফাঁকা;					\
} যখন (0)

#define SPLAY_ENTRY(type)						\
কাঠামো {								\
	কাঠামো type *spe_বাম; /* left element */			\
	কাঠামো type *spe_ডান; /* right element */			\
}

#define SPLAY_বাম(elm, field)		(elm)->field.spe_বাম
#define SPLAY_ডান(elm, field)		(elm)->field.spe_ডান
#define SPLAY_মূল(শীর্ষ_2)		(শীর্ষ_2)->sph_মূল
#define SPLAY_EMPTY(শীর্ষ_2)		(SPLAY_মূল(শীর্ষ_2) == ফাঁকা)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_ডান(শীর্ষ_2, tmp, field) করো {			\
	SPLAY_বাম((শীর্ষ_2)->sph_মূল, field) = SPLAY_ডান(tmp, field);	\
	SPLAY_ডান(tmp, field) = (শীর্ষ_2)->sph_মূল;			\
	(শীর্ষ_2)->sph_মূল = tmp;						\
} যখন (0)
	
#define SPLAY_ROTATE_বাম(শীর্ষ_2, tmp, field) করো {			\
	SPLAY_ডান((শীর্ষ_2)->sph_মূল, field) = SPLAY_বাম(tmp, field);	\
	SPLAY_বাম(tmp, field) = (শীর্ষ_2)->sph_মূল;			\
	(শীর্ষ_2)->sph_মূল = tmp;						\
} যখন (0)

#define SPLAY_LINKLEFT(শীর্ষ_2, tmp, field) করো {				\
	SPLAY_বাম(tmp, field) = (শীর্ষ_2)->sph_মূল;			\
	tmp = (শীর্ষ_2)->sph_মূল;						\
	(শীর্ষ_2)->sph_মূল = SPLAY_বাম((শীর্ষ_2)->sph_মূল, field);		\
} যখন (0)

#define SPLAY_LINKRIGHT(শীর্ষ_2, tmp, field) করো {				\
	SPLAY_ডান(tmp, field) = (শীর্ষ_2)->sph_মূল;			\
	tmp = (শীর্ষ_2)->sph_মূল;						\
	(শীর্ষ_2)->sph_মূল = SPLAY_ডান((শীর্ষ_2)->sph_মূল, field);	\
} যখন (0)

#define SPLAY_ASSEMBLE(শীর্ষ_2, গ্রন্থি, বাম, ডান, field) করো {		\
	SPLAY_ডান(বাম, field) = SPLAY_বাম((শীর্ষ_2)->sph_মূল, field);	\
	SPLAY_বাম(ডান, field) = SPLAY_ডান((শীর্ষ_2)->sph_মূল, field);\
	SPLAY_বাম((শীর্ষ_2)->sph_মূল, field) = SPLAY_ডান(গ্রন্থি, field);	\
	SPLAY_ডান((শীর্ষ_2)->sph_মূল, field) = SPLAY_বাম(গ্রন্থি, field);	\
} যখন (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
শূন্য name##_SPLAY(কাঠামো name *, কাঠামো type *);			\
শূন্য name##_SPLAY_MINMAX(কাঠামো name *, পূর্ণসংখ্যা);				\
কাঠামো type *name##_SPLAY_INSERT(কাঠামো name *, কাঠামো type *);		\
কাঠামো type *name##_SPLAY_REMOVE(কাঠামো name *, কাঠামো type *);		\
									\
/* Finds the node with the same key as elm */				\
স্থির __inline কাঠামো type *						\
name##_SPLAY_FIND(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)			\
{									\
	যদি (SPLAY_EMPTY(শীর্ষ_2))						\
		ফেরত(ফাঁকা);						\
	name##_SPLAY(শীর্ষ_2, elm);					\
	যদি ((cmp)(elm, (শীর্ষ_2)->sph_মূল) == 0)				\
		ফেরত (শীর্ষ_2->sph_মূল);				\
	ফেরত (ফাঁকা);							\
}									\
									\
স্থির __inline কাঠামো type *						\
name##_SPLAY_NEXT(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)			\
{									\
	name##_SPLAY(শীর্ষ_2, elm);					\
	যদি (SPLAY_ডান(elm, field) != ফাঁকা) {				\
		elm = SPLAY_ডান(elm, field);				\
		যখন (SPLAY_বাম(elm, field) != ফাঁকা) {		\
			elm = SPLAY_বাম(elm, field);			\
		}							\
	} অন্যথা								\
		elm = ফাঁকা;						\
	ফেরত (elm);							\
}									\
									\
স্থির __inline কাঠামো type *						\
name##_SPLAY_MIN_MAX(কাঠামো name *শীর্ষ_2, পূর্ণসংখ্যা val)			\
{									\
	name##_SPLAY_MINMAX(শীর্ষ_2, val);					\
        ফেরত (SPLAY_মূল(শীর্ষ_2));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
কাঠামো type *								\
name##_SPLAY_INSERT(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)		\
{									\
    যদি (SPLAY_EMPTY(শীর্ষ_2)) {						\
	    SPLAY_বাম(elm, field) = SPLAY_ডান(elm, field) = ফাঁকা;	\
    } অন্যথা {								\
	    পূর্ণসংখ্যা __comp;							\
	    name##_SPLAY(শীর্ষ_2, elm);					\
	    __comp = (cmp)(elm, (শীর্ষ_2)->sph_মূল);			\
	    যদি(__comp < 0) {						\
		    SPLAY_বাম(elm, field) = SPLAY_বাম((শীর্ষ_2)->sph_মূল, field);\
		    SPLAY_ডান(elm, field) = (শীর্ষ_2)->sph_মূল;		\
		    SPLAY_বাম((শীর্ষ_2)->sph_মূল, field) = ফাঁকা;		\
	    } অন্যথা যদি (__comp > 0) {					\
		    SPLAY_ডান(elm, field) = SPLAY_ডান((শীর্ষ_2)->sph_মূল, field);\
		    SPLAY_বাম(elm, field) = (শীর্ষ_2)->sph_মূল;		\
		    SPLAY_ডান((শীর্ষ_2)->sph_মূল, field) = ফাঁকা;	\
	    } অন্যথা							\
		    ফেরত ((শীর্ষ_2)->sph_মূল);				\
    }									\
    (শীর্ষ_2)->sph_মূল = (elm);						\
    ফেরত (ফাঁকা);							\
}									\
									\
কাঠামো type *								\
name##_SPLAY_REMOVE(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)		\
{									\
	কাঠামো type *__tmp;						\
	যদি (SPLAY_EMPTY(শীর্ষ_2))						\
		ফেরত (ফাঁকা);						\
	name##_SPLAY(শীর্ষ_2, elm);					\
	যদি ((cmp)(elm, (শীর্ষ_2)->sph_মূল) == 0) {			\
		যদি (SPLAY_বাম((শীর্ষ_2)->sph_মূল, field) == ফাঁকা) {	\
			(শীর্ষ_2)->sph_মূল = SPLAY_ডান((শীর্ষ_2)->sph_মূল, field);\
		} অন্যথা {						\
			__tmp = SPLAY_ডান((শীর্ষ_2)->sph_মূল, field);	\
			(শীর্ষ_2)->sph_মূল = SPLAY_বাম((শীর্ষ_2)->sph_মূল, field);\
			name##_SPLAY(শীর্ষ_2, elm);			\
			SPLAY_ডান((শীর্ষ_2)->sph_মূল, field) = __tmp;	\
		}							\
		ফেরত (elm);						\
	}								\
	ফেরত (ফাঁকা);							\
}									\
									\
শূন্য									\
name##_SPLAY(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)			\
{									\
	কাঠামো type __node, *__left, *__right, *__tmp;			\
	পূর্ণসংখ্যা __comp;							\
\
	SPLAY_বাম(&__node, field) = SPLAY_ডান(&__node, field) = ফাঁকা;\
	__left = __right = &__node;					\
\
	যখন ((__comp = (cmp)(elm, (শীর্ষ_2)->sph_মূল))) {		\
		যদি (__comp < 0) {					\
			__tmp = SPLAY_বাম((শীর্ষ_2)->sph_মূল, field);	\
			যদি (__tmp == ফাঁকা)				\
				বিরতি;					\
			যদি ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_ডান(শীর্ষ_2, __tmp, field);	\
				যদি (SPLAY_বাম((শীর্ষ_2)->sph_মূল, field) == ফাঁকা)\
					বিরতি;				\
			}						\
			SPLAY_LINKLEFT(শীর্ষ_2, __right, field);		\
		} অন্যথা যদি (__comp > 0) {				\
			__tmp = SPLAY_ডান((শীর্ষ_2)->sph_মূল, field);	\
			যদি (__tmp == ফাঁকা)				\
				বিরতি;					\
			যদি ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_বাম(শীর্ষ_2, __tmp, field);	\
				যদি (SPLAY_ডান((শীর্ষ_2)->sph_মূল, field) == ফাঁকা)\
					বিরতি;				\
			}						\
			SPLAY_LINKRIGHT(শীর্ষ_2, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(শীর্ষ_2, &__node, __left, __right, field);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
শূন্য name##_SPLAY_MINMAX(কাঠামো name *শীর্ষ_2, পূর্ণসংখ্যা __comp) \
{									\
	কাঠামো type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_বাম(&__node, field) = SPLAY_ডান(&__node, field) = ফাঁকা;\
	__left = __right = &__node;					\
\
	যখন (1) {							\
		যদি (__comp < 0) {					\
			__tmp = SPLAY_বাম((শীর্ষ_2)->sph_মূল, field);	\
			যদি (__tmp == ফাঁকা)				\
				বিরতি;					\
			যদি (__comp < 0){				\
				SPLAY_ROTATE_ডান(শীর্ষ_2, __tmp, field);	\
				যদি (SPLAY_বাম((শীর্ষ_2)->sph_মূল, field) == ফাঁকা)\
					বিরতি;				\
			}						\
			SPLAY_LINKLEFT(শীর্ষ_2, __right, field);		\
		} অন্যথা যদি (__comp > 0) {				\
			__tmp = SPLAY_ডান((শীর্ষ_2)->sph_মূল, field);	\
			যদি (__tmp == ফাঁকা)				\
				বিরতি;					\
			যদি (__comp > 0) {				\
				SPLAY_ROTATE_বাম(শীর্ষ_2, __tmp, field);	\
				যদি (SPLAY_ডান((শীর্ষ_2)->sph_মূল, field) == ফাঁকা)\
					বিরতি;				\
			}						\
			SPLAY_LINKRIGHT(শীর্ষ_2, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(শীর্ষ_2, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_ঢোকাও(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_পরবর্তী(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? ফাঁকা	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? ফাঁকা	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, শীর্ষ_2)					\
	জন্য ((x) = SPLAY_MIN(name, শীর্ষ_2);				\
	     (x) != ফাঁকা;						\
	     (x) = SPLAY_পরবর্তী(name, শীর্ষ_2, x))

/* Macros that define a red-black tree */
#define RB_শীর্ষ(name, type)						\
কাঠামো name {								\
	কাঠামো type *rbh_মূল; /* root of the tree */			\
}

#define RB_INITIALIZER(মূল)						\
	{ ফাঁকা }

#define RB_INIT(মূল) করো {						\
	(মূল)->rbh_মূল = ফাঁকা;					\
} যখন (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
কাঠামো {								\
	কাঠামো type *rbe_বাম;		/* left element */		\
	কাঠামো type *rbe_ডান;		/* right element */		\
	কাঠামো type *rbe_parent;	/* parent element */		\
	পূর্ণসংখ্যা rbe_color;			/* node color */		\
}

#define RB_বাম(elm, field)		(elm)->field.rbe_বাম
#define RB_ডান(elm, field)		(elm)->field.rbe_ডান
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_মূল(শীর্ষ_2)			(শীর্ষ_2)->rbh_মূল
#define RB_EMPTY(শীর্ষ_2)			(RB_মূল(শীর্ষ_2) == ফাঁকা)

#define RB_SET(elm, parent, field) করো {					\
	RB_PARENT(elm, field) = parent;					\
	RB_বাম(elm, field) = RB_ডান(elm, field) = ফাঁকা;		\
	RB_COLOR(elm, field) = RB_RED;					\
} যখন (0)

#define RB_SET_BLACKRED(black, red, field) করো {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} যখন (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	করো {} যখন (0)
#endif

#define RB_ROTATE_বাম(শীর্ষ_2, elm, tmp, field) করো {			\
	(tmp) = RB_ডান(elm, field);					\
	যদি ((RB_ডান(elm, field) = RB_বাম(tmp, field))) {		\
		RB_PARENT(RB_বাম(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	যদি ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		যদি ((elm) == RB_বাম(RB_PARENT(elm, field), field))	\
			RB_বাম(RB_PARENT(elm, field), field) = (tmp);	\
		অন্যথা							\
			RB_ডান(RB_PARENT(elm, field), field) = (tmp);	\
	} অন্যথা								\
		(শীর্ষ_2)->rbh_মূল = (tmp);				\
	RB_বাম(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	যদি ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} যখন (0)

#define RB_ROTATE_ডান(শীর্ষ_2, elm, tmp, field) করো {			\
	(tmp) = RB_বাম(elm, field);					\
	যদি ((RB_বাম(elm, field) = RB_ডান(tmp, field))) {		\
		RB_PARENT(RB_ডান(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	যদি ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		যদি ((elm) == RB_বাম(RB_PARENT(elm, field), field))	\
			RB_বাম(RB_PARENT(elm, field), field) = (tmp);	\
		অন্যথা							\
			RB_ডান(RB_PARENT(elm, field), field) = (tmp);	\
	} অন্যথা								\
		(শীর্ষ_2)->rbh_মূল = (tmp);				\
	RB_ডান(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	যদি ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} যখন (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) স্থির)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr শূন্য name##_RB_INSERT_COLOR(কাঠামো name *, কাঠামো type *);		\
attr শূন্য name##_RB_REMOVE_COLOR(কাঠামো name *, কাঠামো type *, কাঠামো type *);\
attr কাঠামো type *name##_RB_REMOVE(কাঠামো name *, কাঠামো type *);	\
attr কাঠামো type *name##_RB_INSERT(কাঠামো name *, কাঠামো type *);	\
attr কাঠামো type *name##_RB_FIND(কাঠামো name *, কাঠামো type *);		\
attr কাঠামো type *name##_RB_NFIND(কাঠামো name *, কাঠামো type *);	\
attr কাঠামো type *name##_RB_NEXT(কাঠামো type *);			\
attr কাঠামো type *name##_RB_PREV(কাঠামো type *);			\
attr কাঠামো type *name##_RB_MINMAX(কাঠামো name *, পূর্ণসংখ্যা);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) স্থির)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr শূন্য								\
name##_RB_INSERT_COLOR(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)		\
{									\
	কাঠামো type *parent, *gparent, *tmp;				\
	যখন ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		যদি (parent == RB_বাম(gparent, field)) {		\
			tmp = RB_ডান(gparent, field);			\
			যদি (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				চালু;				\
			}						\
			যদি (RB_ডান(parent, field) == elm) {		\
				RB_ROTATE_বাম(শীর্ষ_2, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_ডান(শীর্ষ_2, gparent, tmp, field);	\
		} অন্যথা {						\
			tmp = RB_বাম(gparent, field);			\
			যদি (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				চালু;				\
			}						\
			যদি (RB_বাম(parent, field) == elm) {		\
				RB_ROTATE_ডান(শীর্ষ_2, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_বাম(শীর্ষ_2, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(শীর্ষ_2->rbh_মূল, field) = RB_BLACK;			\
}									\
									\
attr শূন্য								\
name##_RB_REMOVE_COLOR(কাঠামো name *শীর্ষ_2, কাঠামো type *parent, কাঠামো type *elm) \
{									\
	কাঠামো type *tmp;						\
	যখন ((elm == ফাঁকা || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_মূল(শীর্ষ_2)) {					\
		যদি (RB_বাম(parent, field) == elm) {			\
			tmp = RB_ডান(parent, field);			\
			যদি (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_বাম(শীর্ষ_2, parent, tmp, field);\
				tmp = RB_ডান(parent, field);		\
			}						\
			যদি ((RB_বাম(tmp, field) == ফাঁকা ||		\
			    RB_COLOR(RB_বাম(tmp, field), field) == RB_BLACK) &&\
			    (RB_ডান(tmp, field) == ফাঁকা ||		\
			    RB_COLOR(RB_ডান(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} অন্যথা {					\
				যদি (RB_ডান(tmp, field) == ফাঁকা ||	\
				    RB_COLOR(RB_ডান(tmp, field), field) == RB_BLACK) {\
					কাঠামো type *oleft;		\
					যদি ((oleft = RB_বাম(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_ডান(শীর্ষ_2, tmp, oleft, field);\
					tmp = RB_ডান(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				যদি (RB_ডান(tmp, field))		\
					RB_COLOR(RB_ডান(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_বাম(শীর্ষ_2, parent, tmp, field);\
				elm = RB_মূল(শীর্ষ_2);			\
				বিরতি;					\
			}						\
		} অন্যথা {						\
			tmp = RB_বাম(parent, field);			\
			যদি (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_ডান(শীর্ষ_2, parent, tmp, field);\
				tmp = RB_বাম(parent, field);		\
			}						\
			যদি ((RB_বাম(tmp, field) == ফাঁকা ||		\
			    RB_COLOR(RB_বাম(tmp, field), field) == RB_BLACK) &&\
			    (RB_ডান(tmp, field) == ফাঁকা ||		\
			    RB_COLOR(RB_ডান(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} অন্যথা {					\
				যদি (RB_বাম(tmp, field) == ফাঁকা ||	\
				    RB_COLOR(RB_বাম(tmp, field), field) == RB_BLACK) {\
					কাঠামো type *oright;		\
					যদি ((oright = RB_ডান(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_বাম(শীর্ষ_2, tmp, oright, field);\
					tmp = RB_বাম(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				যদি (RB_বাম(tmp, field))		\
					RB_COLOR(RB_বাম(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_ডান(শীর্ষ_2, parent, tmp, field);\
				elm = RB_মূল(শীর্ষ_2);			\
				বিরতি;					\
			}						\
		}							\
	}								\
	যদি (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr কাঠামো type *							\
name##_RB_REMOVE(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)			\
{									\
	কাঠামো type *child, *parent, *old = elm;			\
	পূর্ণসংখ্যা color;							\
	যদি (RB_বাম(elm, field) == ফাঁকা)				\
		child = RB_ডান(elm, field);				\
	অন্যথা যদি (RB_ডান(elm, field) == ফাঁকা)				\
		child = RB_বাম(elm, field);				\
	অন্যথা {								\
		কাঠামো type *বাম;					\
		elm = RB_ডান(elm, field);				\
		যখন ((বাম = RB_বাম(elm, field)))			\
			elm = বাম;					\
		child = RB_ডান(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		যদি (child)						\
			RB_PARENT(child, field) = parent;		\
		যদি (parent) {						\
			যদি (RB_বাম(parent, field) == elm)		\
				RB_বাম(parent, field) = child;		\
			অন্যথা						\
				RB_ডান(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} অন্যথা							\
			RB_মূল(শীর্ষ_2) = child;				\
		যদি (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		যদি (RB_PARENT(old, field)) {				\
			যদি (RB_বাম(RB_PARENT(old, field), field) == old)\
				RB_বাম(RB_PARENT(old, field), field) = elm;\
			অন্যথা						\
				RB_ডান(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} অন্যথা							\
			RB_মূল(শীর্ষ_2) = elm;				\
		RB_PARENT(RB_বাম(old, field), field) = elm;		\
		যদি (RB_ডান(old, field))				\
			RB_PARENT(RB_ডান(old, field), field) = elm;	\
		যদি (parent) {						\
			বাম = parent;					\
			করো {						\
				RB_AUGMENT(বাম);			\
			} যখন ((বাম = RB_PARENT(বাম, field)));	\
		}							\
		যাও color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	যদি (child)							\
		RB_PARENT(child, field) = parent;			\
	যদি (parent) {							\
		যদি (RB_বাম(parent, field) == elm)			\
			RB_বাম(parent, field) = child;			\
		অন্যথা							\
			RB_ডান(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} অন্যথা								\
		RB_মূল(শীর্ষ_2) = child;					\
color:									\
	যদি (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(শীর্ষ_2, parent, child);		\
	ফেরত (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr কাঠামো type *							\
name##_RB_INSERT(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)			\
{									\
	কাঠামো type *tmp;						\
	কাঠামো type *parent = ফাঁকা;					\
	পূর্ণসংখ্যা comp = 0;							\
	tmp = RB_মূল(শীর্ষ_2);						\
	যখন (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		যদি (comp < 0)						\
			tmp = RB_বাম(tmp, field);			\
		অন্যথা যদি (comp > 0)					\
			tmp = RB_ডান(tmp, field);			\
		অন্যথা							\
			ফেরত (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	যদি (parent != ফাঁকা) {						\
		যদি (comp < 0)						\
			RB_বাম(parent, field) = elm;			\
		অন্যথা							\
			RB_ডান(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} অন্যথা								\
		RB_মূল(শীর্ষ_2) = elm;					\
	name##_RB_INSERT_COLOR(শীর্ষ_2, elm);				\
	ফেরত (ফাঁকা);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr কাঠামো type *							\
name##_RB_FIND(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)			\
{									\
	কাঠামো type *tmp = RB_মূল(শীর্ষ_2);				\
	পূর্ণসংখ্যা comp;							\
	যখন (tmp) {							\
		comp = cmp(elm, tmp);					\
		যদি (comp < 0)						\
			tmp = RB_বাম(tmp, field);			\
		অন্যথা যদি (comp > 0)					\
			tmp = RB_ডান(tmp, field);			\
		অন্যথা							\
			ফেরত (tmp);					\
	}								\
	ফেরত (ফাঁকা);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr কাঠামো type *							\
name##_RB_NFIND(কাঠামো name *শীর্ষ_2, কাঠামো type *elm)			\
{									\
	কাঠামো type *tmp = RB_মূল(শীর্ষ_2);				\
	কাঠামো type *res = ফাঁকা;					\
	পূর্ণসংখ্যা comp;							\
	যখন (tmp) {							\
		comp = cmp(elm, tmp);					\
		যদি (comp < 0) {						\
			res = tmp;					\
			tmp = RB_বাম(tmp, field);			\
		}							\
		অন্যথা যদি (comp > 0)					\
			tmp = RB_ডান(tmp, field);			\
		অন্যথা							\
			ফেরত (tmp);					\
	}								\
	ফেরত (res);							\
}									\
									\
/* ARGSUSED */								\
attr কাঠামো type *							\
name##_RB_NEXT(কাঠামো type *elm)					\
{									\
	যদি (RB_ডান(elm, field)) {					\
		elm = RB_ডান(elm, field);				\
		যখন (RB_বাম(elm, field))				\
			elm = RB_বাম(elm, field);			\
	} অন্যথা {							\
		যদি (RB_PARENT(elm, field) &&				\
		    (elm == RB_বাম(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		অন্যথা {							\
			যখন (RB_PARENT(elm, field) &&			\
			    (elm == RB_ডান(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	ফেরত (elm);							\
}									\
									\
/* ARGSUSED */								\
attr কাঠামো type *							\
name##_RB_PREV(কাঠামো type *elm)					\
{									\
	যদি (RB_বাম(elm, field)) {					\
		elm = RB_বাম(elm, field);				\
		যখন (RB_ডান(elm, field))				\
			elm = RB_ডান(elm, field);			\
	} অন্যথা {							\
		যদি (RB_PARENT(elm, field) &&				\
		    (elm == RB_ডান(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		অন্যথা {							\
			যখন (RB_PARENT(elm, field) &&			\
			    (elm == RB_বাম(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	ফেরত (elm);							\
}									\
									\
attr কাঠামো type *							\
name##_RB_MINMAX(কাঠামো name *শীর্ষ_2, পূর্ণসংখ্যা val)				\
{									\
	কাঠামো type *tmp = RB_মূল(শীর্ষ_2);				\
	কাঠামো type *parent = ফাঁকা;					\
	যখন (tmp) {							\
		parent = tmp;						\
		যদি (val < 0)						\
			tmp = RB_বাম(tmp, field);			\
		অন্যথা							\
			tmp = RB_ডান(tmp, field);			\
	}								\
	ফেরত (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_ঢোকাও(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_পরবর্তী(name, x, y)	name##_RB_NEXT(y)
#define RB_পূর্ব(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, শীর্ষ_2)					\
	জন্য ((x) = RB_MIN(name, শীর্ষ_2);					\
	     (x) != ফাঁকা;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, শীর্ষ_2, y)				\
	জন্য ((x) = RB_MIN(name, শীর্ষ_2);					\
	    ((x) != ফাঁকা) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, শীর্ষ_2)				\
	জন্য ((x) = RB_MAX(name, শীর্ষ_2);					\
	     (x) != ফাঁকা;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, শীর্ষ_2, y)			\
	জন্য ((x) = RB_MAX(name, শীর্ষ_2);					\
	    ((x) != ফাঁকা) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
