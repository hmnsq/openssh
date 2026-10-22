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

#অন্তর্ভাৱ "config.h"
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

#define SPLAY_HEAD(name, type)						\
সংরচনা name {								\
	সংরচনা type *sph_মূল; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(মূল)						\
	{ রিক্ত }

#define SPLAY_INIT(মূল) কৰা {						\
	(মূল)->sph_মূল = রিক্ত;					\
} যেতিয়ালৈ (0)

#define SPLAY_ENTRY(type)						\
সংরচনা {								\
	সংরচনা type *spe_বাম; /* left element */			\
	সংরচনা type *spe_ডান; /* right element */			\
}

#define SPLAY_বাম(elm, field)		(elm)->field.spe_বাম
#define SPLAY_ডান(elm, field)		(elm)->field.spe_ডান
#define SPLAY_মূল(head)		(head)->sph_মূল
#define SPLAY_EMPTY(head)		(SPLAY_মূল(head) == রিক্ত)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_ডান(head, tmp, field) কৰা {			\
	SPLAY_বাম((head)->sph_মূল, field) = SPLAY_ডান(tmp, field);	\
	SPLAY_ডান(tmp, field) = (head)->sph_মূল;			\
	(head)->sph_মূল = tmp;						\
} যেতিয়ালৈ (0)
	
#define SPLAY_ROTATE_বাম(head, tmp, field) কৰা {			\
	SPLAY_ডান((head)->sph_মূল, field) = SPLAY_বাম(tmp, field);	\
	SPLAY_বাম(tmp, field) = (head)->sph_মূল;			\
	(head)->sph_মূল = tmp;						\
} যেতিয়ালৈ (0)

#define SPLAY_LINKLEFT(head, tmp, field) কৰা {				\
	SPLAY_বাম(tmp, field) = (head)->sph_মূল;			\
	tmp = (head)->sph_মূল;						\
	(head)->sph_মূল = SPLAY_বাম((head)->sph_মূল, field);		\
} যেতিয়ালৈ (0)

#define SPLAY_LINKRIGHT(head, tmp, field) কৰা {				\
	SPLAY_ডান(tmp, field) = (head)->sph_মূল;			\
	tmp = (head)->sph_মূল;						\
	(head)->sph_মূল = SPLAY_ডান((head)->sph_মূল, field);	\
} যেতিয়ালৈ (0)

#define SPLAY_ASSEMBLE(head, গ্ৰন্থি, বাম, ডান, field) কৰা {		\
	SPLAY_ডান(বাম, field) = SPLAY_বাম((head)->sph_মূল, field);	\
	SPLAY_বাম(ডান, field) = SPLAY_ডান((head)->sph_মূল, field);\
	SPLAY_বাম((head)->sph_মূল, field) = SPLAY_ডান(গ্ৰন্থি, field);	\
	SPLAY_ডান((head)->sph_মূল, field) = SPLAY_বাম(গ্ৰন্থি, field);	\
} যেতিয়ালৈ (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
শূন্য name##_SPLAY(সংরচনা name *, সংরচনা type *);			\
শূন্য name##_SPLAY_MINMAX(সংরচনা name *, পূর্ণাঙ্ক);				\
সংরচনা type *name##_SPLAY_INSERT(সংরচনা name *, সংরচনা type *);		\
সংরচনা type *name##_SPLAY_REMOVE(সংরচনা name *, সংরচনা type *);		\
									\
/* Finds the node with the same key as elm */				\
স্থির __inline সংরচনা type *						\
name##_SPLAY_FIND(সংরচনা name *head, সংরচনা type *elm)			\
{									\
	যদি (SPLAY_EMPTY(head))						\
		ঘূৰাই(রিক্ত);						\
	name##_SPLAY(head, elm);					\
	যদি ((cmp)(elm, (head)->sph_মূল) == 0)				\
		ঘূৰাই (head->sph_মূল);				\
	ঘূৰাই (রিক্ত);							\
}									\
									\
স্থির __inline সংরচনা type *						\
name##_SPLAY_NEXT(সংরচনা name *head, সংরচনা type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	যদি (SPLAY_ডান(elm, field) != রিক্ত) {				\
		elm = SPLAY_ডান(elm, field);				\
		যেতিয়ালৈ (SPLAY_বাম(elm, field) != রিক্ত) {		\
			elm = SPLAY_বাম(elm, field);			\
		}							\
	} অন্যথা								\
		elm = রিক্ত;						\
	ঘূৰাই (elm);							\
}									\
									\
স্থির __inline সংরচনা type *						\
name##_SPLAY_MIN_MAX(সংরচনা name *head, পূর্ণাঙ্ক val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        ঘূৰাই (SPLAY_মূল(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
সংরচনা type *								\
name##_SPLAY_INSERT(সংরচনা name *head, সংরচনা type *elm)		\
{									\
    যদি (SPLAY_EMPTY(head)) {						\
	    SPLAY_বাম(elm, field) = SPLAY_ডান(elm, field) = রিক্ত;	\
    } অন্যথা {								\
	    পূর্ণাঙ্ক __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_মূল);			\
	    যদি(__comp < 0) {						\
		    SPLAY_বাম(elm, field) = SPLAY_বাম((head)->sph_মূল, field);\
		    SPLAY_ডান(elm, field) = (head)->sph_মূল;		\
		    SPLAY_বাম((head)->sph_মূল, field) = রিক্ত;		\
	    } অন্যথা যদি (__comp > 0) {					\
		    SPLAY_ডান(elm, field) = SPLAY_ডান((head)->sph_মূল, field);\
		    SPLAY_বাম(elm, field) = (head)->sph_মূল;		\
		    SPLAY_ডান((head)->sph_মূল, field) = রিক্ত;	\
	    } অন্যথা							\
		    ঘূৰাই ((head)->sph_মূল);				\
    }									\
    (head)->sph_মূল = (elm);						\
    ঘূৰাই (রিক্ত);							\
}									\
									\
সংরচনা type *								\
name##_SPLAY_REMOVE(সংরচনা name *head, সংরচনা type *elm)		\
{									\
	সংরচনা type *__tmp;						\
	যদি (SPLAY_EMPTY(head))						\
		ঘূৰাই (রিক্ত);						\
	name##_SPLAY(head, elm);					\
	যদি ((cmp)(elm, (head)->sph_মূল) == 0) {			\
		যদি (SPLAY_বাম((head)->sph_মূল, field) == রিক্ত) {	\
			(head)->sph_মূল = SPLAY_ডান((head)->sph_মূল, field);\
		} অন্যথা {						\
			__tmp = SPLAY_ডান((head)->sph_মূল, field);	\
			(head)->sph_মূল = SPLAY_বাম((head)->sph_মূল, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_ডান((head)->sph_মূল, field) = __tmp;	\
		}							\
		ঘূৰাই (elm);						\
	}								\
	ঘূৰাই (রিক্ত);							\
}									\
									\
শূন্য									\
name##_SPLAY(সংরচনা name *head, সংরচনা type *elm)			\
{									\
	সংরচনা type __node, *__left, *__right, *__tmp;			\
	পূর্ণাঙ্ক __comp;							\
\
	SPLAY_বাম(&__node, field) = SPLAY_ডান(&__node, field) = রিক্ত;\
	__left = __right = &__node;					\
\
	যেতিয়ালৈ ((__comp = (cmp)(elm, (head)->sph_মূল))) {		\
		যদি (__comp < 0) {					\
			__tmp = SPLAY_বাম((head)->sph_মূল, field);	\
			যদি (__tmp == রিক্ত)				\
				ভঙ্গ;					\
			যদি ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_ডান(head, __tmp, field);	\
				যদি (SPLAY_বাম((head)->sph_মূল, field) == রিক্ত)\
					ভঙ্গ;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} অন্যথা যদি (__comp > 0) {				\
			__tmp = SPLAY_ডান((head)->sph_মূল, field);	\
			যদি (__tmp == রিক্ত)				\
				ভঙ্গ;					\
			যদি ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_বাম(head, __tmp, field);	\
				যদি (SPLAY_ডান((head)->sph_মূল, field) == রিক্ত)\
					ভঙ্গ;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
শূন্য name##_SPLAY_MINMAX(সংরচনা name *head, পূর্ণাঙ্ক __comp) \
{									\
	সংরচনা type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_বাম(&__node, field) = SPLAY_ডান(&__node, field) = রিক্ত;\
	__left = __right = &__node;					\
\
	যেতিয়ালৈ (1) {							\
		যদি (__comp < 0) {					\
			__tmp = SPLAY_বাম((head)->sph_মূল, field);	\
			যদি (__tmp == রিক্ত)				\
				ভঙ্গ;					\
			যদি (__comp < 0){				\
				SPLAY_ROTATE_ডান(head, __tmp, field);	\
				যদি (SPLAY_বাম((head)->sph_মূল, field) == রিক্ত)\
					ভঙ্গ;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} অন্যথা যদি (__comp > 0) {				\
			__tmp = SPLAY_ডান((head)->sph_মূল, field);	\
			যদি (__tmp == রিক্ত)				\
				ভঙ্গ;					\
			যদি (__comp > 0) {				\
				SPLAY_ROTATE_বাম(head, __tmp, field);	\
				যদি (SPLAY_ডান((head)->sph_মূল, field) == রিক্ত)\
					ভঙ্গ;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_ঢোকাও(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? রিক্ত	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? রিক্ত	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	বাবে ((x) = SPLAY_MIN(name, head);				\
	     (x) != রিক্ত;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
সংরচনা name {								\
	সংরচনা type *rbh_মূল; /* root of the tree */			\
}

#define RB_INITIALIZER(মূল)						\
	{ রিক্ত }

#define RB_INIT(মূল) কৰা {						\
	(মূল)->rbh_মূল = রিক্ত;					\
} যেতিয়ালৈ (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
সংরচনা {								\
	সংরচনা type *rbe_বাম;		/* left element */		\
	সংরচনা type *rbe_ডান;		/* right element */		\
	সংরচনা type *rbe_parent;	/* parent element */		\
	পূর্ণাঙ্ক rbe_color;			/* node color */		\
}

#define RB_বাম(elm, field)		(elm)->field.rbe_বাম
#define RB_ডান(elm, field)		(elm)->field.rbe_ডান
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_মূল(head)			(head)->rbh_মূল
#define RB_EMPTY(head)			(RB_মূল(head) == রিক্ত)

#define RB_SET(elm, parent, field) কৰা {					\
	RB_PARENT(elm, field) = parent;					\
	RB_বাম(elm, field) = RB_ডান(elm, field) = রিক্ত;		\
	RB_COLOR(elm, field) = RB_RED;					\
} যেতিয়ালৈ (0)

#define RB_SET_BLACKRED(black, red, field) কৰা {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} যেতিয়ালৈ (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	কৰা {} যেতিয়ালৈ (0)
#endif

#define RB_ROTATE_বাম(head, elm, tmp, field) কৰা {			\
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
		(head)->rbh_মূল = (tmp);				\
	RB_বাম(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	যদি ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} যেতিয়ালৈ (0)

#define RB_ROTATE_ডান(head, elm, tmp, field) কৰা {			\
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
		(head)->rbh_মূল = (tmp);				\
	RB_ডান(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	যদি ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} যেতিয়ালৈ (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) স্থির)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr শূন্য name##_RB_INSERT_COLOR(সংরচনা name *, সংরচনা type *);		\
attr শূন্য name##_RB_REMOVE_COLOR(সংরচনা name *, সংরচনা type *, সংরচনা type *);\
attr সংরচনা type *name##_RB_REMOVE(সংরচনা name *, সংরচনা type *);	\
attr সংরচনা type *name##_RB_INSERT(সংরচনা name *, সংরচনা type *);	\
attr সংরচনা type *name##_RB_FIND(সংরচনা name *, সংরচনা type *);		\
attr সংরচনা type *name##_RB_NFIND(সংরচনা name *, সংরচনা type *);	\
attr সংরচনা type *name##_RB_NEXT(সংরচনা type *);			\
attr সংরচনা type *name##_RB_PREV(সংরচনা type *);			\
attr সংরচনা type *name##_RB_MINMAX(সংরচনা name *, পূর্ণাঙ্ক);			\
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
name##_RB_INSERT_COLOR(সংরচনা name *head, সংরচনা type *elm)		\
{									\
	সংরচনা type *parent, *gparent, *tmp;				\
	যেতিয়ালৈ ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		যদি (parent == RB_বাম(gparent, field)) {		\
			tmp = RB_ডান(gparent, field);			\
			যদি (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				অনুৱর্ত;				\
			}						\
			যদি (RB_ডান(parent, field) == elm) {		\
				RB_ROTATE_বাম(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_ডান(head, gparent, tmp, field);	\
		} অন্যথা {						\
			tmp = RB_বাম(gparent, field);			\
			যদি (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				অনুৱর্ত;				\
			}						\
			যদি (RB_বাম(parent, field) == elm) {		\
				RB_ROTATE_ডান(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_বাম(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_মূল, field) = RB_BLACK;			\
}									\
									\
attr শূন্য								\
name##_RB_REMOVE_COLOR(সংরচনা name *head, সংরচনা type *parent, সংরচনা type *elm) \
{									\
	সংরচনা type *tmp;						\
	যেতিয়ালৈ ((elm == রিক্ত || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_মূল(head)) {					\
		যদি (RB_বাম(parent, field) == elm) {			\
			tmp = RB_ডান(parent, field);			\
			যদি (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_বাম(head, parent, tmp, field);\
				tmp = RB_ডান(parent, field);		\
			}						\
			যদি ((RB_বাম(tmp, field) == রিক্ত ||		\
			    RB_COLOR(RB_বাম(tmp, field), field) == RB_BLACK) &&\
			    (RB_ডান(tmp, field) == রিক্ত ||		\
			    RB_COLOR(RB_ডান(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} অন্যথা {					\
				যদি (RB_ডান(tmp, field) == রিক্ত ||	\
				    RB_COLOR(RB_ডান(tmp, field), field) == RB_BLACK) {\
					সংরচনা type *oleft;		\
					যদি ((oleft = RB_বাম(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_ডান(head, tmp, oleft, field);\
					tmp = RB_ডান(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				যদি (RB_ডান(tmp, field))		\
					RB_COLOR(RB_ডান(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_বাম(head, parent, tmp, field);\
				elm = RB_মূল(head);			\
				ভঙ্গ;					\
			}						\
		} অন্যথা {						\
			tmp = RB_বাম(parent, field);			\
			যদি (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_ডান(head, parent, tmp, field);\
				tmp = RB_বাম(parent, field);		\
			}						\
			যদি ((RB_বাম(tmp, field) == রিক্ত ||		\
			    RB_COLOR(RB_বাম(tmp, field), field) == RB_BLACK) &&\
			    (RB_ডান(tmp, field) == রিক্ত ||		\
			    RB_COLOR(RB_ডান(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} অন্যথা {					\
				যদি (RB_বাম(tmp, field) == রিক্ত ||	\
				    RB_COLOR(RB_বাম(tmp, field), field) == RB_BLACK) {\
					সংরচনা type *oright;		\
					যদি ((oright = RB_ডান(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_বাম(head, tmp, oright, field);\
					tmp = RB_বাম(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				যদি (RB_বাম(tmp, field))		\
					RB_COLOR(RB_বাম(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_ডান(head, parent, tmp, field);\
				elm = RB_মূল(head);			\
				ভঙ্গ;					\
			}						\
		}							\
	}								\
	যদি (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr সংরচনা type *							\
name##_RB_REMOVE(সংরচনা name *head, সংরচনা type *elm)			\
{									\
	সংরচনা type *child, *parent, *old = elm;			\
	পূর্ণাঙ্ক color;							\
	যদি (RB_বাম(elm, field) == রিক্ত)				\
		child = RB_ডান(elm, field);				\
	অন্যথা যদি (RB_ডান(elm, field) == রিক্ত)				\
		child = RB_বাম(elm, field);				\
	অন্যথা {								\
		সংরচনা type *বাম;					\
		elm = RB_ডান(elm, field);				\
		যেতিয়ালৈ ((বাম = RB_বাম(elm, field)))			\
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
			RB_মূল(head) = child;				\
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
			RB_মূল(head) = elm;				\
		RB_PARENT(RB_বাম(old, field), field) = elm;		\
		যদি (RB_ডান(old, field))				\
			RB_PARENT(RB_ডান(old, field), field) = elm;	\
		যদি (parent) {						\
			বাম = parent;					\
			কৰা {						\
				RB_AUGMENT(বাম);			\
			} যেতিয়ালৈ ((বাম = RB_PARENT(বাম, field)));	\
		}							\
		গচ্ছ color;						\
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
		RB_মূল(head) = child;					\
color:									\
	যদি (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	ঘূৰাই (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr সংরচনা type *							\
name##_RB_INSERT(সংরচনা name *head, সংরচনা type *elm)			\
{									\
	সংরচনা type *tmp;						\
	সংরচনা type *parent = রিক্ত;					\
	পূর্ণাঙ্ক comp = 0;							\
	tmp = RB_মূল(head);						\
	যেতিয়ালৈ (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		যদি (comp < 0)						\
			tmp = RB_বাম(tmp, field);			\
		অন্যথা যদি (comp > 0)					\
			tmp = RB_ডান(tmp, field);			\
		অন্যথা							\
			ঘূৰাই (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	যদি (parent != রিক্ত) {						\
		যদি (comp < 0)						\
			RB_বাম(parent, field) = elm;			\
		অন্যথা							\
			RB_ডান(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} অন্যথা								\
		RB_মূল(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	ঘূৰাই (রিক্ত);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr সংরচনা type *							\
name##_RB_FIND(সংরচনা name *head, সংরচনা type *elm)			\
{									\
	সংরচনা type *tmp = RB_মূল(head);				\
	পূর্ণাঙ্ক comp;							\
	যেতিয়ালৈ (tmp) {							\
		comp = cmp(elm, tmp);					\
		যদি (comp < 0)						\
			tmp = RB_বাম(tmp, field);			\
		অন্যথা যদি (comp > 0)					\
			tmp = RB_ডান(tmp, field);			\
		অন্যথা							\
			ঘূৰাই (tmp);					\
	}								\
	ঘূৰাই (রিক্ত);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr সংরচনা type *							\
name##_RB_NFIND(সংরচনা name *head, সংরচনা type *elm)			\
{									\
	সংরচনা type *tmp = RB_মূল(head);				\
	সংরচনা type *res = রিক্ত;					\
	পূর্ণাঙ্ক comp;							\
	যেতিয়ালৈ (tmp) {							\
		comp = cmp(elm, tmp);					\
		যদি (comp < 0) {						\
			res = tmp;					\
			tmp = RB_বাম(tmp, field);			\
		}							\
		অন্যথা যদি (comp > 0)					\
			tmp = RB_ডান(tmp, field);			\
		অন্যথা							\
			ঘূৰাই (tmp);					\
	}								\
	ঘূৰাই (res);							\
}									\
									\
/* ARGSUSED */								\
attr সংরচনা type *							\
name##_RB_NEXT(সংরচনা type *elm)					\
{									\
	যদি (RB_ডান(elm, field)) {					\
		elm = RB_ডান(elm, field);				\
		যেতিয়ালৈ (RB_বাম(elm, field))				\
			elm = RB_বাম(elm, field);			\
	} অন্যথা {							\
		যদি (RB_PARENT(elm, field) &&				\
		    (elm == RB_বাম(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		অন্যথা {							\
			যেতিয়ালৈ (RB_PARENT(elm, field) &&			\
			    (elm == RB_ডান(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	ঘূৰাই (elm);							\
}									\
									\
/* ARGSUSED */								\
attr সংরচনা type *							\
name##_RB_PREV(সংরচনা type *elm)					\
{									\
	যদি (RB_বাম(elm, field)) {					\
		elm = RB_বাম(elm, field);				\
		যেতিয়ালৈ (RB_ডান(elm, field))				\
			elm = RB_ডান(elm, field);			\
	} অন্যথা {							\
		যদি (RB_PARENT(elm, field) &&				\
		    (elm == RB_ডান(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		অন্যথা {							\
			যেতিয়ালৈ (RB_PARENT(elm, field) &&			\
			    (elm == RB_বাম(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	ঘূৰাই (elm);							\
}									\
									\
attr সংরচনা type *							\
name##_RB_MINMAX(সংরচনা name *head, পূর্ণাঙ্ক val)				\
{									\
	সংরচনা type *tmp = RB_মূল(head);				\
	সংরচনা type *parent = রিক্ত;					\
	যেতিয়ালৈ (tmp) {							\
		parent = tmp;						\
		যদি (val < 0)						\
			tmp = RB_বাম(tmp, field);			\
		অন্যথা							\
			tmp = RB_ডান(tmp, field);			\
	}								\
	ঘূৰাই (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_ঢোকাও(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	বাবে ((x) = RB_MIN(name, head);					\
	     (x) != রিক্ত;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	বাবে ((x) = RB_MIN(name, head);					\
	    ((x) != রিক্ত) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	বাবে ((x) = RB_MAX(name, head);					\
	     (x) != রিক্ত;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	বাবে ((x) = RB_MAX(name, head);					\
	    ((x) != রিক্ত) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
