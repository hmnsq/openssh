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
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_درخت_H
#define	SYS_درخت_H

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
ساختار name {								\
	ساختار type *sph_ریشه; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(ریشه)						\
	{ پوچ }

#define SPLAY_INIT(ریشه) انجامبده {						\
	(ریشه)->sph_ریشه = پوچ;					\
} وقتی (0)

#define SPLAY_ENTRY(type)						\
ساختار {								\
	ساختار type *spe_چپ; /* left element */			\
	ساختار type *spe_راست; /* right element */			\
}

#define SPLAY_چپ(elm, field)		(elm)->field.spe_چپ
#define SPLAY_راست(elm, field)		(elm)->field.spe_راست
#define SPLAY_ریشه(head)		(head)->sph_ریشه
#define SPLAY_EMPTY(head)		(SPLAY_ریشه(head) == پوچ)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_راست(head, tmp, field) انجامبده {			\
	SPLAY_چپ((head)->sph_ریشه, field) = SPLAY_راست(tmp, field);	\
	SPLAY_راست(tmp, field) = (head)->sph_ریشه;			\
	(head)->sph_ریشه = tmp;						\
} وقتی (0)
	
#define SPLAY_ROTATE_چپ(head, tmp, field) انجامبده {			\
	SPLAY_راست((head)->sph_ریشه, field) = SPLAY_چپ(tmp, field);	\
	SPLAY_چپ(tmp, field) = (head)->sph_ریشه;			\
	(head)->sph_ریشه = tmp;						\
} وقتی (0)

#define SPLAY_LINKLEFT(head, tmp, field) انجامبده {				\
	SPLAY_چپ(tmp, field) = (head)->sph_ریشه;			\
	tmp = (head)->sph_ریشه;						\
	(head)->sph_ریشه = SPLAY_چپ((head)->sph_ریشه, field);		\
} وقتی (0)

#define SPLAY_LINKRIGHT(head, tmp, field) انجامبده {				\
	SPLAY_راست(tmp, field) = (head)->sph_ریشه;			\
	tmp = (head)->sph_ریشه;						\
	(head)->sph_ریشه = SPLAY_راست((head)->sph_ریشه, field);	\
} وقتی (0)

#define SPLAY_ASSEMBLE(head, گره, چپ, راست, field) انجامبده {		\
	SPLAY_راست(چپ, field) = SPLAY_چپ((head)->sph_ریشه, field);	\
	SPLAY_چپ(راست, field) = SPLAY_راست((head)->sph_ریشه, field);\
	SPLAY_چپ((head)->sph_ریشه, field) = SPLAY_راست(گره, field);	\
	SPLAY_راست((head)->sph_ریشه, field) = SPLAY_چپ(گره, field);	\
} وقتی (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
تهی name##_SPLAY(ساختار name *, ساختار type *);			\
تهی name##_SPLAY_MINMAX(ساختار name *, صحیح);				\
ساختار type *name##_SPLAY_INSERT(ساختار name *, ساختار type *);		\
ساختار type *name##_SPLAY_REMOVE(ساختار name *, ساختار type *);		\
									\
/* Finds the node with the same key as elm */				\
ایستا __inline ساختار type *						\
name##_SPLAY_FIND(ساختار name *head, ساختار type *elm)			\
{									\
	اگر (SPLAY_EMPTY(head))						\
		بازگشت(پوچ);						\
	name##_SPLAY(head, elm);					\
	اگر ((cmp)(elm, (head)->sph_ریشه) == 0)				\
		بازگشت (head->sph_ریشه);				\
	بازگشت (پوچ);							\
}									\
									\
ایستا __inline ساختار type *						\
name##_SPLAY_NEXT(ساختار name *head, ساختار type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	اگر (SPLAY_راست(elm, field) != پوچ) {				\
		elm = SPLAY_راست(elm, field);				\
		وقتی (SPLAY_چپ(elm, field) != پوچ) {		\
			elm = SPLAY_چپ(elm, field);			\
		}							\
	} وگرنه								\
		elm = پوچ;						\
	بازگشت (elm);							\
}									\
									\
ایستا __inline ساختار type *						\
name##_SPLAY_MIN_MAX(ساختار name *head, صحیح val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        بازگشت (SPLAY_ریشه(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
ساختار type *								\
name##_SPLAY_INSERT(ساختار name *head, ساختار type *elm)		\
{									\
    اگر (SPLAY_EMPTY(head)) {						\
	    SPLAY_چپ(elm, field) = SPLAY_راست(elm, field) = پوچ;	\
    } وگرنه {								\
	    صحیح __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_ریشه);			\
	    اگر(__comp < 0) {						\
		    SPLAY_چپ(elm, field) = SPLAY_چپ((head)->sph_ریشه, field);\
		    SPLAY_راست(elm, field) = (head)->sph_ریشه;		\
		    SPLAY_چپ((head)->sph_ریشه, field) = پوچ;		\
	    } وگرنه اگر (__comp > 0) {					\
		    SPLAY_راست(elm, field) = SPLAY_راست((head)->sph_ریشه, field);\
		    SPLAY_چپ(elm, field) = (head)->sph_ریشه;		\
		    SPLAY_راست((head)->sph_ریشه, field) = پوچ;	\
	    } وگرنه							\
		    بازگشت ((head)->sph_ریشه);				\
    }									\
    (head)->sph_ریشه = (elm);						\
    بازگشت (پوچ);							\
}									\
									\
ساختار type *								\
name##_SPLAY_REMOVE(ساختار name *head, ساختار type *elm)		\
{									\
	ساختار type *__tmp;						\
	اگر (SPLAY_EMPTY(head))						\
		بازگشت (پوچ);						\
	name##_SPLAY(head, elm);					\
	اگر ((cmp)(elm, (head)->sph_ریشه) == 0) {			\
		اگر (SPLAY_چپ((head)->sph_ریشه, field) == پوچ) {	\
			(head)->sph_ریشه = SPLAY_راست((head)->sph_ریشه, field);\
		} وگرنه {						\
			__tmp = SPLAY_راست((head)->sph_ریشه, field);	\
			(head)->sph_ریشه = SPLAY_چپ((head)->sph_ریشه, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_راست((head)->sph_ریشه, field) = __tmp;	\
		}							\
		بازگشت (elm);						\
	}								\
	بازگشت (پوچ);							\
}									\
									\
تهی									\
name##_SPLAY(ساختار name *head, ساختار type *elm)			\
{									\
	ساختار type __node, *__left, *__right, *__tmp;			\
	صحیح __comp;							\
\
	SPLAY_چپ(&__node, field) = SPLAY_راست(&__node, field) = پوچ;\
	__left = __right = &__node;					\
\
	وقتی ((__comp = (cmp)(elm, (head)->sph_ریشه))) {		\
		اگر (__comp < 0) {					\
			__tmp = SPLAY_چپ((head)->sph_ریشه, field);	\
			اگر (__tmp == پوچ)				\
				بشکن;					\
			اگر ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_راست(head, __tmp, field);	\
				اگر (SPLAY_چپ((head)->sph_ریشه, field) == پوچ)\
					بشکن;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} وگرنه اگر (__comp > 0) {				\
			__tmp = SPLAY_راست((head)->sph_ریشه, field);	\
			اگر (__tmp == پوچ)				\
				بشکن;					\
			اگر ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_چپ(head, __tmp, field);	\
				اگر (SPLAY_راست((head)->sph_ریشه, field) == پوچ)\
					بشکن;				\
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
تهی name##_SPLAY_MINMAX(ساختار name *head, صحیح __comp) \
{									\
	ساختار type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_چپ(&__node, field) = SPLAY_راست(&__node, field) = پوچ;\
	__left = __right = &__node;					\
\
	وقتی (1) {							\
		اگر (__comp < 0) {					\
			__tmp = SPLAY_چپ((head)->sph_ریشه, field);	\
			اگر (__tmp == پوچ)				\
				بشکن;					\
			اگر (__comp < 0){				\
				SPLAY_ROTATE_راست(head, __tmp, field);	\
				اگر (SPLAY_چپ((head)->sph_ریشه, field) == پوچ)\
					بشکن;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} وگرنه اگر (__comp > 0) {				\
			__tmp = SPLAY_راست((head)->sph_ریشه, field);	\
			اگر (__tmp == پوچ)				\
				بشکن;					\
			اگر (__comp > 0) {				\
				SPLAY_ROTATE_چپ(head, __tmp, field);	\
				اگر (SPLAY_راست((head)->sph_ریشه, field) == پوچ)\
					بشکن;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_درج(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? پوچ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? پوچ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	برای ((x) = SPLAY_MIN(name, head);				\
	     (x) != پوچ;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
ساختار name {								\
	ساختار type *rbh_ریشه; /* root of the tree */			\
}

#define RB_INITIALIZER(ریشه)						\
	{ پوچ }

#define RB_INIT(ریشه) انجامبده {						\
	(ریشه)->rbh_ریشه = پوچ;					\
} وقتی (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
ساختار {								\
	ساختار type *rbe_چپ;		/* left element */		\
	ساختار type *rbe_راست;		/* right element */		\
	ساختار type *rbe_parent;	/* parent element */		\
	صحیح rbe_color;			/* node color */		\
}

#define RB_چپ(elm, field)		(elm)->field.rbe_چپ
#define RB_راست(elm, field)		(elm)->field.rbe_راست
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_ریشه(head)			(head)->rbh_ریشه
#define RB_EMPTY(head)			(RB_ریشه(head) == پوچ)

#define RB_SET(elm, parent, field) انجامبده {					\
	RB_PARENT(elm, field) = parent;					\
	RB_چپ(elm, field) = RB_راست(elm, field) = پوچ;		\
	RB_COLOR(elm, field) = RB_RED;					\
} وقتی (0)

#define RB_SET_BLACKRED(black, red, field) انجامبده {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} وقتی (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	انجامبده {} وقتی (0)
#endif

#define RB_ROTATE_چپ(head, elm, tmp, field) انجامبده {			\
	(tmp) = RB_راست(elm, field);					\
	اگر ((RB_راست(elm, field) = RB_چپ(tmp, field))) {		\
		RB_PARENT(RB_چپ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	اگر ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		اگر ((elm) == RB_چپ(RB_PARENT(elm, field), field))	\
			RB_چپ(RB_PARENT(elm, field), field) = (tmp);	\
		وگرنه							\
			RB_راست(RB_PARENT(elm, field), field) = (tmp);	\
	} وگرنه								\
		(head)->rbh_ریشه = (tmp);				\
	RB_چپ(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	اگر ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} وقتی (0)

#define RB_ROTATE_راست(head, elm, tmp, field) انجامبده {			\
	(tmp) = RB_چپ(elm, field);					\
	اگر ((RB_چپ(elm, field) = RB_راست(tmp, field))) {		\
		RB_PARENT(RB_راست(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	اگر ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		اگر ((elm) == RB_چپ(RB_PARENT(elm, field), field))	\
			RB_چپ(RB_PARENT(elm, field), field) = (tmp);	\
		وگرنه							\
			RB_راست(RB_PARENT(elm, field), field) = (tmp);	\
	} وگرنه								\
		(head)->rbh_ریشه = (tmp);				\
	RB_راست(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	اگر ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} وقتی (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) ایستا)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr تهی name##_RB_INSERT_COLOR(ساختار name *, ساختار type *);		\
attr تهی name##_RB_REMOVE_COLOR(ساختار name *, ساختار type *, ساختار type *);\
attr ساختار type *name##_RB_REMOVE(ساختار name *, ساختار type *);	\
attr ساختار type *name##_RB_INSERT(ساختار name *, ساختار type *);	\
attr ساختار type *name##_RB_FIND(ساختار name *, ساختار type *);		\
attr ساختار type *name##_RB_NFIND(ساختار name *, ساختار type *);	\
attr ساختار type *name##_RB_NEXT(ساختار type *);			\
attr ساختار type *name##_RB_PREV(ساختار type *);			\
attr ساختار type *name##_RB_MINMAX(ساختار name *, صحیح);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) ایستا)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr تهی								\
name##_RB_INSERT_COLOR(ساختار name *head, ساختار type *elm)		\
{									\
	ساختار type *parent, *gparent, *tmp;				\
	وقتی ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		اگر (parent == RB_چپ(gparent, field)) {		\
			tmp = RB_راست(gparent, field);			\
			اگر (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				ادامه;				\
			}						\
			اگر (RB_راست(parent, field) == elm) {		\
				RB_ROTATE_چپ(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_راست(head, gparent, tmp, field);	\
		} وگرنه {						\
			tmp = RB_چپ(gparent, field);			\
			اگر (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				ادامه;				\
			}						\
			اگر (RB_چپ(parent, field) == elm) {		\
				RB_ROTATE_راست(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_چپ(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_ریشه, field) = RB_BLACK;			\
}									\
									\
attr تهی								\
name##_RB_REMOVE_COLOR(ساختار name *head, ساختار type *parent, ساختار type *elm) \
{									\
	ساختار type *tmp;						\
	وقتی ((elm == پوچ || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_ریشه(head)) {					\
		اگر (RB_چپ(parent, field) == elm) {			\
			tmp = RB_راست(parent, field);			\
			اگر (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_چپ(head, parent, tmp, field);\
				tmp = RB_راست(parent, field);		\
			}						\
			اگر ((RB_چپ(tmp, field) == پوچ ||		\
			    RB_COLOR(RB_چپ(tmp, field), field) == RB_BLACK) &&\
			    (RB_راست(tmp, field) == پوچ ||		\
			    RB_COLOR(RB_راست(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} وگرنه {					\
				اگر (RB_راست(tmp, field) == پوچ ||	\
				    RB_COLOR(RB_راست(tmp, field), field) == RB_BLACK) {\
					ساختار type *oleft;		\
					اگر ((oleft = RB_چپ(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_راست(head, tmp, oleft, field);\
					tmp = RB_راست(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				اگر (RB_راست(tmp, field))		\
					RB_COLOR(RB_راست(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_چپ(head, parent, tmp, field);\
				elm = RB_ریشه(head);			\
				بشکن;					\
			}						\
		} وگرنه {						\
			tmp = RB_چپ(parent, field);			\
			اگر (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_راست(head, parent, tmp, field);\
				tmp = RB_چپ(parent, field);		\
			}						\
			اگر ((RB_چپ(tmp, field) == پوچ ||		\
			    RB_COLOR(RB_چپ(tmp, field), field) == RB_BLACK) &&\
			    (RB_راست(tmp, field) == پوچ ||		\
			    RB_COLOR(RB_راست(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} وگرنه {					\
				اگر (RB_چپ(tmp, field) == پوچ ||	\
				    RB_COLOR(RB_چپ(tmp, field), field) == RB_BLACK) {\
					ساختار type *oright;		\
					اگر ((oright = RB_راست(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_چپ(head, tmp, oright, field);\
					tmp = RB_چپ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				اگر (RB_چپ(tmp, field))		\
					RB_COLOR(RB_چپ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_راست(head, parent, tmp, field);\
				elm = RB_ریشه(head);			\
				بشکن;					\
			}						\
		}							\
	}								\
	اگر (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr ساختار type *							\
name##_RB_REMOVE(ساختار name *head, ساختار type *elm)			\
{									\
	ساختار type *child, *parent, *old = elm;			\
	صحیح color;							\
	اگر (RB_چپ(elm, field) == پوچ)				\
		child = RB_راست(elm, field);				\
	وگرنه اگر (RB_راست(elm, field) == پوچ)				\
		child = RB_چپ(elm, field);				\
	وگرنه {								\
		ساختار type *چپ;					\
		elm = RB_راست(elm, field);				\
		وقتی ((چپ = RB_چپ(elm, field)))			\
			elm = چپ;					\
		child = RB_راست(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		اگر (child)						\
			RB_PARENT(child, field) = parent;		\
		اگر (parent) {						\
			اگر (RB_چپ(parent, field) == elm)		\
				RB_چپ(parent, field) = child;		\
			وگرنه						\
				RB_راست(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} وگرنه							\
			RB_ریشه(head) = child;				\
		اگر (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		اگر (RB_PARENT(old, field)) {				\
			اگر (RB_چپ(RB_PARENT(old, field), field) == old)\
				RB_چپ(RB_PARENT(old, field), field) = elm;\
			وگرنه						\
				RB_راست(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} وگرنه							\
			RB_ریشه(head) = elm;				\
		RB_PARENT(RB_چپ(old, field), field) = elm;		\
		اگر (RB_راست(old, field))				\
			RB_PARENT(RB_راست(old, field), field) = elm;	\
		اگر (parent) {						\
			چپ = parent;					\
			انجامبده {						\
				RB_AUGMENT(چپ);			\
			} وقتی ((چپ = RB_PARENT(چپ, field)));	\
		}							\
		برو color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	اگر (child)							\
		RB_PARENT(child, field) = parent;			\
	اگر (parent) {							\
		اگر (RB_چپ(parent, field) == elm)			\
			RB_چپ(parent, field) = child;			\
		وگرنه							\
			RB_راست(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} وگرنه								\
		RB_ریشه(head) = child;					\
color:									\
	اگر (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	بازگشت (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr ساختار type *							\
name##_RB_INSERT(ساختار name *head, ساختار type *elm)			\
{									\
	ساختار type *tmp;						\
	ساختار type *parent = پوچ;					\
	صحیح comp = 0;							\
	tmp = RB_ریشه(head);						\
	وقتی (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		اگر (comp < 0)						\
			tmp = RB_چپ(tmp, field);			\
		وگرنه اگر (comp > 0)					\
			tmp = RB_راست(tmp, field);			\
		وگرنه							\
			بازگشت (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	اگر (parent != پوچ) {						\
		اگر (comp < 0)						\
			RB_چپ(parent, field) = elm;			\
		وگرنه							\
			RB_راست(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} وگرنه								\
		RB_ریشه(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	بازگشت (پوچ);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr ساختار type *							\
name##_RB_FIND(ساختار name *head, ساختار type *elm)			\
{									\
	ساختار type *tmp = RB_ریشه(head);				\
	صحیح comp;							\
	وقتی (tmp) {							\
		comp = cmp(elm, tmp);					\
		اگر (comp < 0)						\
			tmp = RB_چپ(tmp, field);			\
		وگرنه اگر (comp > 0)					\
			tmp = RB_راست(tmp, field);			\
		وگرنه							\
			بازگشت (tmp);					\
	}								\
	بازگشت (پوچ);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr ساختار type *							\
name##_RB_NFIND(ساختار name *head, ساختار type *elm)			\
{									\
	ساختار type *tmp = RB_ریشه(head);				\
	ساختار type *res = پوچ;					\
	صحیح comp;							\
	وقتی (tmp) {							\
		comp = cmp(elm, tmp);					\
		اگر (comp < 0) {						\
			res = tmp;					\
			tmp = RB_چپ(tmp, field);			\
		}							\
		وگرنه اگر (comp > 0)					\
			tmp = RB_راست(tmp, field);			\
		وگرنه							\
			بازگشت (tmp);					\
	}								\
	بازگشت (res);							\
}									\
									\
/* ARGSUSED */								\
attr ساختار type *							\
name##_RB_NEXT(ساختار type *elm)					\
{									\
	اگر (RB_راست(elm, field)) {					\
		elm = RB_راست(elm, field);				\
		وقتی (RB_چپ(elm, field))				\
			elm = RB_چپ(elm, field);			\
	} وگرنه {							\
		اگر (RB_PARENT(elm, field) &&				\
		    (elm == RB_چپ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		وگرنه {							\
			وقتی (RB_PARENT(elm, field) &&			\
			    (elm == RB_راست(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	بازگشت (elm);							\
}									\
									\
/* ARGSUSED */								\
attr ساختار type *							\
name##_RB_PREV(ساختار type *elm)					\
{									\
	اگر (RB_چپ(elm, field)) {					\
		elm = RB_چپ(elm, field);				\
		وقتی (RB_راست(elm, field))				\
			elm = RB_راست(elm, field);			\
	} وگرنه {							\
		اگر (RB_PARENT(elm, field) &&				\
		    (elm == RB_راست(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		وگرنه {							\
			وقتی (RB_PARENT(elm, field) &&			\
			    (elm == RB_چپ(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	بازگشت (elm);							\
}									\
									\
attr ساختار type *							\
name##_RB_MINMAX(ساختار name *head, صحیح val)				\
{									\
	ساختار type *tmp = RB_ریشه(head);				\
	ساختار type *parent = پوچ;					\
	وقتی (tmp) {							\
		parent = tmp;						\
		اگر (val < 0)						\
			tmp = RB_چپ(tmp, field);			\
		وگرنه							\
			tmp = RB_راست(tmp, field);			\
	}								\
	بازگشت (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_درج(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	برای ((x) = RB_MIN(name, head);					\
	     (x) != پوچ;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	برای ((x) = RB_MIN(name, head);					\
	    ((x) != پوچ) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	برای ((x) = RB_MAX(name, head);					\
	     (x) != پوچ;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	برای ((x) = RB_MAX(name, head);					\
	    ((x) != پوچ) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
