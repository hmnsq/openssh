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
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_ڤوکوق_H
#define	SYS_ڤوکوق_H

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
بنية name {								\
	بنية type *sph_اکر; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(اکر)						\
	{ عدم }

#define SPLAY_INIT(اکر) افعل {						\
	(اکر)->sph_اکر = عدم;					\
} طالما (0)

#define SPLAY_ENTRY(type)						\
بنية {								\
	بنية type *spe_کيري; /* left element */			\
	بنية type *spe_کانن; /* right element */			\
}

#define SPLAY_کيري(elm, field)		(elm)->field.spe_کيري
#define SPLAY_کانن(elm, field)		(elm)->field.spe_کانن
#define SPLAY_اکر(head)		(head)->sph_اکر
#define SPLAY_EMPTY(head)		(SPLAY_اکر(head) == عدم)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_کانن(head, tmp, field) افعل {			\
	SPLAY_کيري((head)->sph_اکر, field) = SPLAY_کانن(tmp, field);	\
	SPLAY_کانن(tmp, field) = (head)->sph_اکر;			\
	(head)->sph_اکر = tmp;						\
} طالما (0)
	
#define SPLAY_ROTATE_کيري(head, tmp, field) افعل {			\
	SPLAY_کانن((head)->sph_اکر, field) = SPLAY_کيري(tmp, field);	\
	SPLAY_کيري(tmp, field) = (head)->sph_اکر;			\
	(head)->sph_اکر = tmp;						\
} طالما (0)

#define SPLAY_LINKLEFT(head, tmp, field) افعل {				\
	SPLAY_کيري(tmp, field) = (head)->sph_اکر;			\
	tmp = (head)->sph_اکر;						\
	(head)->sph_اکر = SPLAY_کيري((head)->sph_اکر, field);		\
} طالما (0)

#define SPLAY_LINKRIGHT(head, tmp, field) افعل {				\
	SPLAY_کانن(tmp, field) = (head)->sph_اکر;			\
	tmp = (head)->sph_اکر;						\
	(head)->sph_اکر = SPLAY_کانن((head)->sph_اکر, field);	\
} طالما (0)

#define SPLAY_ASSEMBLE(head, نود, کيري, کانن, field) افعل {		\
	SPLAY_کانن(کيري, field) = SPLAY_کيري((head)->sph_اکر, field);	\
	SPLAY_کيري(کانن, field) = SPLAY_کانن((head)->sph_اکر, field);\
	SPLAY_کيري((head)->sph_اکر, field) = SPLAY_کانن(نود, field);	\
	SPLAY_کانن((head)->sph_اکر, field) = SPLAY_کيري(نود, field);	\
} طالما (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
فراغ name##_SPLAY(بنية name *, بنية type *);			\
فراغ name##_SPLAY_MINMAX(بنية name *, صحيح);				\
بنية type *name##_SPLAY_INSERT(بنية name *, بنية type *);		\
بنية type *name##_SPLAY_REMOVE(بنية name *, بنية type *);		\
									\
/* Finds the node with the same key as elm */				\
ساكن __inline بنية type *						\
name##_SPLAY_FIND(بنية name *head, بنية type *elm)			\
{									\
	إذا (SPLAY_EMPTY(head))						\
		أرجع(عدم);						\
	name##_SPLAY(head, elm);					\
	إذا ((cmp)(elm, (head)->sph_اکر) == 0)				\
		أرجع (head->sph_اکر);				\
	أرجع (عدم);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_NEXT(بنية name *head, بنية type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	إذا (SPLAY_کانن(elm, field) != عدم) {				\
		elm = SPLAY_کانن(elm, field);				\
		طالما (SPLAY_کيري(elm, field) != عدم) {		\
			elm = SPLAY_کيري(elm, field);			\
		}							\
	} وإلا								\
		elm = عدم;						\
	أرجع (elm);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_MIN_MAX(بنية name *head, صحيح val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        أرجع (SPLAY_اکر(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
بنية type *								\
name##_SPLAY_INSERT(بنية name *head, بنية type *elm)		\
{									\
    إذا (SPLAY_EMPTY(head)) {						\
	    SPLAY_کيري(elm, field) = SPLAY_کانن(elm, field) = عدم;	\
    } وإلا {								\
	    صحيح __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_اکر);			\
	    إذا(__comp < 0) {						\
		    SPLAY_کيري(elm, field) = SPLAY_کيري((head)->sph_اکر, field);\
		    SPLAY_کانن(elm, field) = (head)->sph_اکر;		\
		    SPLAY_کيري((head)->sph_اکر, field) = عدم;		\
	    } وإلا إذا (__comp > 0) {					\
		    SPLAY_کانن(elm, field) = SPLAY_کانن((head)->sph_اکر, field);\
		    SPLAY_کيري(elm, field) = (head)->sph_اکر;		\
		    SPLAY_کانن((head)->sph_اکر, field) = عدم;	\
	    } وإلا							\
		    أرجع ((head)->sph_اکر);				\
    }									\
    (head)->sph_اکر = (elm);						\
    أرجع (عدم);							\
}									\
									\
بنية type *								\
name##_SPLAY_REMOVE(بنية name *head, بنية type *elm)		\
{									\
	بنية type *__tmp;						\
	إذا (SPLAY_EMPTY(head))						\
		أرجع (عدم);						\
	name##_SPLAY(head, elm);					\
	إذا ((cmp)(elm, (head)->sph_اکر) == 0) {			\
		إذا (SPLAY_کيري((head)->sph_اکر, field) == عدم) {	\
			(head)->sph_اکر = SPLAY_کانن((head)->sph_اکر, field);\
		} وإلا {						\
			__tmp = SPLAY_کانن((head)->sph_اکر, field);	\
			(head)->sph_اکر = SPLAY_کيري((head)->sph_اکر, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_کانن((head)->sph_اکر, field) = __tmp;	\
		}							\
		أرجع (elm);						\
	}								\
	أرجع (عدم);							\
}									\
									\
فراغ									\
name##_SPLAY(بنية name *head, بنية type *elm)			\
{									\
	بنية type __node, *__left, *__right, *__tmp;			\
	صحيح __comp;							\
\
	SPLAY_کيري(&__node, field) = SPLAY_کانن(&__node, field) = عدم;\
	__left = __right = &__node;					\
\
	طالما ((__comp = (cmp)(elm, (head)->sph_اکر))) {		\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_کيري((head)->sph_اکر, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_کانن(head, __tmp, field);	\
				إذا (SPLAY_کيري((head)->sph_اکر, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_کانن((head)->sph_اکر, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_کيري(head, __tmp, field);	\
				إذا (SPLAY_کانن((head)->sph_اکر, field) == عدم)\
					اكسر;				\
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
فراغ name##_SPLAY_MINMAX(بنية name *head, صحيح __comp) \
{									\
	بنية type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_کيري(&__node, field) = SPLAY_کانن(&__node, field) = عدم;\
	__left = __right = &__node;					\
\
	طالما (1) {							\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_کيري((head)->sph_اکر, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp < 0){				\
				SPLAY_ROTATE_کانن(head, __tmp, field);	\
				إذا (SPLAY_کيري((head)->sph_اکر, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_کانن((head)->sph_اکر, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp > 0) {				\
				SPLAY_ROTATE_کيري(head, __tmp, field);	\
				إذا (SPLAY_کانن((head)->sph_اکر, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_سيسيڤ(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	لكل ((x) = SPLAY_MIN(name, head);				\
	     (x) != عدم;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
بنية name {								\
	بنية type *rbh_اکر; /* root of the tree */			\
}

#define RB_INITIALIZER(اکر)						\
	{ عدم }

#define RB_INIT(اکر) افعل {						\
	(اکر)->rbh_اکر = عدم;					\
} طالما (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
بنية {								\
	بنية type *rbe_کيري;		/* left element */		\
	بنية type *rbe_کانن;		/* right element */		\
	بنية type *rbe_parent;	/* parent element */		\
	صحيح rbe_color;			/* node color */		\
}

#define RB_کيري(elm, field)		(elm)->field.rbe_کيري
#define RB_کانن(elm, field)		(elm)->field.rbe_کانن
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_اکر(head)			(head)->rbh_اکر
#define RB_EMPTY(head)			(RB_اکر(head) == عدم)

#define RB_SET(elm, parent, field) افعل {					\
	RB_PARENT(elm, field) = parent;					\
	RB_کيري(elm, field) = RB_کانن(elm, field) = عدم;		\
	RB_COLOR(elm, field) = RB_RED;					\
} طالما (0)

#define RB_SET_BLACKRED(black, red, field) افعل {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} طالما (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	افعل {} طالما (0)
#endif

#define RB_ROTATE_کيري(head, elm, tmp, field) افعل {			\
	(tmp) = RB_کانن(elm, field);					\
	إذا ((RB_کانن(elm, field) = RB_کيري(tmp, field))) {		\
		RB_PARENT(RB_کيري(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		إذا ((elm) == RB_کيري(RB_PARENT(elm, field), field))	\
			RB_کيري(RB_PARENT(elm, field), field) = (tmp);	\
		وإلا							\
			RB_کانن(RB_PARENT(elm, field), field) = (tmp);	\
	} وإلا								\
		(head)->rbh_اکر = (tmp);				\
	RB_کيري(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} طالما (0)

#define RB_ROTATE_کانن(head, elm, tmp, field) افعل {			\
	(tmp) = RB_کيري(elm, field);					\
	إذا ((RB_کيري(elm, field) = RB_کانن(tmp, field))) {		\
		RB_PARENT(RB_کانن(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		إذا ((elm) == RB_کيري(RB_PARENT(elm, field), field))	\
			RB_کيري(RB_PARENT(elm, field), field) = (tmp);	\
		وإلا							\
			RB_کانن(RB_PARENT(elm, field), field) = (tmp);	\
	} وإلا								\
		(head)->rbh_اکر = (tmp);				\
	RB_کانن(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} طالما (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) ساكن)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
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
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) ساكن)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr فراغ								\
name##_RB_INSERT_COLOR(بنية name *head, بنية type *elm)		\
{									\
	بنية type *parent, *gparent, *tmp;				\
	طالما ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		إذا (parent == RB_کيري(gparent, field)) {		\
			tmp = RB_کانن(gparent, field);			\
			إذا (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_کانن(parent, field) == elm) {		\
				RB_ROTATE_کيري(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_کانن(head, gparent, tmp, field);	\
		} وإلا {						\
			tmp = RB_کيري(gparent, field);			\
			إذا (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_کيري(parent, field) == elm) {		\
				RB_ROTATE_کانن(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_کيري(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_اکر, field) = RB_BLACK;			\
}									\
									\
attr فراغ								\
name##_RB_REMOVE_COLOR(بنية name *head, بنية type *parent, بنية type *elm) \
{									\
	بنية type *tmp;						\
	طالما ((elm == عدم || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_اکر(head)) {					\
		إذا (RB_کيري(parent, field) == elm) {			\
			tmp = RB_کانن(parent, field);			\
			إذا (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_کيري(head, parent, tmp, field);\
				tmp = RB_کانن(parent, field);		\
			}						\
			إذا ((RB_کيري(tmp, field) == عدم ||		\
			    RB_COLOR(RB_کيري(tmp, field), field) == RB_BLACK) &&\
			    (RB_کانن(tmp, field) == عدم ||		\
			    RB_COLOR(RB_کانن(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} وإلا {					\
				إذا (RB_کانن(tmp, field) == عدم ||	\
				    RB_COLOR(RB_کانن(tmp, field), field) == RB_BLACK) {\
					بنية type *oleft;		\
					إذا ((oleft = RB_کيري(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_کانن(head, tmp, oleft, field);\
					tmp = RB_کانن(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				إذا (RB_کانن(tmp, field))		\
					RB_COLOR(RB_کانن(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_کيري(head, parent, tmp, field);\
				elm = RB_اکر(head);			\
				اكسر;					\
			}						\
		} وإلا {						\
			tmp = RB_کيري(parent, field);			\
			إذا (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_کانن(head, parent, tmp, field);\
				tmp = RB_کيري(parent, field);		\
			}						\
			إذا ((RB_کيري(tmp, field) == عدم ||		\
			    RB_COLOR(RB_کيري(tmp, field), field) == RB_BLACK) &&\
			    (RB_کانن(tmp, field) == عدم ||		\
			    RB_COLOR(RB_کانن(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} وإلا {					\
				إذا (RB_کيري(tmp, field) == عدم ||	\
				    RB_COLOR(RB_کيري(tmp, field), field) == RB_BLACK) {\
					بنية type *oright;		\
					إذا ((oright = RB_کانن(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_کيري(head, tmp, oright, field);\
					tmp = RB_کيري(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				إذا (RB_کيري(tmp, field))		\
					RB_COLOR(RB_کيري(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_کانن(head, parent, tmp, field);\
				elm = RB_اکر(head);			\
				اكسر;					\
			}						\
		}							\
	}								\
	إذا (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr بنية type *							\
name##_RB_REMOVE(بنية name *head, بنية type *elm)			\
{									\
	بنية type *child, *parent, *old = elm;			\
	صحيح color;							\
	إذا (RB_کيري(elm, field) == عدم)				\
		child = RB_کانن(elm, field);				\
	وإلا إذا (RB_کانن(elm, field) == عدم)				\
		child = RB_کيري(elm, field);				\
	وإلا {								\
		بنية type *کيري;					\
		elm = RB_کانن(elm, field);				\
		طالما ((کيري = RB_کيري(elm, field)))			\
			elm = کيري;					\
		child = RB_کانن(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		إذا (child)						\
			RB_PARENT(child, field) = parent;		\
		إذا (parent) {						\
			إذا (RB_کيري(parent, field) == elm)		\
				RB_کيري(parent, field) = child;		\
			وإلا						\
				RB_کانن(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} وإلا							\
			RB_اکر(head) = child;				\
		إذا (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		إذا (RB_PARENT(old, field)) {				\
			إذا (RB_کيري(RB_PARENT(old, field), field) == old)\
				RB_کيري(RB_PARENT(old, field), field) = elm;\
			وإلا						\
				RB_کانن(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} وإلا							\
			RB_اکر(head) = elm;				\
		RB_PARENT(RB_کيري(old, field), field) = elm;		\
		إذا (RB_کانن(old, field))				\
			RB_PARENT(RB_کانن(old, field), field) = elm;	\
		إذا (parent) {						\
			کيري = parent;					\
			افعل {						\
				RB_AUGMENT(کيري);			\
			} طالما ((کيري = RB_PARENT(کيري, field)));	\
		}							\
		اذهب color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	إذا (child)							\
		RB_PARENT(child, field) = parent;			\
	إذا (parent) {							\
		إذا (RB_کيري(parent, field) == elm)			\
			RB_کيري(parent, field) = child;			\
		وإلا							\
			RB_کانن(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} وإلا								\
		RB_اکر(head) = child;					\
color:									\
	إذا (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	أرجع (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr بنية type *							\
name##_RB_INSERT(بنية name *head, بنية type *elm)			\
{									\
	بنية type *tmp;						\
	بنية type *parent = عدم;					\
	صحيح comp = 0;							\
	tmp = RB_اکر(head);						\
	طالما (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		إذا (comp < 0)						\
			tmp = RB_کيري(tmp, field);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_کانن(tmp, field);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	إذا (parent != عدم) {						\
		إذا (comp < 0)						\
			RB_کيري(parent, field) = elm;			\
		وإلا							\
			RB_کانن(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} وإلا								\
		RB_اکر(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	أرجع (عدم);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr بنية type *							\
name##_RB_FIND(بنية name *head, بنية type *elm)			\
{									\
	بنية type *tmp = RB_اکر(head);				\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0)						\
			tmp = RB_کيري(tmp, field);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_کانن(tmp, field);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	أرجع (عدم);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr بنية type *							\
name##_RB_NFIND(بنية name *head, بنية type *elm)			\
{									\
	بنية type *tmp = RB_اکر(head);				\
	بنية type *res = عدم;					\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0) {						\
			res = tmp;					\
			tmp = RB_کيري(tmp, field);			\
		}							\
		وإلا إذا (comp > 0)					\
			tmp = RB_کانن(tmp, field);			\
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
	إذا (RB_کانن(elm, field)) {					\
		elm = RB_کانن(elm, field);				\
		طالما (RB_کيري(elm, field))				\
			elm = RB_کيري(elm, field);			\
	} وإلا {							\
		إذا (RB_PARENT(elm, field) &&				\
		    (elm == RB_کيري(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		وإلا {							\
			طالما (RB_PARENT(elm, field) &&			\
			    (elm == RB_کانن(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
/* ARGSUSED */								\
attr بنية type *							\
name##_RB_PREV(بنية type *elm)					\
{									\
	إذا (RB_کيري(elm, field)) {					\
		elm = RB_کيري(elm, field);				\
		طالما (RB_کانن(elm, field))				\
			elm = RB_کانن(elm, field);			\
	} وإلا {							\
		إذا (RB_PARENT(elm, field) &&				\
		    (elm == RB_کانن(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		وإلا {							\
			طالما (RB_PARENT(elm, field) &&			\
			    (elm == RB_کيري(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	أرجع (elm);							\
}									\
									\
attr بنية type *							\
name##_RB_MINMAX(بنية name *head, صحيح val)				\
{									\
	بنية type *tmp = RB_اکر(head);				\
	بنية type *parent = عدم;					\
	طالما (tmp) {							\
		parent = tmp;						\
		إذا (val < 0)						\
			tmp = RB_کيري(tmp, field);			\
		وإلا							\
			tmp = RB_کانن(tmp, field);			\
	}								\
	أرجع (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_سيسيڤ(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	لكل ((x) = RB_MIN(name, head);					\
	     (x) != عدم;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	لكل ((x) = RB_MIN(name, head);					\
	    ((x) != عدم) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	لكل ((x) = RB_MAX(name, head);					\
	     (x) != عدم;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	لكل ((x) = RB_MAX(name, head);					\
	    ((x) != عدم) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
