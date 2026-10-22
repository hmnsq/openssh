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
بنية name {								\
	بنية type *sph_جڑ; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(جڑ)						\
	{ عدم }

#define SPLAY_INIT(جڑ) افعل {						\
	(جڑ)->sph_جڑ = عدم;					\
} طالما (0)

#define SPLAY_ENTRY(type)						\
بنية {								\
	بنية type *spe_بایاں; /* left element */			\
	بنية type *spe_دایاں; /* right element */			\
}

#define SPLAY_بایاں(elm, field)		(elm)->field.spe_بایاں
#define SPLAY_دایاں(elm, field)		(elm)->field.spe_دایاں
#define SPLAY_جڑ(head)		(head)->sph_جڑ
#define SPLAY_EMPTY(head)		(SPLAY_جڑ(head) == عدم)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_دایاں(head, tmp, field) افعل {			\
	SPLAY_بایاں((head)->sph_جڑ, field) = SPLAY_دایاں(tmp, field);	\
	SPLAY_دایاں(tmp, field) = (head)->sph_جڑ;			\
	(head)->sph_جڑ = tmp;						\
} طالما (0)
	
#define SPLAY_ROTATE_بایاں(head, tmp, field) افعل {			\
	SPLAY_دایاں((head)->sph_جڑ, field) = SPLAY_بایاں(tmp, field);	\
	SPLAY_بایاں(tmp, field) = (head)->sph_جڑ;			\
	(head)->sph_جڑ = tmp;						\
} طالما (0)

#define SPLAY_LINKLEFT(head, tmp, field) افعل {				\
	SPLAY_بایاں(tmp, field) = (head)->sph_جڑ;			\
	tmp = (head)->sph_جڑ;						\
	(head)->sph_جڑ = SPLAY_بایاں((head)->sph_جڑ, field);		\
} طالما (0)

#define SPLAY_LINKRIGHT(head, tmp, field) افعل {				\
	SPLAY_دایاں(tmp, field) = (head)->sph_جڑ;			\
	tmp = (head)->sph_جڑ;						\
	(head)->sph_جڑ = SPLAY_دایاں((head)->sph_جڑ, field);	\
} طالما (0)

#define SPLAY_ASSEMBLE(head, گرہ, بایاں, دایاں, field) افعل {		\
	SPLAY_دایاں(بایاں, field) = SPLAY_بایاں((head)->sph_جڑ, field);	\
	SPLAY_بایاں(دایاں, field) = SPLAY_دایاں((head)->sph_جڑ, field);\
	SPLAY_بایاں((head)->sph_جڑ, field) = SPLAY_دایاں(گرہ, field);	\
	SPLAY_دایاں((head)->sph_جڑ, field) = SPLAY_بایاں(گرہ, field);	\
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
	إذا ((cmp)(elm, (head)->sph_جڑ) == 0)				\
		أرجع (head->sph_جڑ);				\
	أرجع (عدم);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_NEXT(بنية name *head, بنية type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	إذا (SPLAY_دایاں(elm, field) != عدم) {				\
		elm = SPLAY_دایاں(elm, field);				\
		طالما (SPLAY_بایاں(elm, field) != عدم) {		\
			elm = SPLAY_بایاں(elm, field);			\
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
        أرجع (SPLAY_جڑ(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
بنية type *								\
name##_SPLAY_INSERT(بنية name *head, بنية type *elm)		\
{									\
    إذا (SPLAY_EMPTY(head)) {						\
	    SPLAY_بایاں(elm, field) = SPLAY_دایاں(elm, field) = عدم;	\
    } وإلا {								\
	    صحيح __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_جڑ);			\
	    إذا(__comp < 0) {						\
		    SPLAY_بایاں(elm, field) = SPLAY_بایاں((head)->sph_جڑ, field);\
		    SPLAY_دایاں(elm, field) = (head)->sph_جڑ;		\
		    SPLAY_بایاں((head)->sph_جڑ, field) = عدم;		\
	    } وإلا إذا (__comp > 0) {					\
		    SPLAY_دایاں(elm, field) = SPLAY_دایاں((head)->sph_جڑ, field);\
		    SPLAY_بایاں(elm, field) = (head)->sph_جڑ;		\
		    SPLAY_دایاں((head)->sph_جڑ, field) = عدم;	\
	    } وإلا							\
		    أرجع ((head)->sph_جڑ);				\
    }									\
    (head)->sph_جڑ = (elm);						\
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
	إذا ((cmp)(elm, (head)->sph_جڑ) == 0) {			\
		إذا (SPLAY_بایاں((head)->sph_جڑ, field) == عدم) {	\
			(head)->sph_جڑ = SPLAY_دایاں((head)->sph_جڑ, field);\
		} وإلا {						\
			__tmp = SPLAY_دایاں((head)->sph_جڑ, field);	\
			(head)->sph_جڑ = SPLAY_بایاں((head)->sph_جڑ, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_دایاں((head)->sph_جڑ, field) = __tmp;	\
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
	SPLAY_بایاں(&__node, field) = SPLAY_دایاں(&__node, field) = عدم;\
	__left = __right = &__node;					\
\
	طالما ((__comp = (cmp)(elm, (head)->sph_جڑ))) {		\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_بایاں((head)->sph_جڑ, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_دایاں(head, __tmp, field);	\
				إذا (SPLAY_بایاں((head)->sph_جڑ, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_دایاں((head)->sph_جڑ, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_بایاں(head, __tmp, field);	\
				إذا (SPLAY_دایاں((head)->sph_جڑ, field) == عدم)\
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
	SPLAY_بایاں(&__node, field) = SPLAY_دایاں(&__node, field) = عدم;\
	__left = __right = &__node;					\
\
	طالما (1) {							\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_بایاں((head)->sph_جڑ, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp < 0){				\
				SPLAY_ROTATE_دایاں(head, __tmp, field);	\
				إذا (SPLAY_بایاں((head)->sph_جڑ, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_دایاں((head)->sph_جڑ, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp > 0) {				\
				SPLAY_ROTATE_بایاں(head, __tmp, field);	\
				إذا (SPLAY_دایاں((head)->sph_جڑ, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_داخل_کرو(name, x, y)	name##_SPLAY_INSERT(x, y)
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
	بنية type *rbh_جڑ; /* root of the tree */			\
}

#define RB_INITIALIZER(جڑ)						\
	{ عدم }

#define RB_INIT(جڑ) افعل {						\
	(جڑ)->rbh_جڑ = عدم;					\
} طالما (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
بنية {								\
	بنية type *rbe_بایاں;		/* left element */		\
	بنية type *rbe_دایاں;		/* right element */		\
	بنية type *rbe_parent;	/* parent element */		\
	صحيح rbe_color;			/* node color */		\
}

#define RB_بایاں(elm, field)		(elm)->field.rbe_بایاں
#define RB_دایاں(elm, field)		(elm)->field.rbe_دایاں
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_جڑ(head)			(head)->rbh_جڑ
#define RB_EMPTY(head)			(RB_جڑ(head) == عدم)

#define RB_SET(elm, parent, field) افعل {					\
	RB_PARENT(elm, field) = parent;					\
	RB_بایاں(elm, field) = RB_دایاں(elm, field) = عدم;		\
	RB_COLOR(elm, field) = RB_RED;					\
} طالما (0)

#define RB_SET_BLACKRED(black, red, field) افعل {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} طالما (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	افعل {} طالما (0)
#endif

#define RB_ROTATE_بایاں(head, elm, tmp, field) افعل {			\
	(tmp) = RB_دایاں(elm, field);					\
	إذا ((RB_دایاں(elm, field) = RB_بایاں(tmp, field))) {		\
		RB_PARENT(RB_بایاں(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		إذا ((elm) == RB_بایاں(RB_PARENT(elm, field), field))	\
			RB_بایاں(RB_PARENT(elm, field), field) = (tmp);	\
		وإلا							\
			RB_دایاں(RB_PARENT(elm, field), field) = (tmp);	\
	} وإلا								\
		(head)->rbh_جڑ = (tmp);				\
	RB_بایاں(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} طالما (0)

#define RB_ROTATE_دایاں(head, elm, tmp, field) افعل {			\
	(tmp) = RB_بایاں(elm, field);					\
	إذا ((RB_بایاں(elm, field) = RB_دایاں(tmp, field))) {		\
		RB_PARENT(RB_دایاں(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		إذا ((elm) == RB_بایاں(RB_PARENT(elm, field), field))	\
			RB_بایاں(RB_PARENT(elm, field), field) = (tmp);	\
		وإلا							\
			RB_دایاں(RB_PARENT(elm, field), field) = (tmp);	\
	} وإلا								\
		(head)->rbh_جڑ = (tmp);				\
	RB_دایاں(tmp, field) = (elm);					\
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
		إذا (parent == RB_بایاں(gparent, field)) {		\
			tmp = RB_دایاں(gparent, field);			\
			إذا (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_دایاں(parent, field) == elm) {		\
				RB_ROTATE_بایاں(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_دایاں(head, gparent, tmp, field);	\
		} وإلا {						\
			tmp = RB_بایاں(gparent, field);			\
			إذا (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_بایاں(parent, field) == elm) {		\
				RB_ROTATE_دایاں(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_بایاں(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_جڑ, field) = RB_BLACK;			\
}									\
									\
attr فراغ								\
name##_RB_REMOVE_COLOR(بنية name *head, بنية type *parent, بنية type *elm) \
{									\
	بنية type *tmp;						\
	طالما ((elm == عدم || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_جڑ(head)) {					\
		إذا (RB_بایاں(parent, field) == elm) {			\
			tmp = RB_دایاں(parent, field);			\
			إذا (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_بایاں(head, parent, tmp, field);\
				tmp = RB_دایاں(parent, field);		\
			}						\
			إذا ((RB_بایاں(tmp, field) == عدم ||		\
			    RB_COLOR(RB_بایاں(tmp, field), field) == RB_BLACK) &&\
			    (RB_دایاں(tmp, field) == عدم ||		\
			    RB_COLOR(RB_دایاں(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} وإلا {					\
				إذا (RB_دایاں(tmp, field) == عدم ||	\
				    RB_COLOR(RB_دایاں(tmp, field), field) == RB_BLACK) {\
					بنية type *oleft;		\
					إذا ((oleft = RB_بایاں(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_دایاں(head, tmp, oleft, field);\
					tmp = RB_دایاں(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				إذا (RB_دایاں(tmp, field))		\
					RB_COLOR(RB_دایاں(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_بایاں(head, parent, tmp, field);\
				elm = RB_جڑ(head);			\
				اكسر;					\
			}						\
		} وإلا {						\
			tmp = RB_بایاں(parent, field);			\
			إذا (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_دایاں(head, parent, tmp, field);\
				tmp = RB_بایاں(parent, field);		\
			}						\
			إذا ((RB_بایاں(tmp, field) == عدم ||		\
			    RB_COLOR(RB_بایاں(tmp, field), field) == RB_BLACK) &&\
			    (RB_دایاں(tmp, field) == عدم ||		\
			    RB_COLOR(RB_دایاں(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} وإلا {					\
				إذا (RB_بایاں(tmp, field) == عدم ||	\
				    RB_COLOR(RB_بایاں(tmp, field), field) == RB_BLACK) {\
					بنية type *oright;		\
					إذا ((oright = RB_دایاں(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_بایاں(head, tmp, oright, field);\
					tmp = RB_بایاں(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				إذا (RB_بایاں(tmp, field))		\
					RB_COLOR(RB_بایاں(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_دایاں(head, parent, tmp, field);\
				elm = RB_جڑ(head);			\
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
	إذا (RB_بایاں(elm, field) == عدم)				\
		child = RB_دایاں(elm, field);				\
	وإلا إذا (RB_دایاں(elm, field) == عدم)				\
		child = RB_بایاں(elm, field);				\
	وإلا {								\
		بنية type *بایاں;					\
		elm = RB_دایاں(elm, field);				\
		طالما ((بایاں = RB_بایاں(elm, field)))			\
			elm = بایاں;					\
		child = RB_دایاں(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		إذا (child)						\
			RB_PARENT(child, field) = parent;		\
		إذا (parent) {						\
			إذا (RB_بایاں(parent, field) == elm)		\
				RB_بایاں(parent, field) = child;		\
			وإلا						\
				RB_دایاں(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} وإلا							\
			RB_جڑ(head) = child;				\
		إذا (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		إذا (RB_PARENT(old, field)) {				\
			إذا (RB_بایاں(RB_PARENT(old, field), field) == old)\
				RB_بایاں(RB_PARENT(old, field), field) = elm;\
			وإلا						\
				RB_دایاں(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} وإلا							\
			RB_جڑ(head) = elm;				\
		RB_PARENT(RB_بایاں(old, field), field) = elm;		\
		إذا (RB_دایاں(old, field))				\
			RB_PARENT(RB_دایاں(old, field), field) = elm;	\
		إذا (parent) {						\
			بایاں = parent;					\
			افعل {						\
				RB_AUGMENT(بایاں);			\
			} طالما ((بایاں = RB_PARENT(بایاں, field)));	\
		}							\
		اذهب color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	إذا (child)							\
		RB_PARENT(child, field) = parent;			\
	إذا (parent) {							\
		إذا (RB_بایاں(parent, field) == elm)			\
			RB_بایاں(parent, field) = child;			\
		وإلا							\
			RB_دایاں(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} وإلا								\
		RB_جڑ(head) = child;					\
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
	tmp = RB_جڑ(head);						\
	طالما (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		إذا (comp < 0)						\
			tmp = RB_بایاں(tmp, field);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_دایاں(tmp, field);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	إذا (parent != عدم) {						\
		إذا (comp < 0)						\
			RB_بایاں(parent, field) = elm;			\
		وإلا							\
			RB_دایاں(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} وإلا								\
		RB_جڑ(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	أرجع (عدم);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr بنية type *							\
name##_RB_FIND(بنية name *head, بنية type *elm)			\
{									\
	بنية type *tmp = RB_جڑ(head);				\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0)						\
			tmp = RB_بایاں(tmp, field);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_دایاں(tmp, field);			\
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
	بنية type *tmp = RB_جڑ(head);				\
	بنية type *res = عدم;					\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0) {						\
			res = tmp;					\
			tmp = RB_بایاں(tmp, field);			\
		}							\
		وإلا إذا (comp > 0)					\
			tmp = RB_دایاں(tmp, field);			\
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
	إذا (RB_دایاں(elm, field)) {					\
		elm = RB_دایاں(elm, field);				\
		طالما (RB_بایاں(elm, field))				\
			elm = RB_بایاں(elm, field);			\
	} وإلا {							\
		إذا (RB_PARENT(elm, field) &&				\
		    (elm == RB_بایاں(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		وإلا {							\
			طالما (RB_PARENT(elm, field) &&			\
			    (elm == RB_دایاں(RB_PARENT(elm, field), field)))\
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
	إذا (RB_بایاں(elm, field)) {					\
		elm = RB_بایاں(elm, field);				\
		طالما (RB_دایاں(elm, field))				\
			elm = RB_دایاں(elm, field);			\
	} وإلا {							\
		إذا (RB_PARENT(elm, field) &&				\
		    (elm == RB_دایاں(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		وإلا {							\
			طالما (RB_PARENT(elm, field) &&			\
			    (elm == RB_بایاں(RB_PARENT(elm, field), field)))\
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
	بنية type *tmp = RB_جڑ(head);				\
	بنية type *parent = عدم;					\
	طالما (tmp) {							\
		parent = tmp;						\
		إذا (val < 0)						\
			tmp = RB_بایاں(tmp, field);			\
		وإلا							\
			tmp = RB_دایاں(tmp, field);			\
	}								\
	أرجع (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_داخل_کرو(name, x, y)	name##_RB_INSERT(x, y)
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
