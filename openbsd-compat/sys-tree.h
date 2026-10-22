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

#ifndef	SYS_دەرەخ_H
#define	SYS_دەرەخ_H

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
	بنية type *sph_يىلتىز; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(يىلتىز)						\
	{ عدم }

#define SPLAY_INIT(يىلتىز) افعل {						\
	(يىلتىز)->sph_يىلتىز = عدم;					\
} طالما (0)

#define SPLAY_ENTRY(type)						\
بنية {								\
	بنية type *spe_سول; /* left element */			\
	بنية type *spe_ئوڭ; /* right element */			\
}

#define SPLAY_سول(elm, field)		(elm)->field.spe_سول
#define SPLAY_ئوڭ(elm, field)		(elm)->field.spe_ئوڭ
#define SPLAY_يىلتىز(head)		(head)->sph_يىلتىز
#define SPLAY_EMPTY(head)		(SPLAY_يىلتىز(head) == عدم)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_ئوڭ(head, tmp, field) افعل {			\
	SPLAY_سول((head)->sph_يىلتىز, field) = SPLAY_ئوڭ(tmp, field);	\
	SPLAY_ئوڭ(tmp, field) = (head)->sph_يىلتىز;			\
	(head)->sph_يىلتىز = tmp;						\
} طالما (0)
	
#define SPLAY_ROTATE_سول(head, tmp, field) افعل {			\
	SPLAY_ئوڭ((head)->sph_يىلتىز, field) = SPLAY_سول(tmp, field);	\
	SPLAY_سول(tmp, field) = (head)->sph_يىلتىز;			\
	(head)->sph_يىلتىز = tmp;						\
} طالما (0)

#define SPLAY_LINKLEFT(head, tmp, field) افعل {				\
	SPLAY_سول(tmp, field) = (head)->sph_يىلتىز;			\
	tmp = (head)->sph_يىلتىز;						\
	(head)->sph_يىلتىز = SPLAY_سول((head)->sph_يىلتىز, field);		\
} طالما (0)

#define SPLAY_LINKRIGHT(head, tmp, field) افعل {				\
	SPLAY_ئوڭ(tmp, field) = (head)->sph_يىلتىز;			\
	tmp = (head)->sph_يىلتىز;						\
	(head)->sph_يىلتىز = SPLAY_ئوڭ((head)->sph_يىلتىز, field);	\
} طالما (0)

#define SPLAY_ASSEMBLE(head, تۈگۈن, سول, ئوڭ, field) افعل {		\
	SPLAY_ئوڭ(سول, field) = SPLAY_سول((head)->sph_يىلتىز, field);	\
	SPLAY_سول(ئوڭ, field) = SPLAY_ئوڭ((head)->sph_يىلتىز, field);\
	SPLAY_سول((head)->sph_يىلتىز, field) = SPLAY_ئوڭ(تۈگۈن, field);	\
	SPLAY_ئوڭ((head)->sph_يىلتىز, field) = SPLAY_سول(تۈگۈن, field);	\
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
	إذا ((cmp)(elm, (head)->sph_يىلتىز) == 0)				\
		أرجع (head->sph_يىلتىز);				\
	أرجع (عدم);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_NEXT(بنية name *head, بنية type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	إذا (SPLAY_ئوڭ(elm, field) != عدم) {				\
		elm = SPLAY_ئوڭ(elm, field);				\
		طالما (SPLAY_سول(elm, field) != عدم) {		\
			elm = SPLAY_سول(elm, field);			\
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
        أرجع (SPLAY_يىلتىز(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
بنية type *								\
name##_SPLAY_INSERT(بنية name *head, بنية type *elm)		\
{									\
    إذا (SPLAY_EMPTY(head)) {						\
	    SPLAY_سول(elm, field) = SPLAY_ئوڭ(elm, field) = عدم;	\
    } وإلا {								\
	    صحيح __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_يىلتىز);			\
	    إذا(__comp < 0) {						\
		    SPLAY_سول(elm, field) = SPLAY_سول((head)->sph_يىلتىز, field);\
		    SPLAY_ئوڭ(elm, field) = (head)->sph_يىلتىز;		\
		    SPLAY_سول((head)->sph_يىلتىز, field) = عدم;		\
	    } وإلا إذا (__comp > 0) {					\
		    SPLAY_ئوڭ(elm, field) = SPLAY_ئوڭ((head)->sph_يىلتىز, field);\
		    SPLAY_سول(elm, field) = (head)->sph_يىلتىز;		\
		    SPLAY_ئوڭ((head)->sph_يىلتىز, field) = عدم;	\
	    } وإلا							\
		    أرجع ((head)->sph_يىلتىز);				\
    }									\
    (head)->sph_يىلتىز = (elm);						\
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
	إذا ((cmp)(elm, (head)->sph_يىلتىز) == 0) {			\
		إذا (SPLAY_سول((head)->sph_يىلتىز, field) == عدم) {	\
			(head)->sph_يىلتىز = SPLAY_ئوڭ((head)->sph_يىلتىز, field);\
		} وإلا {						\
			__tmp = SPLAY_ئوڭ((head)->sph_يىلتىز, field);	\
			(head)->sph_يىلتىز = SPLAY_سول((head)->sph_يىلتىز, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_ئوڭ((head)->sph_يىلتىز, field) = __tmp;	\
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
	SPLAY_سول(&__node, field) = SPLAY_ئوڭ(&__node, field) = عدم;\
	__left = __right = &__node;					\
\
	طالما ((__comp = (cmp)(elm, (head)->sph_يىلتىز))) {		\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_سول((head)->sph_يىلتىز, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_ئوڭ(head, __tmp, field);	\
				إذا (SPLAY_سول((head)->sph_يىلتىز, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_ئوڭ((head)->sph_يىلتىز, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_سول(head, __tmp, field);	\
				إذا (SPLAY_ئوڭ((head)->sph_يىلتىز, field) == عدم)\
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
	SPLAY_سول(&__node, field) = SPLAY_ئوڭ(&__node, field) = عدم;\
	__left = __right = &__node;					\
\
	طالما (1) {							\
		إذا (__comp < 0) {					\
			__tmp = SPLAY_سول((head)->sph_يىلتىز, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp < 0){				\
				SPLAY_ROTATE_ئوڭ(head, __tmp, field);	\
				إذا (SPLAY_سول((head)->sph_يىلتىز, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} وإلا إذا (__comp > 0) {				\
			__tmp = SPLAY_ئوڭ((head)->sph_يىلتىز, field);	\
			إذا (__tmp == عدم)				\
				اكسر;					\
			إذا (__comp > 0) {				\
				SPLAY_ROTATE_سول(head, __tmp, field);	\
				إذا (SPLAY_ئوڭ((head)->sph_يىلتىز, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_قىستۇرۇش(name, x, y)	name##_SPLAY_INSERT(x, y)
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
	بنية type *rbh_يىلتىز; /* root of the tree */			\
}

#define RB_INITIALIZER(يىلتىز)						\
	{ عدم }

#define RB_INIT(يىلتىز) افعل {						\
	(يىلتىز)->rbh_يىلتىز = عدم;					\
} طالما (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
بنية {								\
	بنية type *rbe_سول;		/* left element */		\
	بنية type *rbe_ئوڭ;		/* right element */		\
	بنية type *rbe_parent;	/* parent element */		\
	صحيح rbe_color;			/* node color */		\
}

#define RB_سول(elm, field)		(elm)->field.rbe_سول
#define RB_ئوڭ(elm, field)		(elm)->field.rbe_ئوڭ
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_يىلتىز(head)			(head)->rbh_يىلتىز
#define RB_EMPTY(head)			(RB_يىلتىز(head) == عدم)

#define RB_SET(elm, parent, field) افعل {					\
	RB_PARENT(elm, field) = parent;					\
	RB_سول(elm, field) = RB_ئوڭ(elm, field) = عدم;		\
	RB_COLOR(elm, field) = RB_RED;					\
} طالما (0)

#define RB_SET_BLACKRED(black, red, field) افعل {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} طالما (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	افعل {} طالما (0)
#endif

#define RB_ROTATE_سول(head, elm, tmp, field) افعل {			\
	(tmp) = RB_ئوڭ(elm, field);					\
	إذا ((RB_ئوڭ(elm, field) = RB_سول(tmp, field))) {		\
		RB_PARENT(RB_سول(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		إذا ((elm) == RB_سول(RB_PARENT(elm, field), field))	\
			RB_سول(RB_PARENT(elm, field), field) = (tmp);	\
		وإلا							\
			RB_ئوڭ(RB_PARENT(elm, field), field) = (tmp);	\
	} وإلا								\
		(head)->rbh_يىلتىز = (tmp);				\
	RB_سول(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	إذا ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} طالما (0)

#define RB_ROTATE_ئوڭ(head, elm, tmp, field) افعل {			\
	(tmp) = RB_سول(elm, field);					\
	إذا ((RB_سول(elm, field) = RB_ئوڭ(tmp, field))) {		\
		RB_PARENT(RB_ئوڭ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	إذا ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		إذا ((elm) == RB_سول(RB_PARENT(elm, field), field))	\
			RB_سول(RB_PARENT(elm, field), field) = (tmp);	\
		وإلا							\
			RB_ئوڭ(RB_PARENT(elm, field), field) = (tmp);	\
	} وإلا								\
		(head)->rbh_يىلتىز = (tmp);				\
	RB_ئوڭ(tmp, field) = (elm);					\
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
		إذا (parent == RB_سول(gparent, field)) {		\
			tmp = RB_ئوڭ(gparent, field);			\
			إذا (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_ئوڭ(parent, field) == elm) {		\
				RB_ROTATE_سول(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_ئوڭ(head, gparent, tmp, field);	\
		} وإلا {						\
			tmp = RB_سول(gparent, field);			\
			إذا (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				استمر;				\
			}						\
			إذا (RB_سول(parent, field) == elm) {		\
				RB_ROTATE_ئوڭ(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_سول(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_يىلتىز, field) = RB_BLACK;			\
}									\
									\
attr فراغ								\
name##_RB_REMOVE_COLOR(بنية name *head, بنية type *parent, بنية type *elm) \
{									\
	بنية type *tmp;						\
	طالما ((elm == عدم || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_يىلتىز(head)) {					\
		إذا (RB_سول(parent, field) == elm) {			\
			tmp = RB_ئوڭ(parent, field);			\
			إذا (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_سول(head, parent, tmp, field);\
				tmp = RB_ئوڭ(parent, field);		\
			}						\
			إذا ((RB_سول(tmp, field) == عدم ||		\
			    RB_COLOR(RB_سول(tmp, field), field) == RB_BLACK) &&\
			    (RB_ئوڭ(tmp, field) == عدم ||		\
			    RB_COLOR(RB_ئوڭ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} وإلا {					\
				إذا (RB_ئوڭ(tmp, field) == عدم ||	\
				    RB_COLOR(RB_ئوڭ(tmp, field), field) == RB_BLACK) {\
					بنية type *oleft;		\
					إذا ((oleft = RB_سول(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_ئوڭ(head, tmp, oleft, field);\
					tmp = RB_ئوڭ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				إذا (RB_ئوڭ(tmp, field))		\
					RB_COLOR(RB_ئوڭ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_سول(head, parent, tmp, field);\
				elm = RB_يىلتىز(head);			\
				اكسر;					\
			}						\
		} وإلا {						\
			tmp = RB_سول(parent, field);			\
			إذا (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_ئوڭ(head, parent, tmp, field);\
				tmp = RB_سول(parent, field);		\
			}						\
			إذا ((RB_سول(tmp, field) == عدم ||		\
			    RB_COLOR(RB_سول(tmp, field), field) == RB_BLACK) &&\
			    (RB_ئوڭ(tmp, field) == عدم ||		\
			    RB_COLOR(RB_ئوڭ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} وإلا {					\
				إذا (RB_سول(tmp, field) == عدم ||	\
				    RB_COLOR(RB_سول(tmp, field), field) == RB_BLACK) {\
					بنية type *oright;		\
					إذا ((oright = RB_ئوڭ(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_سول(head, tmp, oright, field);\
					tmp = RB_سول(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				إذا (RB_سول(tmp, field))		\
					RB_COLOR(RB_سول(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_ئوڭ(head, parent, tmp, field);\
				elm = RB_يىلتىز(head);			\
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
	إذا (RB_سول(elm, field) == عدم)				\
		child = RB_ئوڭ(elm, field);				\
	وإلا إذا (RB_ئوڭ(elm, field) == عدم)				\
		child = RB_سول(elm, field);				\
	وإلا {								\
		بنية type *سول;					\
		elm = RB_ئوڭ(elm, field);				\
		طالما ((سول = RB_سول(elm, field)))			\
			elm = سول;					\
		child = RB_ئوڭ(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		إذا (child)						\
			RB_PARENT(child, field) = parent;		\
		إذا (parent) {						\
			إذا (RB_سول(parent, field) == elm)		\
				RB_سول(parent, field) = child;		\
			وإلا						\
				RB_ئوڭ(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} وإلا							\
			RB_يىلتىز(head) = child;				\
		إذا (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		إذا (RB_PARENT(old, field)) {				\
			إذا (RB_سول(RB_PARENT(old, field), field) == old)\
				RB_سول(RB_PARENT(old, field), field) = elm;\
			وإلا						\
				RB_ئوڭ(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} وإلا							\
			RB_يىلتىز(head) = elm;				\
		RB_PARENT(RB_سول(old, field), field) = elm;		\
		إذا (RB_ئوڭ(old, field))				\
			RB_PARENT(RB_ئوڭ(old, field), field) = elm;	\
		إذا (parent) {						\
			سول = parent;					\
			افعل {						\
				RB_AUGMENT(سول);			\
			} طالما ((سول = RB_PARENT(سول, field)));	\
		}							\
		اذهب color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	إذا (child)							\
		RB_PARENT(child, field) = parent;			\
	إذا (parent) {							\
		إذا (RB_سول(parent, field) == elm)			\
			RB_سول(parent, field) = child;			\
		وإلا							\
			RB_ئوڭ(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} وإلا								\
		RB_يىلتىز(head) = child;					\
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
	tmp = RB_يىلتىز(head);						\
	طالما (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		إذا (comp < 0)						\
			tmp = RB_سول(tmp, field);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_ئوڭ(tmp, field);			\
		وإلا							\
			أرجع (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	إذا (parent != عدم) {						\
		إذا (comp < 0)						\
			RB_سول(parent, field) = elm;			\
		وإلا							\
			RB_ئوڭ(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} وإلا								\
		RB_يىلتىز(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	أرجع (عدم);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr بنية type *							\
name##_RB_FIND(بنية name *head, بنية type *elm)			\
{									\
	بنية type *tmp = RB_يىلتىز(head);				\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0)						\
			tmp = RB_سول(tmp, field);			\
		وإلا إذا (comp > 0)					\
			tmp = RB_ئوڭ(tmp, field);			\
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
	بنية type *tmp = RB_يىلتىز(head);				\
	بنية type *res = عدم;					\
	صحيح comp;							\
	طالما (tmp) {							\
		comp = cmp(elm, tmp);					\
		إذا (comp < 0) {						\
			res = tmp;					\
			tmp = RB_سول(tmp, field);			\
		}							\
		وإلا إذا (comp > 0)					\
			tmp = RB_ئوڭ(tmp, field);			\
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
	إذا (RB_ئوڭ(elm, field)) {					\
		elm = RB_ئوڭ(elm, field);				\
		طالما (RB_سول(elm, field))				\
			elm = RB_سول(elm, field);			\
	} وإلا {							\
		إذا (RB_PARENT(elm, field) &&				\
		    (elm == RB_سول(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		وإلا {							\
			طالما (RB_PARENT(elm, field) &&			\
			    (elm == RB_ئوڭ(RB_PARENT(elm, field), field)))\
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
	إذا (RB_سول(elm, field)) {					\
		elm = RB_سول(elm, field);				\
		طالما (RB_ئوڭ(elm, field))				\
			elm = RB_ئوڭ(elm, field);			\
	} وإلا {							\
		إذا (RB_PARENT(elm, field) &&				\
		    (elm == RB_ئوڭ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		وإلا {							\
			طالما (RB_PARENT(elm, field) &&			\
			    (elm == RB_سول(RB_PARENT(elm, field), field)))\
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
	بنية type *tmp = RB_يىلتىز(head);				\
	بنية type *parent = عدم;					\
	طالما (tmp) {							\
		parent = tmp;						\
		إذا (val < 0)						\
			tmp = RB_سول(tmp, field);			\
		وإلا							\
			tmp = RB_ئوڭ(tmp, field);			\
	}								\
	أرجع (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_قىستۇرۇش(name, x, y)	name##_RB_INSERT(x, y)
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
