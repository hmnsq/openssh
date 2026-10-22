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

#ଅନ୍ତର୍ଭାଵ "config.h"
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_ବୃକ୍ଷ_H
#define	SYS_ବୃକ୍ଷ_H

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
ସଂରଚନା name {								\
	ସଂରଚନା type *sph_ମୂଳ; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(ମୂଳ)						\
	{ ଖାଲି }

#define SPLAY_INIT(ମୂଳ) କର {						\
	(ମୂଳ)->sph_ମୂଳ = ଖାଲି;					\
} ଯେତେବେଳେ (0)

#define SPLAY_ENTRY(type)						\
ସଂରଚନା {								\
	ସଂରଚନା type *spe_ବାମ; /* left element */			\
	ସଂରଚନା type *spe_ଡାହାଣ; /* right element */			\
}

#define SPLAY_ବାମ(elm, field)		(elm)->field.spe_ବାମ
#define SPLAY_ଡାହାଣ(elm, field)		(elm)->field.spe_ଡାହାଣ
#define SPLAY_ମୂଳ(head)		(head)->sph_ମୂଳ
#define SPLAY_EMPTY(head)		(SPLAY_ମୂଳ(head) == ଖାଲି)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_ଡାହାଣ(head, tmp, field) କର {			\
	SPLAY_ବାମ((head)->sph_ମୂଳ, field) = SPLAY_ଡାହାଣ(tmp, field);	\
	SPLAY_ଡାହାଣ(tmp, field) = (head)->sph_ମୂଳ;			\
	(head)->sph_ମୂଳ = tmp;						\
} ଯେତେବେଳେ (0)
	
#define SPLAY_ROTATE_ବାମ(head, tmp, field) କର {			\
	SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field) = SPLAY_ବାମ(tmp, field);	\
	SPLAY_ବାମ(tmp, field) = (head)->sph_ମୂଳ;			\
	(head)->sph_ମୂଳ = tmp;						\
} ଯେତେବେଳେ (0)

#define SPLAY_LINKLEFT(head, tmp, field) କର {				\
	SPLAY_ବାମ(tmp, field) = (head)->sph_ମୂଳ;			\
	tmp = (head)->sph_ମୂଳ;						\
	(head)->sph_ମୂଳ = SPLAY_ବାମ((head)->sph_ମୂଳ, field);		\
} ଯେତେବେଳେ (0)

#define SPLAY_LINKRIGHT(head, tmp, field) କର {				\
	SPLAY_ଡାହାଣ(tmp, field) = (head)->sph_ମୂଳ;			\
	tmp = (head)->sph_ମୂଳ;						\
	(head)->sph_ମୂଳ = SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field);	\
} ଯେତେବେଳେ (0)

#define SPLAY_ASSEMBLE(head, ଗଣ୍ଠି, ବାମ, ଡାହାଣ, field) କର {		\
	SPLAY_ଡାହାଣ(ବାମ, field) = SPLAY_ବାମ((head)->sph_ମୂଳ, field);	\
	SPLAY_ବାମ(ଡାହାଣ, field) = SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field);\
	SPLAY_ବାମ((head)->sph_ମୂଳ, field) = SPLAY_ଡାହାଣ(ଗଣ୍ଠି, field);	\
	SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field) = SPLAY_ବାମ(ଗଣ୍ଠି, field);	\
} ଯେତେବେଳେ (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
ଶୂନ୍ୟ name##_SPLAY(ସଂରଚନା name *, ସଂରଚନା type *);			\
ଶୂନ୍ୟ name##_SPLAY_MINMAX(ସଂରଚନା name *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);				\
ସଂରଚନା type *name##_SPLAY_INSERT(ସଂରଚନା name *, ସଂରଚନା type *);		\
ସଂରଚନା type *name##_SPLAY_REMOVE(ସଂରଚନା name *, ସଂରଚନା type *);		\
									\
/* Finds the node with the same key as elm */				\
ସ୍ଥିର __inline ସଂରଚନା type *						\
name##_SPLAY_FIND(ସଂରଚନା name *head, ସଂରଚନା type *elm)			\
{									\
	ଯଦି (SPLAY_EMPTY(head))						\
		ଫେରନ୍ତୁ(ଖାଲି);						\
	name##_SPLAY(head, elm);					\
	ଯଦି ((cmp)(elm, (head)->sph_ମୂଳ) == 0)				\
		ଫେରନ୍ତୁ (head->sph_ମୂଳ);				\
	ଫେରନ୍ତୁ (ଖାଲି);							\
}									\
									\
ସ୍ଥିର __inline ସଂରଚନା type *						\
name##_SPLAY_NEXT(ସଂରଚନା name *head, ସଂରଚନା type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	ଯଦି (SPLAY_ଡାହାଣ(elm, field) != ଖାଲି) {				\
		elm = SPLAY_ଡାହାଣ(elm, field);				\
		ଯେତେବେଳେ (SPLAY_ବାମ(elm, field) != ଖାଲି) {		\
			elm = SPLAY_ବାମ(elm, field);			\
		}							\
	} ଅନ୍ୟଥା								\
		elm = ଖାଲି;						\
	ଫେରନ୍ତୁ (elm);							\
}									\
									\
ସ୍ଥିର __inline ସଂରଚନା type *						\
name##_SPLAY_MIN_MAX(ସଂରଚନା name *head, ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        ଫେରନ୍ତୁ (SPLAY_ମୂଳ(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
ସଂରଚନା type *								\
name##_SPLAY_INSERT(ସଂରଚନା name *head, ସଂରଚନା type *elm)		\
{									\
    ଯଦି (SPLAY_EMPTY(head)) {						\
	    SPLAY_ବାମ(elm, field) = SPLAY_ଡାହାଣ(elm, field) = ଖାଲି;	\
    } ଅନ୍ୟଥା {								\
	    ପୂର୍ଣ୍ଣସଂଖ୍ୟା __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_ମୂଳ);			\
	    ଯଦି(__comp < 0) {						\
		    SPLAY_ବାମ(elm, field) = SPLAY_ବାମ((head)->sph_ମୂଳ, field);\
		    SPLAY_ଡାହାଣ(elm, field) = (head)->sph_ମୂଳ;		\
		    SPLAY_ବାମ((head)->sph_ମୂଳ, field) = ଖାଲି;		\
	    } ଅନ୍ୟଥା ଯଦି (__comp > 0) {					\
		    SPLAY_ଡାହାଣ(elm, field) = SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field);\
		    SPLAY_ବାମ(elm, field) = (head)->sph_ମୂଳ;		\
		    SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field) = ଖାଲି;	\
	    } ଅନ୍ୟଥା							\
		    ଫେରନ୍ତୁ ((head)->sph_ମୂଳ);				\
    }									\
    (head)->sph_ମୂଳ = (elm);						\
    ଫେରନ୍ତୁ (ଖାଲି);							\
}									\
									\
ସଂରଚନା type *								\
name##_SPLAY_REMOVE(ସଂରଚନା name *head, ସଂରଚନା type *elm)		\
{									\
	ସଂରଚନା type *__tmp;						\
	ଯଦି (SPLAY_EMPTY(head))						\
		ଫେରନ୍ତୁ (ଖାଲି);						\
	name##_SPLAY(head, elm);					\
	ଯଦି ((cmp)(elm, (head)->sph_ମୂଳ) == 0) {			\
		ଯଦି (SPLAY_ବାମ((head)->sph_ମୂଳ, field) == ଖାଲି) {	\
			(head)->sph_ମୂଳ = SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field);\
		} ଅନ୍ୟଥା {						\
			__tmp = SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field);	\
			(head)->sph_ମୂଳ = SPLAY_ବାମ((head)->sph_ମୂଳ, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field) = __tmp;	\
		}							\
		ଫେରନ୍ତୁ (elm);						\
	}								\
	ଫେରନ୍ତୁ (ଖାଲି);							\
}									\
									\
ଶୂନ୍ୟ									\
name##_SPLAY(ସଂରଚନା name *head, ସଂରଚନା type *elm)			\
{									\
	ସଂରଚନା type __node, *__left, *__right, *__tmp;			\
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା __comp;							\
\
	SPLAY_ବାମ(&__node, field) = SPLAY_ଡାହାଣ(&__node, field) = ଖାଲି;\
	__left = __right = &__node;					\
\
	ଯେତେବେଳେ ((__comp = (cmp)(elm, (head)->sph_ମୂଳ))) {		\
		ଯଦି (__comp < 0) {					\
			__tmp = SPLAY_ବାମ((head)->sph_ମୂଳ, field);	\
			ଯଦି (__tmp == ଖାଲି)				\
				ଭାଙ୍ଗ;					\
			ଯଦି ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_ଡାହାଣ(head, __tmp, field);	\
				ଯଦି (SPLAY_ବାମ((head)->sph_ମୂଳ, field) == ଖାଲି)\
					ଭାଙ୍ଗ;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} ଅନ୍ୟଥା ଯଦି (__comp > 0) {				\
			__tmp = SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field);	\
			ଯଦି (__tmp == ଖାଲି)				\
				ଭାଙ୍ଗ;					\
			ଯଦି ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_ବାମ(head, __tmp, field);	\
				ଯଦି (SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field) == ଖାଲି)\
					ଭାଙ୍ଗ;				\
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
ଶୂନ୍ୟ name##_SPLAY_MINMAX(ସଂରଚନା name *head, ପୂର୍ଣ୍ଣସଂଖ୍ୟା __comp) \
{									\
	ସଂରଚନା type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_ବାମ(&__node, field) = SPLAY_ଡାହାଣ(&__node, field) = ଖାଲି;\
	__left = __right = &__node;					\
\
	ଯେତେବେଳେ (1) {							\
		ଯଦି (__comp < 0) {					\
			__tmp = SPLAY_ବାମ((head)->sph_ମୂଳ, field);	\
			ଯଦି (__tmp == ଖାଲି)				\
				ଭାଙ୍ଗ;					\
			ଯଦି (__comp < 0){				\
				SPLAY_ROTATE_ଡାହାଣ(head, __tmp, field);	\
				ଯଦି (SPLAY_ବାମ((head)->sph_ମୂଳ, field) == ଖାଲି)\
					ଭାଙ୍ଗ;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} ଅନ୍ୟଥା ଯଦି (__comp > 0) {				\
			__tmp = SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field);	\
			ଯଦି (__tmp == ଖାଲି)				\
				ଭାଙ୍ଗ;					\
			ଯଦି (__comp > 0) {				\
				SPLAY_ROTATE_ବାମ(head, __tmp, field);	\
				ଯଦି (SPLAY_ଡାହାଣ((head)->sph_ମୂଳ, field) == ଖାଲି)\
					ଭାଙ୍ଗ;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_ଭର୍ତ୍ତି(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? ଖାଲି	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? ଖାଲି	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	ପାଇଁ ((x) = SPLAY_MIN(name, head);				\
	     (x) != ଖାଲି;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
ସଂରଚନା name {								\
	ସଂରଚନା type *rbh_ମୂଳ; /* root of the tree */			\
}

#define RB_INITIALIZER(ମୂଳ)						\
	{ ଖାଲି }

#define RB_INIT(ମୂଳ) କର {						\
	(ମୂଳ)->rbh_ମୂଳ = ଖାଲି;					\
} ଯେତେବେଳେ (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
ସଂରଚନା {								\
	ସଂରଚନା type *rbe_ବାମ;		/* left element */		\
	ସଂରଚନା type *rbe_ଡାହାଣ;		/* right element */		\
	ସଂରଚନା type *rbe_parent;	/* parent element */		\
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rbe_color;			/* node color */		\
}

#define RB_ବାମ(elm, field)		(elm)->field.rbe_ବାମ
#define RB_ଡାହାଣ(elm, field)		(elm)->field.rbe_ଡାହାଣ
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_ମୂଳ(head)			(head)->rbh_ମୂଳ
#define RB_EMPTY(head)			(RB_ମୂଳ(head) == ଖାଲି)

#define RB_SET(elm, parent, field) କର {					\
	RB_PARENT(elm, field) = parent;					\
	RB_ବାମ(elm, field) = RB_ଡାହାଣ(elm, field) = ଖାଲି;		\
	RB_COLOR(elm, field) = RB_RED;					\
} ଯେତେବେଳେ (0)

#define RB_SET_BLACKRED(black, red, field) କର {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} ଯେତେବେଳେ (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	କର {} ଯେତେବେଳେ (0)
#endif

#define RB_ROTATE_ବାମ(head, elm, tmp, field) କର {			\
	(tmp) = RB_ଡାହାଣ(elm, field);					\
	ଯଦି ((RB_ଡାହାଣ(elm, field) = RB_ବାମ(tmp, field))) {		\
		RB_PARENT(RB_ବାମ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ଯଦି ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		ଯଦି ((elm) == RB_ବାମ(RB_PARENT(elm, field), field))	\
			RB_ବାମ(RB_PARENT(elm, field), field) = (tmp);	\
		ଅନ୍ୟଥା							\
			RB_ଡାହାଣ(RB_PARENT(elm, field), field) = (tmp);	\
	} ଅନ୍ୟଥା								\
		(head)->rbh_ମୂଳ = (tmp);				\
	RB_ବାମ(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ଯଦି ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} ଯେତେବେଳେ (0)

#define RB_ROTATE_ଡାହାଣ(head, elm, tmp, field) କର {			\
	(tmp) = RB_ବାମ(elm, field);					\
	ଯଦି ((RB_ବାମ(elm, field) = RB_ଡାହାଣ(tmp, field))) {		\
		RB_PARENT(RB_ଡାହାଣ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ଯଦି ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		ଯଦି ((elm) == RB_ବାମ(RB_PARENT(elm, field), field))	\
			RB_ବାମ(RB_PARENT(elm, field), field) = (tmp);	\
		ଅନ୍ୟଥା							\
			RB_ଡାହାଣ(RB_PARENT(elm, field), field) = (tmp);	\
	} ଅନ୍ୟଥା								\
		(head)->rbh_ମୂଳ = (tmp);				\
	RB_ଡାହାଣ(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ଯଦି ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} ଯେତେବେଳେ (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) ସ୍ଥିର)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr ଶୂନ୍ୟ name##_RB_INSERT_COLOR(ସଂରଚନା name *, ସଂରଚନା type *);		\
attr ଶୂନ୍ୟ name##_RB_REMOVE_COLOR(ସଂରଚନା name *, ସଂରଚନା type *, ସଂରଚନା type *);\
attr ସଂରଚନା type *name##_RB_REMOVE(ସଂରଚନା name *, ସଂରଚନା type *);	\
attr ସଂରଚନା type *name##_RB_INSERT(ସଂରଚନା name *, ସଂରଚନା type *);	\
attr ସଂରଚନା type *name##_RB_FIND(ସଂରଚନା name *, ସଂରଚନା type *);		\
attr ସଂରଚନା type *name##_RB_NFIND(ସଂରଚନା name *, ସଂରଚନା type *);	\
attr ସଂରଚନା type *name##_RB_NEXT(ସଂରଚନା type *);			\
attr ସଂରଚନା type *name##_RB_PREV(ସଂରଚନା type *);			\
attr ସଂରଚନା type *name##_RB_MINMAX(ସଂରଚନା name *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) ସ୍ଥିର)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr ଶୂନ୍ୟ								\
name##_RB_INSERT_COLOR(ସଂରଚନା name *head, ସଂରଚନା type *elm)		\
{									\
	ସଂରଚନା type *parent, *gparent, *tmp;				\
	ଯେତେବେଳେ ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		ଯଦି (parent == RB_ବାମ(gparent, field)) {		\
			tmp = RB_ଡାହାଣ(gparent, field);			\
			ଯଦି (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				ଜାରି;				\
			}						\
			ଯଦି (RB_ଡାହାଣ(parent, field) == elm) {		\
				RB_ROTATE_ବାମ(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_ଡାହାଣ(head, gparent, tmp, field);	\
		} ଅନ୍ୟଥା {						\
			tmp = RB_ବାମ(gparent, field);			\
			ଯଦି (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				ଜାରି;				\
			}						\
			ଯଦି (RB_ବାମ(parent, field) == elm) {		\
				RB_ROTATE_ଡାହାଣ(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_ବାମ(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_ମୂଳ, field) = RB_BLACK;			\
}									\
									\
attr ଶୂନ୍ୟ								\
name##_RB_REMOVE_COLOR(ସଂରଚନା name *head, ସଂରଚନା type *parent, ସଂରଚନା type *elm) \
{									\
	ସଂରଚନା type *tmp;						\
	ଯେତେବେଳେ ((elm == ଖାଲି || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_ମୂଳ(head)) {					\
		ଯଦି (RB_ବାମ(parent, field) == elm) {			\
			tmp = RB_ଡାହାଣ(parent, field);			\
			ଯଦି (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_ବାମ(head, parent, tmp, field);\
				tmp = RB_ଡାହାଣ(parent, field);		\
			}						\
			ଯଦି ((RB_ବାମ(tmp, field) == ଖାଲି ||		\
			    RB_COLOR(RB_ବାମ(tmp, field), field) == RB_BLACK) &&\
			    (RB_ଡାହାଣ(tmp, field) == ଖାଲି ||		\
			    RB_COLOR(RB_ଡାହାଣ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} ଅନ୍ୟଥା {					\
				ଯଦି (RB_ଡାହାଣ(tmp, field) == ଖାଲି ||	\
				    RB_COLOR(RB_ଡାହାଣ(tmp, field), field) == RB_BLACK) {\
					ସଂରଚନା type *oleft;		\
					ଯଦି ((oleft = RB_ବାମ(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_ଡାହାଣ(head, tmp, oleft, field);\
					tmp = RB_ଡାହାଣ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				ଯଦି (RB_ଡାହାଣ(tmp, field))		\
					RB_COLOR(RB_ଡାହାଣ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_ବାମ(head, parent, tmp, field);\
				elm = RB_ମୂଳ(head);			\
				ଭାଙ୍ଗ;					\
			}						\
		} ଅନ୍ୟଥା {						\
			tmp = RB_ବାମ(parent, field);			\
			ଯଦି (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_ଡାହାଣ(head, parent, tmp, field);\
				tmp = RB_ବାମ(parent, field);		\
			}						\
			ଯଦି ((RB_ବାମ(tmp, field) == ଖାଲି ||		\
			    RB_COLOR(RB_ବାମ(tmp, field), field) == RB_BLACK) &&\
			    (RB_ଡାହାଣ(tmp, field) == ଖାଲି ||		\
			    RB_COLOR(RB_ଡାହାଣ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} ଅନ୍ୟଥା {					\
				ଯଦି (RB_ବାମ(tmp, field) == ଖାଲି ||	\
				    RB_COLOR(RB_ବାମ(tmp, field), field) == RB_BLACK) {\
					ସଂରଚନା type *oright;		\
					ଯଦି ((oright = RB_ଡାହାଣ(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_ବାମ(head, tmp, oright, field);\
					tmp = RB_ବାମ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				ଯଦି (RB_ବାମ(tmp, field))		\
					RB_COLOR(RB_ବାମ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_ଡାହାଣ(head, parent, tmp, field);\
				elm = RB_ମୂଳ(head);			\
				ଭାଙ୍ଗ;					\
			}						\
		}							\
	}								\
	ଯଦି (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr ସଂରଚନା type *							\
name##_RB_REMOVE(ସଂରଚନା name *head, ସଂରଚନା type *elm)			\
{									\
	ସଂରଚନା type *child, *parent, *old = elm;			\
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା color;							\
	ଯଦି (RB_ବାମ(elm, field) == ଖାଲି)				\
		child = RB_ଡାହାଣ(elm, field);				\
	ଅନ୍ୟଥା ଯଦି (RB_ଡାହାଣ(elm, field) == ଖାଲି)				\
		child = RB_ବାମ(elm, field);				\
	ଅନ୍ୟଥା {								\
		ସଂରଚନା type *ବାମ;					\
		elm = RB_ଡାହାଣ(elm, field);				\
		ଯେତେବେଳେ ((ବାମ = RB_ବାମ(elm, field)))			\
			elm = ବାମ;					\
		child = RB_ଡାହାଣ(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		ଯଦି (child)						\
			RB_PARENT(child, field) = parent;		\
		ଯଦି (parent) {						\
			ଯଦି (RB_ବାମ(parent, field) == elm)		\
				RB_ବାମ(parent, field) = child;		\
			ଅନ୍ୟଥା						\
				RB_ଡାହାଣ(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} ଅନ୍ୟଥା							\
			RB_ମୂଳ(head) = child;				\
		ଯଦି (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		ଯଦି (RB_PARENT(old, field)) {				\
			ଯଦି (RB_ବାମ(RB_PARENT(old, field), field) == old)\
				RB_ବାମ(RB_PARENT(old, field), field) = elm;\
			ଅନ୍ୟଥା						\
				RB_ଡାହାଣ(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} ଅନ୍ୟଥା							\
			RB_ମୂଳ(head) = elm;				\
		RB_PARENT(RB_ବାମ(old, field), field) = elm;		\
		ଯଦି (RB_ଡାହାଣ(old, field))				\
			RB_PARENT(RB_ଡାହାଣ(old, field), field) = elm;	\
		ଯଦି (parent) {						\
			ବାମ = parent;					\
			କର {						\
				RB_AUGMENT(ବାମ);			\
			} ଯେତେବେଳେ ((ବାମ = RB_PARENT(ବାମ, field)));	\
		}							\
		ଯାଅ color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	ଯଦି (child)							\
		RB_PARENT(child, field) = parent;			\
	ଯଦି (parent) {							\
		ଯଦି (RB_ବାମ(parent, field) == elm)			\
			RB_ବାମ(parent, field) = child;			\
		ଅନ୍ୟଥା							\
			RB_ଡାହାଣ(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} ଅନ୍ୟଥା								\
		RB_ମୂଳ(head) = child;					\
color:									\
	ଯଦି (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	ଫେରନ୍ତୁ (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr ସଂରଚନା type *							\
name##_RB_INSERT(ସଂରଚନା name *head, ସଂରଚନା type *elm)			\
{									\
	ସଂରଚନା type *tmp;						\
	ସଂରଚନା type *parent = ଖାଲି;					\
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା comp = 0;							\
	tmp = RB_ମୂଳ(head);						\
	ଯେତେବେଳେ (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		ଯଦି (comp < 0)						\
			tmp = RB_ବାମ(tmp, field);			\
		ଅନ୍ୟଥା ଯଦି (comp > 0)					\
			tmp = RB_ଡାହାଣ(tmp, field);			\
		ଅନ୍ୟଥା							\
			ଫେରନ୍ତୁ (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	ଯଦି (parent != ଖାଲି) {						\
		ଯଦି (comp < 0)						\
			RB_ବାମ(parent, field) = elm;			\
		ଅନ୍ୟଥା							\
			RB_ଡାହାଣ(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} ଅନ୍ୟଥା								\
		RB_ମୂଳ(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	ଫେରନ୍ତୁ (ଖାଲି);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr ସଂରଚନା type *							\
name##_RB_FIND(ସଂରଚନା name *head, ସଂରଚନା type *elm)			\
{									\
	ସଂରଚନା type *tmp = RB_ମୂଳ(head);				\
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା comp;							\
	ଯେତେବେଳେ (tmp) {							\
		comp = cmp(elm, tmp);					\
		ଯଦି (comp < 0)						\
			tmp = RB_ବାମ(tmp, field);			\
		ଅନ୍ୟଥା ଯଦି (comp > 0)					\
			tmp = RB_ଡାହାଣ(tmp, field);			\
		ଅନ୍ୟଥା							\
			ଫେରନ୍ତୁ (tmp);					\
	}								\
	ଫେରନ୍ତୁ (ଖାଲି);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr ସଂରଚନା type *							\
name##_RB_NFIND(ସଂରଚନା name *head, ସଂରଚନା type *elm)			\
{									\
	ସଂରଚନା type *tmp = RB_ମୂଳ(head);				\
	ସଂରଚନା type *res = ଖାଲି;					\
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା comp;							\
	ଯେତେବେଳେ (tmp) {							\
		comp = cmp(elm, tmp);					\
		ଯଦି (comp < 0) {						\
			res = tmp;					\
			tmp = RB_ବାମ(tmp, field);			\
		}							\
		ଅନ୍ୟଥା ଯଦି (comp > 0)					\
			tmp = RB_ଡାହାଣ(tmp, field);			\
		ଅନ୍ୟଥା							\
			ଫେରନ୍ତୁ (tmp);					\
	}								\
	ଫେରନ୍ତୁ (res);							\
}									\
									\
/* ARGSUSED */								\
attr ସଂରଚନା type *							\
name##_RB_NEXT(ସଂରଚନା type *elm)					\
{									\
	ଯଦି (RB_ଡାହାଣ(elm, field)) {					\
		elm = RB_ଡାହାଣ(elm, field);				\
		ଯେତେବେଳେ (RB_ବାମ(elm, field))				\
			elm = RB_ବାମ(elm, field);			\
	} ଅନ୍ୟଥା {							\
		ଯଦି (RB_PARENT(elm, field) &&				\
		    (elm == RB_ବାମ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		ଅନ୍ୟଥା {							\
			ଯେତେବେଳେ (RB_PARENT(elm, field) &&			\
			    (elm == RB_ଡାହାଣ(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	ଫେରନ୍ତୁ (elm);							\
}									\
									\
/* ARGSUSED */								\
attr ସଂରଚନା type *							\
name##_RB_PREV(ସଂରଚନା type *elm)					\
{									\
	ଯଦି (RB_ବାମ(elm, field)) {					\
		elm = RB_ବାମ(elm, field);				\
		ଯେତେବେଳେ (RB_ଡାହାଣ(elm, field))				\
			elm = RB_ଡାହାଣ(elm, field);			\
	} ଅନ୍ୟଥା {							\
		ଯଦି (RB_PARENT(elm, field) &&				\
		    (elm == RB_ଡାହାଣ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		ଅନ୍ୟଥା {							\
			ଯେତେବେଳେ (RB_PARENT(elm, field) &&			\
			    (elm == RB_ବାମ(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	ଫେରନ୍ତୁ (elm);							\
}									\
									\
attr ସଂରଚନା type *							\
name##_RB_MINMAX(ସଂରଚନା name *head, ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)				\
{									\
	ସଂରଚନା type *tmp = RB_ମୂଳ(head);				\
	ସଂରଚନା type *parent = ଖାଲି;					\
	ଯେତେବେଳେ (tmp) {							\
		parent = tmp;						\
		ଯଦି (val < 0)						\
			tmp = RB_ବାମ(tmp, field);			\
		ଅନ୍ୟଥା							\
			tmp = RB_ଡାହାଣ(tmp, field);			\
	}								\
	ଫେରନ୍ତୁ (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_ଭର୍ତ୍ତି(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	ପାଇଁ ((x) = RB_MIN(name, head);					\
	     (x) != ଖାଲି;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	ପାଇଁ ((x) = RB_MIN(name, head);					\
	    ((x) != ଖାଲି) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	ପାଇଁ ((x) = RB_MAX(name, head);					\
	     (x) != ଖାଲି;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	ପାଇଁ ((x) = RB_MAX(name, head);					\
	    ((x) != ଖାଲି) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
