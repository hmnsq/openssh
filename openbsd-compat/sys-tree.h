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

#include "config.h"
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	_SYS_TREE_H_
#define	_SYS_TREE_H_

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
struct name {								\
	struct type *sph_root; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(root)						\
	{ NULL }

#define SPLAY_INIT(root) do {						\
	(root)->sph_root = NULL;					\
} 동안 (0)

#define SPLAY_ENTRY(type)						\
struct {								\
	struct type *spe_left; /* left element */			\
	struct type *spe_right; /* right element */			\
}

#define SPLAY_LEFT(elm, field)		(elm)->field.spe_left
#define SPLAY_RIGHT(elm, field)		(elm)->field.spe_right
#define SPLAY_ROOT(head)		(head)->sph_root
#define SPLAY_EMPTY(head)		(SPLAY_ROOT(head) == NULL)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_RIGHT(head, tmp, field) do {			\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(tmp, field);	\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} 동안 (0)
	
#define SPLAY_ROTATE_LEFT(head, tmp, field) do {			\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(tmp, field);	\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} 동안 (0)

#define SPLAY_LINKLEFT(head, tmp, field) do {				\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);		\
} 동안 (0)

#define SPLAY_LINKRIGHT(head, tmp, field) do {				\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);	\
} 동안 (0)

#define SPLAY_ASSEMBLE(head, node, left, right, field) do {		\
	SPLAY_RIGHT(left, field) = SPLAY_LEFT((head)->sph_root, field);	\
	SPLAY_LEFT(right, field) = SPLAY_RIGHT((head)->sph_root, field);\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(node, field);	\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(node, field);	\
} 동안 (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
void name##_SPLAY(struct name *, struct type *);			\
void name##_SPLAY_MINMAX(struct name *, 정수);				\
struct type *name##_SPLAY_INSERT(struct name *, struct type *);		\
struct type *name##_SPLAY_REMOVE(struct name *, struct type *);		\
									\
/* Finds the node with the same key as elm */				\
static __inline struct type *						\
name##_SPLAY_FIND(struct name *head, struct type *elm)			\
{									\
	만약 (SPLAY_EMPTY(head))						\
		반환(NULL);						\
	name##_SPLAY(head, elm);					\
	만약 ((cmp)(elm, (head)->sph_root) == 0)				\
		반환 (head->sph_root);				\
	반환 (NULL);							\
}									\
									\
static __inline struct type *						\
name##_SPLAY_NEXT(struct name *head, struct type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	만약 (SPLAY_RIGHT(elm, field) != NULL) {				\
		elm = SPLAY_RIGHT(elm, field);				\
		동안 (SPLAY_LEFT(elm, field) != NULL) {		\
			elm = SPLAY_LEFT(elm, field);			\
		}							\
	} 아니면								\
		elm = NULL;						\
	반환 (elm);							\
}									\
									\
static __inline struct type *						\
name##_SPLAY_MIN_MAX(struct name *head, 정수 val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        반환 (SPLAY_ROOT(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
struct type *								\
name##_SPLAY_INSERT(struct name *head, struct type *elm)		\
{									\
    만약 (SPLAY_EMPTY(head)) {						\
	    SPLAY_LEFT(elm, field) = SPLAY_RIGHT(elm, field) = NULL;	\
    } 아니면 {								\
	    정수 __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_root);			\
	    만약(__comp < 0) {						\
		    SPLAY_LEFT(elm, field) = SPLAY_LEFT((head)->sph_root, field);\
		    SPLAY_RIGHT(elm, field) = (head)->sph_root;		\
		    SPLAY_LEFT((head)->sph_root, field) = NULL;		\
	    } 아니면 만약 (__comp > 0) {					\
		    SPLAY_RIGHT(elm, field) = SPLAY_RIGHT((head)->sph_root, field);\
		    SPLAY_LEFT(elm, field) = (head)->sph_root;		\
		    SPLAY_RIGHT((head)->sph_root, field) = NULL;	\
	    } 아니면							\
		    반환 ((head)->sph_root);				\
    }									\
    (head)->sph_root = (elm);						\
    반환 (NULL);							\
}									\
									\
struct type *								\
name##_SPLAY_REMOVE(struct name *head, struct type *elm)		\
{									\
	struct type *__tmp;						\
	만약 (SPLAY_EMPTY(head))						\
		반환 (NULL);						\
	name##_SPLAY(head, elm);					\
	만약 ((cmp)(elm, (head)->sph_root) == 0) {			\
		만약 (SPLAY_LEFT((head)->sph_root, field) == NULL) {	\
			(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);\
		} 아니면 {						\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_RIGHT((head)->sph_root, field) = __tmp;	\
		}							\
		반환 (elm);						\
	}								\
	반환 (NULL);							\
}									\
									\
void									\
name##_SPLAY(struct name *head, struct type *elm)			\
{									\
	struct type __node, *__left, *__right, *__tmp;			\
	정수 __comp;							\
\
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	동안 ((__comp = (cmp)(elm, (head)->sph_root))) {		\
		만약 (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			만약 (__tmp == NULL)				\
				break;					\
			만약 ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				만약 (SPLAY_LEFT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} 아니면 만약 (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			만약 (__tmp == NULL)				\
				break;					\
			만약 ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				만약 (SPLAY_RIGHT((head)->sph_root, field) == NULL)\
					break;				\
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
void name##_SPLAY_MINMAX(struct name *head, 정수 __comp) \
{									\
	struct type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	동안 (1) {							\
		만약 (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			만약 (__tmp == NULL)				\
				break;					\
			만약 (__comp < 0){				\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				만약 (SPLAY_LEFT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} 아니면 만약 (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			만약 (__tmp == NULL)				\
				break;					\
			만약 (__comp > 0) {				\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				만약 (SPLAY_RIGHT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_INSERT(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	위해 ((x) = SPLAY_MIN(name, head);				\
	     (x) != NULL;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
struct name {								\
	struct type *rbh_root; /* root of the tree */			\
}

#define RB_INITIALIZER(root)						\
	{ NULL }

#define RB_INIT(root) do {						\
	(root)->rbh_root = NULL;					\
} 동안 (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
struct {								\
	struct type *rbe_left;		/* left element */		\
	struct type *rbe_right;		/* right element */		\
	struct type *rbe_parent;	/* parent element */		\
	정수 rbe_color;			/* node color */		\
}

#define RB_LEFT(elm, field)		(elm)->field.rbe_left
#define RB_RIGHT(elm, field)		(elm)->field.rbe_right
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_ROOT(head)			(head)->rbh_root
#define RB_EMPTY(head)			(RB_ROOT(head) == NULL)

#define RB_SET(elm, parent, field) do {					\
	RB_PARENT(elm, field) = parent;					\
	RB_LEFT(elm, field) = RB_RIGHT(elm, field) = NULL;		\
	RB_COLOR(elm, field) = RB_RED;					\
} 동안 (0)

#define RB_SET_BLACKRED(black, red, field) do {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} 동안 (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	do {} 동안 (0)
#endif

#define RB_ROTATE_LEFT(head, elm, tmp, field) do {			\
	(tmp) = RB_RIGHT(elm, field);					\
	만약 ((RB_RIGHT(elm, field) = RB_LEFT(tmp, field))) {		\
		RB_PARENT(RB_LEFT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	만약 ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		만약 ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		아니면							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} 아니면								\
		(head)->rbh_root = (tmp);				\
	RB_LEFT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	만약 ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} 동안 (0)

#define RB_ROTATE_RIGHT(head, elm, tmp, field) do {			\
	(tmp) = RB_LEFT(elm, field);					\
	만약 ((RB_LEFT(elm, field) = RB_RIGHT(tmp, field))) {		\
		RB_PARENT(RB_RIGHT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	만약 ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		만약 ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		아니면							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} 아니면								\
		(head)->rbh_root = (tmp);				\
	RB_RIGHT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	만약 ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} 동안 (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) static)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr void name##_RB_INSERT_COLOR(struct name *, struct type *);		\
attr void name##_RB_REMOVE_COLOR(struct name *, struct type *, struct type *);\
attr struct type *name##_RB_REMOVE(struct name *, struct type *);	\
attr struct type *name##_RB_INSERT(struct name *, struct type *);	\
attr struct type *name##_RB_FIND(struct name *, struct type *);		\
attr struct type *name##_RB_NFIND(struct name *, struct type *);	\
attr struct type *name##_RB_NEXT(struct type *);			\
attr struct type *name##_RB_PREV(struct type *);			\
attr struct type *name##_RB_MINMAX(struct name *, 정수);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) static)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr void								\
name##_RB_INSERT_COLOR(struct name *head, struct type *elm)		\
{									\
	struct type *parent, *gparent, *tmp;				\
	동안 ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		만약 (parent == RB_LEFT(gparent, field)) {		\
			tmp = RB_RIGHT(gparent, field);			\
			만약 (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			만약 (RB_RIGHT(parent, field) == elm) {		\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_RIGHT(head, gparent, tmp, field);	\
		} 아니면 {						\
			tmp = RB_LEFT(gparent, field);			\
			만약 (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			만약 (RB_LEFT(parent, field) == elm) {		\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_LEFT(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_root, field) = RB_BLACK;			\
}									\
									\
attr void								\
name##_RB_REMOVE_COLOR(struct name *head, struct type *parent, struct type *elm) \
{									\
	struct type *tmp;						\
	동안 ((elm == NULL || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_ROOT(head)) {					\
		만약 (RB_LEFT(parent, field) == elm) {			\
			tmp = RB_RIGHT(parent, field);			\
			만약 (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = RB_RIGHT(parent, field);		\
			}						\
			만약 ((RB_LEFT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} 아니면 {					\
				만약 (RB_RIGHT(tmp, field) == NULL ||	\
				    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK) {\
					struct type *oleft;		\
					만약 ((oleft = RB_LEFT(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_RIGHT(head, tmp, oleft, field);\
					tmp = RB_RIGHT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				만약 (RB_RIGHT(tmp, field))		\
					RB_COLOR(RB_RIGHT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				break;					\
			}						\
		} 아니면 {						\
			tmp = RB_LEFT(parent, field);			\
			만약 (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				tmp = RB_LEFT(parent, field);		\
			}						\
			만약 ((RB_LEFT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} 아니면 {					\
				만약 (RB_LEFT(tmp, field) == NULL ||	\
				    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) {\
					struct type *oright;		\
					만약 ((oright = RB_RIGHT(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_LEFT(head, tmp, oright, field);\
					tmp = RB_LEFT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				만약 (RB_LEFT(tmp, field))		\
					RB_COLOR(RB_LEFT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				break;					\
			}						\
		}							\
	}								\
	만약 (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr struct type *							\
name##_RB_REMOVE(struct name *head, struct type *elm)			\
{									\
	struct type *child, *parent, *old = elm;			\
	정수 color;							\
	만약 (RB_LEFT(elm, field) == NULL)				\
		child = RB_RIGHT(elm, field);				\
	아니면 만약 (RB_RIGHT(elm, field) == NULL)				\
		child = RB_LEFT(elm, field);				\
	아니면 {								\
		struct type *left;					\
		elm = RB_RIGHT(elm, field);				\
		동안 ((left = RB_LEFT(elm, field)))			\
			elm = left;					\
		child = RB_RIGHT(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		만약 (child)						\
			RB_PARENT(child, field) = parent;		\
		만약 (parent) {						\
			만약 (RB_LEFT(parent, field) == elm)		\
				RB_LEFT(parent, field) = child;		\
			아니면						\
				RB_RIGHT(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} 아니면							\
			RB_ROOT(head) = child;				\
		만약 (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		만약 (RB_PARENT(old, field)) {				\
			만약 (RB_LEFT(RB_PARENT(old, field), field) == old)\
				RB_LEFT(RB_PARENT(old, field), field) = elm;\
			아니면						\
				RB_RIGHT(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} 아니면							\
			RB_ROOT(head) = elm;				\
		RB_PARENT(RB_LEFT(old, field), field) = elm;		\
		만약 (RB_RIGHT(old, field))				\
			RB_PARENT(RB_RIGHT(old, field), field) = elm;	\
		만약 (parent) {						\
			left = parent;					\
			do {						\
				RB_AUGMENT(left);			\
			} 동안 ((left = RB_PARENT(left, field)));	\
		}							\
		goto color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	만약 (child)							\
		RB_PARENT(child, field) = parent;			\
	만약 (parent) {							\
		만약 (RB_LEFT(parent, field) == elm)			\
			RB_LEFT(parent, field) = child;			\
		아니면							\
			RB_RIGHT(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} 아니면								\
		RB_ROOT(head) = child;					\
color:									\
	만약 (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	반환 (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr struct type *							\
name##_RB_INSERT(struct name *head, struct type *elm)			\
{									\
	struct type *tmp;						\
	struct type *parent = NULL;					\
	정수 comp = 0;							\
	tmp = RB_ROOT(head);						\
	동안 (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		만약 (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		아니면 만약 (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		아니면							\
			반환 (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	만약 (parent != NULL) {						\
		만약 (comp < 0)						\
			RB_LEFT(parent, field) = elm;			\
		아니면							\
			RB_RIGHT(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} 아니면								\
		RB_ROOT(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	반환 (NULL);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr struct type *							\
name##_RB_FIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_ROOT(head);				\
	정수 comp;							\
	동안 (tmp) {							\
		comp = cmp(elm, tmp);					\
		만약 (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		아니면 만약 (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		아니면							\
			반환 (tmp);					\
	}								\
	반환 (NULL);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr struct type *							\
name##_RB_NFIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_ROOT(head);				\
	struct type *res = NULL;					\
	정수 comp;							\
	동안 (tmp) {							\
		comp = cmp(elm, tmp);					\
		만약 (comp < 0) {						\
			res = tmp;					\
			tmp = RB_LEFT(tmp, field);			\
		}							\
		아니면 만약 (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		아니면							\
			반환 (tmp);					\
	}								\
	반환 (res);							\
}									\
									\
/* ARGSUSED */								\
attr struct type *							\
name##_RB_NEXT(struct type *elm)					\
{									\
	만약 (RB_RIGHT(elm, field)) {					\
		elm = RB_RIGHT(elm, field);				\
		동안 (RB_LEFT(elm, field))				\
			elm = RB_LEFT(elm, field);			\
	} 아니면 {							\
		만약 (RB_PARENT(elm, field) &&				\
		    (elm == RB_LEFT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		아니면 {							\
			동안 (RB_PARENT(elm, field) &&			\
			    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	반환 (elm);							\
}									\
									\
/* ARGSUSED */								\
attr struct type *							\
name##_RB_PREV(struct type *elm)					\
{									\
	만약 (RB_LEFT(elm, field)) {					\
		elm = RB_LEFT(elm, field);				\
		동안 (RB_RIGHT(elm, field))				\
			elm = RB_RIGHT(elm, field);			\
	} 아니면 {							\
		만약 (RB_PARENT(elm, field) &&				\
		    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		아니면 {							\
			동안 (RB_PARENT(elm, field) &&			\
			    (elm == RB_LEFT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	반환 (elm);							\
}									\
									\
attr struct type *							\
name##_RB_MINMAX(struct name *head, 정수 val)				\
{									\
	struct type *tmp = RB_ROOT(head);				\
	struct type *parent = NULL;					\
	동안 (tmp) {							\
		parent = tmp;						\
		만약 (val < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		아니면							\
			tmp = RB_RIGHT(tmp, field);			\
	}								\
	반환 (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_INSERT(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	위해 ((x) = RB_MIN(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	위해 ((x) = RB_MIN(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	위해 ((x) = RB_MAX(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	위해 ((x) = RB_MAX(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
