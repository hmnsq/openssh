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
بنية name {								\
	بنية type *sph_root; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(root)						\
	{ عدم }

#define SPLAY_INIT(root) עשה {						\
	(root)->sph_root = عدم;					\
} כלעוד (0)

#define SPLAY_ENTRY(type)						\
بنية {								\
	بنية type *spe_left; /* left element */			\
	بنية type *spe_right; /* right element */			\
}

#define SPLAY_LEFT(elm, field)		(elm)->field.spe_left
#define SPLAY_RIGHT(elm, field)		(elm)->field.spe_right
#define SPLAY_ROOT(head)		(head)->sph_root
#define SPLAY_EMPTY(head)		(SPLAY_ROOT(head) == عدم)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_RIGHT(head, tmp, field) עשה {			\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(tmp, field);	\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} כלעוד (0)
	
#define SPLAY_ROTATE_LEFT(head, tmp, field) עשה {			\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(tmp, field);	\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} כלעוד (0)

#define SPLAY_LINKLEFT(head, tmp, field) עשה {				\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);		\
} כלעוד (0)

#define SPLAY_LINKRIGHT(head, tmp, field) עשה {				\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);	\
} כלעוד (0)

#define SPLAY_ASSEMBLE(head, node, left, right, field) עשה {		\
	SPLAY_RIGHT(left, field) = SPLAY_LEFT((head)->sph_root, field);	\
	SPLAY_LEFT(right, field) = SPLAY_RIGHT((head)->sph_root, field);\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(node, field);	\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(node, field);	\
} כלעוד (0)

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
	אם (SPLAY_EMPTY(head))						\
		החזר(عدم);						\
	name##_SPLAY(head, elm);					\
	אם ((cmp)(elm, (head)->sph_root) == 0)				\
		החזר (head->sph_root);				\
	החזר (عدم);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_NEXT(بنية name *head, بنية type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	אם (SPLAY_RIGHT(elm, field) != عدم) {				\
		elm = SPLAY_RIGHT(elm, field);				\
		כלעוד (SPLAY_LEFT(elm, field) != عدم) {		\
			elm = SPLAY_LEFT(elm, field);			\
		}							\
	} אחרת								\
		elm = عدم;						\
	החזר (elm);							\
}									\
									\
ساكن __inline بنية type *						\
name##_SPLAY_MIN_MAX(بنية name *head, صحيح val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        החזר (SPLAY_ROOT(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
بنية type *								\
name##_SPLAY_INSERT(بنية name *head, بنية type *elm)		\
{									\
    אם (SPLAY_EMPTY(head)) {						\
	    SPLAY_LEFT(elm, field) = SPLAY_RIGHT(elm, field) = عدم;	\
    } אחרת {								\
	    صحيح __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_root);			\
	    אם(__comp < 0) {						\
		    SPLAY_LEFT(elm, field) = SPLAY_LEFT((head)->sph_root, field);\
		    SPLAY_RIGHT(elm, field) = (head)->sph_root;		\
		    SPLAY_LEFT((head)->sph_root, field) = عدم;		\
	    } אחרת אם (__comp > 0) {					\
		    SPLAY_RIGHT(elm, field) = SPLAY_RIGHT((head)->sph_root, field);\
		    SPLAY_LEFT(elm, field) = (head)->sph_root;		\
		    SPLAY_RIGHT((head)->sph_root, field) = عدم;	\
	    } אחרת							\
		    החזר ((head)->sph_root);				\
    }									\
    (head)->sph_root = (elm);						\
    החזר (عدم);							\
}									\
									\
بنية type *								\
name##_SPLAY_REMOVE(بنية name *head, بنية type *elm)		\
{									\
	بنية type *__tmp;						\
	אם (SPLAY_EMPTY(head))						\
		החזר (عدم);						\
	name##_SPLAY(head, elm);					\
	אם ((cmp)(elm, (head)->sph_root) == 0) {			\
		אם (SPLAY_LEFT((head)->sph_root, field) == عدم) {	\
			(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);\
		} אחרת {						\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_RIGHT((head)->sph_root, field) = __tmp;	\
		}							\
		החזר (elm);						\
	}								\
	החזר (عدم);							\
}									\
									\
فراغ									\
name##_SPLAY(بنية name *head, بنية type *elm)			\
{									\
	بنية type __node, *__left, *__right, *__tmp;			\
	صحيح __comp;							\
\
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = عدم;\
	__left = __right = &__node;					\
\
	כלעוד ((__comp = (cmp)(elm, (head)->sph_root))) {		\
		אם (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			אם (__tmp == عدم)				\
				اكسر;					\
			אם ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				אם (SPLAY_LEFT((head)->sph_root, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} אחרת אם (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			אם (__tmp == عدم)				\
				اكسر;					\
			אם ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				אם (SPLAY_RIGHT((head)->sph_root, field) == عدم)\
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
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = عدم;\
	__left = __right = &__node;					\
\
	כלעוד (1) {							\
		אם (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			אם (__tmp == عدم)				\
				اكسر;					\
			אם (__comp < 0){				\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				אם (SPLAY_LEFT((head)->sph_root, field) == عدم)\
					اكسر;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} אחרת אם (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			אם (__tmp == عدم)				\
				اكسر;					\
			אם (__comp > 0) {				\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				אם (SPLAY_RIGHT((head)->sph_root, field) == عدم)\
					اكسر;				\
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
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? عدم	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	עבור ((x) = SPLAY_MIN(name, head);				\
	     (x) != عدم;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
بنية name {								\
	بنية type *rbh_root; /* root of the tree */			\
}

#define RB_INITIALIZER(root)						\
	{ عدم }

#define RB_INIT(root) עשה {						\
	(root)->rbh_root = عدم;					\
} כלעוד (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
بنية {								\
	بنية type *rbe_left;		/* left element */		\
	بنية type *rbe_right;		/* right element */		\
	بنية type *rbe_parent;	/* parent element */		\
	صحيح rbe_color;			/* node color */		\
}

#define RB_LEFT(elm, field)		(elm)->field.rbe_left
#define RB_RIGHT(elm, field)		(elm)->field.rbe_right
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_ROOT(head)			(head)->rbh_root
#define RB_EMPTY(head)			(RB_ROOT(head) == عدم)

#define RB_SET(elm, parent, field) עשה {					\
	RB_PARENT(elm, field) = parent;					\
	RB_LEFT(elm, field) = RB_RIGHT(elm, field) = عدم;		\
	RB_COLOR(elm, field) = RB_RED;					\
} כלעוד (0)

#define RB_SET_BLACKRED(black, red, field) עשה {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} כלעוד (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	עשה {} כלעוד (0)
#endif

#define RB_ROTATE_LEFT(head, elm, tmp, field) עשה {			\
	(tmp) = RB_RIGHT(elm, field);					\
	אם ((RB_RIGHT(elm, field) = RB_LEFT(tmp, field))) {		\
		RB_PARENT(RB_LEFT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	אם ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		אם ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		אחרת							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} אחרת								\
		(head)->rbh_root = (tmp);				\
	RB_LEFT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	אם ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} כלעוד (0)

#define RB_ROTATE_RIGHT(head, elm, tmp, field) עשה {			\
	(tmp) = RB_LEFT(elm, field);					\
	אם ((RB_LEFT(elm, field) = RB_RIGHT(tmp, field))) {		\
		RB_PARENT(RB_RIGHT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	אם ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		אם ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		אחרת							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} אחרת								\
		(head)->rbh_root = (tmp);				\
	RB_RIGHT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	אם ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} כלעוד (0)

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
	כלעוד ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		אם (parent == RB_LEFT(gparent, field)) {		\
			tmp = RB_RIGHT(gparent, field);			\
			אם (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				استمر;				\
			}						\
			אם (RB_RIGHT(parent, field) == elm) {		\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_RIGHT(head, gparent, tmp, field);	\
		} אחרת {						\
			tmp = RB_LEFT(gparent, field);			\
			אם (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				استمر;				\
			}						\
			אם (RB_LEFT(parent, field) == elm) {		\
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
attr فراغ								\
name##_RB_REMOVE_COLOR(بنية name *head, بنية type *parent, بنية type *elm) \
{									\
	بنية type *tmp;						\
	כלעוד ((elm == عدم || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_ROOT(head)) {					\
		אם (RB_LEFT(parent, field) == elm) {			\
			tmp = RB_RIGHT(parent, field);			\
			אם (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = RB_RIGHT(parent, field);		\
			}						\
			אם ((RB_LEFT(tmp, field) == عدم ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == عدم ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} אחרת {					\
				אם (RB_RIGHT(tmp, field) == عدم ||	\
				    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK) {\
					بنية type *oleft;		\
					אם ((oleft = RB_LEFT(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_RIGHT(head, tmp, oleft, field);\
					tmp = RB_RIGHT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				אם (RB_RIGHT(tmp, field))		\
					RB_COLOR(RB_RIGHT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				اكسر;					\
			}						\
		} אחרת {						\
			tmp = RB_LEFT(parent, field);			\
			אם (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				tmp = RB_LEFT(parent, field);		\
			}						\
			אם ((RB_LEFT(tmp, field) == عدم ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == عدم ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} אחרת {					\
				אם (RB_LEFT(tmp, field) == عدم ||	\
				    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) {\
					بنية type *oright;		\
					אם ((oright = RB_RIGHT(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_LEFT(head, tmp, oright, field);\
					tmp = RB_LEFT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				אם (RB_LEFT(tmp, field))		\
					RB_COLOR(RB_LEFT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				اكسر;					\
			}						\
		}							\
	}								\
	אם (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr بنية type *							\
name##_RB_REMOVE(بنية name *head, بنية type *elm)			\
{									\
	بنية type *child, *parent, *old = elm;			\
	صحيح color;							\
	אם (RB_LEFT(elm, field) == عدم)				\
		child = RB_RIGHT(elm, field);				\
	אחרת אם (RB_RIGHT(elm, field) == عدم)				\
		child = RB_LEFT(elm, field);				\
	אחרת {								\
		بنية type *left;					\
		elm = RB_RIGHT(elm, field);				\
		כלעוד ((left = RB_LEFT(elm, field)))			\
			elm = left;					\
		child = RB_RIGHT(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		אם (child)						\
			RB_PARENT(child, field) = parent;		\
		אם (parent) {						\
			אם (RB_LEFT(parent, field) == elm)		\
				RB_LEFT(parent, field) = child;		\
			אחרת						\
				RB_RIGHT(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} אחרת							\
			RB_ROOT(head) = child;				\
		אם (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		אם (RB_PARENT(old, field)) {				\
			אם (RB_LEFT(RB_PARENT(old, field), field) == old)\
				RB_LEFT(RB_PARENT(old, field), field) = elm;\
			אחרת						\
				RB_RIGHT(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} אחרת							\
			RB_ROOT(head) = elm;				\
		RB_PARENT(RB_LEFT(old, field), field) = elm;		\
		אם (RB_RIGHT(old, field))				\
			RB_PARENT(RB_RIGHT(old, field), field) = elm;	\
		אם (parent) {						\
			left = parent;					\
			עשה {						\
				RB_AUGMENT(left);			\
			} כלעוד ((left = RB_PARENT(left, field)));	\
		}							\
		اذهب color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	אם (child)							\
		RB_PARENT(child, field) = parent;			\
	אם (parent) {							\
		אם (RB_LEFT(parent, field) == elm)			\
			RB_LEFT(parent, field) = child;			\
		אחרת							\
			RB_RIGHT(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} אחרת								\
		RB_ROOT(head) = child;					\
color:									\
	אם (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	החזר (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr بنية type *							\
name##_RB_INSERT(بنية name *head, بنية type *elm)			\
{									\
	بنية type *tmp;						\
	بنية type *parent = عدم;					\
	صحيح comp = 0;							\
	tmp = RB_ROOT(head);						\
	כלעוד (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		אם (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		אחרת אם (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		אחרת							\
			החזר (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	אם (parent != عدم) {						\
		אם (comp < 0)						\
			RB_LEFT(parent, field) = elm;			\
		אחרת							\
			RB_RIGHT(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} אחרת								\
		RB_ROOT(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	החזר (عدم);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr بنية type *							\
name##_RB_FIND(بنية name *head, بنية type *elm)			\
{									\
	بنية type *tmp = RB_ROOT(head);				\
	صحيح comp;							\
	כלעוד (tmp) {							\
		comp = cmp(elm, tmp);					\
		אם (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		אחרת אם (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		אחרת							\
			החזר (tmp);					\
	}								\
	החזר (عدم);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr بنية type *							\
name##_RB_NFIND(بنية name *head, بنية type *elm)			\
{									\
	بنية type *tmp = RB_ROOT(head);				\
	بنية type *res = عدم;					\
	صحيح comp;							\
	כלעוד (tmp) {							\
		comp = cmp(elm, tmp);					\
		אם (comp < 0) {						\
			res = tmp;					\
			tmp = RB_LEFT(tmp, field);			\
		}							\
		אחרת אם (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		אחרת							\
			החזר (tmp);					\
	}								\
	החזר (res);							\
}									\
									\
/* ARGSUSED */								\
attr بنية type *							\
name##_RB_NEXT(بنية type *elm)					\
{									\
	אם (RB_RIGHT(elm, field)) {					\
		elm = RB_RIGHT(elm, field);				\
		כלעוד (RB_LEFT(elm, field))				\
			elm = RB_LEFT(elm, field);			\
	} אחרת {							\
		אם (RB_PARENT(elm, field) &&				\
		    (elm == RB_LEFT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		אחרת {							\
			כלעוד (RB_PARENT(elm, field) &&			\
			    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	החזר (elm);							\
}									\
									\
/* ARGSUSED */								\
attr بنية type *							\
name##_RB_PREV(بنية type *elm)					\
{									\
	אם (RB_LEFT(elm, field)) {					\
		elm = RB_LEFT(elm, field);				\
		כלעוד (RB_RIGHT(elm, field))				\
			elm = RB_RIGHT(elm, field);			\
	} אחרת {							\
		אם (RB_PARENT(elm, field) &&				\
		    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		אחרת {							\
			כלעוד (RB_PARENT(elm, field) &&			\
			    (elm == RB_LEFT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	החזר (elm);							\
}									\
									\
attr بنية type *							\
name##_RB_MINMAX(بنية name *head, صحيح val)				\
{									\
	بنية type *tmp = RB_ROOT(head);				\
	بنية type *parent = عدم;					\
	כלעוד (tmp) {							\
		parent = tmp;						\
		אם (val < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		אחרת							\
			tmp = RB_RIGHT(tmp, field);			\
	}								\
	החזר (parent);						\
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
	עבור ((x) = RB_MIN(name, head);					\
	     (x) != عدم;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	עבור ((x) = RB_MIN(name, head);					\
	    ((x) != عدم) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	עבור ((x) = RB_MAX(name, head);					\
	     (x) != عدم;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	עבור ((x) = RB_MAX(name, head);					\
	    ((x) != عدم) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
