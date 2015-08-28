/*
   Copyright (c) 2015 by duanx

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; If not, see <http://www.gnu.org/licenses/>.
   */
#ifndef _UTIL_H_
#define _UTIL_H_
#include <stdio.h>

/************************list**************************/
typedef struct list_s{
	struct list_s *pre,*nxt;
}list_t;
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(PTR,TYPE,MEMBER) ({	\
		typeof(((TYPE *)0)->MEMBER)*_ptr=PTR;		\
		(TYPE *)((char*)_ptr-offsetof(TYPE,MEMBER));})

void list_init(list_t *head);
int list_empty(list_t *head);
void list_add(list_t *head,list_t *item);
void list_del(list_t *item);
int list_find(list_t *head,list_t *l);
/************************end list**************************/


double ntob64(char *data);
unsigned int ntob32(char *data);
unsigned int ntob24(char *data);
unsigned short ntob16(char *data);
char * b64ton(char *data,double val);
char * b32ton(char *data,unsigned int val);
char * b24ton(char *data,unsigned int val);
char * b16ton(char *data,unsigned short val);
int strtoint(char *s);
long timems();
void vectorrandom(char *vec,int len);

#endif
