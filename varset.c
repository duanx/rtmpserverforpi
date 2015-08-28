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

#include "rtmpserver.h"
#include <string.h>
#include <stdlib.h>

bool varset_init(varset_t *var,int len)
{
	var->free=var->pool=malloc(len*sizeof(entry_t));
	if(!var->pool){
		rs_debug("varset malloc failed\n");
		return FALSE;
	}
	var->entrys=malloc(len*sizeof(entry_t*));
	if(!var->entrys){
		rs_debug("varset malloc failed\n");
		return FALSE;
	}
	var->cursize=0;
	var->hashsize=len;
	memset(var->pool,0,len*sizeof(entry_t));
	memset(var->entrys,0,len*sizeof(entry_t*));
	return TRUE;
}
static inline int tohash(varset_t *var,char *key)
{
	char *p=key;
	int hash=0;
	while(*p){
		hash+=*p;
		p++;
	}
	hash%=var->hashsize;
	return hash;
}
static entry_t *pop(varset_t *var)
{
	entry_t *e;
	if(var->cursize>=var->hashsize)
		return NULL;
	e=var->free;
	var->cursize++;
	var->free=var->free+1;
	return e;
}

static bool varset_put(varset_t *var,char *key,void *value,entrycls_t cls,int len)
{
	entry_t *e;
	int hash,keylen;
	if(var->cursize>=var->hashsize)
		return FALSE;
	hash=tohash(var,key);
	if(!(e=pop(var)))
		return FALSE;
	if(cls==ESTRING){
		if(len>127){
			strncpy(e->val._strval,value,127);
			e->val._strval[127]='\0';
		}else{
			strcpy(e->val._strval,value);
			e->val._strval[len]='\0';
		}
	}
	else if(cls==EDOUBLE)
		e->val._doubleval=*(double*)value;
	else if(cls==EBOOL)
		e->val._boolval=*(bool*)value;
	e->cls=cls;
	keylen=strlen(key)+1;
	if(keylen>32)
		keylen=32;
	memcpy(e->key,key,keylen);
	e->nxt=var->entrys[hash];
	var->entrys[hash]=e;
	return TRUE;
}

bool varset_putstr(varset_t *var,char *key,char *value,int len)
{
	return varset_put(var,key,value,ESTRING,len);
}
bool varset_putbool(varset_t *var,char *key,bool value)
{
	return varset_put(var,key,&value,EBOOL,0);
}
bool varset_putdouble(varset_t *var,char *key,double value)
{
	return varset_put(var,key,&value,EDOUBLE,0);
}
entry_t * varset_get(varset_t *var,char *key)
{
	entry_t *e;
	int hash;
	hash=tohash(var,key);
	e=var->entrys[hash];
	while(e){
		if(!strcmp(e->key,key))
			return e;
		e=e->nxt;
	}
	return NULL;
}
void varset_uninit(varset_t *var)
{
	free(var->pool);
	free(var->entrys);
	var->cursize=0;
	var->hashsize=0;
}
