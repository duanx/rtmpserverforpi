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

#include <string.h>
#include <stdlib.h>
#include "util.h"
#include "amf.h"

void property_uninit(struct property *head)
{
	struct property *p=head->nxt;
	struct property *p2;
	while(p!=head){
		p2=p;
		p=p->nxt;
		free(p2);
	}
	free(p);
}
void property_add(struct property *head,struct property *prop)
{
	head->pre->nxt=prop;
	prop->pre=head->pre;
	prop->nxt=head;
	head->pre=prop;
}
void property_init(struct property *prop)
{
	memset(prop,0,sizeof(struct property));
	prop->pre=prop->nxt=prop;
}
char * amf_encode_str(char *data,const struct str *val)
{
	int len;
	char *p=data;
	len=val->len;
	if(len<65535){
		*p++=string_maker;
		p=b16ton(p,len);
	}else{
		*p++=long_string_maker;
		p=b32ton(p,len);
	}
	memcpy(p,val->val,len);
	p+=len;
	return p;
}
char * amf_encode_num(char *data,double val)
{
	char *p=(char*)data;
	*p++=number_maker;
	p=b64ton(p,val);
	return p;
}

char * amf_decode_str(char *data,struct str *val)
{
	val->len=ntob16(data);
	data+=2;
	val->val=data;
	data+=val->len;
	return data;
}
char * amf_decode_longstr(char *data,struct str *val)
{
	val->len=ntob16(data);
	data+=4;
	val->val=data;
	data+=val->len;
	return data;
}
double amf_decode_num(char *data)
{
	double n=ntob64(data);
	return n;
}
char * amf_decode_obj(char *data,struct obj *obj)
{
	char *p=data;
	int maker;
	struct property *prop;
	/*init obj*/
	obj->num=0;
	obj->props=malloc(sizeof(struct property));
	prop=obj->props;
	memset(prop,0,sizeof(struct property));
	prop->pre=prop->nxt=prop;
	/*end init obj*/
	while(p[0]!=0||p[1]!=0||p[2]!=obj_end_maker){
		/*str at first if it was object*/
		prop=malloc(sizeof(struct property));
		property_init(prop);
		p=amf_decode_str(p,&prop->name);
		maker=*p++;
		prop->maker=maker;
		switch(maker){
			case number_maker:
				prop->numval=amf_decode_num(p);p+=8;
				break;
			case string_maker:
				p=amf_decode_str(p,&prop->strval);
				break;
			case obj_maker:
				p=amf_decode_obj(p,&prop->objval);
				break;
		}
		property_add(obj->props,prop);
		obj->num++;
	}
	if(obj_end_maker==ntob24(p))
		p+=3;
	return p;
}
char * amf_decode_nameval(char *data,struct str *name,struct str *val)
{
	char *p=data;
	p=amf_decode_str(data,name);
	p++;//maker
	p=amf_decode_str(data,val);
	return p;
}
char * amf_encode_nameval(char *data,const struct str *name,const struct str *val)
{
	char *p=data;
	p=b16ton(p,name->len);
	memcpy(p,name->val,name->len);
	p+=name->len;
	p=amf_encode_str(p,val);
	return p;
}
char * amf_encode_namenumval(char *data,const struct str *name,double val)
{
	int len;
	char *p=data;
	len=name->len;
	p=b16ton(p,len);
	memcpy(p,name->val,len);
	p+=len;
	p=amf_encode_num(p,val);
	return p;
}
char * amf_encode_nameboolean(char *data,const struct str *name,int val)
{
	int len;
	char *p=data;
	len=name->len;
	p=b16ton(p,len);
	memcpy(p,name->val,len);
	p+=len;
	p=amf_encode_boolean(p,val);
	return p;
}
int amf_decode_boolean(char *data)
{
	int b=*data;
	return b;
}
char * amf_encode_boolean(char *data,int val)
{
	*data++=boolean_maker;
	*data++ = val ? 0x01 : 0x00;
	return data;
}
struct property * obj_getproperty(struct obj *obj,int index)
{
	int i=0;
	struct property *head,*p;
	if(!obj)return NULL;
	head=obj->props;
	p=head->nxt;
	while(i<index&&p){
		p=p->nxt;
		i++;
	}
	if(i==index)
		return p;
	else
		return NULL;
}

#ifdef TEST
int main(int argc,char **argv)
{

	return 0;
}

#endif
