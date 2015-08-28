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
#ifndef _AMF_H_
#define _AMF_H_
#define number_maker 0
#define boolean_maker 1
#define string_maker 2
#define obj_maker 3
#define movieclip_maker 4
#define null_maker 5
#define undefine_maker 6
#define reference_maker 7
#define ecma_array_maker 8
#define obj_end_maker 9
#define string_array_maker 10
#define date_maker 11
#define long_string_maker 12
#define unsupport_maker 13
#define recordset_maker 14
#define xml_document_maker 15
#define typed_obj_maker 16

struct str{
	char *val;
	int len;
};
struct property;
struct obj{
	int num;
	struct property *props;
};
struct property{
	int maker;
	struct str name;
	union prop{
		double _numval;
		struct str _strval;
		struct obj _objval;
	}prop;
#define numval prop._numval
#define strval prop._strval
#define objval prop._objval
	struct property *pre,*nxt;
};
#define str_match(a1,a2)	((a1)->len == (a2)->len && !memcmp((a1)->val,(a2)->val,(a1)->len))
 
char * amf_encode_str(char *data,const struct str *val);
char * amf_encode_nameval(char *data,const struct str *name,const struct str *val);
char * amf_encode_num(char *data,double val);
char * amf_encode_namenumval(char *data,const struct str *name,double val);
char * amf_encode_nameboolean(char *data,const struct str *name,int val);
char * amf_encode_boolean(char *data,int val);
int amf_decode_boolean(char *data);
char * amf_decode_obj(char *data,struct obj *obj);
struct property * obj_getproperty(struct obj *obj,int index);
void property_uninit(struct property *head);

char * amf_decode_str(char *data,struct str *val);
char * amf_decode_nameval(char *data,struct str *name,struct str *val);
char * amf_decode_longstr(char *data,struct str *val);
double amf_decode_num(char *data);

#endif

