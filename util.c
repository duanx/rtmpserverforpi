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

#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#define STOI(x) x-'0'

int getip(char *ip)
{
	/*x.x.x.x*/
	/*status     1:x 2:. 3:end*/
	int status,ret,index;
	int value,shift,i;
	i=ret=index=0;status=1;shift=24;
	while(status!=3){
		switch(status){
			case 1:
				/*atoi*/
				value=0;
				while(ip[index]!='.'&&ip[index]!='\0'){
					value=(ip[index]-'0')+value*10;
					index++;
				}
				/*end atoi*/
				ret=(ret|((value&0xff)<<shift));shift-=8;
				status=2;
				break;
			case 2:
				index++;
				if(i>=3)
					status=3;
				else{
					i++;
					status=1;
				}
				break;
		}
	}
	//struct in_addr ai={0};
	//ai.s_addr=ret;printf("%s\n",inet_ntoa(ai));
	return ret;
}
int strtoint(char *s)
{
	int i,l,v;
	l=strlen(s);
	i=v=0;
	while(i<l){
		v=v*10+STOI(s[i]);
		i++;
	}
	return v;
}
char * b16ton(char *data,unsigned short val)
{
	data[0]=val>>8;
	data[1]=val&0xff;
	return data+2;
}
char * b24ton(char *data,unsigned int val)
{
	data[0]=val>>16;
	data[1]=val>>8;
	data[2]=val&0xff;
	return data+3;
}
char * b32ton(char *data,unsigned int val)
{
	data[0]=val>>24;
	data[1]=val>>16;
	data[2]=val>>8;
	data[3]=val&0xff;
	return data+4;
}
unsigned short ntob16(char *data)
{
	unsigned short val;
	unsigned char *c=(unsigned char*)data;
	val = (c[0] << 8) | (c[1]);
	return val;
}
unsigned int ntob24(char *data)
{
	unsigned int val;
	unsigned char *c=(unsigned char*)data;
	val = (c[0] << 16) | (c[1] << 8) | c[2];
	return val;
}
unsigned int ntob32(char *data)
{
	unsigned int val;
	unsigned char *c=(unsigned char *)data;
	val = (c[0] << 24) | (c[1] << 16) | c[2]<<8|c[3];
	return val;
}
double ntob64(char *val)
{
	double n;
	unsigned char *p=(unsigned char*)&n;
	p[0]=val[7];
	p[1]=val[6];
	p[2]=val[5];
	p[3]=val[4];
	p[4]=val[3];
	p[5]=val[2];
	p[6]=val[1];
	p[7]=val[0];
	return n;
}
char * b64ton(char *data,double val)
{
	char *p=(char*)data;
	unsigned char *p2=(unsigned char*)&val;
	p[0]=p2[7];
	p[1]=p2[6];
	p[2]=p2[5];
	p[3]=p2[4];
	p[4]=p2[3];
	p[5]=p2[2];
	p[6]=p2[1];
	p[7]=p2[0];
	p+=8;
	return p;
}
long timems()
{
	struct timeval ts;
	gettimeofday(&ts,NULL);
	return ts.tv_sec*1000+ts.tv_usec/1000;
}
void vectorrandom(char *vec,int len)
{
	int i=0;
	while(i<len){
		vec[i]=rand()%256;
		i++;
	}
}
void list_add(list_t *head,list_t *item)
{
	head->pre->nxt=item;
	item->pre=head->pre;
	head->pre=item;
	item->nxt=head;
}
void list_del(list_t *item)
{
	item->pre->nxt=item->nxt;
	item->nxt->pre=item->pre;
}
void list_init(list_t *head)
{
	head->nxt=head->pre=head;
}
int list_empty(list_t *head)
{
	if(head->nxt==head)
		return 0;
	else
		return -1;
}
int list_find(list_t *head,list_t *l)
{
	int ret=-1;
	list_t *t1;
	t1=head->nxt;
	while(t1!=head){
		if(t1==l){
			ret=0;
			break;
		}
		t1=head->nxt;
	}
	return ret;
}
