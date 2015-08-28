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
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct livecache_s{
	live_t *caches;
	int free;
	int cachesize;
}livecache_t;

static livecache_t g_livecache;
static list_t g_lives;

bool livecache_init(int caches)
{
	live_t *l;
	if(g_livecache.cachesize>0){
		printf("livecache already exist\n");
		exit(-1);
	}
	l=malloc(sizeof(live_t)*caches);
	if(!l){
		printf("malloc livecache failed\n");
		return FALSE;
	}
	memset(l,0,sizeof(live_t)*caches);
	g_livecache.caches=l;
	g_livecache.free=0;
	g_livecache.cachesize=caches;
	list_init(&g_lives);
	return TRUE;
}
void livecache_uninit()
{
	if(!g_livecache.cachesize)
		return;
	free(g_livecache.caches);
	g_livecache.cachesize=0;
}
live_t * livecache_get()
{
	live_t *l;
	if(g_livecache.free>=g_livecache.cachesize){
		printf("couldn't get live from livecache\n");
		exit(-1);
	}
	l=&g_livecache.caches[g_livecache.free];
	if(l->flags&LIVE_ENABLE){
		printf("live enabled from livecache\n");
		exit(-1);
	}
	memset(l,0,sizeof(live_t));
	l->flags|=LIVE_ENABLE;
	g_livecache.free++;
	while(g_livecache.free<g_livecache.cachesize){
		if(!g_livecache.caches[g_livecache.free].flags&LIVE_ENABLE)
			break;
		g_livecache.free++;
	}
	if(g_livecache.free>=g_livecache.cachesize){
		printf("livecache_get failed\n");
		exit(-1);
	}
	list_init(&l->listeners);
	list_add(&g_lives,&l->active);
	return l;
}
void livecache_put(live_t *l)
{
	int index;
	if(!l->flags&LIVE_ENABLE)
		return;
	index=l-g_livecache.caches;
	if(index<0||index>=g_livecache.cachesize){
		printf("livecache_put failed\n");
		exit(-1);
	}
	g_livecache.free=index;
	list_del(&l->active);
	l->flags&=~LIVE_ENABLE;
}
static bool live_needread(live_t *l,unsigned int rindex)
{
	if(rindex!=l->windex){
		return TRUE;
	}
	else
		return FALSE;
}

void live_active()
{
	live_t *l;
	list_t *list,*listenlist;
	rtransfer_t *rtt;
	transferbuf_t *tbuf;

	list=g_lives.nxt;
	while(list!=&g_lives){
		l=container_of(list,live_t,active);
		rtt=l->publish;
		if(rtt&&(rtt->flags&LIVEDATA_PUT)){
			//printf("to live len:%d\n",rtt->recvbuf.offset);
			if(!live_writefromtbuf(l,&rtt->recvbuf,&rtt->rp.rtm,FALSE)){
				rtt->flags&=~LIVEDATA_PUT;
				rtmpmsg_init(&rtt->rp.rtm);
				transferbuf_init(&rtt->recvbuf,BUFSIZE);
			}
		}
		listenlist=l->listeners.nxt;
		while(listenlist!=&l->listeners){
			rtt=container_of(listenlist,rtransfer_t,livelist);
			if(rtt->flags&TRAN_UPDATE||live_needread(l,rtt->rindex)||rtt->flags&TRAN_WRITE){
				usleep(5000);
				goto j1;
			}
			//printf("rindex:%d windex:%d\n",rtt->rindex,l->windex);
			tbuf=&rtt->sndbuf;
			transferbuf_init(tbuf,BUFSIZE);
			transferbuf_writefromlive(tbuf,l,rtt);
j1:
			listenlist=listenlist->nxt;
		}
		list=list->nxt;
	}
}
static bool live_rindex_update(int orgwindex,int len,int rindex,int windex)
{
	if(orgwindex==rindex)
		return FALSE;
	if(orgwindex<rindex){
		if((orgwindex+len)>=rindex)
			return TRUE;
		else
			return FALSE;
	}else{
		if((orgwindex+len)%LIVEBUFSIZE>=rindex&&windex<orgwindex)
			return TRUE;
		else
			return FALSE;

	}
}
static bool shouldupdate_rindex(live_t *l,int updatewindex,int len)
{
	list_t *list;
	rtransfer_t *rtt;
	list=l->listeners.nxt;
	while(list!=&l->listeners){
		rtt=container_of(list,rtransfer_t,livelist);
		if(!live_rindex_update(l->windex,len,rtt->rindex,updatewindex)){
			return TRUE;
		}
		list=list->nxt;
	}
	return FALSE;
}
static int readbh(live_t *l,rtransfer_t *rtt,int *len,int upper)
{
	int bhlen;
	bufhead_t *bh,bh2;
	bhlen=sizeof(bufhead_t);
	if(upper<bhlen){
		memcpy((char*)&bh2,l->buf+rtt->rindex,upper);
		memcpy(((char*)&bh2)+upper,l->buf,bhlen-upper);
		rtt->rindex=(rtt->rindex+bhlen)%LIVEBUFSIZE;
		upper=LIVEBUFSIZE-rtt->rindex;
		*len=bh2.payload_len;
		bh=&bh2;
	}else{
		bh=(bufhead_t*)(l->buf+rtt->rindex);
		rtt->rindex=(rtt->rindex+bhlen)%LIVEBUFSIZE;
		upper-=bhlen;
		*len=bh->payload_len;
	}
	if(bh->ver!=BH_VER){
		printf("BH_VER check3 failed\n");
		exit(-1);
	}
	return upper;
}
static int readtbuf(rtransfer_t *rtt,int len,int upper)
{
	if(upper<=len)
		upper=LIVEBUFSIZE-(len-upper);
	else
		upper-=len;
	rtt->rindex=(rtt->rindex+len)%LIVEBUFSIZE;
	return upper;
}
static void _update_rindex(live_t *l,int updatewindex,rtransfer_t *rtt)
{
	int bhlen,len,upper,orgrindex;
	bufhead_t *bh;
	len=LIVEBUFSIZE;
	orgrindex=rtt->rindex;
	bhlen=sizeof(bufhead_t);
	if(rtt->rindex<=updatewindex){
		bh=(bufhead_t*)(l->buf+rtt->rindex);
		if(bh->ver!=BH_VER){
			printf("BH_VER check failed\n");
			exit(-1);
		}
		//printf("go through:%d\n",bh->payload_len);
		rtt->rindex=(rtt->rindex+bhlen+bh->payload_len)%len;
	}else{
		//upper
		int payload_len;
		upper=len-rtt->rindex;
		upper=readbh(l,rtt,&payload_len,upper);
		readtbuf(rtt,payload_len,upper);
	}
	rs_log(RS_DEBUG,"windex from %d to %d ,rindex from %d to %d\n",l->windex,updatewindex,orgrindex,rtt->rindex);
}
static void update_rindex(live_t *l,int updatewindex,int len)
{
	list_t *list;
	rtransfer_t *rtt;
	list=l->listeners.nxt;
	while(list!=&l->listeners){
		rtt=container_of(list,rtransfer_t,livelist);
		while(!live_rindex_update(l->windex,len,rtt->rindex,updatewindex)){
			_update_rindex(l,updatewindex,rtt);
		}
		list=list->nxt;
	}
}

static int writebh(live_t *l,int payload_len,int upper,rtmpmsg_t *msg)
{
	int bhlen;
	bufhead_t *bh,bh2;
	bhlen=sizeof(bufhead_t);
	if(upper<bhlen){
		bh2.ver=BH_VER;
		bh2.payload_len=payload_len;
		bh2.type=msg->type;
		bh2.chunkid=msg->chunkid;
		bh2.ts=msg->ts;
		memcpy(l->buf+l->windex,(char*)&bh2,upper);
		memcpy(l->buf,(char*)&bh2+upper,bhlen-upper);
		l->windex=(l->windex+bhlen)%LIVEBUFSIZE;
		upper=LIVEBUFSIZE-l->windex;
	}else{
		bh=(bufhead_t*)(l->buf+l->windex);
		bh->ver=BH_VER;
		bh->payload_len=payload_len;
		bh->chunkid=msg->chunkid;
		bh->type=msg->type;
		bh->ts=msg->ts;
		l->windex+=bhlen;
		upper-=bhlen;
	}
	return upper;
}
static int writetbuf(live_t *l,char *buf,int len,int upper)
{
	if(upper<len){
		memcpy(l->buf+l->windex,buf,upper);
		memcpy(l->buf,buf+upper,len-upper);
		l->windex=(l->windex+len)%LIVEBUFSIZE;
		upper=LIVEBUFSIZE-l->windex;
	}else{
		memcpy(l->buf+l->windex,buf,len);
		l->windex=(l->windex+len)%LIVEBUFSIZE;
		upper-=len;
	}
	return upper;
}
bool live_writefromtbuf(live_t *l,transferbuf_t *tbuf,rtmpmsg_t *msg,bool overwrite)
{
	int len,upper,orgwindex,updatewindex;
	len=LIVEBUFSIZE;
	upper=len-l->windex;
	orgwindex=l->windex;
	updatewindex=(orgwindex+sizeof(bufhead_t)+tbuf->offset)%LIVEBUFSIZE;
	if(!shouldupdate_rindex(l,updatewindex,sizeof(bufhead_t)+tbuf->offset)){
		if(overwrite){
			if(!(l->flags&LIVE_SNDDELAY)){
				l->flags|=LIVE_SNDDELAY;
				rs_log(RS_WARN,"send delay,receive waiting......\n");
			}
			return FALSE;
		}else{
			update_rindex(l,updatewindex,sizeof(bufhead_t)+tbuf->offset);
			upper=writebh(l,tbuf->offset,upper,msg);
			upper=writetbuf(l,tbuf->buf,tbuf->offset,upper);
		}
	}else{
		if(overwrite&&l->flags&LIVE_SNDDELAY){
			l->flags&=~LIVE_SNDDELAY;
			rs_log(RS_WARN,"send delay resume......\n");
		}
		upper=writebh(l,tbuf->offset,upper,msg);
		upper=writetbuf(l,tbuf->buf,tbuf->offset,upper);
	}
	return TRUE;
	//printf("to windex:%d\n",l->windex);
}
live_t * live_find(char *path)
{
	live_t *l;
	list_t *list;
	list=g_lives.nxt;
	while(list!=&g_lives){
		l=container_of(list,live_t,active);
		if(!strcmp(l->path,path))
			return l;
		list=list->nxt;
	}
	return NULL;
}
inline bool livealone(live_t *l)
{
	if(!l){
		printf("livealone failed\n");
		exit(-1);
	}
	if(!l->publish&&!list_empty(&l->listeners))
		return TRUE;
	else
		return FALSE;
}
