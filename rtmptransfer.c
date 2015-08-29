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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "amf.h"
#include "util.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define RTMP_C1_LEN 1536
#define RTMP_VERSION 0x3
#define RECVTIMEOUT 10000
#define CHUNKSIZE 128

#define _sstr(x) {x,sizeof(x)-1}
#define sstr(x) static const struct str str_##x=_sstr(#x)
/*
   const static char g_publish_type[3][]={
   "live","record","append"
   };
   */
static rtmp_t g_rtmp;

sstr(_result);
sstr(_error);
sstr(level);//level
sstr(onStatus);
sstr(status);
sstr(warning);
sstr(error);
sstr(code);//code
static const struct str str_code_result=_sstr("NetConnection.Connect.Success");
static const struct str str_publish_start=_sstr("NetStream.Publish.Start");
static const struct str str_play_start=_sstr("NetStream.Play.Start");
static const struct str str_seek_notify=_sstr("NetStream.Seek.Notify");
static const struct str str_publish_fail=_sstr("NetStream.Publish.Failed");
static const struct str str_play_fail=_sstr("NetStream.Play.Failed");
sstr(description);//description
static const struct str str_desc_result=_sstr("Connection successed");
static const struct str str_netstream_desc_result=_sstr("Netstream successed");
static const struct str str_netstream_desc_failresult=_sstr("Netstream failed");

typedef enum transferstatus_s{
	SHUTDOWN=0,
	FINISH,
	PROCESSING,
	FAILED=-1
}transferstatus_t;

rtransfer_t *gtransfer,*gfree;
int gtransfersize,curtransfersize;

static inline void _forsnd(rtmpmsg_t *rtm)
{
	rtm->chunkindex=0; 
	rtm->chunkoffset=0;
	rtm->chunktotalsize=(rtm->payload_len+rtm->chunksize-1)/rtm->chunksize;
}
static void rtmpmsg_forsnd_area(rtmpmsg_t *rtm,area_t *at)
{
	rtm->payload_len=at->offset-at->offset_op;
	_forsnd(rtm);
}
static void rtmpmsg_forsnd(rtmpmsg_t *rtm,transferbuf_t *sndbuf)
{
	rtm->payload_len=sndbuf->offset-sndbuf->offset_op;
	_forsnd(rtm);
}
static char * ctrltype_write(ctrltype_t ct,rtmpmsg_t *msg,char *data,char *edata)
{
	switch(ct){
		default:

			break;
		case	STREAM_BEGIN:
			if(data+5>edata){
				rs_log(RS_ERROR,"ctrltype_write failed(stream_begin)\n");
				exit(-1);
			}
			data=b16ton(data,ct);
			data=b32ton(data,msg->streamid);
			break;
		case STREAM_EOF:
			if(data+5>edata){
				rs_log(RS_ERROR,"ctrltype_write failed(stream_eof)\n");
				exit(-1);
			}
			data=b16ton(data,ct);
			data=b32ton(data,msg->streamid);
			break;
	}
	return data;
}

static char * rtmpchunk_set_basicheader(rtmpchunk_t *rc,char *p)
{
	*p=(unsigned char)rc->type<<SHIFT_CTYPE;
	if(rc->chunkid<64){
		*p|=(unsigned char)(rc->chunkid&0x3f);
		p++;
	}else if(rc->chunkid<320){
		p++;
		*p=rc->chunkid-64;
		p++;
	}else{
		*p|=0x1;
		p++;
		p=b16ton(p,rc->chunkid-64);
	}
	return p;
}
static inline int getheaderlen(rtmpchunk_t *rc,int ts)
{
	int headerlen;
	if(rc->chunkid<64)
		headerlen=1;
	else if(rc->chunkid<320){
		headerlen=2;
	}else
		headerlen=3;
	switch(rc->type){
		case TYPE0:
			headerlen+=TYPE0_LEN;
			if(ts>0xffffff)
				headerlen+=4;
			break;
		case TYPE1:
			headerlen+=TYPE1_LEN;
			if(ts>0xffffff)
				headerlen+=4;
			break;
		case TYPE2:
			headerlen+=TYPE2_LEN;
			if(ts>0xffffff)
				headerlen+=4;
			break;
		case TYPE3:
			break;
	}
	return headerlen;
}

static inline char * _setheader(rtmpchunk_t *rc,char *p,rtmpmsg_t *msg)
{
	p=rtmpchunk_set_basicheader(rc,p);
	switch(rc->type){
		case TYPE0:
			if(msg->ts>=0xffffff)
				p=b24ton(p,0xffffff);
			else
				p=b24ton(p,msg->ts);
			p=b24ton(p,msg->payload_len);
			*p++=msg->type;
			p=b32ton(p,msg->streamid);
			if(msg->ts>=0xffffff)
				p=b32ton(p,msg->ts);
			break;
		case TYPE1:
			if(msg->ts>=0xffffff)
				p=b24ton(p,0xffffff);
			else
				p=b24ton(p,msg->ts);
			p=b24ton(p,msg->payload_len);
			*p++=msg->type;
			if(msg->ts>=0xffffff)
				p=b32ton(p,msg->ts);
			break;
		case TYPE2:
			if(msg->ts>=0xffffff){
				p=b24ton(p,0xffffff);
				p=b32ton(p,msg->ts);
			}else
				p=b24ton(p,msg->ts);
			break;
		case TYPE3:

			break;
	}
	return p;
}
static void rtmpchunk_setheader_chunk(rtmpchunk_t *rc,rtmpmsg_t *msg)
{
	char *p;
	p=rc->header;
	p=_setheader(rc,p,msg);
	rc->headerlen=p-rc->header;
}
static int rtmpchunk_setheader_area(rtmpchunk_t *rc,rtmpmsg_t *msg,area_t *at)
{
	int headerlen;
	char *p;
	headerlen=getheaderlen(rc,msg->ts);
	p=at->payload+at->offset_op-headerlen;
	at->offset_op-=headerlen;
	_setheader(rc,p,msg);
	return headerlen;
}

static int rtmpchunk_setheader(rtmpchunk_t *rc,rtmpmsg_t *msg,transferbuf_t *sbuf)
{
	int headerlen;
	char *p;
	headerlen=getheaderlen(rc,msg->ts);
	p=sbuf->buf+sbuf->offset_op-headerlen;
	sbuf->offset_op-=headerlen;
	_setheader(rc,p,msg);
	return headerlen;
}

static int _recv(int fd,char *buf,int len)
{
	int c;
	struct sockaddr_in s_addr;
	socklen_t sl;
	sl=sizeof(s_addr);
	c=recvfrom(fd,buf,len,0,(struct sockaddr*)&s_addr,&sl);
	if(c<0){
		if(errno!=EAGAIN&&errno!=EWOULDBLOCK){
			rs_log(RS_DEBUG,"_recv len:%d c:%d\n",len,c);
			perror("recvfrom(_recv)");
			if(len<=0)
				exit(-1);
		}
	}
	return c;
}
static int _snd(int fd,char *buf,int len,raddr_t *addr)
{
	ssize_t c=0;
	struct sockaddr_in s_addr;
	s_addr.sin_family=AF_INET;
	s_addr.sin_port=htons(addr->port);
	s_addr.sin_addr.s_addr=htonl(addr->ip);
	c=sendto(fd,buf,len,0,(struct sockaddr*)&s_addr,sizeof(s_addr));
	if(c<0){
		if(errno!=EAGAIN&&errno!=EWOULDBLOCK){
			rs_log(RS_DEBUG,"_snd len:%d c:%d\n",len,c);
			perror("sendto(_snd)");
			if(errno==EPIPE)
				c=0;
		}
	}
	return c;
}
void rs_update(rs_t *rs,rtransfer_t *rtt)
{
	list_t *list;
	list=rs->transfer.nxt;
	while(list!=&rs->transfer){
		rtt=container_of(list,rtransfer_t,rttlist);
		if(!(rtt->flags&TRAN_UPDATE))
			goto j1;
		rtt->ev.events=0;
		if(rtt->flags&TRAN_WRITE){
			rtt->ev.events|=EPOLLOUT;
		}else
			rtt->ev.events&=~EPOLLOUT;
		if(rtt->flags&TRAN_READ)
			rtt->ev.events|=EPOLLIN;
		else{
			rtt->ev.events&=~EPOLLIN;
		}
		if(epoll_ctl(rs->epoll_fd,EPOLL_CTL_MOD,rtt->fd,&rtt->ev)<0){
			perror("epoll_ctl");
			exit(-1);
		}
		rtt->flags&=~TRAN_UPDATE;
j1:
		list=list->nxt;
	}
}

bool rtransfer_preinit()
{
	gtransfersize=GTRANSFER_SIZE;
	gfree=gtransfer=malloc(sizeof(rtransfer_t)*gtransfersize);
	if(!gtransfer){
		rs_debug("preinit malloc failed\n");
		return FALSE;
	}
	memset(gfree,0,sizeof(rtransfer_t)*gtransfersize);
	curtransfersize=0;
	g_rtmp.chunksize=CHUNKSIZE;
	g_rtmp.winsize=WINSIZE;
	g_rtmp.streamids=1;
	return TRUE;
}

void transferbuf_writechunk(transferbuf_t *tbuf,rtmpmsg_t *msg,char *payload,int payload_len)
{
	rtmpchunk_t chunk;
	chunk.chunkid=msg->chunkid;
	chunk.type=TYPE0;
	rtmpchunk_setheader_chunk(&chunk,msg);
	transferbuf_write(tbuf,chunk.header,chunk.headerlen);
	transferbuf_write(tbuf,payload,payload_len);
}
rtransfer_t * rtransfer_get()
{
	rtransfer_t *cur;
	if(curtransfersize>=gtransfersize){
		rs_log(RS_ERROR,"exceed max transfer size..................\n");
		return NULL;
	}
	cur=gfree;
	memset(cur,0,sizeof(*cur));
	cur->flags|=TRAN_STATUS;
	curtransfersize++;
	if(curtransfersize>=gtransfersize)
		gfree=NULL;
	else{
		int end=gtransfer+gtransfersize-1-gfree;
		int i=0;
		while(i<end){
			if(!(gfree[i].flags&TRAN_STATUS)){
				gfree=gfree+i;
				break;
			}
			i++;
		}
		if(i==end){
			end=gfree-gtransfer;
			i=0;
			while(i<end){
				if(!(gfree[i].flags&TRAN_STATUS)){
					gfree=gfree+i;
					break;
				}

				i++;
			}
			if(i==end){
				rs_log(RS_ERROR,"rtransfer_get failed\n");
				return NULL;
			}
		}
	}
	return cur;
}
void rtransfer_put(rtransfer_t *rtt)
{
	curtransfersize--;
	rtt->flags&=~TRAN_STATUS;
	if(rtt<gfree)
		gfree=rtt;
}
void rtransfer_return(rs_t *rs,rtransfer_t *rtt)
{
	list_del(&rtt->rttlist);
	if(epoll_ctl(rs->epoll_fd,EPOLL_CTL_DEL,rtt->fd,&rtt->ev)<0){
		perror("epoll_ctl");
	}
	close(rtt->fd);
	transfer_removefromlive(rtt);
	varset_uninit(&rtt->rp.varset);
	chunkset_uninit(&rtt->rp.cs);
	rtt->ev.events=0;
	rtransfer_put(rtt);
}

void rtransfer_postuninit()
{
	free(gtransfer);
	gtransfersize=curtransfersize=0;
}

rtransfer_t *rtransfer_findlisten()
{
	int i=0;
	while(i<gtransfersize){
		if(gtransfer[i].flags&TRAN_LISTEN)
			break;
		i++;
	}
	if(i>=gtransfersize){
		rs_log(RS_ERROR,"can't find listener\n");
		return NULL;
	}else
		return &gtransfer[i];
}
int handshake1(rtransfer_t *rtt)
{
	unsigned int uptime;
	char version;
	char *rbuf,*wbuf;
	unsigned int time;
	rtmpr_t *rp;
	rp=&rtt->rp;
	rbuf=rtt->recvbuf.buf;
	wbuf=rtt->sndbuf.buf;
	rbuf++;
	uptime=*(int*)rbuf;
	rp->cuptime=uptime;
	rbuf+=4;
	uptime=*(int*)rbuf;
	rbuf+=4;
	memcpy(rp->crandomecho,rbuf,RTMP_C1_LEN-8);
	rs_log(RS_DEBUG,"c0,c1\n");
	transferbuf_init(&rtt->sndbuf,RTMP_C1_LEN+1+RTMP_C1_LEN);
	version=RTMP_VERSION;
	transferbuf_write(&rtt->sndbuf,&version,1);wbuf++;
	uptime=rsystime();
	transferbuf_write(&rtt->sndbuf,(char*)&uptime,4);
	rp->suptime=uptime;
	wbuf+=4;
	/*zero*/
	uptime=0;
	transferbuf_write(&rtt->sndbuf,(char*)&uptime,4);
	wbuf+=4;
	/*end zero*/
	vectorrandom(rp->srandomecho,RTMP_C1_LEN-8);
	transferbuf_write(&rtt->sndbuf,rp->srandomecho,RTMP_C1_LEN-8);
	time=rp->cuptime;
	/*time1*/
	transferbuf_write(&rtt->sndbuf,(char*)&time,4);
	/*time2*/
	time=0;
	transferbuf_write(&rtt->sndbuf,(char*)&time,4);
	/*end time2*/
	transferbuf_write(&rtt->sndbuf,(char*)rp->crandomecho,RTMP_C1_LEN-8);

	rp->status=SHANDSHAKE;
	rtt->flags|=TRAN_WRITE;
	rtt->flags|=TRAN_UPDATE;
	transferbuf_init(&rtt->recvbuf,RTMP_C1_LEN);
	return 0;
}
int handshake2(rtransfer_t *rtt)
{
	char *rbuf;
	rtmpr_t *rp;
	rp=&rtt->rp;
	rbuf=rtt->recvbuf.buf;
	unsigned int time;
	char randomecho[RTMP_C1_LEN-8];
	time=*(int*)rbuf;
	rs_log(RS_DEBUG,"time1:%d\n",time);
	rbuf+=4;
	time=*(int*)rbuf;
	rs_log(RS_DEBUG,"time2:%d\n",time);
	rbuf+=4;
	memcpy(randomecho,rbuf,RTMP_C1_LEN-8);
	if(memcmp(randomecho,rp->srandomecho,RTMP_C1_LEN-8)){
		rs_log(RS_WARN,"match randomecho failed\n");
		return FAILED;
	}
	rs_log(RS_DEBUG,"c2\n");
	rp->status=SHANDSHAKED;
	return 0;
}

static void writestreameof(list_t *head)
{
	rtransfer_t *rtt;
	list_t *list;
	rtmpmsg_t *msg;
	transferbuf_t *recvbuf;

	list=head->nxt;
	while(list!=head){
		rtt=container_of(list,rtransfer_t,livelist);
		recvbuf=&rtt->recvbuf;
		msg=&rtt->rp.rtm;
		rtmpmsg_init(msg);
		msg->type=TCONTROLMSG;
		msg->payload_len=6;
		msg->chunkid=0x2;
		msg->streamid=rtt->rp.streamid;
		transferbuf_init(recvbuf,BUFSIZE);
		ctrltype_write(STREAM_EOF,msg,recvbuf->buf,recvbuf->buf+5);
		recvbuf->offset+=6;
		live_writefromtbuf(rtt->live,&rtt->recvbuf,msg,TRUE);
		rs_warn("send player fd:%d the STREAM_EOF of control msg,streamid:%d\n",rtt->fd,msg->streamid);
		rtmpmsg_init(msg);
		transferbuf_init(recvbuf,BUFSIZE);
		list=list->nxt;
	}
}

int clientdeletestream(rtransfer_t *rtt)
{
	char *rbuf;
	double num,savenum,streamid;
	bool boolval;
	live_t *l;
	rtmpr_t *rp;
	rp=&rtt->rp;
	rbuf=rtt->recvbuf.buf;
	unsigned char maker;
	struct str name,val;

	maker=*rbuf++;
	l=rtt->live;
	if(maker!=string_maker){
		rs_log(RS_WARN,"parse str maker failed\n");
		return -1;
	}
	rbuf=amf_decode_str(rbuf,&name);
	maker=*rbuf++;
	if(maker!=number_maker){
		rs_log(RS_WARN,"parse num maker failed\n");
		return -1;
	}
	savenum=amf_decode_num(rbuf);rbuf+=8;
	rs_log(RS_DEBUG,"deletestream\n");
	rs_log(RS_DEBUG,"txn:%lf\n",savenum);
	if(strcmp(name.val,"deleteStream"))
		return -1;
	maker=*rbuf++;
	if(maker!=obj_maker&&maker!=null_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	if(maker==obj_maker){
		while(1){
			if(!*rbuf&&!*(rbuf+1)&&*(rbuf+2)==obj_end_maker){
				rbuf+=3;
				break;
			}
			rbuf=amf_decode_str(rbuf,&name);
			maker=*rbuf++;
			switch(maker){
				case string_maker:
					rbuf=amf_decode_str(rbuf,&val);
					rs_log(RS_DEBUG,"%s=%s\n",name.val,val.val);
					varset_putstr(&rp->varset,name.val,val.val,val.len);
					break;
				case number_maker:
					num=amf_decode_num(rbuf);rbuf+=8;
					rs_log(RS_DEBUG,"%s=%f\n",name.val,num);
					varset_putdouble(&rp->varset,name.val,num);
					break;
				case boolean_maker:
					boolval=*rbuf++;
					rs_log(RS_DEBUG,"%s=%d\n",name.val,boolval);
					varset_putbool(&rp->varset,name.val,boolval);
					break;
				default:
					rs_log(RS_DEBUG,"can't support this maker yet\n");
					break;
			}
		}
	}
	maker=*rbuf++;
	if(maker!=number_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	streamid=amf_decode_num(rbuf);rbuf+=8;
	if(streamid!=rtt->rp.streamid){
		rs_log(RS_DEBUG,"deletestreamid:f failed,rtt streamid:%f\n",streamid,rtt->rp.streamid);
		return -1;
	}
	if(!transfer_removefromlive(rtt)){
		if(list_empty(&l->listeners)){
			writestreameof(&l->listeners);
		}
	}

	rp->status=SINIT;
	rtmpmsg_init(&rtt->rp.rtm);
	transferbuf_init(&rtt->recvbuf,BUFSIZE);
	chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);

	return 0;
}

int clientcreatestream(rtransfer_t *rtt)
{
	char *rbuf,*wbuf;
	double num,savenum;
	bool boolval;

	rtmpr_t *rp;
	rp=&rtt->rp;
	rbuf=rtt->recvbuf.buf;
	transferbuf_t *sndbuf;
	unsigned char maker;
	struct str name,val;

	sndbuf=&rtt->sndbuf;
	maker=*rbuf++;
	if(maker!=string_maker){
		rs_log(RS_WARN,"parse str maker failed\n");
		return -1;
	}
	rbuf=amf_decode_str(rbuf,&name);
	maker=*rbuf++;
	if(maker!=number_maker){
		rs_log(RS_WARN,"parse num maker failed\n");
		return -1;
	}
	savenum=amf_decode_num(rbuf);rbuf+=8;
	rs_log(RS_DEBUG,"createstream\n");
	rs_log(RS_DEBUG,"txn:%lf\n",savenum);
	if(strcmp(name.val,"createStream"))
		return -1;
	maker=*rbuf++;
	if(maker!=obj_maker&&maker!=null_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	if(maker==obj_maker){
		while(1){
			if(!*rbuf&&!*(rbuf+1)&&*(rbuf+2)==obj_end_maker)
				break;
			rbuf=amf_decode_str(rbuf,&name);
			maker=*rbuf++;
			switch(maker){
				case string_maker:
					rbuf=amf_decode_str(rbuf,&val);
					rs_log(RS_DEBUG,"%s=%s\n",name.val,val.val);
					varset_putstr(&rp->varset,name.val,val.val,val.len);
					break;
				case number_maker:
					num=amf_decode_num(rbuf);rbuf+=8;
					rs_log(RS_DEBUG,"%s=%f\n",name.val,num);
					varset_putdouble(&rp->varset,name.val,num);
					break;
				case boolean_maker:
					boolval=*rbuf++;
					rs_log(RS_DEBUG,"%s=%d\n",name.val,boolval);
					varset_putbool(&rp->varset,name.val,boolval);
					break;
				default:
					rs_log(RS_DEBUG,"can't support this maker yet\n");
					break;
			}
		}
	}
	transferbuf_init(&rtt->sndbuf,BUFSIZE);
	transferbuf_use(&rtt->sndbuf,MSG_HEADER_MAX);
	wbuf=amf_encode_str(sndbuf->buf+sndbuf->offset,&str__result);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	num=savenum;
	wbuf=amf_encode_num(sndbuf->buf+sndbuf->offset,num);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);

	maker=null_maker;
	transferbuf_write(sndbuf,(char*)&maker,1);

	num=g_rtmp.streamids++;
	rp->streamid=num;
	wbuf=amf_encode_num(sndbuf->buf+sndbuf->offset,num);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);

	rp->status=SCREATESTREAM;
	//rtt->flags|=(TRAN_WRITE|TRAN_UPDATE);
	rtt->flags|=TRAN_WRITE;
	rtt->flags|=TRAN_UPDATE;

	rtmpmsg_init(&rtt->rp.rtm);
	transferbuf_init(&rtt->recvbuf,BUFSIZE);
	chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
	rtt->rp.rtmsnd=rtt->rp.rtm;
	rtmpmsg_forsnd(&rtt->rp.rtmsnd,&rtt->sndbuf);

	return 0;
}

static int preclientconnectres(rtransfer_t *rtt)
{
	rtmpmsg_t *msg,msg1;
	msg=&msg1;
	char ctrlmsg[6],val[4];
	*msg=rtt->rp.rtmsnd;
	transferbuf_init(&rtt->sndbuf,BUFSIZE);

	rtmpmsg_init(msg);
	msg->type=TWINDOW_ACKNOWLEDGEMENT;
	msg->payload_len=sizeof(int);
	msg->chunkid=0x2;
	msg->streamid=0;
	b32ton(val,msg->winsize);
	transferbuf_writechunk(&rtt->sndbuf,msg,val,msg->payload_len);

	rtmpmsg_init(msg);
	msg->type=TPEER_BANDWIDTH;
	msg->payload_len=sizeof(int)+1;
	msg->chunkid=0x2;
	msg->streamid=0;
	b32ton(val,msg->peerbandwidth);
	transferbuf_writechunk(&rtt->sndbuf,msg,val,sizeof(int));
	val[0]=DYNAMIC;
	transferbuf_write(&rtt->sndbuf,val,1);

	ctrltype_write(STREAM_BEGIN,msg,ctrlmsg,ctrlmsg+5);
	rtmpmsg_init(msg);
	msg->type=TCONTROLMSG;
	msg->payload_len=6;
	msg->chunkid=0x2;
	msg->streamid=0;
	transferbuf_writechunk(&rtt->sndbuf,msg,ctrlmsg,msg->payload_len);
	return transferbuf_snd(rtt,&rtt->sndbuf,rtt->sndbuf.offset);
}

int clientconnectres(rtransfer_t *rtt)
{
	char *rbuf,*wbuf;
	double num;
	bool boolval;

	rtmpr_t *rp;
	rp=&rtt->rp;
	rbuf=rtt->recvbuf.buf;
	transferbuf_t *sndbuf;
	unsigned char maker;
	struct str name,val;

	sndbuf=&rtt->sndbuf;
	maker=*rbuf++;
	if(maker!=string_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	rbuf=amf_decode_str(rbuf,&name);
	maker=*rbuf++;
	if(maker!=number_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	num=amf_decode_num(rbuf);rbuf+=8;
	rs_log(RS_DEBUG,"connect\n");
	rs_log(RS_DEBUG,"txn:%lf\n",num);
	if(strcmp(name.val,"connect"))
		return -1;
	maker=*rbuf++;
	if(maker!=obj_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	while(1){
		if(!*rbuf&&!*(rbuf+1)&&*(rbuf+2)==obj_end_maker)
			break;
		rbuf=amf_decode_str(rbuf,&name);
		maker=*rbuf++;
		switch(maker){
			case string_maker:
				rbuf=amf_decode_str(rbuf,&val);
				rs_log(RS_DEBUG,"%s=%s\n",name.val,val.val);
				varset_putstr(&rp->varset,name.val,val.val,val.len);
				break;
			case number_maker:
				num=amf_decode_num(rbuf);rbuf+=8;
				rs_log(RS_DEBUG,"%s=%f\n",name.val,num);
				varset_putdouble(&rp->varset,name.val,num);
				break;
			case boolean_maker:
				boolval=*rbuf++;
				rs_log(RS_DEBUG,"%s=%d\n",name.val,boolval);
				varset_putbool(&rp->varset,name.val,boolval);
				break;
			default:
				rs_log(RS_DEBUG,"can't support this maker yet\n");
				break;
		}
	}
	preclientconnectres(rtt);

	/*connectres*/
	transferbuf_init(&rtt->sndbuf,BUFSIZE);
	transferbuf_use(&rtt->sndbuf,MSG_HEADER_MAX);
	wbuf=amf_encode_str(sndbuf->buf+sndbuf->offset,&str__result);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	num=1;
	wbuf=amf_encode_num(sndbuf->buf+sndbuf->offset,num);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);

	maker=obj_maker;
	transferbuf_write(sndbuf,(char*)&maker,1);
	wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_level,&str_status);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_code,&str_code_result);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_description,&str_desc_result);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	maker=0x0;
	transferbuf_write(sndbuf,(char*)&maker,1);
	maker=0x0;
	transferbuf_write(sndbuf,(char*)&maker,1);
	maker=obj_end_maker;
	transferbuf_write(sndbuf,(char*)&maker,1);

	rp->status=SCONNCMDED;
	rtt->flags|=(TRAN_WRITE|TRAN_UPDATE);
	rtmpmsg_init(&rtt->rp.rtm);
	transferbuf_init(&rtt->recvbuf,BUFSIZE);
	chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
	rtt->rp.rtmsnd=rtt->rp.rtm;
	rtmpmsg_forsnd(&rtt->rp.rtmsnd,&rtt->sndbuf);
	return 0;
}


void rtmpmsg_init(rtmpmsg_t *rtm)
{
	rtm->payload_len=0;
	rtm->chunktotalsize=0;
	rtm->chunkindex=0; 
	rtm->chunkoffset=0;
}
static int sndoffset(int fd,rtmpchunkdata_t *rcd,raddr_t *addr)
{
	char *payload=rcd->data;
	int c;
	int ret=FAILED;
	if(rcd->offset==rcd->offset_op)
		return FINISH;
	while((c=_snd(fd,payload+rcd->offset,rcd->offset_op-rcd->offset,addr))>0){
		rcd->offset+=c;
		if(rcd->offset==rcd->offset_op){
			ret=FINISH;
			break;
		}
	}
	if(c<0){
		//rs_log(RS_DEBUG,"sndoffset failed ret:%d len:%d rcd offset:%d offset_op:%d\n",ret,rcd->offset_op-rcd->offset,rcd->offset,rcd->offset_op);
	}
	else if(!c)
		ret=SHUTDOWN;
	return ret;
}

static inline int chunkgetlen(int index,int chunksize,int max)
{
	int off,len;
	off=index*chunksize;
	len=chunksize;
	if(off+len>max)
		len=max-off;
	return len;
}
static inline int _setrcd(rtmpmsg_t *msg,rtransfer_t *rtt,rtmpchunkdata_t *rcd,char *data,int headerlen)
{
	int payload_len;
	rcd->data=data;
	rcd->offset=0;
	payload_len=chunkgetlen(msg->chunkindex,msg->chunksize,msg->payload_len);
	rcd->offset_op=payload_len+headerlen;
	//rs_debug("headerlen:%d chunkpayload_len:%d offset_op:%d\n",headerlen,payload_len,rcd->offset_op);
	return sndoffset(rtt->fd,rcd,&rtt->addr);
}

static int chunksnd_area(rtransfer_t *rtt,rtmpchunkdata_t *rcd,area_t *at,int headerlen)
{
	rtmpmsg_t *msg;
	msg=&at->msg;
	return _setrcd(msg,rtt,rcd,at->payload+at->offset_op,headerlen);
}

static int chunksnd(rtransfer_t *rtt,rtmpchunkdata_t *rcd,transferbuf_t *sbuf,int headerlen)
{
	rtmpmsg_t *msg;
	int payload_len;
	msg=&rtt->rp.rtmsnd;
	rcd->data=sbuf->buf+sbuf->offset_op;
	rcd->offset=0;
	payload_len=chunkgetlen(msg->chunkindex,msg->chunksize,msg->payload_len);
	rcd->offset_op=payload_len+headerlen;
	//rs_debug("headerlen:%d chunkpayload_len:%d offset_op:%d\n",headerlen,payload_len,rcd->offset_op);
	return sndoffset(rtt->fd,rcd,&rtt->addr);
}

int rtmpchunksnd(rtransfer_t *rtt)
{
	int ret,headerlen;
	rtmpchunkdata_t *rcd;
	rtmpchunk_t chunk;
	transferbuf_t *sbuf;
	rtmpmsg_t *msg;
	bufheader_t *bh;

	msg=&rtt->rp.rtmsnd;
	sbuf=&rtt->sndbuf;
	rcd=(rtmpchunkdata_t*)(sbuf->buf+BUFSIZE-msg->chunksize-MSG_HEADER_MAX-sizeof(rtmpchunkdata_t));
	bh=(bufheader_t*)sbuf->buf;
	if(bh->sig==BUFSIG&&bh->ver==BUFVER){
		area_t *at;
		at=area_get(sbuf,bh->offset_area);
		//rs_log(RS_DEBUG,"area_get atoffset:%d atoffset_op:%d tbuf offset:%d offset_op:%d\n",at->offset,at->offset_op,sbuf->offset,sbuf->offset_op);
		msg=&at->msg;
		//snd
		if(!msg->chunkindex){
			//rs_log(RS_DEBUG,"begin send rtmpmsg......\n");
			//rs_log(RS_DEBUG,"bufoffset_op:%d bufoffset:%d\n",sbuf->offset_op,sbuf->offset);
		}

		if((ret=sndoffset(rtt->fd,rcd,&rtt->addr))!=FINISH)
			return ret;
		if(msg->chunkindex==0){
			chunk.chunkid=msg->chunkid;
			chunk.type=TYPE0;
		}else{
			chunk.chunkid=msg->chunkid;
			chunk.type=TYPE3;
		}
		/*initial chunk header*/
		if(msg->ms==CHUNKTYPE){
			headerlen=rtmpchunk_setheader_area(&chunk,msg,at);
			msg->ms=CHUNKPAYLOAD;
			if((ret=chunksnd_area(rtt,rcd,at,headerlen))!=FINISH)
				return ret;
			msg->ms=CHUNKFINISH;
		}else if(msg->ms==CHUNKPAYLOAD){
			msg->ms=CHUNKFINISH;
		}
		at->offset_op+=rcd->offset;
		//rs_log(RS_DEBUG,"chunk sended... at offset:%d at offset_op:%d\n",at->offset,at->offset_op);
		//rs_debug("send rtmpchunk finish...rcdoffset_op:%d rcdoffset:%d chunktype:%d chunkid:%d chunkindex:%d chunksize:%d msgpayload_len:%d bufoffset_op:%d bufoffset:%d\n",rcd->offset_op,rcd->offset,chunk.type,chunk.chunkid,msg->chunkindex,msg->chunksize,msg->payload_len,sbuf->offset_op,sbuf->offset);
		memset(rcd,0,sizeof(rtmpchunkdata_t));
		msg->chunkindex++;
		msg->ms=CHUNKTYPE;
		if(at->offset==at->offset_op){
			bh->offset_area++;
			sbuf->offset_op+=at->offset+sizeof(*at);
			//rs_log(RS_DEBUG,"area sended... at offset:%d at offset_op:%d tbuf offset:%d offset_op:%d\n",at->offset,at->offset_op,sbuf->offset,sbuf->offset_op);
		}

		if(rtt->sndbuf.offset_op==rtt->sndbuf.offset){
			//rs_log(RS_DEBUG,"finish send rtmpmsg......\n");
			memset(bh,0,sizeof(*bh));
		}
	}else{
		if(!msg->chunkindex){
			//rs_debug("begin send rtmpmsg......\n");
		}

		if((ret=sndoffset(rtt->fd,rcd,&rtt->addr))!=FINISH)
			return ret;
		if(msg->chunkindex==0){
			chunk.chunkid=msg->chunkid;
			chunk.type=TYPE0;
		}else{
			chunk.chunkid=msg->chunkid;
			chunk.type=TYPE3;
		}
		/*initial chunk header*/
		if(msg->ms==CHUNKTYPE){
			headerlen=rtmpchunk_setheader(&chunk,msg,sbuf);
			msg->ms=CHUNKPAYLOAD;
			if((ret=chunksnd(rtt,rcd,sbuf,headerlen))!=FINISH)
				return ret;
			msg->ms=CHUNKFINISH;
		}else if(msg->ms==CHUNKPAYLOAD){
			msg->ms=CHUNKFINISH;
		}
		sbuf->offset_op+=rcd->offset;
		//rs_debug("send rtmpchunk finish...rcdoffset_op:%d rcdoffset:%d chunktype:%d chunkid:%d chunkindex:%d chunksize:%d msgpayload_len:%d bufoffset_op:%d bufoffset:%d\n",rcd->offset_op,rcd->offset,chunk.type,chunk.chunkid,msg->chunkindex,msg->chunksize,msg->payload_len,sbuf->offset_op,sbuf->offset);
		memset(rcd,0,sizeof(rtmpchunkdata_t));
		msg->chunkindex++;
		msg->ms=CHUNKTYPE;
		if(rtt->sndbuf.offset_op==rtt->sndbuf.offset){
			//rs_debug("finish send rtmpmsg......\n");
		}
	}
	return FINISH;
}
static void set_spspps(transferbuf_t *sndbuf,rtmpmsg_t *msg,rtransfer_t *pub)
{
	area_t *at;
	at=area_new(sndbuf);
	at->msg=*msg;
	at_use(at,sndbuf,MSG_HEADER_MAX);
	area_write(at,sndbuf,pub->rp.script_data,pub->rp.script_data_len);
	at->msg.type=TDATA_AMF0;
	sndbuf->offset+=at->offset;
	rtmpmsg_forsnd_area(&at->msg,at);
	at=area_new(sndbuf);
	at->msg=*msg;
	at_use(at,sndbuf,MSG_HEADER_MAX);
	area_write(at,sndbuf,pub->rp.audio_spec,pub->rp.audio_spec_len);
	sndbuf->offset+=at->offset;
	at->msg.type=TAUDIO;
	rtmpmsg_forsnd_area(&at->msg,at);
	at=area_new(sndbuf);
	at->msg=*msg;
	at_use(at,sndbuf,MSG_HEADER_MAX);
	area_write(at,sndbuf,pub->rp.video_seq_header,pub->rp.video_seq_header_len);
	sndbuf->offset+=at->offset;
	at->msg.type=TVIDEO;
	rtmpmsg_forsnd_area(&at->msg,at);
}

bool preparerecord(record_t *r,struct rtmptransfer_s *rtt,char *streamname)
{
	char *path;
	/*init playpath right*/
	if(!streamname||!(path=record_getpath(streamname))){
		rs_debug("find %s failed\n",streamname);
		return FALSE;
	}
	if((r->fd=open(path,O_RDONLY))<0){
		perror("open");
		rs_debug("this is no file in %s\n",path);
		return FALSE;
	}else{
		rs_warn("record file %s is alive...\n",path);
		close(r->fd);
	}
	if(df_init(&r->flv,path)){
		rs_debug("flv init failed\n");
		return FALSE;
	}
	/*begin ts*/
	r->dts0=rsystime();
	rtt->flags|=RECORD_BEGIN;
	return TRUE;
}

int clientplay(rtransfer_t *rtt)
{
	char *rbuf,*wbuf;
	entry_t *e;
	bool reset;
	double num;
	area_t *at;
	rtransfer_t *pub;

	rtmpr_t *rp;
	rp=&rtt->rp;
	rbuf=rtt->recvbuf.buf;
	transferbuf_t *sndbuf;
	unsigned char maker;
	struct str name;

	sndbuf=&rtt->sndbuf;
	maker=*rbuf++;
	if(maker!=string_maker){
		rs_debug("parse amf0 maker failed\n");
		return -1;
	}
	rbuf=amf_decode_str(rbuf,&name);
	maker=*rbuf++;
	if(maker!=number_maker){
		rs_debug("parse amf0 maker failed\n");
		return -1;
	}
	num=amf_decode_num(rbuf);rbuf+=8;
	rs_log(RS_DEBUG,"play\n");
	rs_log(RS_DEBUG,"txn:%lf\n",num);
	if(strcmp(name.val,"play"))
		return -1;
	maker=*rbuf++;
	if(maker!=null_maker){
		rs_log(RS_DEBUG,"parse null amf0 maker failed\n");
		return -1;
	}

	maker=*rbuf++;
	if(maker!=string_maker){
		rs_log(RS_DEBUG,"parse str amf0 maker failed\n");
		return -1;
	}
	rbuf=amf_decode_str(rbuf,&name);
	varset_putstr(&rp->varset,"streamname",name.val,name.len);
	if(rtt->recvbuf.buf+rtt->recvbuf.offset>rbuf){
		maker=*rbuf++;
		if(maker!=number_maker){
			rs_log(RS_DEBUG,"parse num amf0 maker failed\n");
			return -1;
		}
		num=amf_decode_num(rbuf);rbuf+=8;
		varset_putdouble(&rp->varset,"start",num);
	}else
		varset_putdouble(&rp->varset,"start",-2);
	if(rtt->recvbuf.buf+rtt->recvbuf.offset>rbuf){
		maker=*rbuf++;
		if(maker!=number_maker){
			rs_log(RS_DEBUG,"parse num amf0 maker failed\n");
			return -1;
		}
		num=amf_decode_num(rbuf);rbuf+=8;
		varset_putdouble(&rp->varset,"duration",num);
	}else
		varset_putdouble(&rp->varset,"duration",-1);
	if(rtt->recvbuf.buf+rtt->recvbuf.offset>rbuf){
		maker=*rbuf++;
		if(maker!=boolean_maker){
			rs_log(RS_DEBUG,"parse boolean amf0 maker failed\n");
			return -1;
		}
		reset=(bool)amf_decode_boolean(rbuf);rbuf+=1;
		varset_putbool(&rp->varset,"reset",reset);
	}

	e=varset_get(&rp->varset,"streamname");
	transfer_joinlive(rtt,e->val._strval);
	if(!rtt->live->publish){
		preparerecord(&rtt->record,rtt,e->val._strval);
	}

	transferbuf_init(&rtt->sndbuf,BUFSIZE);
	at=area_new(sndbuf);
	at_use(at,sndbuf,MSG_HEADER_MAX);
	//rs_log(RS_DEBUG,"after area_use atoffset:%d tbuf offset:%d offset_op:%d\n",at->offset,sndbuf->offset,sndbuf->offset_op);
	wbuf=amf_encode_str(at->payload+at->offset,&str_onStatus);
	at->offset+=wbuf-(at->payload+at->offset);
	num=0;
	wbuf=amf_encode_num(at->payload+at->offset,num);
	at->offset+=wbuf-(at->payload+at->offset);
	maker=null_maker;
	area_write(at,sndbuf,(char*)&maker,1);

	maker=obj_maker;
	area_write(at,sndbuf,(char*)&maker,1);
	wbuf=amf_encode_nameval(at->payload+at->offset,&str_level,&str_status);
	at->offset+=wbuf-(at->payload+at->offset);
	wbuf=amf_encode_nameval(at->payload+at->offset,&str_code,&str_play_start);
	at->offset+=wbuf-(at->payload+at->offset);
	wbuf=amf_encode_nameval(at->payload+at->offset,&str_description,&str_netstream_desc_result);
	at->offset+=wbuf-(at->payload+at->offset);
	maker=0x0;
	area_write(at,sndbuf,(char*)&maker,1);
	maker=0x0;
	area_write(at,sndbuf,(char*)&maker,1);
	maker=obj_end_maker;
	area_write(at,sndbuf,(char*)&maker,1);
	sndbuf->offset+=at->offset;
	//rs_log(RS_DEBUG,"area_write at offset:%d tbuf offset:%d offset_op:%d\n",at->offset,sndbuf->offset,sndbuf->offset_op);
	at->msg=rtt->rp.rtm;
	rtmpmsg_forsnd_area(&at->msg,at);
	pub=rtt->live->publish;
	if(pub)
		set_spspps(sndbuf,&rtt->rp.rtm,pub);
	//area_print(sndbuf);
	rp->status=SPLAYED;
	rtt->flags|=(TRAN_WRITE|TRAN_UPDATE);
	rtmpmsg_init(&rtt->rp.rtm);
	transferbuf_init(&rtt->recvbuf,BUFSIZE);
	chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
	return FINISH;
}

int clientpublish(rtransfer_t *rtt)
{
	char *rbuf,*wbuf;
	double num;
	entry_t *e,*e1;
	bool ret;

	rtmpr_t *rp;
	rp=&rtt->rp;
	rbuf=rtt->recvbuf.buf;
	transferbuf_t *sndbuf;
	unsigned char maker;
	struct str name;

	sndbuf=&rtt->sndbuf;
	maker=*rbuf++;
	if(maker!=string_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	rbuf=amf_decode_str(rbuf,&name);
	maker=*rbuf++;
	if(maker!=number_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	num=amf_decode_num(rbuf);rbuf+=8;
	rs_log(RS_DEBUG,"publish\n");
	rs_log(RS_DEBUG,"txn:%lf\n",num);
	if(strcmp(name.val,"publish"))
		return -1;
	maker=*rbuf++;
	if(maker!=null_maker){
		rs_log(RS_DEBUG,"parse null amf0 maker failed\n");
		return -1;
	}

	maker=*rbuf++;
	if(maker!=string_maker){
		rs_log(RS_DEBUG,"parse str amf0 maker failed\n");
		return -1;
	}
	rbuf=amf_decode_str(rbuf,&name);
	varset_putstr(&rp->varset,"publish",name.val,name.len);
	maker=*rbuf++;
	if(maker!=string_maker){
		rs_log(RS_DEBUG,"parse str amf0 maker failed\n");
		return -1;
	}
	rbuf=amf_decode_str(rbuf,&name);
	varset_putstr(&rp->varset,"publish_type",name.val,name.len);
	e=varset_get(&rp->varset,"publish");
	e1=varset_get(&rp->varset,"publish_type");
	if((ret=transfer_createlive(rtt,e->val._strval,e1->val._strval))){
		rs_log(RS_WARN,"livepath alreay exist\n");
	}

	transferbuf_init(&rtt->sndbuf,BUFSIZE);
	transferbuf_use(&rtt->sndbuf,MSG_HEADER_MAX);
	wbuf=amf_encode_str(sndbuf->buf+sndbuf->offset,&str_onStatus);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	num=0;
	wbuf=amf_encode_num(sndbuf->buf+sndbuf->offset,num);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	maker=null_maker;
	transferbuf_write(sndbuf,(char*)&maker,1);

	maker=obj_maker;
	transferbuf_write(sndbuf,(char*)&maker,1);
	wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_level,&str_status);
	sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	if(!ret){
		wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_code,&str_publish_start);
		sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
		wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_description,&str_netstream_desc_result);
		sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	}else{
		wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_code,&str_publish_fail);
		sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
		wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_description,&str_netstream_desc_failresult);
		sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
	}
	maker=0x0;
	transferbuf_write(sndbuf,(char*)&maker,1);
	maker=0x0;
	transferbuf_write(sndbuf,(char*)&maker,1);
	maker=obj_end_maker;
	transferbuf_write(sndbuf,(char*)&maker,1);
	if(!ret)
		rp->status=SPUBLISHED;
	else
		rp->status=SPUBLISHFAIL;
	rtt->flags|=(TRAN_WRITE|TRAN_UPDATE);
	rtmpmsg_init(&rtt->rp.rtm);
	transferbuf_init(&rtt->recvbuf,BUFSIZE);
	chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
	rtt->rp.rtmsnd=rtt->rp.rtm;
	rtmpmsg_forsnd(&rtt->rp.rtmsnd,&rtt->sndbuf);

	return FINISH;
}

static int updateoffset(int fd,rtmpchunkdata_t *rcd)
{
	char *payload=rcd->payload;
	int c;
	int ret=FAILED;
	if(rcd->offset==rcd->offset_op)
		return FINISH;
	while((c=_recv(fd,payload+rcd->offset,rcd->offset_op-rcd->offset))>0){
		rcd->offset+=c;
		if(rcd->offset==rcd->offset_op){
			ret=FINISH;
			break;
		}
	}
	if(c<0){
		//rs_log(RS_DEBUG,"updateoffset failed ret:%d len:%d rcd offset:%d rcd offset_op:%d\n",ret,rcd->offset_op-rcd->offset,rcd->offset,rcd->offset_op);
	}else if(!c)
		ret=SHUTDOWN;
	return ret;
}

static int recvchunkid(rtransfer_t *rtt,rtmpchunkdata_t *rcd,rtmpchunk_t *rc)
{
	int ret;
	char *p=rcd->payload+1;
	if(!rc->chunkid){
		rcd->offset_op=2;
		if((ret=updateoffset(rtt->fd,rcd))!=FINISH)
			return ret;
		rc->chunkid=(unsigned char)*p;
		rc->chunkid+=64;
	}else if(rc->chunkid==1){
		rcd->offset_op=3;
		if((ret=updateoffset(rtt->fd,rcd))!=FINISH)
			return ret;
		rc->chunkid=*(unsigned short*)p;
		rc->chunkid+=64;
	}
	return FINISH;
}
static int recvchunkhead(rtransfer_t *rtt,rtmpchunkdata_t *rcd,rtmpchunk_t *rc)
{
	char *p;
	int ret;
	rtmpmsg_t *msg=&rtt->rp.rtm;
	const rtmpmsg_t *prertm;
	unsigned long ts;
	transferbuf_t *rbuf=&rtt->recvbuf;
	msg->chunkid=rc->chunkid;
	p=rcd->payload+rcd->offset;
	switch(rc->type){
		default:

			break;
		case TYPE0:
			rcd->offset_op=rcd->offset+TYPE0_LEN;
			rcd->data=rcd->payload+rcd->offset_op;
			if((ret=updateoffset(rtt->fd,rcd))!=FINISH)
				return ret;
			msg->ts=ntob24(p);p+=3;
			msg->payload_len=ntob24(p);p+=3;
			rbuf->offset_op=msg->payload_len;
			msg->type=*p;p++;
			msg->streamid=ntob32(p);
			if(msg->ts>=0xffffff){
				msg->ts=ntob32(p);p+=4;
			}
			msg->chunktotalsize=(msg->payload_len+msg->chunksize-1)/msg->chunksize;
			chunkset_put(&rtt->rp.cs,rc->chunkid,(const rtmpmsg_t*)msg);

			//rs_debug("chunktotalsize:%d\n",msg->chunktotalsize);
			break;
		case TYPE1:
			rcd->offset_op=rcd->offset+TYPE1_LEN;
			rcd->data=rcd->payload+rcd->offset_op;
			if((ret=updateoffset(rtt->fd,rcd))!=FINISH)
				return ret;
			ts=ntob24(p);p+=3;
			msg->payload_len=ntob24(p);p+=3;
			rbuf->offset_op=msg->payload_len;
			msg->chunktotalsize=(msg->payload_len+msg->chunksize-1)/msg->chunksize;
			msg->type=*p;p++;
			if(ts>=0xffffff)
				ts=ntob32(p);p+=4;

			msg->ts+=ts;
			prertm=chunkset_get(&rtt->rp.cs,rc->chunkid);
			if(!prertm){
				rs_log(RS_DEBUG,"could not find in chunkset,what to do...\n");
				return -1;
			}
			msg->streamid=prertm->streamid;
			chunkset_put(&rtt->rp.cs,rc->chunkid,(const rtmpmsg_t*)msg);
			break;
		case TYPE2:
			rcd->offset_op=rcd->offset+TYPE2_LEN;
			rcd->data=rcd->payload+rcd->offset_op;
			if((ret=updateoffset(rtt->fd,rcd))!=FINISH)
				return ret;
			ts=ntob24(p);p+=3;
			if(ts>=0xffffff)
				ts=ntob32(p);p+=4;
			msg->ts+=ts;
			prertm=chunkset_get(&rtt->rp.cs,rc->chunkid);
			if(!prertm){
				rs_log(RS_DEBUG,"could not find in chunkset,what to do...\n");
				return -1;
			}
			msg->payload_len=prertm->payload_len;
			if(!rbuf->offset_op)
				rbuf->offset_op=msg->payload_len;
			msg->type=prertm->type;
			msg->streamid=prertm->streamid;
			chunkset_put(&rtt->rp.cs,rc->chunkid,(const rtmpmsg_t*)msg);
			break;
		case TYPE3:
			rcd->offset_op=rcd->offset+TYPE3_LEN;
			rcd->data=rcd->payload+rcd->offset_op;
			prertm=chunkset_get(&rtt->rp.cs,rc->chunkid);
			if(!prertm){
				rs_log(RS_DEBUG,"could not find in chunkset,what to do...\n");
				return -1;
			}
			msg->ts=prertm->ts;
			msg->payload_len=prertm->payload_len;
			if(!rbuf->offset_op)
				rbuf->offset_op=msg->payload_len;
			msg->type=prertm->type;
			msg->streamid=prertm->streamid;
			chunkset_put(&rtt->rp.cs,rc->chunkid,(const rtmpmsg_t *)msg);
			break;
	}
	//rs_debug("recv fd:%d type:%d payload_len:%d chunkindex:%d chunktotalsize:%d chunkoffset:%d\n",rtt->fd,msg->type,msg->payload_len,msg->chunkindex,msg->chunktotalsize,msg->chunkoffset);
	return FINISH;
}
static int recvchunks(rtransfer_t *rtt,rtmpchunkdata_t *rcd,rtmpchunk_t *rc)
{
	int len;
	rtmpmsg_t *msg=&rtt->rp.rtm;
	len=chunkgetlen(msg->chunkindex,msg->chunksize,msg->payload_len);
	rcd->payload_len=len;
	rcd->offset_op=rcd->offset+len;
	return updateoffset(rtt->fd,rcd);
}
static char * readchunktype(char *p,rtmpchunk_t *rc)
{
	rc->type=*p++;
	rc->chunkid=rc->type&0x3f;
	rc->type=((unsigned char)rc->type)>>SHIFT_CTYPE;
	return p;
}

static char * readchunkid(char *p,rtmpchunk_t *rc)
{
	if(!rc->chunkid){
		rc->chunkid=(unsigned char)*p;
		rc->chunkid+=64;
		p++;
	}else if(rc->chunkid==1){
		rc->chunkid=*(unsigned short*)p;
		rc->chunkid+=64;
		p+=2;
	}
	return p;
}

static void readchunkhead(char *p,rtmpchunk_t *rc,rtransfer_t *rtt)
{
	const rtmpmsg_t *prertm;
	unsigned long ts;
	rtmpmsg_t *msg=&rtt->rp.rtm;
	transferbuf_t *rbuf=&rtt->recvbuf;
	switch(rc->type){
		default:

			break;
		case TYPE0:
			msg->ts=ntob24(p);p+=3;
			msg->payload_len=ntob24(p);p+=3;
			rbuf->offset_op=msg->payload_len;
			msg->type=*p;p++;
			msg->streamid=ntob32(p);
			msg->chunktotalsize=(msg->payload_len+msg->chunksize-1)/msg->chunksize;
			chunkset_put(&rtt->rp.cs,rc->chunkid,(const rtmpmsg_t*)msg);
			break;
		case TYPE1:
			ts=ntob24(p);p+=3;
			msg->ts+=ts;
			msg->payload_len=ntob24(p);p+=3;
			rbuf->offset_op=msg->payload_len;
			msg->chunktotalsize=(msg->payload_len+msg->chunksize-1)/msg->chunksize;
			msg->type=*p;p++;

			prertm=chunkset_get(&rtt->rp.cs,rc->chunkid);
			if(!prertm){
				rs_log(RS_DEBUG,"could not find in chunkset,what to do...\n");
			}
			msg->streamid=prertm->streamid;
			chunkset_put(&rtt->rp.cs,rc->chunkid,(const rtmpmsg_t*)msg);
			break;
		case TYPE2:
			ts=ntob24(p);p+=3;
			msg->ts+=ts;
			prertm=chunkset_get(&rtt->rp.cs,rc->chunkid);
			if(!prertm){
				rs_log(RS_DEBUG,"could not find in chunkset,what to do...\n");
			}
			msg->payload_len=prertm->payload_len;
			msg->type=prertm->type;
			msg->streamid=prertm->streamid;
			chunkset_put(&rtt->rp.cs,rc->chunkid,(const rtmpmsg_t*)msg);
			break;
		case TYPE3:
			prertm=chunkset_get(&rtt->rp.cs,rc->chunkid);
			if(!prertm){
				rs_log(RS_DEBUG,"could not find in chunkset,what to do...\n");
			}
			msg->ts=prertm->ts;
			msg->payload_len=prertm->payload_len;
			if(!rbuf->offset_op)
				rbuf->offset_op=msg->payload_len;
			msg->type=prertm->type;
			msg->streamid=prertm->streamid;
			chunkset_put(&rtt->rp.cs,rc->chunkid,(const rtmpmsg_t *)msg);
			break;
	}
}

int rtmpchunkrecv(rtransfer_t *rtt)
{
	rtmpchunk_t chunk={0};
	rtmpmsg_t *msg;
	transferbuf_t *rbuf=&rtt->recvbuf;
	char *p,*pi;
	rtmpchunkdata_t *rcd;
	int ret;

	msg=&rtt->rp.rtm;
	rcd=(rtmpchunkdata_t*)(rbuf->buf+BUFSIZE-msg->chunksize-MSG_HEADER_MAX-sizeof(rtmpchunkdata_t));
	if(!msg->payload_len){
		//rs_log(RS_DEBUG,"recv rtmpmsg begin......\n");
	}
	while(1){
		p=rcd->payload;
		if((ret=updateoffset(rtt->fd,rcd))!=FINISH)
			return ret;
		if(!rcd->offset_op){
			msg->ms=CHUNKTYPE;
			rcd->offset_op=1;
			if((ret=updateoffset(rtt->fd,rcd))!=FINISH)
				return ret;
			chunk.type=*p++;
			chunk.chunkid=chunk.type&0x3f;
			chunk.type=((unsigned char)chunk.type)>>SHIFT_CTYPE;
			msg->ms=CHUNKID;
			if((ret=recvchunkid(rtt,rcd,&chunk))!=FINISH){
				return ret;
			}
			msg->ms=CHUNKHEAD;
			if((ret=recvchunkhead(rtt,rcd,&chunk))!=FINISH){
				return ret;
			}
			msg->ms=CHUNKPAYLOAD;
			if((ret=recvchunks(rtt,rcd,&chunk))!=FINISH){
				return PROCESSING;
			}
			msg->chunkid=chunk.chunkid;
			msg->ms=CHUNKFINISH;
		}else if(msg->ms==CHUNKTYPE){
			pi=readchunktype(p,&chunk);
			msg->ms=CHUNKID;
			if((ret=recvchunkid(rtt,rcd,&chunk))!=FINISH){
				return ret;
			}
			msg->ms=CHUNKHEAD;
			if((ret=recvchunkhead(rtt,rcd,&chunk))!=FINISH){
				return ret;
			}
			msg->ms=CHUNKPAYLOAD;
			if((ret=recvchunks(rtt,rcd,&chunk))!=FINISH){
				return ret;
			}
			msg->chunkid=chunk.chunkid;
			msg->ms=CHUNKFINISH;
		}else if(msg->ms==CHUNKID){
			pi=readchunktype(p,&chunk);
			readchunkid(pi,&chunk);
			msg->ms=CHUNKHEAD;
			if((ret=recvchunkhead(rtt,rcd,&chunk))!=FINISH){
				return PROCESSING;
			}
			msg->ms=CHUNKPAYLOAD;
			if((ret=recvchunks(rtt,rcd,&chunk))!=FINISH){
				return PROCESSING;
			}
			msg->chunkid=chunk.chunkid;
			msg->ms=CHUNKFINISH;
		}else if(msg->ms==CHUNKHEAD){
			pi=readchunktype(p,&chunk);
			pi=readchunkid(pi,&chunk);
			readchunkhead(pi,&chunk,rtt);
			msg->ms=CHUNKPAYLOAD;
			if((ret=recvchunks(rtt,rcd,&chunk))!=FINISH){
				return PROCESSING;
			}
			msg->chunkid=chunk.chunkid;
			msg->ms=CHUNKFINISH;
		}else if(msg->ms==CHUNKPAYLOAD){
			pi=readchunktype(p,&chunk);
			pi=readchunkid(pi,&chunk);
			readchunkhead(pi,&chunk,rtt);
			msg->chunkid=chunk.chunkid;
			msg->ms=CHUNKTYPE;
		}
		//rs_log(RS_DEBUG,"recvhead finish... type:%d chunkindex:%d rcd payload_len:%d msg payload:%d rcd offset:%d rcd offset_op:%d \n",chunk.type,msg->chunkindex,rcd->payload_len,msg->payload_len,rcd->offset,rcd->offset_op);
		msg->chunkindex++;
		/*to buf*/
		memcpy(rbuf->buf+rbuf->offset,rcd->data,rcd->payload_len);
		rbuf->offset+=rcd->payload_len;
		//rs_log(RS_DEBUG,"tobuf finish,rbuf offset:%d rbuf offset_op:%d\n",rbuf->offset,rbuf->offset_op);
		if(rbuf->offset==rbuf->offset_op){
			//rs_log(RS_DEBUG,"recv rtmpmsg finish......\n");
			msg->ms=0;
			memset((char*)rcd,0,sizeof(rtmpchunkdata_t));
			break;
		}else{
			msg->ms=0;
			memset((char*)rcd,0,sizeof(rtmpchunkdata_t));
		}
	}
	return FINISH;
}

int clientwinack(rtransfer_t *rtt)
{
	char *rbuf;
	int val;

	rbuf=rtt->recvbuf.buf;
	val=ntob32(rbuf);
	rs_log(RS_WARN,"winack:%d fd:%d\n",val,rtt->fd);
	rtmpmsg_init(&rtt->rp.rtm);
	transferbuf_init(&rtt->recvbuf,BUFSIZE);
	chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
	return 0;
}

static void savedatascript(rtmpr_t *rp,transferbuf_t *tbuf)
{
	if(!rp->script_data_len){
		rp->script_data_len=tbuf->offset;
		rp->script_data_type=TDATA_AMF0;
		memcpy(rp->script_data,tbuf,tbuf->offset);
	}
}

static void saveaudiospec(rtmpr_t *rp,transferbuf_t *tbuf)
{
	/*AACPacketType*/
	if(!rp->audio_spec_len){
		rp->audio_spec_len=tbuf->offset;
		rp->audio_type=TAUDIO;
		memcpy(rp->audio_spec,tbuf,tbuf->offset);
	}
}

static void savevideoseq(rtmpr_t *rp,transferbuf_t *tbuf)
{
	/*AVC sequence header*/
	if(!rp->video_seq_header_len){
		rp->video_seq_header_len=tbuf->offset;
		rp->video_type=TVIDEO;
		memcpy(rp->video_seq_header,tbuf,tbuf->offset);
	}
}

static void clientctrl(rtransfer_t *rtt)
{
	rtmpmsg_init(&rtt->rp.rtm);
	transferbuf_init(&rtt->recvbuf,BUFSIZE);
	chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
}

static int seekto(rtransfer_t *rtt,double ts)
{

	return 0;
}

static int clientseek(rtransfer_t *rtt)
{
	char *rbuf,*wbuf;
	double num;
	int ret;

	rbuf=rtt->recvbuf.buf;
	transferbuf_t *sndbuf;
	unsigned char maker;
	struct str name;

	sndbuf=&rtt->sndbuf;
	maker=*rbuf++;
	if(maker!=string_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	rbuf=amf_decode_str(rbuf,&name);
	maker=*rbuf++;
	if(maker!=number_maker){
		rs_log(RS_DEBUG,"parse amf0 maker failed\n");
		return -1;
	}
	num=amf_decode_num(rbuf);rbuf+=8;
	if(strcmp(name.val,"seek"))
		return -1;
	maker=*rbuf++;
	if(maker!=null_maker){
		rs_log(RS_DEBUG,"parse null amf0 maker failed\n");
		return -1;
	}

	maker=*rbuf++;
	if(maker!=number_maker){
		rs_log(RS_DEBUG,"parse str amf0 maker failed\n");
		return -1;
	}
	num=amf_decode_num(rbuf);rbuf+=8;
	rs_warn("seek to ts:%f\n",num);
	ret=seekto(rtt,num);

	if(rtt->flags&TRAN_WRITE)
		rs_warn("sending... when seeking\n");
	if(!area_haveareabuf(sndbuf)){
		area_t *at;
		rtmpmsg_t *msg;
		msg=&rtt->rp.rtm;
		at=area_new(sndbuf);
		at_use(at,sndbuf,MSG_HEADER_MAX);

		wbuf=amf_encode_str(at->payload+at->offset,&str_onStatus);
		at->offset+=wbuf-(at->payload+at->offset);
		num=0;
		wbuf=amf_encode_num(at->payload+at->offset,num);
		at->offset+=wbuf-(at->payload+at->offset);
		maker=null_maker;
		area_write(at,sndbuf,(char*)&maker,1);

		maker=obj_maker;
		area_write(at,sndbuf,(char*)&maker,1);
		if(!ret){
			wbuf=amf_encode_nameval(at->payload+at->offset,&str_level,&str_status);
			at->offset+=wbuf-(at->payload+at->offset);
		}else{
			wbuf=amf_encode_nameval(at->payload+at->offset,&str_level,&str_error);
			at->offset+=wbuf-(at->payload+at->offset);
		}

		wbuf=amf_encode_nameval(at->payload+at->offset,&str_code,&str_seek_notify);
		at->offset+=wbuf-(at->payload+at->offset);
		wbuf=amf_encode_nameval(at->payload+at->offset,&str_description,&str_netstream_desc_result);
		at->offset+=wbuf-(at->payload+at->offset);
		maker=0x0;
		area_write(at,sndbuf,(char*)&maker,1);
		maker=0x0;
		area_write(at,sndbuf,(char*)&maker,1);
		maker=obj_end_maker;
		area_write(at,sndbuf,(char*)&maker,1);

		at->msg=*msg;
		rtmpmsg_forsnd_area(&at->msg,at);
	}else{
		transferbuf_init(&rtt->sndbuf,BUFSIZE);
		transferbuf_use(&rtt->sndbuf,MSG_HEADER_MAX);
		wbuf=amf_encode_str(sndbuf->buf+sndbuf->offset,&str_onStatus);
		sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
		num=0;
		wbuf=amf_encode_num(sndbuf->buf+sndbuf->offset,num);
		sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
		maker=null_maker;
		transferbuf_write(sndbuf,(char*)&maker,1);

		maker=obj_maker;
		transferbuf_write(sndbuf,(char*)&maker,1);
		if(!ret){
			wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_level,&str_status);
			sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
		}else{
			wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_level,&str_error);
			sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
		}

		wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_code,&str_seek_notify);
		sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
		wbuf=amf_encode_nameval(sndbuf->buf+sndbuf->offset,&str_description,&str_netstream_desc_result);
		sndbuf->offset+=wbuf-(sndbuf->buf+sndbuf->offset);
		maker=0x0;
		transferbuf_write(sndbuf,(char*)&maker,1);
		maker=0x0;
		transferbuf_write(sndbuf,(char*)&maker,1);
		maker=obj_end_maker;
		transferbuf_write(sndbuf,(char*)&maker,1);
		rtt->rp.rtmsnd=rtt->rp.rtm;
		rtmpmsg_forsnd(&rtt->rp.rtmsnd,&rtt->sndbuf);
	}
	rtmpmsg_init(&rtt->rp.rtm);
	transferbuf_init(&rtt->recvbuf,BUFSIZE);
	chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
	rtt->flags|=(TRAN_WRITE|TRAN_UPDATE);
	return FINISH;
}

int rtransfer_recv(rtransfer_t *rtt)
{
	int ret;
	char *rbuf,maker;
	struct str name;
	rtmpr_t *rp;
	rp=&rtt->rp;
	rbuf=rtt->recvbuf.buf;
	switch(rp->status){
		default:

			break;
		case SINIT:
			rtt->flags|=TRAN_NOT_RTMPPROTOCAL;
			if(rtt->recvbuf.offset!=0){
				ret=transferbuf_recv(rtt->fd,&rtt->recvbuf,rtt->recvbuf.total-rtt->recvbuf.offset);
				if(!ret)
					return SHUTDOWN;
			}else{
				transferbuf_init(&rtt->recvbuf,RTMP_C1_LEN+1);
				ret=transferbuf_recv(rtt->fd,&rtt->recvbuf,1);
				if(!ret)
					return SHUTDOWN;
				if(ret!=1)
					return PROCESSING;
				rs_log(RS_DEBUG,"peer rtmpversion:%d\n",rbuf[0]);
				if(rbuf[0]!=RTMP_VERSION){
					rs_log(RS_DEBUG,"peer rtmpversion check failed\n");
					return FAILED;
				}
				ret=transferbuf_recv(rtt->fd,&rtt->recvbuf,RTMP_C1_LEN);
				if(!ret)
					return SHUTDOWN;
				else if(ret<0)
					return FAILED;
			}
			if(transferbuf_full(&rtt->recvbuf)){
				handshake1(rtt);
			}
			break;
		case SHANDSHAKE:
			ret=transferbuf_recv(rtt->fd,&rtt->recvbuf,rtt->recvbuf.total-rtt->recvbuf.offset);
			if(!ret)
				return SHUTDOWN;
			else if(ret<0)
				return FAILED;
			if(transferbuf_full(&rtt->recvbuf)){
				if(handshake2(rtt))
					return FAILED;
				else{
					transferbuf_init(&rtt->recvbuf,BUFSIZE);
					chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
				}
			}
			break;
		case SHANDSHAKED:
			rtt->flags&=~TRAN_NOT_RTMPPROTOCAL;
		case SCONNCMDED:
		case SCREATESTREAM:
		case SPUBLISHED:
		case SPLAYED:
			if(rtt->flags&LIVEDATA_PUT){
				usleep(2000);
				return PROCESSING;
			}
			ret=rtmpchunkrecv(rtt);
			if(ret!=FINISH)
				return ret;
			switch(rtt->rp.rtm.type){
				default:
					rs_log(RS_WARN,"unknown rtmp msg type:%d\n",rtt->rp.rtm.type);
					rtmpmsg_init(&rtt->rp.rtm);
					transferbuf_init(&rtt->recvbuf,BUFSIZE);
					chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
					break;
				case TCONTROLMSG:
					clientctrl(rtt);
					break;
				case TACKNOWLEDGEMENT:
				case TWINDOW_ACKNOWLEDGEMENT:
					clientwinack(rtt);
					break;
				case TCMD_AMF0:
					maker=*rbuf++;
					if(maker!=string_maker){
						rs_log(RS_WARN,"parse str maker failed\n");
						return -1;
					}
					rbuf=amf_decode_str(rbuf,&name);
					maker=*rbuf++;
					if(maker!=number_maker){
						rs_log(RS_WARN,"parse num maker failed\n");
						return -1;
					}
					rbuf+=8;
					if(!strcmp(name.val,"createStream"))
						clientcreatestream(rtt);
					else if(!strcmp(name.val,"connect")){
						clientconnectres(rtt);
					}else if(!strcmp(name.val,"publish"))
						clientpublish(rtt);
					else if(!strcmp(name.val,"play"))
						clientplay(rtt);
					else if(!strcmp(name.val,"deleteStream"))
						clientdeletestream(rtt);
					else if(!strcmp(name.val,"seek"))
						clientseek(rtt);
					else{
						rs_log(RS_DEBUG,"name:%s\n",name.val);
						rs_log(RS_DEBUG,"unknown amf0 msg\n");
						rtmpmsg_init(&rtt->rp.rtm);
						transferbuf_init(&rtt->recvbuf,BUFSIZE);
						chunkdata_init(&rtt->rp.rtm,&rtt->recvbuf);
						rtt->rp.rtmsnd=rtt->rp.rtm;
						rtmpmsg_forsnd(&rtt->rp.rtmsnd,&rtt->sndbuf);
					}
					break;
				case TDATA_AMF0:
					savedatascript(&rtt->rp,&rtt->recvbuf);
					rtt->flags|=LIVEDATA_PUT;
					break;
				case TAUDIO:
					/*AACPacketType*/
					if(rtt->recvbuf.buf[1]==0){
						saveaudiospec(&rtt->rp,&rtt->recvbuf);
					}
					//rs_log(RS_DEBUG,"recv payloadlen %d\n",rtt->rp.rtm.payload_len);
					rtt->flags|=LIVEDATA_PUT;
					break;
				case TVIDEO:
					/*AVC sequence header*/
					if(rtt->recvbuf.buf[1]==0){
						savevideoseq(&rtt->rp,&rtt->recvbuf);
					}
					//rs_log(RS_DEBUG,"recv payloadlen %d\n",rtt->rp.rtm.payload_len);
					rtt->flags|=LIVEDATA_PUT;
					break;
			}
			break;
	}
	return FINISH;
}
int rtransfer_snd(rtransfer_t *rtt)
{
	int ret=FAILED;
	if(rtt->flags&TRAN_NOT_RTMPPROTOCAL){
		ret=transferbuf_snd(rtt,&rtt->sndbuf,rtt->sndbuf.offset);
		if(!ret)
			ret=SHUTDOWN;
		else if(ret<0)
			ret=FAILED;
		else if(rtt->sndbuf.offset_op==rtt->sndbuf.offset){
			if(rtt->flags&TRAN_WRITE){
				rtt->flags&=~TRAN_WRITE;
				rtt->flags|=TRAN_UPDATE;
			}
		}
	}else{
		while(1){
			ret=rtmpchunksnd(rtt);
			if(ret!=FINISH){
				break;
			}
			if(rtt->sndbuf.offset_op==rtt->sndbuf.offset){
				//rs_log(RS_DEBUG," snd payloadlen %d\n",rtt->rp.rtmsnd.payload_len);
				rtmpmsg_init(&rtt->rp.rtmsnd);
				if(rtt->flags&TRAN_WRITE){
					rtt->flags&=~TRAN_WRITE;
					rtt->flags|=TRAN_UPDATE;
				}
				ret=FINISH;
				break;
			}
		}
	}
	return ret;
}
int transferbuf_recv(int fd,transferbuf_t *buf,int len)
{
	int c;
	struct sockaddr_in s_addr;
	socklen_t sl;
	sl=sizeof(s_addr);
	transferbuf_check(buf,len);
	c=recvfrom(fd,buf->buf+buf->offset,len,0,(struct sockaddr*)&s_addr,&sl);
	if(!c){
		rs_log(RS_WARN,"buf recv len:%d c:%d\n",len,c);
		perror("transferbuf_recv");
	}
	if(c>0)
		buf->offset+=c;
	return c;
}
void chunkdata_init(rtmpmsg_t *msg,struct transferbuf_s *buf)
{
	rtmpchunkdata_t *rcd;
	rcd=(rtmpchunkdata_t*)(buf->buf+BUFSIZE-msg->chunksize-sizeof(rtmpchunkdata_t));
	memset(rcd,0,sizeof(rtmpchunkdata_t));
}
void transferbuf_init(transferbuf_t *buf,int len)
{
	buf->total=len;
	buf->offset=0;
	buf->offset_op=0;
}
void transferbuf_check(transferbuf_t *buf,int len)
{
	if(buf->offset+len>buf->total){
		rs_log(RS_DEBUG,"exceed max bufsize(offset:%d len:%d total:%d)\n",buf->offset,len,buf->total);
		exit(-1);
	}
}
int transferbuf_snd(rtransfer_t *rtt,transferbuf_t *buf,int len)
{
	ssize_t c=0;
	struct sockaddr_in s_addr;
	s_addr.sin_family=AF_INET;
	s_addr.sin_port=htons(rtt->addr.port);
	s_addr.sin_addr.s_addr=htonl(rtt->addr.ip);
	c=sendto(rtt->fd,buf->buf+buf->offset_op,len,0,(struct sockaddr*)&s_addr,sizeof(s_addr));
	if(c<0){
		if(errno!=EAGAIN&&errno!=EWOULDBLOCK){
			rs_log(RS_DEBUG,"_snd len:%d c:%d\n",len,c);
			perror("sendto(_snd)");
			if(errno==EPIPE)
				c=0;
		}
	}else
		buf->offset_op+=c;
	//rs_debug("len:%d - snd len:%d\n",len,c);
	//rs_debug("fd:%d ip:%d port:%d len:%d sndoffset:%d\n",rtt->fd,rtt->addr.ip,rtt->addr.port,len,buf->offset_op);
	return c;
}
int transferbuf_full(transferbuf_t *buf)
{
	return buf->offset==buf->total;
}
char * transferbuf_use(transferbuf_t *buf,int len)
{
	char *off;
	transferbuf_check(buf,len);
	off=buf->buf+buf->offset;
	buf->offset+=len;
	buf->offset_op=buf->offset;
	return off;
}
void transferbuf_write(transferbuf_t *buf,char *base,int len)
{
	transferbuf_check(buf,len);
	memcpy(buf->buf+buf->offset,base,len);
	buf->offset+=len;
}
void rs_deltransfer(rs_t *rs,rtransfer_t *rtt)
{
	if(epoll_ctl(rs->epoll_fd,EPOLL_CTL_DEL,rtt->fd,&rtt->ev)<0){
		perror("epoll_ctl");
		exit(-1);
	}
	rtt->flags&=~TRAN_STATUS;
	list_del(&rtt->rttlist);
}
bool rs_addtransfer(rs_t *rs,rtransfer_t *rtt)
{
	if(epoll_ctl(rs->epoll_fd,EPOLL_CTL_ADD,rtt->fd,&rtt->ev)<0){
		perror("epoll_ctl");
		return FALSE;
	}
	rtt->flags|=TRAN_STATUS;
	list_add(&rs->transfer,&rtt->rttlist);
	return TRUE;
}
bool rtransfer_bind(rtransfer_t *rtt,raddr_t *addr)
{
	int sock,flags=1;
	char *host;
	struct sockaddr_in s_addr;
	if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
		perror("socket");
		return FALSE;
	}
	if((setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&flags,sizeof(flags)))<0){  
		perror("setsockopt");  
		return FALSE;
	} 
	s_addr.sin_family=AF_INET;
	s_addr.sin_port=htons(addr->port);
	host=addr->hostname;
	if(host&&(!strcmp(host,"127.0.0.1")||!strcmp(host,"localhost")))
		//s_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
		s_addr.sin_addr.s_addr=INADDR_ANY;
	else{
		rs_log(RS_ERROR,"can't support other hostname yet\n");
		return FALSE;
	}
	if(bind(sock,(struct sockaddr*)&s_addr,sizeof(s_addr))<0){
		perror("bind");
		return FALSE;
	}
	rtt->flags|=TRAN_READ;
	rtransfer_setfd(rtt,sock);
	return TRUE;
}
static void printsndbuf(int fd)
{
	int bufsize;
	socklen_t solen=sizeof(bufsize);
	getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, &solen);
	rs_debug("fd:%d socket snd bufsize %d\n",fd,bufsize);
}
static void printrcvbuf(int fd)
{
	int bufsize;
	socklen_t solen=sizeof(bufsize);
	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, &solen);
	rs_debug("fd:%d socket recv bufsize %d\n",fd,bufsize);
}
/*
   static void setrcvbuf(int fd,int size)
   {
   int bufsize,bufsize2;
   socklen_t solen=sizeof(bufsize);
   getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, &solen);
   setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,solen);
   getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize2, &solen);
   rs_log(RS_DEBUG,"fd:%d set socket recv bufsize from:%d to:%d\n",fd,bufsize,bufsize2);
   }
   static void setsndbuf(int fd,int size)
   {
   int bufsize,bufsize2;
   socklen_t solen=sizeof(bufsize);
   getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, &solen);
   setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&size,solen);
   getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize2, &solen);
   rs_log(RS_DEBUG,"fd:%d set socket send bufsize from:%d to:%d\n",fd,bufsize,bufsize2);
   }
   */

void rtransfer_setfd(rtransfer_t *rtt,int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	rtt->fd=fd;
	if(rtt->flags&TRAN_READ)
		rtt->ev.events|=EPOLLIN;
	if(rtt->flags&TRAN_WRITE)
		rtt->ev.events|=EPOLLOUT;
	printsndbuf(rtt->fd);
	printrcvbuf(rtt->fd);
	rtt->ev.data.fd=rtt->fd;
}
bool rtransfer_init(rtransfer_t *rtt)
{
	if(varset_init(&rtt->rp.varset,30))
		return FALSE;
	if(chunkset_init(&rtt->rp.cs,30))
		return FALSE;
	rtt->rp.rtm.chunksize=g_rtmp.chunksize;
	rtt->rp.rtm.winsize=g_rtmp.winsize;
	rtt->rp.rtm.peerbandwidth=g_rtmp.winsize;
	rtt->rp.rtmsnd.chunksize=g_rtmp.chunksize;
	rtt->rp.rtmsnd.winsize=g_rtmp.winsize;
	rtt->rp.rtmsnd.peerbandwidth=g_rtmp.winsize;
	chunkdata_init(&rtt->rp.rtm,&rtt->sndbuf);
	return TRUE;
}
bool rtransfer_setlisten(rtransfer_t *rtt)
{
	if(listen(rtt->fd,SOMAXCONN)<0){
		perror("listen");
		return FALSE;
	}
	rtt->flags|=TRAN_LISTEN;
	return TRUE;
}
bool chunkset_init(chunkset_t *cs,int size)
{
	cs->size=size;
	cs->cursize=0;
	cs->msgs=malloc(sizeof(rtmpmsg_t)*size);
	if(!cs->msgs){
		rs_debug("chunkset init failed\n");
		return FALSE;
	}
	memset(cs->msgs,0,sizeof(rtmpmsg_t)*size);
	return TRUE;
}
void chunkset_uninit(chunkset_t *cs)
{
	cs->size=cs->cursize=0;
	free(cs->msgs);
}
void chunkset_put(chunkset_t *cs,unsigned int csid,const rtmpmsg_t *rtm)
{
	int hash=0;
	rtmpmsg_t *prtm;
	hash=csid%cs->size;
	prtm=&cs->msgs[hash];
	if(!prtm)
		cs->cursize++;
	*prtm=*rtm;
}
const rtmpmsg_t * chunkset_get(chunkset_t *cs,unsigned int csid)
{
	int hash=0;
	const rtmpmsg_t *prtm;
	hash=csid%cs->size;
	prtm=(const rtmpmsg_t*)&cs->msgs[hash];
	if(prtm)
		return prtm;
	else
		return NULL;
}
void transferbuf_writefromlive(transferbuf_t *tbuf,live_t *l,rtransfer_t *rtt)
{
	int len,bhlen,upper;
	bufhead_t *bh,bh2;
	len=LIVEBUFSIZE;
	bhlen=sizeof(bufhead_t);
	upper=len-rtt->rindex;
	//rs_debug("rindex from:%d ",rtt->rindex);
	//bh
	if(upper<bhlen){
		memcpy((char*)&bh2,l->buf+rtt->rindex,upper);
		rtt->rindex=0;
		memcpy(((char*)&bh2)+upper,l->buf+rtt->rindex,bhlen-upper);
		rtt->rindex+=bhlen-upper;
		bh=&bh2;
		upper=LIVEBUFSIZE-rtt->rindex;
	}else{
		bh=(bufhead_t*)(l->buf+rtt->rindex);
		rtt->rindex+=bhlen;
		upper-=bhlen;
	}
	//rs_debug("payloadlen:%d ",bh->payload_len);
	if(bh->ver!=BH_VER){
		rs_log(RS_ERROR,"BH_VER check2 failed\n");
		exit(-1);
	}
	//tbuf
	transferbuf_use(tbuf,MSG_HEADER_MAX);
	if(upper<bh->payload_len){
		transferbuf_write(tbuf,l->buf+rtt->rindex,upper);
		transferbuf_write(tbuf,l->buf,bh->payload_len-upper);

	}else{
		transferbuf_write(tbuf,l->buf+rtt->rindex,bh->payload_len);
	}
	rtt->rp.rtmsnd.type=bh->type;
	rtt->rp.rtmsnd.ts=bh->ts;
	rtt->rp.rtmsnd.chunkid=bh->chunkid;
	rtt->rindex=(rtt->rindex+bh->payload_len)%LIVEBUFSIZE;
	rtmpmsg_forsnd(&rtt->rp.rtmsnd,tbuf);
	if(rtransfer_snd(rtt)!=FINISH){
		rtt->flags|=(TRAN_WRITE|TRAN_UPDATE);
	}
}

bool transfer_removefromlive(rtransfer_t *rtt)
{
	live_t *live=NULL;
	bool del=FALSE;
	entry_t *e;

	live=rtt->live;
	if(live){
		e=varset_get(&rtt->rp.varset,"publish");
		if(e){
			live->publish=NULL;
			del=TRUE;
			rs_warn("remove publish from live\n");
		}
		e=varset_get(&rtt->rp.varset,"streamname");
		if(e){
			list_del(&rtt->livelist);
			del=TRUE;
			rs_warn("remove listener from live\n");
		}
		if(!livealone(live)){
			livecache_put(live);
			rs_warn("livecache return as live empty\n");
		}
		rtt->live=NULL;
	}
	return del;
}

bool transfer_createlive(rtransfer_t *rtt,char *path,char *type)
{
	live_t *l=NULL;
	if((l=live_find(path))&&l->publish){
		return FALSE;
	}
	if(!l)
		l=livecache_get();
	if(l->publish)
		return FALSE;
	l->publish=rtt;
	l->path=path;l->type=type;
	rtt->live=l;
	return TRUE;
}

bool transfer_joinlive(rtransfer_t *rtt,char *path)
{
	live_t *l;
	if(!(l=live_find(path))){
		l=livecache_get();
		l->path=path;
	}
	rtt->rindex=l->windex;
	list_add(&l->listeners,&rtt->livelist);
	rtt->live=l;
	return TRUE;
}

void sndheader(rtransfer_t *pub,rtransfer_t *rtt)
{
	transferbuf_t *tbuf;
	tbuf=&rtt->sndbuf;
	rtt->rp.rtmsnd.type=pub->rp.script_data_type;
	rtt->rp.rtmsnd.ts=0;
	transferbuf_init(tbuf,BUFSIZE);
	transferbuf_use(tbuf,MSG_HEADER_MAX);
	transferbuf_write(tbuf,pub->rp.script_data,pub->rp.script_data_len);
	rtmpmsg_forsnd(&rtt->rp.rtmsnd,tbuf);
	rtransfer_snd(rtt);

	rtt->rp.rtmsnd.type=pub->rp.video_type;
	rtt->rp.rtmsnd.ts=0;
	transferbuf_init(tbuf,BUFSIZE);
	transferbuf_use(tbuf,MSG_HEADER_MAX);
	transferbuf_write(tbuf,pub->rp.video_seq_header,pub->rp.video_seq_header_len);
	rtmpmsg_forsnd(&rtt->rp.rtmsnd,tbuf);
	rtransfer_snd(rtt);

	rtt->rp.rtmsnd.type=pub->rp.audio_type;
	rtt->rp.rtmsnd.ts=0;
	transferbuf_init(tbuf,BUFSIZE);
	transferbuf_use(tbuf,MSG_HEADER_MAX);
	transferbuf_write(tbuf,pub->rp.audio_spec,pub->rp.audio_spec_len);
	rtmpmsg_forsnd(&rtt->rp.rtmsnd,tbuf);
	rtransfer_snd(rtt);
}
area_t * area_new(transferbuf_t *tbuf)
{
	area_t *at;
	int i=0;
	bufheader_t *bh=(bufheader_t*)(tbuf->buf);
	if(bh->sig!=BUFSIG&&bh->ver!=BUFVER){
		transferbuf_check(tbuf,sizeof(bufheader_t));
		bh->sig=BUFSIG;
		bh->ver=BUFVER;
		bh->size=0;
		bh->offset_area=0;
		tbuf->offset+=sizeof(bufheader_t);
		tbuf->offset_op=tbuf->offset;
	}
	at=(area_t*)(tbuf->buf+sizeof(bufheader_t));
	transferbuf_check(tbuf,sizeof(*at));
	while(i<bh->size){
		at=(area_t*)(at->payload+at->offset);
		i++;
	}
	bh->size++;
	memset((char*)at,0,sizeof(*at));
	tbuf->offset+=sizeof(*at);
	return at;
}
void area_print(transferbuf_t *tbuf)
{
	area_t *at;
	int i=0;
	bufheader_t *bh=(bufheader_t*)(tbuf->buf);
	if(bh->sig!=BUFSIG&&bh->ver!=BUFVER){
		return;
	}
	at=(area_t*)(tbuf->buf+sizeof(bufheader_t));
	rs_log(RS_WARN,"bufhead size:%d ",bh->size);
	while(i<bh->size){
		rs_log(RS_WARN,"at%d offset:%d offset_op:%d",i,at->offset,at->offset_op);
		at=(area_t*)(at->payload+at->offset);
		i++;
	}
	rs_log(RS_WARN,"\n");
}
void area_write(area_t *at,transferbuf_t *tbuf,char *buf,int len)
{
	transferbuf_check(tbuf,len);
	memcpy(at->payload+at->offset,buf,len);
	at->offset+=len;
	//tbuf->offset+=len;
}

area_t * area_get(transferbuf_t *tbuf,int atindex)
{
	int i=0,end;
	area_t *at;
	bufheader_t *bh=(bufheader_t*)(tbuf->buf);
	if(bh->sig!=BUFSIG&&bh->ver!=BUFVER){
		rs_log(RS_DEBUG,"area_get failed\n");
		return NULL;
	}
	end=bh->size-1;
	if(end<atindex){
		rs_log(RS_DEBUG,"atindex failed\n");
		exit(-1);
	}
	at=(area_t*)(tbuf->buf+sizeof(bufheader_t));
	while(i<atindex){
		at=(area_t*)(at->payload+at->offset);
		i++;
	}
	return at;
}
char * at_use(area_t *at,transferbuf_t *tbuf,int len)
{
	char *off;
	transferbuf_check(tbuf,len);
	off=at->payload+at->offset;
	at->offset+=len;
	at->offset_op=at->offset;
	//tbuf->offset+=len;
	return off;
}
char * record_getpath(char *streamname)
{
	static char _spath[1024];
	if(!streamname){
		rs_debug("record getpath failed,streamname:%s\n",streamname);
		return NULL;
	}
	sprintf(_spath,"%s/%s%s",RECORD_DIR,streamname,".flv");
	return _spath;
}
bool clientrecord(record_t *r,struct rtmptransfer_s *rtt,char *data,int len)
{
	transferbuf_t *sndbuf;
	rtmpmsg_t *msg;
	area_t *at;

	sndbuf=&rtt->sndbuf;
	msg=&rtt->rp.rtmsnd;
	msg->chunkid=0x04;
	msg->type=r->dp.type;
	msg->ts=r->dp.ts;
	msg->streamid=rtt->rp.streamid;

	transferbuf_init(sndbuf,BUFSIZE);
	at=area_new(sndbuf);
	at->msg=*msg;
	at_use(at,sndbuf,MSG_HEADER_MAX);
	area_write(at,sndbuf,data,len);
	sndbuf->offset+=at->offset;
	rtmpmsg_forsnd_area(&at->msg,at);

	if(rtransfer_snd(rtt)!=FINISH){
		rtt->flags|=(TRAN_WRITE|TRAN_UPDATE);
		return FALSE;
	}else
		return TRUE;
}
struct dpacket * record_getframe(record_t *r)
{
	struct dpacket *dp;
	if(!r->dp.datalen){
		dp=df_getpack(&r->flv);
		if(dp->datalen>102400){
			rs_debug("frame size bigger than 102400......\n");
			exit(-1);
		}
		r->dp=*dp;
		memcpy(r->data,r->dp.data,r->dp.datalen);
		r->dp.data=r->data;
	}
	return &r->dp;
}
void record_frameclear(record_t *r)
{
	r->dp.datalen=0;
}
void record_return(record_t *r,struct rtmptransfer_s *rtt)
{
	df_uninit(&r->flv);
	rtt->flags&=~RECORD_BEGIN;
}
void record_init()
{
	if(!mkdir(RECORD_DIR,S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP)){
		rs_warn("mkdir %s\n for recording",RECORD_DIR);
	}
}
bool area_haveareabuf(transferbuf_t *tbuf)
{
	bufheader_t *bh=(bufheader_t*)(tbuf->buf);
	if(bh->sig!=BUFSIG&&bh->ver!=BUFVER)
		return FALSE;
	else
		return TRUE;
}
