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
#include <sys/epoll.h>
#include "util.h"
#include "flv.h"
#include "sys.h"

#ifndef _RTMP_SERVER_H_
#define _RTMP_SERVER_H_

#define VER "1.0"
#define EVENTS_MAX 100
#define BUFSIZE (1024*64)
#define GTRANSFER_SIZE EVENTS_MAX
#define CHUNKSIZE 128
#define WINSIZE 10000000
#define LIVEBUFSIZE (512*1024)
#define MSG_HEADER_MAX 18

typedef enum bool_s{
	FALSE=-1,
	TRUE=0
}bool;

/************************rtmp**************************/
typedef enum limittype_s{
	HARD=0,
	SOFT,
	DYNAMIC
}limittype_t;

typedef enum ctrltype_s{
	STREAM_BEGIN=0,
	STREAM_EOF,
	STREAM_DRY,
	SET_BUFLEN,
	STREAM_ISRECORD,
	PINGREQ=6,
	PINGRES
}ctrltype_t;

typedef enum rtmpstatus_s{
	SINIT=0,
	SCONNING,
	SCONNED,
	SHANDSHAKE, //Version Sent
	SHANDSHAKED, //Handshake Done
	SCONNCMDED,
	SCREATESTREAM,
	SPUBLISHING,
	SPUBLISHED,
	SPLAYING,
	SPLAYED,
	SCONNFAIL=-20,
	SPLAYFAIL,
	SPUBLISHFAIL,
	SCONNCMDFAIL,
	SHANDSHAKEFAIL
}rtmpstatus_t;

typedef enum rtmpmsgtype_s{
	TCMD_AMF0=20,
	TCMD_AMF3=17,
	TDATA_AMF0=18,
	TDATA_AMF3=15,
	TAUDIO=8,
	TVIDEO=9,
	TCHUNKSIZE=1,
	TABORTMSG=2,
	TACKNOWLEDGEMENT=3,
	TCONTROLMSG=4,
	TWINDOW_ACKNOWLEDGEMENT=5,
	TPEER_BANDWIDTH=6
}rtmpmsgtype_t;

typedef enum chunktype_s{
	TYPE0=0,
	TYPE1,
	TYPE2,
	TYPE3
}chunktype_t;

typedef struct rtmpchunk_s{
	chunktype_t type;
#define SHIFT_CTYPE 6
	unsigned int chunkid;
	char header[MSG_HEADER_MAX];
	int headerlen;
#define TYPE0_LEN 11
#define TYPE1_LEN 7
#define TYPE2_LEN 3
#define TYPE3_LEN 0
}rtmpchunk_t;

typedef struct chunkset_s{
	struct rtmpmsg_s *msgs;
	int cursize;
	int size;
}chunkset_t;

typedef struct rtmp_s{
	int chunksize;
	int streamids;
	int winsize;
}rtmp_t;

typedef enum msgstatus_s{
	CHUNKTYPE=0,
	CHUNKID,
	CHUNKHEAD,
	CHUNKPAYLOAD,
	CHUNKFINISH
}msgstatus_t;

typedef struct rtmpchunkdata_s{
	int payload_len;
	char *data;
	int offset;
	int offset_op;
	char payload[1];
}rtmpchunkdata_t;

typedef struct rtmpmsg_s{
	rtmpmsgtype_t type;
	unsigned int ts;
	int streamid;
	char *payload;
	int payload_len;
	int chunksize;
	int chunkid;
	int chunktotalsize;//how many chunks in rtmpmsg
	int chunkindex; //the x chunk
	int chunkoffset;//offset in curchunk
	int winsize;
	int peerbandwidth;
	msgstatus_t ms;
}rtmpmsg_t;

typedef enum audiocodec_s{
	CODEC_SND_NONE=0x01,
	CODEC_SND_ADPCM=0x2,
	CODEC_SND_AAC=0x400,
	CODEC_SND_ALL=0xfff
}audiocodec_t;

typedef enum videocodec_s{
	CODEC_VID_UNUSED=0x1,
	CODEC_VID_H264=0x80,
	CODEC_VID_ALL=0xff
}videocodec_t;

typedef enum videofunction_s{
	SUPPORT_VID_CLIENT_SEEK
}videofunction_t;

typedef enum encoding_s{
	ENCODING_AMF0=0,
	ENCODING_AMF3=3
}encoding_t;

typedef union val_s{
	char _strval[128];
	double _doubleval;
	bool _boolval;
}val_t;

typedef enum entrycls_e{
	ESTRING,
	EDOUBLE,
	EBOOL
}entrycls_t;

typedef struct entry_s{
	char key[32];
	val_t val;
	entrycls_t cls;
	int status;
	struct entry_s *nxt;
}entry_t;

typedef struct varset_s{
	int hashsize;
	int cursize;
	entry_t **entrys;
	entry_t *pool;
	entry_t *free;
}varset_t;

typedef struct rtmpparser_s{
	int flags;
#define RTMPWRITE 1<<0
	rtmpstatus_t status;
	unsigned int cuptime;
	unsigned int suptime;
	char crandomecho[1536-8];
	char srandomecho[1536-8];
	varset_t varset;
	chunkset_t cs;
	int streamid;
	rtmpmsg_t rtm;
	rtmpmsg_t rtmsnd;
	char audio_spec[512];
	int audio_type;
	int audio_spec_len;
	char video_seq_header[1024];
	int video_seq_header_len;
	int video_type;
	char script_data[1024];
	int  script_data_len;
	int script_data_type;
}rtmpr_t;

struct transferbuf_s;
void rtmpmsg_init(rtmpmsg_t *rtm);
const rtmpmsg_t * chunkset_get(chunkset_t *cs,unsigned int csid);
void chunkset_put(chunkset_t *cs,unsigned int csid,const rtmpmsg_t *rchunk);
void chunkset_uninit(chunkset_t *cs);
bool chunkset_init(chunkset_t *cs,int size);
bool varset_init(varset_t *var,int len);
bool varset_putstr(varset_t *var,char *key,char *value,int len);
bool varset_putbool(varset_t *var,char *key,bool value);
bool varset_putdouble(varset_t *var,char *key,double value);
entry_t * varset_get(varset_t *var,char *key);
void varset_uninit(varset_t *var);
void chunkdata_init(rtmpmsg_t *msg,struct transferbuf_s *buf);

/************************end rtmp**************************/


/************************livebuf**************************/
typedef struct bufhead_s{
	int ver;
#define BH_VER 1
	int payload_len;
	unsigned int chunkid;
	rtmpmsgtype_t type;
	unsigned int ts;
}bufhead_t;
struct transferbuf_s;
typedef struct live_s{
	int flags;
#define LIVE_ENABLE 1<<0
#define LIVE_SNDDELAY 1<<1
	struct rtmptransfer_s *publish;
	list_t listeners;
	int listenersize;
	unsigned int windex;
	char buf[LIVEBUFSIZE];
	list_t active;
	char *path;
	char *type;
}live_t;

void livecache_uninit();
bool livecache_init(int caches);
bool livealone(live_t *l);
live_t * livecache_get();
void livecache_put(live_t *l);
void live_active();
live_t * live_find(char *path);
bool live_writefromtbuf(live_t *l,struct transferbuf_s *tbuf,rtmpmsg_t *msg,bool overwrite);

/************************end livebuf**************************/


/************************record**************************/
#define RECORD_DIR "records"
typedef struct record_s{
	int fd;
	unsigned long dts0;
	unsigned long pts0;
	struct dpacket dp;
	struct dflv flv;
	char data[102400];
}record_t;

char * record_getpath(char *streamname);
void record_init();
bool clientrecord(record_t *r,struct rtmptransfer_s *rtt,char *data,int len);
struct dpacket * record_getframe(record_t *r);
void record_frameclear(record_t *r);
bool preparerecord(record_t *r,struct rtmptransfer_s *rtt,char *streamname);
void record_return(record_t *r,struct rtmptransfer_s *rtt);


/************************end record**************************/


/************************rtmptransfer**************************/
typedef enum addr_type_s{
	UDP,
	TCP
}addrtype_t;

typedef struct raddr_s{
	char *hostname;
	unsigned int ip;
	unsigned short port;
	addrtype_t type;
}raddr_t;

typedef struct transferbuf_s{
	char buf[BUFSIZE];
	int total;
	int offset;
	int offset_op;
}transferbuf_t;

typedef struct bufheader_s{
	int sig;
#define BUFSIG 0xfe
	int ver;
#define BUFVER 1
	int size;
	int offset_area;
}bufheader_t;

typedef struct area_s{
	/*area header*/
	int offset;
	int offset_op;
	rtmpmsg_t msg;
	/*end area header*/
	char payload[1];
}area_t;

typedef struct rtmptransfer_s{
	rtmpr_t rp;
	record_t record;
	int fd;
	int flags;
#define TRAN_STATUS (1<<0)
#define TRAN_READ (1<<1)
#define TRAN_WRITE (1<<2)
#define TRAN_LISTEN (1<<3)
#define TRAN_UPDATE (1<<4)
#define TRAN_NOT_RTMPPROTOCAL (1<<5)
#define LIVEDATA_PUT (1<<6) //publish transfer need to push audio/video data to live listener
#define LIVEDATA_SENDING (1<<7) //sending livedata to listener
#define RECORD_BEGIN (1<<8)
	struct epoll_event ev;
	transferbuf_t recvbuf;
	transferbuf_t sndbuf;
	raddr_t addr;
	unsigned int rindex;
	list_t livelist;
	live_t *live;
	list_t rttlist;
}rtransfer_t;

void transferbuf_init(transferbuf_t *buf,int len);
void transferbuf_check(transferbuf_t *buf,int len);
int transferbuf_recv(int fd,transferbuf_t *buf,int len);
int transferbuf_full(transferbuf_t *buf);
void transferbuf_write(transferbuf_t *buf,char *base,int len);
int transferbuf_snd(rtransfer_t *rtt,transferbuf_t *buf,int len);
char * transferbuf_use(transferbuf_t *buf,int len);
void transferbuf_writefromlive(transferbuf_t *tbuf,live_t *l,rtransfer_t *rtt);

bool rtransfer_init(rtransfer_t *rtt);
bool rtransfer_bind(rtransfer_t *rtt,raddr_t *addr);
bool rtransfer_setlisten(rtransfer_t *rtt);
rtransfer_t * rtransfer_get();
void rtransfer_setfd(rtransfer_t *rtt,int fd);
struct rtmpserver_s;
void rtransfer_return(struct rtmpserver_s *rs,rtransfer_t *rtt);
void rtransfer_put(rtransfer_t *rtt);
bool rtransfer_preinit();
void rtransfer_postuninit();
rtransfer_t *rtransfer_findlisten();
bool transfer_createlive(rtransfer_t *rtt,char *path,char *type);
bool transfer_removefromlive(rtransfer_t *rtt);
bool transfer_joinlive(rtransfer_t *rtt,char *path);
int rtransfer_recv(rtransfer_t *rtt);
int rtransfer_snd(rtransfer_t *rtt);
int rtmprecv(rtmpr_t *rp);
int rtmpsnd(rtmpr_t *rp);
int rtmpparse(rtmpr_t *rp);
void sndheader(rtransfer_t *pub,rtransfer_t *rtt);

area_t * area_new(transferbuf_t *tbuf);
void area_write(area_t *at,transferbuf_t *tbuf,char *buf,int len);
bool area_haveareabuf(transferbuf_t *tbuf);
area_t * area_get(transferbuf_t *tbuf,int atindex);
char * at_use(area_t *at,transferbuf_t *sndbuf,int len);
void area_print(transferbuf_t *tbuf);

/************************end rtmptransfer**************************/


/************************rtmpserver**************************/
typedef enum sstatus_s{
	STOP=0,
	START
}sstatus_t;

typedef struct rtmpserver_s{
	int events_max;
	int epoll_fd;
	struct epoll_event events[EVENTS_MAX];
	list_t transfer;
	int transfer_size;
	raddr_t server;
	sstatus_t status;
}rs_t;

bool rs_init(rs_t *rs);
void rs_run(rs_t *rs);
bool rs_prepare(rs_t *rs);
void rs_uninit(rs_t *rs);
bool rs_addtransfer(rs_t *rs,rtransfer_t *tt);
void rs_deltransfer(rs_t *rs,rtransfer_t *rtt);
void rs_update(rs_t *rs,rtransfer_t *rtt);

/************************end rtmpserver**************************/

/************************rtmplog**************************/
typedef enum loglel_s{
	RS_WARN=0,
	RS_DEBUG,
	RS_ERROR
}loglel_t;
void rs_log(loglel_t lel,char *fmt, ...);
void rs_warn(char *fmt, ...);
void rs_debug(char *fmt, ...);
void rs_err(char *fmt, ...);
/************************end rtmplog**************************/

#endif
