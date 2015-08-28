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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "flv.h"
#define BUFDEFAULT 4096

static struct aacpacket aacp;
static struct h264packet vcp;
static struct scriptpacket scp;
struct sbuf{
	char *databuf;
	int buflen;
};
static struct sbuf gsb;
static struct sbuf *pgsb=&gsb;
static void sbuf_uninitbuf()
{
	if(pgsb->databuf)
		free(pgsb->databuf);
	pgsb->buflen=0;
}
static void sbuf_initbuf(int size)
{
	if(size<=0){
		printf("sbuf init failed,size:%d\n",size);
		exit(-1);
	}
	if(pgsb->databuf)
		sbuf_uninitbuf();
	if(!(pgsb->databuf=malloc(size))){
		printf("pgsb malloc failed\n");
		exit(-1);
	}
	pgsb->buflen=size;
	aacp.dp.data=pgsb->databuf;
	vcp.dp.data=pgsb->databuf;
	scp.dp.data=pgsb->databuf;
}
static void inline sbuf_update(int len)
{
	if(pgsb->buflen<len)
		sbuf_initbuf(len);
}
int df_init(struct dflv *df,char *path)
{
	if(!path||(df->fd=open(path,O_RDONLY))<0||read(df->fd,&df->flv,13)<=0){
		printf("df init failed\n");
		return -1;
	}
	/*
	   printf("ver:%d\n",df->flv.ver);
	   printf("flagaudio:%d\n",df->flv.flagaudio);
	   printf("flagvideo:%d\n",df->flv.flagvideo);
	   */
	sbuf_initbuf(BUFDEFAULT);
	printf("df init ok\n");
	return 0;
}
void df_uninit(struct dflv *pdf)
{
	if(pdf->fd){
		close(pdf->fd);
		pdf->fd=0;
	}
	sbuf_uninitbuf();
	printf("df uninit ok\n");
}
static inline unsigned char revertchar(unsigned char s)
{
	char tmp=(s&0xf)<<4;
	s=((s>>4)&0xf)|tmp;
	return s;
}

int audio_packset(struct dpacket *dp,struct dflv *df)
{
	struct aacpacket *aacp=(struct aacpacket *)dp;
	if((read(df->fd,&aacp->sndflags,1))<=0){
		printf("audio read failed\n");
		return -1;
	}
	aacp->sndflags=revertchar(aacp->sndflags);
	if((aacp->sndflags&SNDFMTMASK)==SNDFMT_AAC){
		if((read(df->fd,&aacp->packettype,1))<=0){
			printf("read packet type failed\n");
			return -1;
		}
		if(lseek(df->fd,-2,SEEK_CUR)<0){
			perror("lseek");
			return -1;
		}
		dp->datalen=dp->packlen;
		sbuf_update(dp->datalen);
		if((read(df->fd,dp->data,dp->datalen))<=0){
			printf("read audio data failed\n");
			return -1;
		}
	}else{
		printf("don't known this flag:%d\n",aacp->sndflags);
		return -1;
	}
	//printf("audio fmt:%d soundrate:%d soundsize:%d soundtype:%d packettype:%d\n",aacp->sndflags&SNDFMTMASK,(aacp->sndflags&SNDRATEMASK)>>4,(aacp->sndflags&SNDSIZEMASK)>>6,(aacp->sndflags&SNDTYPEMASK)>>7,aacp->packettype);
	return 0;
}
int video_packset(struct dpacket *dp,struct dflv *df)
{
	struct h264packet *vcp=(struct h264packet *)dp;
	int len=0;
	read(df->fd,&vcp->h264flags,1);len++;
	vcp->h264flags=revertchar(vcp->h264flags);
	if(((vcp->h264flags&AVC_CIDMASK)>>4)==AVC2){
		read(df->fd,&vcp->packettype,1);len++;
		read(df->fd,vcp->compositiontime,3);
		len+=3;
	}else{
		printf("don't known this flag:%d\n",vcp->h264flags);
		return -1;
	}
	//printf("video frametype:%d cid:%d packettype:%d\n",vcp->h264flags&AVC_TYPEMASK,(vcp->h264flags&AVC_CIDMASK)>>4,vcp->packettype);
	if(lseek(df->fd,-len,SEEK_CUR)<0)
		perror("lseek");
	dp->datalen=dp->packlen;
	sbuf_update(dp->datalen);
	if((read(df->fd,dp->data,dp->datalen))<=0){
		printf("read video data failed\n");
		return -1;
	}
	return 0;
}
int script_packset(struct dpacket *dp,struct dflv *df)
{
	//struct scriptpacket *scp=(struct scriptpacket *)dp;
	dp->datalen=dp->packlen;
	sbuf_update(dp->datalen);
	if(read(df->fd,dp->data,dp->packlen)<=0){
		printf("read script data failed\n");
		return -1;
	}
	return 0;
}
void df_getnxtpack(struct dflv *df)
{

}
struct dpacket * df_getpack(struct dflv *df)
{
	struct flvtag ft;
	struct dpacket *dp;
	if((read(df->fd,(char*)&ft,11)<=0)){
		printf("get pack failed\n");
		goto j1;
	}
	ft.datalen=ft.datasize[0]<<16|ft.datasize[1]<<8|ft.datasize[2];
	if(ft.datalen<=0){
		printf("ft.datalen:%d,what's wrong.\n",ft.datalen);
		return NULL;
	}
	if(ft.tagtype==PACKET_TYPE_AUDIO){
		dp=df->dp=(struct dpacket*)&aacp;
	}else if(ft.tagtype==PACKET_TYPE_VIDEO){
		dp=df->dp=(struct dpacket*)&vcp;
	}else if(ft.tagtype==PACKET_TYPE_SCRIPT){
		dp=df->dp=(struct dpacket*)&scp;
	}else{
		printf("can't process this type yet,type:%d\n",ft.tagtype);
		return NULL;
	}
	dp->packlen=ft.datalen;
	dp->pack_set(dp,df);
	if(read(df->fd,&ft.tagsize,4)<=0){
		printf("read tagsize,failed\n");
		goto j1;
	}
	//printf("tagsize:%d\n",ntohl(ft.tagsize));
	dp->ts=ft.timestamp[0]<<16|ft.timestamp[1]<<8|ft.timestamp[2];
	dp->type=ft.tagtype;
	dp->streamid=ft.streamid[0]<<16|ft.streamid[1]<<8|ft.streamid[2];
	if(dp->ts<0||dp->streamid<0){
		printf("get ts or streamid failed\n");
	}
	return dp;
j1:
	return NULL;
}
void dp_print(struct dpacket *dp)
{
	struct aacpacket *acp;
	struct h264packet *hp;
	printf("frame_ts:%d frame_class:%d framelen:%d ",dp->ts,dp->type,dp->datalen);
	if(dp->type==PACKET_TYPE_VIDEO){
		hp=(struct h264packet*)dp;
		printf("frametype:%d codecid:%d packettype:%d\n",hp->h264flags&AVC_TYPEMASK,(hp->h264flags&AVC_CIDMASK)>>4,hp->packettype);
	}else if(dp->type==PACKET_TYPE_AUDIO){
		acp=(struct aacpacket*)dp;
		printf("audio fmt:%d soundrate:%d soundsize:%d soundtype:%d packettype:%d\n",acp->sndflags&SNDFMTMASK,(acp->sndflags&SNDRATEMASK)>>4,(acp->sndflags&SNDSIZEMASK)>>6,(acp->sndflags&SNDTYPEMASK)>>7,acp->packettype);
	}else
		printf("\n");
}
static struct aacpacket aacp={
	.dp.pack_set=audio_packset,
};
static struct h264packet vcp={
	.dp.pack_set=video_packset
};
static struct scriptpacket scp={
	.dp.pack_set=script_packset
};
