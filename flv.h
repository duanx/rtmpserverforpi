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
#ifndef _FLV_H_
#define _FLV_H_
struct dflv;
struct dpacket{
	unsigned int ts;
	unsigned int streamid;
#define PACKET_TYPE_SCRIPT 18
#define PACKET_TYPE_AUDIO 8
#define PACKET_TYPE_VIDEO 9
	int type;
	int packlen;
	char *data;
	int datalen;
	int (*pack_set)(struct dpacket *dp,struct dflv *df);
};
struct scriptpacket{
	struct dpacket dp;
};
struct aacpacket{
	struct dpacket dp;
#define SNDFMTMASK 0xf
#define SNDFMT_PCM 0
#define SNDFMT_ADPCM 1
#define SNDFMT_MP3 2
#define SNDFMT_AAC 10
#define SNDRATEMASK 0x30
#define SNDRATE_5 0
#define SNDRATE_11 1
#define SNDRATE_22 2
#define SNDRATE_44 3
#define SNDSIZEMASK 0x40
#define SNDSIZE_8B 0
#define SNDSIZE_16B 1
#define SNDTYPEMASK 0x80
#define SNDTYPE_MONO 0
#define SNDTYPE_STEREO 1
	unsigned char sndflags;
#define AAC_PACKTYPE_SEQHEADER 0
#define AAC_PACKTYPE_RAW 1
	unsigned char packettype;
};
struct h264packet{
	struct dpacket dp;
	/*frame type*/
#define AVC_TYPEMASK 0xf
#define AVC_KEYFRAME 1
#define AVC_INTERFRAME 2
#define AVC_DISPOSABLE_INTERFRAME 3
#define AVC_GENERATEKEYFRAME 4
#define AVC_VIDEO_INFO 5
	/*codecid*/
#define AVC_CIDMASK 0xf0
#define AVC_SORENSON 2
#define AVC_SCREENVIDEO 3
#define AVC_VP6 4
#define AVC_VP6_alpha 5
#define AVC_SCREENVIDEO2 6
#define AVC2 7
	unsigned char h264flags;
#define AVC_PACKTYPE_SEQHEADER 0
#define AVC_PACKTYPE_NALU 1
#define AVC_PACKTYPE_ENDSEQ 2
	unsigned char packettype;
	char compositiontime[3];
};
struct flvtag{
	/*flv tag*/
	unsigned char tagtype:5;
	unsigned char filter:1;
	unsigned char reserved:2;
	unsigned char datasize[3];
	unsigned char timestamp[3];
	unsigned char timestampext;
	unsigned char streamid[3];
	unsigned int tagsize;
	/*end flv tag*/
	unsigned int datalen;
}__attribute__((__packed__));
struct flv{
	/*tag header*/
	unsigned char sig[3];
	unsigned char ver;
	unsigned char flagvideo:1;
	unsigned char flagvideoreserved:1;
	unsigned char flagaudio:1;
	unsigned char flagaudioreserved:5;
	unsigned int hdlen;
	/*end tag header*/
	unsigned int inittagsize;
};
struct dflv{
	int fd;
	struct flv flv;
	struct dpacket *dp;
};
int df_init(struct dflv *df,char *path);
struct dpacket * df_getpack(struct dflv *df);
void df_getnxtpack(struct dflv *df);
void dp_print(struct dpacket *dp);
void df_uninit(struct dflv *pdf);
#endif
