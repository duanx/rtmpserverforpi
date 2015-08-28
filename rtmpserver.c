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
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

#define EPTIMEOUT 6
#define PIDPATH "/var/run/rtmpserver.pid"

const static raddr_t saddr={"127.0.0.1",0,1935};
rs_t *_rs;

void sig(int sig)
{
	if(sig==SIGINT)
		_rs->status=STOP;
	else if(sig==SIGPIPE)
		rs_log(RS_WARN,"sigpipe from peer...\n");
}
bool rs_init(rs_t *rs)
{
	memset(rs,0,sizeof(*rs));
	rs->events_max=EVENTS_MAX;
	rs->server=saddr;
	if(rtransfer_preinit()||livecache_init(30))
		return FALSE;
	list_init(&rs->transfer);
	record_init();
	return TRUE;
}
bool rs_prepare(rs_t *rs)
{
	int fd;
	rtransfer_t *listen;
	if(!(listen=rtransfer_get()))
		return FALSE;

	fd=epoll_create(rs->events_max);
	if(fd<0){
		perror("epoll create");
		return FALSE;
	}
	rs->epoll_fd=fd;

	if(rtransfer_init(listen))
		return FALSE;
	if(rtransfer_bind(listen,&rs->server))
		return FALSE;
	if(rtransfer_setlisten(listen))
		return FALSE;
	if(rs_addtransfer(rs,listen))
		return FALSE;
	rs->status=START;
	return TRUE;
}

static void recordsnd(rs_t *rs)
{
	list_t *list;
	rtransfer_t *trans;
	record_t *r;
	struct dpacket *dp;
	unsigned long cur,ptsdelta;
	list=rs->transfer.nxt;
	while(list!=&rs->transfer){
		trans=container_of(list,rtransfer_t,rttlist);
		if(trans->flags&RECORD_BEGIN&&!(trans->flags&TRAN_WRITE)){
			r=&trans->record;
			if(!(dp=record_getframe(r))){
				record_return(r,trans);
				goto j1;
			}
			cur=rsystime();
			ptsdelta=dp->ts-r->pts0;
			if(cur-r->dts0>=ptsdelta){
				if(clientrecord(r,trans,dp->data,dp->datalen))
					rs_update(rs,trans);
				record_frameclear(r);
				r->dts0+=ptsdelta;
				r->pts0=dp->ts;
			}
		}
j1:
		list=list->nxt;
	}
}

static void failedcheck(rs_t *rs)
{
	list_t *list;
	rtransfer_t *trans;
	list=rs->transfer.nxt;
	while(list!=&rs->transfer){
		trans=container_of(list,rtransfer_t,rttlist);
		if(trans->rp.status<0&&!(trans->flags&TRAN_WRITE)){
			rs_log(RS_ERROR,"close fd:%d\n",trans->fd);
			rtransfer_return(rs,trans);
		}
		list=list->nxt;
	}
}

void rs_run(rs_t *rs)
{
	int nfds,i,ret;
	rtransfer_t *trans;
	list_t *list;
	if(rs->status==STOP)
		rs_debug("check rtmpserver status failed.\n");
	else if(rs->epoll_fd<0||rs->events_max<=0){
		rs_debug("check rtmpserver arg\n");
		rs->status=STOP;
	}else
		rs_debug("server is running...\n");
	while(rs->status){
		nfds=epoll_wait(rs->epoll_fd,rs->events,rs->events_max,EPTIMEOUT);
		if(nfds<0){
			//rs_log(RS_DEBUG,"nfds failed\n");
			continue;
		}else if(nfds>0){
			i=0;
			while(i<nfds){
				list=rs->transfer.nxt;
				while(list!=&rs->transfer){
					trans=container_of(list,rtransfer_t,rttlist);
					if((rs->events[i].data.fd==trans->fd)&&trans->flags&TRAN_STATUS){
						break;
					}
					list=list->nxt;
				}
				if(list==&rs->transfer){
					goto j1;
				}
				if(trans->flags&TRAN_LISTEN){
					int fd;
					struct sockaddr_in addr;
					socklen_t addrlen=sizeof(addr);
					rtransfer_t *new;
					if((fd=accept(trans->fd,(struct sockaddr*)&addr,&addrlen))<0){
						perror("accept");
					}else{
						//getpeername(fd,(struct sockaddr*)&addr,&addrlen);  
						if(!(new=rtransfer_get())){
							rs_warn("transfer_t memory is full,can't add new one\n");
							close(fd);
						}else{
							if(rtransfer_init(new)){
								rtransfer_put(new);
								varset_uninit(&new->rp.varset);
								chunkset_uninit(&new->rp.cs);
								close(fd);
							}else{
								new->addr.port=ntob16((char*)&addr.sin_port);
								new->addr.ip=ntob32((char*)&addr.sin_addr);
								new->flags|=TRAN_READ;
								rtransfer_setfd(new,fd);
								rs_addtransfer(rs,new);
								rs_warn("new fd:%d ip:%d port:%d\n",fd,new->addr.ip,new->addr.port);
							}
						}
					}
				}else{
					if((rs->events[i].events&EPOLLIN)&&(ret=rtransfer_recv(trans))<=0){
						if(!ret){
							rs_log(RS_WARN,"(recv)listener:%d down\n",trans->fd);
							rtransfer_return(rs,trans);
							continue;
						}else{
							//rs_log(RS_DEBUG,"listener:%d recv not yet\n",trans->fd);
						}
					}
					if((rs->events[i].events&EPOLLOUT)&&(ret=rtransfer_snd(trans))<=0){
						if(!ret){
							rs_log(RS_WARN,"(snd)listener:%d down\n",trans->fd);
							rtransfer_return(rs,trans);
							continue;
						}else{
							//rs_log(RS_DEBUG,"listener:%d snd not yet\n",trans->fd);
						}
					}
				}
				live_active();
				rs_update(rs,trans);
j1:
				i++;
			}
		}
		failedcheck(rs);
		recordsnd(rs);
	}
}

void rs_uninit(rs_t *rs)
{
	rtransfer_t *listen;
	listen=rtransfer_findlisten();
	if(!listen)
		exit(-1);
	rtransfer_return(rs,listen);
	livecache_uninit();
	rtransfer_postuninit();
	close(rs->epoll_fd);
}

int getpidfromdir()
{
	int fd,fpid;
	char path[1024];
	if((fd=open(PIDPATH,O_RDONLY))>=0){
		if(read(fd,path,1024)<=0){
			rs_debug("read run/pid failed\n");
			close(fd);
			return -1;
		}else{
			sscanf(path,"%d",&fpid);
			close(fd);
			return fpid;
		}
	}else
		return -1;

}

static bool rkillpid()
{
	int fpid;
	if((fpid=getpidfromdir())>=0){
		kill(fpid,SIGINT);
		usleep(200000);
		return TRUE;
	}else
		return FALSE;
}
static void killpidpath()
{
	unlink(PIDPATH);
}

static void createpid(int pid)
{
	char spid[128];
	int fd,spidlen;
	rkillpid();
	if((fd=open(PIDPATH,O_CREAT|O_RDWR,S_IRUSR|S_IWUSR))<0){
		rs_warn("open pidpath failed\n");
	}
	spidlen=sprintf(spid,"%d",pid);
	if(write(fd,spid,spidlen)!=spidlen){
		rs_warn("write pidpath failed\n");
	}
	close(fd);
}
static void usage()
{
	fprintf(stderr,"rtmpserver ver:%s by duanx\n\n",VER);
	fprintf(stderr,"usage: rtmpserver [nodaemon] [stop]\n");
	exit(-1);
}
static int opt(int argc,char **argv)
{
	int arg,index=0;
	if(argc>3){
		usage();
	}
	argc--;
	while(index<=argc){
		if(strstr(argv[index],"rtmpserver")){
			arg=0;
		}
		else if(!strcmp(argv[index],"stop")){
			arg=1;
		}else if(!strcmp(argv[index],"nodaemon")){
			arg=2;
		}else{
			arg=-1;
			break;
		}
		index++;
	}
	return arg;
}
int main(int argc,char **argv)
{
	int pid=0,arg,uid,euid;
	signal(SIGINT,sig);
	signal(SIGPIPE,sig);
	arg=opt(argc,argv);
	uid=getuid();
	euid=geteuid();
	/*for create /var/run/x.pid*/
	setuid(euid);
	if(arg<0)
		usage();
	else if(arg==1){
		/*stop*/
		if(!rkillpid()){
			killpidpath();
			rs_warn("server stopped\n");
		}
		return 0;
	}
	rs_warn("server started\n");
	if(!arg&&(pid=rdaemon())<0){
		exit(-1);
	}else if(pid){
		createpid(pid);
		exit(-1);
	}
	else{
		signal(SIGINT,sig);
		signal(SIGPIPE,sig);
		/*cancel root permission*/
		setuid(uid);
	}
	if(!(_rs=malloc(sizeof(rs_t)))){
		rs_warn("rs malloc failed\n");
		exit(-1);
	}
	if(rs_init(_rs))
		exit(-1);
	if(rs_prepare(_rs))
		exit(-1);
	rs_run(_rs);
	rs_uninit(_rs);
	free(_rs);
	rs_log(RS_WARN,"server down\n");
	return 0;
}
