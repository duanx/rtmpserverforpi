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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <error.h>
#include <unistd.h>
#include <stdlib.h>

unsigned long rsystime()
{
	struct timeval ts;
	gettimeofday(&ts,NULL);
	return ts.tv_sec*1000+ts.tv_usec/1000;
}
int rfork()
{
	pid_t pid;
	if((pid=fork())<0){
		perror("fork");
	}
	return (int)pid;
}

int rdaemon()
{
	int pid,fd;
	if((pid=rfork())<0){
		return -1;
	}
	if(!pid){
		if(setsid()<0)
			perror("setsid");
		if((fd=open("/dev/null",O_RDWR,0))!=-1){
			dup2(fd,0);
			dup2(fd,1);
			dup2(fd,2);
		}
		if(fd>2)
			close(fd);
	}
	return pid;
}
