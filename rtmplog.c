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
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>

static char _log[4096];
static loglel_t loglevel=RS_ERROR;
static const char *logstr[]={
	" [WARN]","[DEBUG]","[ERROR]"
};

static void _rs_log(loglel_t lel,char *fmt,va_list args)
{
	char *p;
	int len;
	struct tm log_tm;
	struct timeval tv;
#ifdef RSLOG
	if(lel>loglevel)
		return;
	len=strlen(logstr[lel]);
	memcpy(_log,logstr[lel],len);
	p=_log+len;
	gettimeofday(&tv,NULL);
	localtime_r(&tv.tv_sec,&log_tm);
	len=sprintf(p,"%d-%02d-%02d %02d:%02d:%02d:%04u   ",log_tm.tm_year+1900,log_tm.tm_mon+1,log_tm.tm_mday,log_tm.tm_hour,log_tm.tm_min,log_tm.tm_sec,(uint32_t)(tv.tv_usec/1000));
	p+=len;
	vsnprintf(p,4095,fmt,args);
	_log[4095]='\0';
	fprintf(stderr,"%s",_log);
#endif
}

void rs_log(loglel_t lel,char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    _rs_log(lel,fmt,args);
    va_end(args);

}

void rs_warn(char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    _rs_log(RS_WARN,fmt,args);
    va_end(args);
}
void rs_debug(char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    _rs_log(RS_DEBUG,fmt,args);
    va_end(args);
}
void rs_error(char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    _rs_log(RS_ERROR,fmt,args);
    va_end(args);
}
