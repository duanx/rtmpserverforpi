cc=gcc

server=rtmpserver

COMMONCFLAGS+=-Wall -g -pg -DDEBUG -DRSLOG
CFLAGS+=$(COMMONCFLAGS) 
LDLIBS+=

headers=

serobj=rtmplog.o rtmptransfer.o rtmplive.o util.o amf.o varset.o linux.o flv.o

all:$(server)

$(server): $(serobj) $(server).o $(headers)
	$(cc) $(CFLAGS) $(serobj) $(server).o -o $@
	chown root:root $(server)
	chmod u+s $(server)
	mkdir -p records

dist:$(server)
	strip $(server)

.PHONY :clean
clean:
	rm -f $(server) $(serobj) $(server).o
