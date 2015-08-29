rtmpserver for raspberry pi

1,make

2,start rtmpserver
raspberry pi's ip address was 192.168.1.1 for example

3,use one client to publish
(e.g)ffmpeg -re i test.flv -f flv -strict -2 -acodec aac -ar 44100 -vcodec h264 rtmp://192.168.1.1:1935/live/hello

4,use one client to play
(e.g)ffplay rtmp://192.168.1.1:1935/live/hello

by duanxiangqaz@hotmail.com
