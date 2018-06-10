# EasyDarwin开源流媒体服务器

![snapshot](snapshot.png)

## 安装部署

- [下载解压 release 包](https://github.com/EasyDarwin/EasyDarwin/releases)

- 运行服务

	Windows 平台执行 `start.bat` 运行 EasyDarwin
	
	Linux 平台, 执行 `start.sh` 运行

- 停止服务

	Windows 平台执行 `stop.bat` 停止 EasyDarwin
	
	Linux 平台执行 `stop.sh` 停止

- 测试推流

        ffmpeg -i rtmp://live.hkstv.hk.lxdns.com/live/hks -rtsp_transport tcp -vcodec h264 -f rtsp rtsp://localhost/test

- 测试播放

        ffplay -rtsp_transport tcp rtsp://localhost/test  

## 开发模式运行

	cd EasyDarwin && npm i
	npm i -g nodemon
	npm run dev		      


## 下一步开发计划

- 系统运行信息统计：CPU、内存、分发流量、累积运行时间等；
- 拉模式转发/分发；
- 服务端录像；