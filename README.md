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

## 可以使用EasyPusher测试手机推流,[下载地址](https://github.com/EasyDSS/EasyPusher)

### 推流URL规则: rtsp://{ip}:{port}/{id} ， 例如 : rtsp://www.easydarwin.org:554/your_stream_id

## EasyPusher参数设置如下
![snapshot](EasyPusher1.jpg)
## 可使用vlc播放器、[EasyScreenLive](https://github.com/EasyDSS/EasyScreenLive)、[EasyPlayer-RTSP](https://github.com/EasyDSS/EasyPlayer-RTSP-Win/releases)、[EasyPlayerPro](https://github.com/EasyDSS/EasyPlayerPro-Win)测试播放

- 效果图:

- ![snapshot](result.png)


## 开发模式运行

	cd EasyDarwin && npm i
	npm i -g nodemon
	npm run dev		      

## 获取更多信息
- 邮件：support@easydarwin.org
- WEB：www.EasyDarwin.org
- QQ交流群：436297092

## 下一步开发计划

- 系统运行信息统计：CPU、内存、分发流量、累积运行时间等；
- 拉模式转发/分发；
- 服务端录像；