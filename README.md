# EasyDarwin

EasyDarwin Node.js 版本 [Demo](http://www.easydarwin.org:10008)

## 安装部署

1. 准备 Node.js 运行环境

    Node.js version >= v8

2. 安装依赖库

        git clone --depth=1 https://github.com/EasyDarwin/EasyDarwin.git
        cd EasyDarwin && npm i --no-save

## 运行测试

1. 启动流媒体服务

        cd EasyDarwin && npm run start

2. 测试推流

        ffmpeg -i rtmp://live.hkstv.hk.lxdns.com/live/hks -rtsp_transport tcp -vcodec h264 -f rtsp rtsp://www.easydarwin.org/test

3. 测试播放

        ffplay -rtsp_transport tcp rtsp://www.easydarwin.org/test        