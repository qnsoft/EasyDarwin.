/*
	Copyleft (c) 2012-2016 EasyDarwin.ORG.  All rights reserved.
	Github: https://github.com/EasyDarwin
	WEChat: EasyDarwin
	Website: http://www.EasyDarwin.org
*/

#ifndef __HTTP_SESSION_H__
#define __HTTP_SESSION_H__

#include "HTTPSessionInterface.h"

#include "HTTPRequest.h"
#include <QTSSModule.h>
#include <boost/function.hpp>

using namespace std;

class HTTPSession : public HTTPSessionInterface
{
public:
	HTTPSession();
	virtual ~HTTPSession();

	void PostRequest(const string& msg, const string& uri = "/", const string& host = "");
	void PostResponse(const string& msg, bool close = true);

	const string& GetTalkbackSession() const { return talkbackSession_; }
	void SetTalkbackSession(const string& session) { talkbackSession_ = session; }

	int GetDarwinHTTPPort() const { return darwinHttpPort_; }
    strDevice* GetDeviceInfo() const { return device_; }

    Easy_SessionType GetSessionType() const { return sessionType_; }

private:
	virtual SInt64 Run();

	QTSS_Error sendHTTPPacket(const string& msg);
	// Does request prep & request cleanup, respectively
	QTSS_Error setupRequest();
	void cleanupRequest();
	bool isRightChannel(const char* channel) const;

	QTSS_Error processRequest();
	QTSS_Error execNetMsgErrorReqHandler(HTTPStatusCode errCode);
	QTSS_Error execNetMsgDSRegisterReq(const char* json);
	QTSS_Error execNetMsgDSPushStreamAck(const char* json);
	QTSS_Error execNetMsgCSFreeStreamReq(const char *json);
	QTSS_Error execNetMsgDSStreamStopAck(const char* json) const;
	QTSS_Error execNetMsgDSPostSnapReq(const char* json);
	static QTSS_Error execNetMsgDSPTZControlAck(const char* json);
	QTSS_Error execNetMsgDSPresetControlAck(const char* json) const;

	QTSS_Error execNetMsgCSTalkbackControlReq(const char* json);
	static QTSS_Error execNetMSGDSTalkbackControlAck(const char* json);
	QTSS_Error execNetMSGDSSnapAck(const char* json);

	QTSS_Error execNetMsgCSDeviceListReq(const char* json);
	QTSS_Error execNetMsgCSCameraListReq(const char* json);

    QTSS_Error snapHandler(const char* json);

	QTSS_Error execNetMsgCSSnapReqRESTful(const char* queryString);
	QTSS_Error execNetMsgCSStartStreamReqRESTful(const char* queryString);
	QTSS_Error execNetMsgCSStopStreamReqRESTful(const char* queryString);
	QTSS_Error execNetMsgCSGetDeviceListReqRESTful(const char* queryString);
	QTSS_Error execNetMsgCSGetCameraListReqRESTful(const char* queryString);
	QTSS_Error execNetMsgCSPTZControlReqRESTful(const char* queryString);
	QTSS_Error execNetMsgCSPresetControlReqRESTful(const char* queryString);

	QTSS_Error execNetMsgCSGetBaseConfigReqRESTful(const char* queryString);
	QTSS_Error execNetMsgCSSetBaseConfigReqRESTful(const char* queryString);

	QTSS_Error execNetMsgCSGetServerInfoReqRESTful(const char* queryString);

	QTSS_Error execNetMsgCSRestartReqRESTful(const char* queryString);

	QTSS_Error execNetMsgCSGetUsagesReqRESTful(const char* queryString);

	QTSS_Error dumpRequestData();

	// test current connections handled by this object against server pref connection limit
	static bool overMaxConnections(UInt32 buffer);

	void addDevice() const;
    void unRegDevSession() const;

	void initHandlerMap();

	void createApiHandler(const string& url, QTSS_Error(HTTPSession::*action)(const char*));
	void createProtocolHandler(const string& url, QTSS_Error(HTTPSession::*action)(const char*));

    void setChannelSnap(const string& url, const string& channel);

	enum
	{
		kReadingRequest = 0,		//读取报文
		kFilteringRequest = 1,		//过滤报文
		kPreprocessingRequest = 2,	//预处理报文
		kProcessingRequest = 3,		//处理报文
		kSendingResponse = 4,		//发送响应报文
		kCleaningUp = 5,			//清空本次处理的报文内容

		kReadingFirstRequest = 6,	//第一次读取Session报文，主要用来做Session协议区分（HTTP/TCP/RTSP等等）
		kHaveCompleteMessage = 7	// 读取到完整的报文
	};

	//UInt32 fCurrentModule;
    UInt32 state_;

    HTTPRequest* request_;
    OSMutex readMutex_;
    OSMutex sendMutex_;

	//QTSS_RoleParams     fRoleParams;//module param blocks for roles.
	QTSS_ModuleState moduleState_;

    Easy_SessionType    sessionType_;	//普通socket,NVR,智能主机，摄像机

	string talkbackSession_;

	int darwinHttpPort_;

	map<string, boost::function<QTSS_Error(const char*)> > handlerMap_;

    strDevice* device_;

    char* requestBody_;

	UInt32 contentOffset_;

};

#endif // __HTTP_SESSION_H__
