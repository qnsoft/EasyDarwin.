/*
    Copyleft (c) 2012-2016 EasyDarwin.ORG.  All rights reserved.
    Github: https://github.com/EasyDarwin
    WEChat: EasyDarwin
    Website: http://www.EasyDarwin.org
*/
/*
    File:       HTTPSession.cpp
    Contains:   EasyCMS HTTPSession
*/

#include "HTTPSession.h"

#include "QTSServerInterface.h"
#include "OSArrayObjectDeleter.h"
#include "QTSSMemoryDeleter.h"
#include "EasyUtil.h"
#include "QueryParamList.h"
#include "Format.h"

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/bind.hpp>
#include <set>

#if __FreeBSD__ || __hpux__	
#include <unistd.h>
#endif

#include <errno.h>

#if __solaris__ || __linux__ || __sgi__	|| __hpux__
#include <crypt.h>
#endif

using namespace std;

static const int sIPSize = 20;
static const int sPortSize = 6;

#define	WIDTHBYTES(c)		((c+31)/32*4)	// c = width * bpp
#define	SNAP_CAPTURE_TIME	30
#define SNAP_IMAGE_WIDTH	320
#define	SNAP_IMAGE_HEIGHT	180
#define	SNAP_SIZE			SNAP_IMAGE_WIDTH * SNAP_IMAGE_HEIGHT * 3 + 58

HTTPSession::HTTPSession()
    : HTTPSessionInterface()
    , state_(kReadingFirstRequest)
    , request_(NULL)
    , sessionType_(EasyHTTPSession)
    , device_(NULL)
    , requestBody_(NULL)
    , contentOffset_(0)
{
    this->SetTaskName("HTTPSession");

    //All EasyCameraSession/EasyNVRSession/EasyHTTPSession
    QTSServerInterface::GetServer()->AlterCurrentHTTPSessionCount(1);

    moduleState_.curModule = NULL;
    moduleState_.curTask = this;
    moduleState_.curRole = 0;
    moduleState_.globalLockRequested = false;

    OSRefTableEx* sessionMap = QTSServerInterface::GetServer()->GetHTTPSessionMap();
    sessionMap->Register(sessionId_, this);

    initHandlerMap();

    qtss_printf("Create HTTPSession:%s\n", sessionId_.c_str());
}

void HTTPSession::initHandlerMap()
{
    createProtocolHandler("protocol/cms/device/register", &HTTPSession::execNetMsgDSRegisterReq);

    createApiHandler("protocol/ums/device/uploadsnap", &HTTPSession::snapHandler);
    createApiHandler("api/v1/getdevicelist", &HTTPSession::execNetMsgCSGetDeviceListReqRESTful);
    createApiHandler("api/v1/getdeviceinfo", &HTTPSession::execNetMsgCSGetCameraListReqRESTful);
    createApiHandler("api/v1/startdevicestream", &HTTPSession::execNetMsgCSStartStreamReqRESTful);
    createApiHandler("api/v1/stopdevicestream", &HTTPSession::execNetMsgCSStopStreamReqRESTful);
    createApiHandler("api/v1/ptzcontrol", &HTTPSession::execNetMsgCSPTZControlReqRESTful);
    createApiHandler("api/v1/presetcontrol", &HTTPSession::execNetMsgCSPresetControlReqRESTful);
    createApiHandler("api/v1/getbaseconfig", &HTTPSession::execNetMsgCSGetBaseConfigReqRESTful);
    createApiHandler("api/v1/setbaseconfig", &HTTPSession::execNetMsgCSSetBaseConfigReqRESTful);
    createApiHandler("api/v1/restart", &HTTPSession::execNetMsgCSRestartReqRESTful);
    createApiHandler("api/v1/getserverinfo", &HTTPSession::execNetMsgCSGetServerInfoReqRESTful);
}

void HTTPSession::createApiHandler(const string& url, QTSS_Error(HTTPSession::*action)(const char*))
{
    handlerMap_.insert(std::pair<string, boost::function<QTSS_Error(const char*)> >(url, boost::bind(action, this, boost::placeholders::_1)));
}

void HTTPSession::createProtocolHandler(const string& url, QTSS_Error(HTTPSession::*action)(const char*))
{
    handlerMap_.insert(std::pair<string, boost::function<QTSS_Error(const char*)> >(url, boost::bind(action, this, boost::placeholders::_1)));
}

HTTPSession::~HTTPSession()
{
    if (GetSessionType() == EasyHTTPSession)
    {
        OSMutex* mutexMap = QTSServerInterface::GetServer()->GetDeviceSessionMap()->GetMutex();
        OSHashMap* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap()->GetMap();
        {
            OSMutexLocker lock(mutexMap);

            for (OSRefIt itRef = deviceMap->begin(); itRef != deviceMap->end(); ++itRef)
            {
                HTTPSession* session = static_cast<HTTPSession*>(itRef->second->GetObjectPtr());
                if (session->GetTalkbackSession() == sessionId_)
                {
                    session->SetTalkbackSession("");
                }
            }
        }
    }

    fLiveSession = false;
    this->cleanupRequest();

    QTSServerInterface::GetServer()->AlterCurrentHTTPSessionCount(-1);

    OSRefTableEx* sessionMap = QTSServerInterface::GetServer()->GetHTTPSessionMap();
    sessionMap->UnRegister(sessionId_);

    qtss_printf("Release HTTPSession:%s\n", sessionId_.c_str());

    if (requestBody_)
    {
        delete[] requestBody_;
        requestBody_ = NULL;
    }

    StrPtrLen* remoteAddr = fSocket.GetRemoteAddrStr();
    char msgStr[2048] = { 0 };

    switch (sessionType_)
    {
    case EasyCameraSession:
        unRegDevSession();
        qtss_snprintf(msgStr, sizeof(msgStr), "EasyCameraSession offline from ip[%s], device_serial[%s]", remoteAddr->Ptr, device_->serial_.c_str());
        break;
    case EasyNVRSession:
        unRegDevSession();
        qtss_snprintf(msgStr, sizeof(msgStr), "EasyCameraSession offline from ip[%s], device_serial[%s]", remoteAddr->Ptr, device_->serial_.c_str());
        break;
    case EasyHTTPSession:
        qtss_snprintf(msgStr, sizeof(msgStr), "EasyHTTPSession offline from ip[%s]", remoteAddr->Ptr);
        break;
    default:
        qtss_snprintf(msgStr, sizeof(msgStr), "Unknown session offline from ip[%s]", remoteAddr->Ptr);
        break;
    }

    QTSServerInterface::LogError(qtssMessageVerbosity, msgStr);

    if (device_)
    {
        delete device_;
        device_ = NULL;
    }
}

SInt64 HTTPSession::Run()
{
    const EventFlags events = this->GetEvents();
    QTSS_Error err = QTSS_NoErr;

    // Some callbacks look for this struct in the thread object
    OSThreadDataSetter theSetter(&moduleState_, NULL);

    if (events & kKillEvent)
        fLiveSession = false;

    if (events & kTimeoutEvent)
    {
        if (device_)
        {
            string msgStr = Format("Timeout HTTPSession，Device_serial[%s]", device_->serial_);
            QTSServerInterface::LogError(qtssMessageVerbosity, const_cast<char*>(msgStr.c_str()));
        }

        fLiveSession = false;
        this->Signal(kKillEvent);
    }

    while (this->IsLiveSession())
    {
        switch (state_)
        {
        case kReadingFirstRequest:
            if ((err = fInputStream.ReadRequest()) == QTSS_NoErr)
            {
                fInputSocketP->RequestEvent(EV_RE);
                return 0;
            }

            if ((err != QTSS_RequestArrived) && (err != E2BIG))
            {
                // Any other error implies that the client has gone away. At this point,
                // we can't have 2 sockets, so we don't need to do the "half closed" check
                // we do below
                Assert(err > 0);
                Assert(!this->IsLiveSession());
                break;
            }

            if ((err == QTSS_RequestArrived) || (err == E2BIG))
                state_ = kHaveCompleteMessage;
            continue;

        case kReadingRequest:
        {
            OSMutexLocker readMutexLocker(&readMutex_);

            if ((err = fInputStream.ReadRequest()) == QTSS_NoErr)
            {
                fInputSocketP->RequestEvent(EV_RE);
                return 0;
            }

            if ((err != QTSS_RequestArrived) && (err != E2BIG) && (err != QTSS_BadArgument))
            {
                //Any other error implies that the input connection has gone away.
                // We should only kill the whole session if we aren't doing HTTP.
                // (If we are doing HTTP, the POST connection can go away)
                Assert(err > 0);
                if (fOutputSocketP->IsConnected())
                {
                    // If we've gotten here, this must be an HTTP session with
                    // a dead input connection. If that's the case, we should
                    // clean up immediately so as to not have an open socket
                    // needlessly lingering around, taking up space.
                    Assert(fOutputSocketP != fInputSocketP);
                    Assert(!fInputSocketP->IsConnected());
                    fInputSocketP->Cleanup();

                    return 0;
                }
                Assert(!this->IsLiveSession());
                break;
            }
            state_ = kHaveCompleteMessage;
        }
        case kHaveCompleteMessage:

            Assert(fInputStream.GetRequestBuffer());

            Assert(request_ == NULL);
            request_ = new HTTPRequest(&QTSServerInterface::GetServerHeader(), fInputStream.GetRequestBuffer());

            readMutex_.Lock();
            fSessionMutex.Lock();

            fOutputStream.ResetBytesWritten();

            if ((err == E2BIG) || (err == QTSS_BadArgument))
            {
                execNetMsgErrorReqHandler(httpBadRequest);
                state_ = kSendingResponse;
                break;
            }

            Assert(err == QTSS_RequestArrived);
            state_ = kFilteringRequest;

        case kFilteringRequest:
        {
            fTimeoutTask.RefreshTimeout();

            if (sessionType_ != EasyHTTPSession && device_ && !device_->serial_.empty())
                addDevice();

            const QTSS_Error theErr = setupRequest();

            if (theErr == QTSS_WouldBlock)
            {
                this->ForceSameThread();
                fInputSocketP->RequestEvent(EV_RE);
                // We are holding mutexes, so we need to force
                // the same thread to be used for next Run()
                return 0;
            }

            if (theErr != QTSS_NoErr)
            {
                execNetMsgErrorReqHandler(httpBadRequest);
            }

            if (fOutputStream.GetBytesWritten() > 0)
            {
                state_ = kSendingResponse;
                break;
            }

            state_ = kPreprocessingRequest;
            break;
        }

        case kPreprocessingRequest:
            processRequest();

            if (fOutputStream.GetBytesWritten() > 0)
            {
                delete[] requestBody_;
                requestBody_ = NULL;
                state_ = kSendingResponse;
                break;
            }

            delete[] requestBody_;
            requestBody_ = NULL;
            state_ = kCleaningUp;
            break;

        case kProcessingRequest:
            if (fOutputStream.GetBytesWritten() == 0)
            {
                execNetMsgErrorReqHandler(httpInternalServerError);
                state_ = kSendingResponse;
                break;
            }

            state_ = kSendingResponse;
        case kSendingResponse:
            Assert(request_ != NULL);

            err = fOutputStream.Flush();

            if (err == EAGAIN)
            {
                // If we get this error, we are currently flow-controlled and should
                // wait for the socket to become writeable again
                fSocket.RequestEvent(EV_WR);
                this->ForceSameThread();
                // We are holding mutexes, so we need to force
                // the same thread to be used for next Run()
                return 0;
            }
            if (err != QTSS_NoErr)
            {
                // Any other error means that the client has disconnected, right?
                Assert(!this->IsLiveSession());
                break;
            }

            state_ = kCleaningUp;

        case kCleaningUp:
            // Cleaning up consists of making sure we've read all the incoming Request Body
            // data off of the socket
            if (this->GetRemainingReqBodyLen() > 0)
            {
                err = this->dumpRequestData();

                if (err == EAGAIN)
                {
                    fInputSocketP->RequestEvent(EV_RE);
                    this->ForceSameThread();    // We are holding mutexes, so we need to force
                    // the same thread to be used for next Run()
                    return 0;
                }
            }

            this->cleanupRequest();

            state_ = kReadingRequest;
        default: break;
        }
    }

    this->cleanupRequest();

    if (fObjectHolders == 0)
        return -1;

    return 0;
}

QTSS_Error HTTPSession::sendHTTPPacket(const string& msg)
{
    OSMutexLocker lock(&sendMutex_);

    string sendString = msg;
    UInt32 theLengthSent = 0;
    UInt32 amtInBuffer = sendString.size();
    do
    {
        const QTSS_Error theErr = fOutputSocketP->Send(sendString.c_str(), amtInBuffer, &theLengthSent);

        if (theErr != QTSS_NoErr && theErr != EAGAIN)
            return theErr;

        if (theLengthSent == amtInBuffer)
            // We were able to send all the data in the buffer. Great. Flush it.
            return QTSS_NoErr;
        // Not all the data was sent, so report an EAGAIN
        sendString.erase(0, theLengthSent);
        amtInBuffer = sendString.size();
        theLengthSent = 0;

    } while (amtInBuffer > 0);

    return QTSS_NoErr;
}
void HTTPSession::PostRequest(const string& msg, const string& uri, const string& host)
{
    HTTPRequest httpReq(&QTSServerInterface::GetServerHeader());

    StrPtrLen hostTemp(const_cast<char*>(host.c_str()), host.size());
    StrPtrLen uriTemp(const_cast<char*>(uri.c_str()), uri.size());
    if (httpReq.CreateRequestHeader(&hostTemp, &uriTemp))
    {
        if (!msg.empty())
            httpReq.AppendContentLengthHeader(static_cast<UInt32>(msg.size()));

        httpReq.AppendConnectionKeepAliveHeader();
        StrPtrLen type("application/json");
        httpReq.AppendResponseHeader(httpContentTypeHeader, &type);

        StrPtrLen* ackPtr = httpReq.GetCompleteHTTPHeader();
        string sendString(ackPtr->Ptr, ackPtr->Len);
        if (!msg.empty())
            sendString.append(msg.c_str(), msg.size());

        sendHTTPPacket(sendString);
    }
}

void HTTPSession::PostResponse(const string& msg, bool close)
{
    HTTPRequest httpAck(&QTSServerInterface::GetServerHeader(), httpResponseType);

    if (httpAck.CreateResponseHeader(httpOK))
    {
        if (!msg.empty())
            httpAck.AppendContentLengthHeader(static_cast<UInt32>(msg.size()));

        //httpAck.AppendConnectionCloseHeader();
        StrPtrLen all("*");
        httpAck.AppendResponseHeader(httpAccessControlAllowOriginHeader, &all);
        StrPtrLen type("application/json");
        httpAck.AppendResponseHeader(httpContentTypeHeader, &type);

        StrPtrLen* ackPtr = httpAck.GetCompleteHTTPHeader();
        string sendString(ackPtr->Ptr, ackPtr->Len);
        if (!msg.empty())
            sendString.append(msg.c_str(), msg.size());

        sendHTTPPacket(sendString);
    }

    if (close)
        this->Signal(Task::kKillEvent);
}

QTSS_Error HTTPSession::setupRequest()
{
    QTSS_Error theErr = request_->Parse();
    if (theErr != QTSS_NoErr)
        return QTSS_BadArgument;

    if (request_->GetMethod() == httpGetMethod)
    {
        if (request_->GetRequestPath() != NULL)
        {
            string sRequest(request_->GetRequestPath());
            if (!sRequest.empty())
            {
                boost::to_lower(sRequest);

                if (handlerMap_.find(sRequest) != handlerMap_.end())
                {
                    return handlerMap_[sRequest](request_->GetQueryString());
                }
            }
        }

        execNetMsgCSGetUsagesReqRESTful(NULL);

        return QTSS_NoErr;
    }

    //READ json Content

    //1、get json content length
    StrPtrLen* lengthPtr = request_->GetHeaderValue(httpContentLengthHeader);

    StringParser theContentLenParser(lengthPtr);
    theContentLenParser.ConsumeWhitespace();
    const UInt32 content_length = theContentLenParser.ConsumeInteger(NULL);

    //qtss_printf("HTTPSession read content-length:%d \n", content_length);

    if (content_length <= 0)
    {
        return QTSS_BadArgument;
    }

    // Check for the existence of 2 attributes in the request: a pointer to our buffer for
    // the request body, and the current offset in that buffer. If these attributes exist,
    // then we've already been here for this request. If they don't exist, add them.

    if (requestBody_ == NULL)
    {
        // First time we've been here for this request. Create a buffer for the content body and
        // shove it in the request.
        requestBody_ = new char[content_length + 1];
    }

    UInt32 theLen = sizeof(contentOffset_);
    // We have our buffer and offset. Read the data.
    //theErr = QTSS_Read(this, theRequestBody + theBufferOffset, content_length - theBufferOffset, &theLen);
    theErr = fInputStream.Read(requestBody_ + contentOffset_, content_length - contentOffset_, &theLen);
    Assert(theErr != QTSS_BadArgument);

    if ((theErr != QTSS_NoErr) && (theErr != EAGAIN))
    {
        delete[] requestBody_;
        requestBody_ = NULL;

        // NEED TO RETURN HTTP ERROR RESPONSE
        return QTSS_RequestFailed;
    }
    /*
    if (theErr == QTSS_RequestFailed)
    {
        OSCharArrayDeleter charArrayPathDeleter(theRequestBody);

        // NEED TO RETURN HTTP ERROR RESPONSE
        return QTSS_RequestFailed;
    }
    */

    //qtss_printf("HTTPSession read content-length:%d (%d/%d) \n", theLen, theBufferOffset + theLen, content_length);
    if ((theErr == QTSS_WouldBlock) || (theLen < (content_length - contentOffset_)))
    {
        //
        // Update our offset in the buffer
        contentOffset_ += theLen;
        // The entire content body hasn't arrived yet. Request a read event and wait for it.

        Assert(theErr == QTSS_NoErr);
        return QTSS_WouldBlock;
    }

    contentOffset_ = 0;

    return theErr;
}

void HTTPSession::cleanupRequest()
{
    if (request_ != NULL)
    {
        // NULL out any references to the current request
        delete request_;
        request_ = NULL;
    }

    fSessionMutex.Unlock();
    readMutex_.Unlock();

    // Clear out our last value for request body length before moving onto the next request
    this->SetRequestBodyLength(-1);
}

bool HTTPSession::overMaxConnections(UInt32 buffer)
{
    QTSServerInterface* theServer = QTSServerInterface::GetServer();
    const SInt32 maxConns = theServer->GetPrefs()->GetMaxConnections();
    bool overLimit = false;

    if (maxConns > -1) // limit connections
    {
        const UInt32 maxConnections = static_cast<UInt32>(maxConns) + buffer;
        if (theServer->GetNumServiceSessions() > maxConnections)
        {
            overLimit = true;
        }
    }
    return overLimit;
}

QTSS_Error HTTPSession::dumpRequestData()
{
    char theDumpBuffer[EASY_REQUEST_BUFFER_SIZE_LEN];

    QTSS_Error theErr = QTSS_NoErr;
    while (theErr == QTSS_NoErr)
        theErr = this->Read(theDumpBuffer, EASY_REQUEST_BUFFER_SIZE_LEN, NULL);

    return theErr;
}

QTSS_Error HTTPSession::execNetMsgDSPostSnapReq(const char* json)
{
    //if (!fAuthenticated) return httpUnAuthorized;

    if (!device_)
        return QTSS_ValueNotFound;

    EasyMsgDSPostSnapREQ parse(json);

    string image = parse.GetBodyValue(EASY_TAG_IMAGE);
    string channel = parse.GetBodyValue(EASY_TAG_CHANNEL);
    string device_serial = parse.GetBodyValue(EASY_TAG_SERIAL);
    string strType = parse.GetBodyValue(EASY_TAG_TYPE);
    string reserve = parse.GetBodyValue(EASY_TAG_RESERVE);

    if (channel.empty())
        channel = "1";

    //#define SAVE_SNAP_BY_TIME

#ifdef SAVE_SNAP_BY_TIME
    string strTime = EasyUtil::NowTime(EASY_TIME_FORMAT_YYYYMMDDHHMMSSEx);
#endif //SAVE_SNAP_BY_TIME


    if (device_serial.empty() || image.empty() || strType.empty())
    {
        return QTSS_BadArgument;
    }

    image = EasyUtil::Base64Decode(image.data(), image.size());

    QTSSCharArrayDeleter snapPath(QTSServerInterface::GetServer()->GetPrefs()->GetSnapLocalPath());
    string jpgDir = string(snapPath).append(device_serial);
    OS::RecursiveMakeDir(const_cast<char*>(jpgDir.c_str()));
#ifdef SAVE_SNAP_BY_TIME
    string jpgPath = Format("%s/%s_%s_%s.%s", jpgDir, device_serial, channel, strTime, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
#else
    string jpgPath = Format("%s/%s_%s.%s", jpgDir, device_serial, channel, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
#endif //SAVE_SNAP_BY_TIME

    const int picType = EasyProtocol::GetSnapType(strType);

    if (picType == EASY_SNAP_TYPE_JPEG)
    {
        FILE* fSnap = ::fopen(jpgPath.c_str(), "wb");
        if (!fSnap)
        {
            return QTSS_NoErr;
        }
        boost::shared_ptr<FILE> fileClose(fSnap, &fclose);
        fwrite(image.data(), 1, image.size(), fSnap);
    }

    //web path

    device_->channels_[channel].status_ = "online";

    QTSSCharArrayDeleter snapWebPath(QTSServerInterface::GetServer()->GetPrefs()->GetSnapWebPath());
#ifdef SAVE_SNAP_BY_TIME
    const string snapURL = Format("%s%s/%s_%s_%s.%s", string(QTSServerInterface::GetServer()->GetPrefs()->GetSnapWebPath()), device_serial,
        device_serial, channel, strTime, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
#else
    const string snapURL = Format("%s%s/%s_%s.%s", string(snapWebPath), device_serial,
        device_serial, channel, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
#endif //SAVE_SNAP_BY_TIME
    device_->HoldSnapPath(snapURL, channel);

    EasyProtocolACK rsp(MSG_SD_POST_SNAP_ACK);
    EasyJsonValue header, body;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = parse.GetHeaderValue(EASY_TAG_CSEQ);
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    body[EASY_TAG_SERIAL] = device_serial;
    body[EASY_TAG_CHANNEL] = channel;

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg, false);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgErrorReqHandler(HTTPStatusCode errCode)
{
    //HTTP Header
    HTTPRequest httpAck(&QTSServerInterface::GetServerHeader(), httpResponseType);

    if (httpAck.CreateResponseHeader(errCode))
    {
        StrPtrLen* ackPtr = httpAck.GetCompleteHTTPHeader();
        UInt32 theLengthSent = 0;
        const QTSS_Error theErr = fOutputSocketP->Send(ackPtr->Ptr, ackPtr->Len, &theLengthSent);
        if (theErr != QTSS_NoErr && theErr != EAGAIN)
        {
            return theErr;
        }
    }

    this->fLiveSession = false;

    return QTSS_NoErr;
}

void HTTPSession::addDevice() const
{
    QTSS_RoleParams theParams;
    theParams.DeviceInfoParams.serial_ = const_cast<char*>(device_->serial_.c_str());
    theParams.DeviceInfoParams.token_ = const_cast<char*>(device_->password_.c_str());

    string type = EasyProtocol::GetAppTypeString(device_->eAppType);
    string channel;
    QTSSCharArrayDeleter snapWebPath(QTSServerInterface::GetServer()->GetPrefs()->GetSnapWebPath());
    if (device_->eAppType == EASY_APP_TYPE_CAMERA)
    {
        channel = "1";
        const string snapURL = Format("%s%s/%s_%s.%s", string(snapWebPath), device_->serial_,
            device_->serial_, channel, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
        device_->HoldSnapPath(snapURL, channel);
    }
    else if (device_->eAppType == EASY_APP_TYPE_NVR)
    {
        for (EasyDevices::iterator it = device_->channels_.begin(); it != device_->channels_.end(); ++it)
        {
            channel.append("/");
            channel += it->first;

            const string snapURL = Format("%s%s/%s_%s.%s", string(snapWebPath), device_->serial_,
                device_->serial_, it->first, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
            device_->HoldSnapPath(snapURL, it->first);
        }
    }

    if (channel.empty())
        channel = "0";

    string deviceType = EasyProtocol::GetTerminalTypeString(device_->eDeviceType);

    theParams.DeviceInfoParams.channels_ = const_cast<char*>(channel.c_str());
    theParams.DeviceInfoParams.deviceType_ = const_cast<char*>(deviceType.c_str());
    theParams.DeviceInfoParams.type_ = const_cast<char*>(type.c_str());

    const UInt32 numModules = QTSServerInterface::GetNumModulesInRole(QTSSModule::kRedisSetDeviceRole);
    for (const UInt32 currentModule = 0; currentModule < numModules;)
    {
        QTSSModule* theModule = QTSServerInterface::GetModule(QTSSModule::kRedisSetDeviceRole, currentModule);
        (void)theModule->CallDispatch(Easy_RedisSetDevice_Role, &theParams);
        break;
    }
}

/*
    1.获取TerminalType和AppType,进行逻辑验证，不符合则返回400 httpBadRequest;
    2.验证Serial和Token进行权限验证，不符合则返回401 httpUnAuthorized;
    3.获取Name和Tag信息进行本地保存或者写入Redis;
    4.如果是APPType为EasyNVR,获取Channels通道信息本地保存或者写入Redis
*/
QTSS_Error HTTPSession::execNetMsgDSRegisterReq(const char* json)
{
    QTSS_Error theErr = QTSS_NoErr;

    EasyMsgDSRegisterREQ regREQ(json);

    if (!device_)
        device_ = new strDevice;

    //update info each time
    if (!device_->GetDevInfo(json))
        return  QTSS_BadArgument;

    while (!fAuthenticated)
    {
        //1.获取TerminalType和AppType,进行逻辑验证，不符合则返回400 httpBadRequest;
        const int appType = regREQ.GetAppType();
        //int terminalType = regREQ.GetTerminalType();
        switch (appType)
        {
        case EASY_APP_TYPE_CAMERA:
            sessionType_ = EasyCameraSession;
            //fTerminalType = terminalType;
            break;
        case EASY_APP_TYPE_NVR:
            sessionType_ = EasyNVRSession;
            //fTerminalType = terminalType;
            break;
        default:
            break;
        }

        if (sessionType_ >= EasyHTTPSession)
        {
            //设备注册既不是EasyCamera，也不是EasyNVR，返回错误
            theErr = QTSS_BadArgument;
            break;
        }

        //2.验证Serial和Token进行权限验证，不符合则返回401 httpUnAuthorized;
        string serial = regREQ.GetBodyValue(EASY_TAG_SERIAL);
        string token = regREQ.GetBodyValue(EASY_TAG_TOKEN);

        if (serial.empty())
        {
            theErr = QTSS_AttrDoesntExist;
            break;
        }

        //验证Serial和Token是否合法
        /*if (false)
        {
            theErr = QTSS_NotPreemptiveSafe;
            break;
        }*/

        OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
        const OS_Error regErr = deviceMap->Register(device_->serial_, this);
        if (regErr == OS_NoErr)
        {
            string msgStr = Format("Device register,Device_serial %s", device_->serial_);
            QTSServerInterface::LogError(qtssMessageVerbosity, const_cast<char*>(msgStr.c_str()));

            addDevice();

            /*QTSS_RoleParams theParams;
            theParams.logParams.serial = (char*)serial.c_str();
            theParams.logParams.msg = (char*)msgStr.c_str();
            UInt32 numModules = QTSServerInterface::GetNumModulesInRole(QTSSModule::kRedisLogRole);
            for (UInt32 currentModule = 0; currentModule < numModules;)
            {
                QTSSModule* theModule = QTSServerInterface::GetModule(QTSSModule::kRedisLogRole, currentModule);
                (void)theModule->CallDispatch(Easy_RedisLog_Role, &theParams);
                break;
            }*/

            fAuthenticated = true;
        }
        else
        {
            //设备冲突的时候将前一个设备给挤掉,因为断电、断网情况下连接是不会断开的，如果设备来电、网络通顺之后就会产生冲突，
            //一个连接的超时时90秒，要等到90秒之后设备才能正常注册上线。
            OSRefTableEx::OSRefEx* theDevRef = deviceMap->Resolve(device_->serial_);
            if (theDevRef)//找到指定设备
            {
                OSRefReleaserEx releaser(deviceMap, device_->serial_);
                HTTPSession* pDevSession = static_cast<HTTPSession*>(theDevRef->GetObjectPtr());//获得当前设备会话
                pDevSession->Signal(Task::kKillEvent);//终止设备连接
            }
            //这一次仍然返回上线冲突，因为虽然给设备发送了Task::kKillEvent消息，但设备可能不会立即终止，否则就要循环等待是否已经终止！
            theErr = QTSS_AttrNameExists;;
        }
        break;
    }

    //fAuthenticated = false;

    if (theErr != QTSS_NoErr)	return theErr;

    //走到这说明该设备成功注册或者心跳
    EasyProtocol req(json);
    EasyProtocolACK rsp(MSG_SD_REGISTER_ACK);
    EasyJsonValue header, body;
    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = req.GetHeaderValue(EASY_TAG_CSEQ);
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    body[EASY_TAG_SERIAL] = device_->serial_;

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg, false);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSFreeStreamReq(const char* json)//客户端的停止直播请求
{
    //算法描述：查找指定设备，若设备存在，则向设备发出停止流请求
    /*//暂时注释掉，实际上是需要认证的
    if(!fAuthenticated)//没有进行认证请求
    return httpUnAuthorized;
    */
    EasyProtocol req(json);

    string strDeviceSerial = req.GetBodyValue(EASY_TAG_SERIAL);
    string strChannel = req.GetBodyValue(EASY_TAG_CHANNEL);

    if (strDeviceSerial.empty())
    {
        return QTSS_BadArgument;
    }

    string strReserve = req.GetBodyValue(EASY_TAG_RESERVE);
    const string strProtocol = req.GetBodyValue(EASY_TAG_PROTOCOL);

    //为可选参数填充默认值
    if (strChannel.empty())
        strChannel = "1";
    if (strReserve.empty())
        strReserve = "1";

    std::string log = Format("%s-%s %s", strDeviceSerial, strChannel, "stop stream");
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSRefTableEx::OSRefEx * theDevRef = deviceMap->Resolve(strDeviceSerial);
    if (!theDevRef)//找不到指定设备
        return EASY_ERROR_DEVICE_NOT_FOUND;

    OSRefReleaserEx releaser(deviceMap, strDeviceSerial);
    //走到这说明存在指定设备，则该设备发出停止推流请求
    HTTPSession* pDevSession = static_cast<HTTPSession*>(theDevRef->GetObjectPtr());//获得当前设备回话

    EasyProtocolACK reqreq(MSG_SD_STREAM_STOP_REQ);
    EasyJsonValue headerheader, bodybody;

    headerheader[EASY_TAG_CSEQ] = EasyUtil::ToString(pDevSession->GetCSeq());//注意这个地方不能直接将UINT32->int,因为会造成数据失真
    headerheader[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;

    bodybody[EASY_TAG_SERIAL] = strDeviceSerial;
    bodybody[EASY_TAG_CHANNEL] = strChannel;
    bodybody[EASY_TAG_RESERVE] = strReserve;
    bodybody[EASY_TAG_PROTOCOL] = strProtocol;
    bodybody[EASY_TAG_FROM] = sessionId_;
    bodybody[EASY_TAG_TO] = pDevSession->GetSessionID();
    bodybody[EASY_TAG_VIA] = QTSServerInterface::GetServer()->GetCloudServiceNodeID();

    reqreq.SetHead(headerheader);
    reqreq.SetBody(bodybody);

    log = Format("%s-%s %s", strDeviceSerial, strChannel, "MSG_SD_STREAM_STOP_REQ");
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());

    const string buffer = reqreq.GetMsg();
    pDevSession->PostRequest(buffer);

    //直接对客户端（EasyDarWin)进行正确回应
    EasyProtocolACK rsp(MSG_SC_FREE_STREAM_ACK);
    EasyJsonValue header, body;
    header[EASY_TAG_CSEQ] = req.GetHeaderValue(EASY_TAG_CSEQ);
    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    body[EASY_TAG_SERIAL] = strDeviceSerial;
    body[EASY_TAG_CHANNEL] = strChannel;
    body[EASY_TAG_RESERVE] = strReserve;
    body[EASY_TAG_PROTOCOL] = strProtocol;

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgDSStreamStopAck(const char* json) const
{
    if (!fAuthenticated)
    {
        return httpUnAuthorized;
    }

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSStartStreamReqRESTful(const char* queryString)//放到ProcessRequest所在的状态去处理，方便多次循环调用
{
    /*
    if(!fAuthenticated)
    return httpUnAuthorized;
    */

    if (!queryString)
        return QTSS_BadArgument;

    string decQueryString = EasyUtil::Urldecode(queryString);

    QueryParamList parList(decQueryString);
    const char* chSerial = parList.DoFindCGIValueForParam(EASY_TAG_L_DEVICE);
    const char* chChannel = parList.DoFindCGIValueForParam(EASY_TAG_L_CHANNEL);
    const char* chReserve = parList.DoFindCGIValueForParam(EASY_TAG_L_RESERVE);

    if (!chSerial || string(chSerial).empty())
        return QTSS_BadArgument;

    if (!isRightChannel(chChannel))
        chChannel = "1";
    if (!chReserve)
        chReserve = "1";

    std::string log = Format("%s-%s %s", string(chSerial), string(chChannel), "start stream");
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());

    UInt32 strCSeq = GetCSeq();
    string service;

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSRefTableEx::OSRefEx* theDevRef = deviceMap->Resolve(chSerial);
    if (!theDevRef)
        return EASY_ERROR_DEVICE_NOT_FOUND;

    OSRefReleaserEx releaser(deviceMap, chSerial);
    HTTPSession* pDevSession = static_cast<HTTPSession*>(theDevRef->GetObjectPtr());

    strDevice* deviceInfo = pDevSession->GetDeviceInfo();
    if (!deviceInfo)
        return EASY_ERROR_DEVICE_NOT_FOUND;

    if (deviceInfo->eAppType == EASY_APP_TYPE_NVR)
    {
        EasyDevices& channels = deviceInfo->channels_;
        if (channels.find(chChannel) == channels.end())
            return QTSS_BadArgument;

        if (channels[chChannel].status_ == string("offline"))
            return QTSS_BadArgument;
    }

    char chDssIP[sIPSize] = { 0 };
    char chDssPort[sPortSize] = { 0 };
    char chHTTPPort[sPortSize] = { 0 };

    QTSS_RoleParams theParams;
    theParams.GetAssociatedDarwinParams.inSerial = const_cast<char*>(chSerial);
    theParams.GetAssociatedDarwinParams.inChannel = const_cast<char*>(chChannel);
    theParams.GetAssociatedDarwinParams.outDssIP = chDssIP;
    theParams.GetAssociatedDarwinParams.outHTTPPort = chHTTPPort;
    theParams.GetAssociatedDarwinParams.outDssPort = chDssPort;
    theParams.GetAssociatedDarwinParams.isOn = false;

    UInt32 numModules = QTSServerInterface::GetNumModulesInRole(QTSSModule::kRedisGetEasyDarwinRole);
    for (UInt32 currentModule = 0; currentModule < numModules; ++currentModule)
    {
        QTSSModule* theModule = QTSServerInterface::GetModule(QTSSModule::kRedisGetEasyDarwinRole, currentModule);
        (void)theModule->CallDispatch(Easy_RedisGetEasyDarwin_Role, &theParams);
    }

    int errorNo = EASY_ERROR_SUCCESS_OK;

    if (chDssIP[0] != 0)
    {
        string strDssIP = chDssIP;
        string strHttpPort = chHTTPPort;
        string strDssPort = chDssPort;

        service = string("IP=") + strDssIP + ";Port=" + strHttpPort + ";Type=EasyDarwin";

        if (!theParams.GetAssociatedDarwinParams.isOn)
        {
            EasyProtocolACK reqreq(MSG_SD_PUSH_STREAM_REQ);
            EasyJsonValue headerheader, bodybody;

            headerheader[EASY_TAG_CSEQ] = EasyUtil::ToString(pDevSession->GetCSeq());
            headerheader[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;

            bodybody[EASY_TAG_SERVER_IP] = strDssIP;
            bodybody[EASY_TAG_SERVER_PORT] = strDssPort;
            bodybody[EASY_TAG_SERIAL] = chSerial;
            bodybody[EASY_TAG_CHANNEL] = chChannel;
            bodybody[EASY_TAG_RESERVE] = chReserve;
            bodybody[EASY_TAG_FROM] = sessionId_;
            bodybody[EASY_TAG_TO] = pDevSession->GetSessionID();
            bodybody[EASY_TAG_VIA] = QTSServerInterface::GetServer()->GetCloudServiceNodeID();

            darwinHttpPort_ = EasyUtil::String2Int(strHttpPort);

            reqreq.SetHead(headerheader);
            reqreq.SetBody(bodybody);

            log = Format("%s-%s %s", string(chSerial), string(chChannel), "MSG_SD_PUSH_STREAM_REQ");
            QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());
            const string buffer = reqreq.GetMsg();
            pDevSession->PostRequest(buffer);

            fTimeoutTask.SetTimeout(3 * 1000);
            fTimeoutTask.RefreshTimeout();

            return QTSS_NoErr;
        }
    }
    else
    {
        errorNo = EASY_ERROR_SERVER_UNAVAILABLE;
    }

    EasyProtocolACK rsp(MSG_SC_START_STREAM_ACK);
    EasyJsonValue header, body;
    body[EASY_TAG_SERVICE] = service;
    body[EASY_TAG_SERIAL] = chSerial;
    body[EASY_TAG_CHANNEL] = chChannel;
    body[EASY_TAG_RESERVE] = chReserve;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = EasyUtil::ToString(strCSeq);
    header[EASY_TAG_ERROR_NUM] = errorNo;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(errorNo);

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}


QTSS_Error HTTPSession::execNetMsgCSStopStreamReqRESTful(const char* queryString)//放到ProcessRequest所在的状态去处理，方便多次循环调用
{
    /*//暂时注释掉，实际上是需要认证的
    if(!fAuthenticated)//没有进行认证请求
    return httpUnAuthorized;
    */

    if (queryString == NULL)
    {
        return QTSS_BadArgument;
    }

    const string decQueryString = EasyUtil::Urldecode(queryString);

    QueryParamList parList(decQueryString);
    const char* strDeviceSerial = parList.DoFindCGIValueForParam(EASY_TAG_L_DEVICE);//获取设备序列号
    const char* strChannel = parList.DoFindCGIValueForParam(EASY_TAG_L_CHANNEL);//获取通道
    const char* strReserve = parList.DoFindCGIValueForParam(EASY_TAG_L_RESERVE);//

    //为可选参数填充默认值
    if (!isRightChannel(strChannel))
        strChannel = "1";
    if (strReserve == NULL)
        strReserve = "1";

    std::string log = Format("%s-%s %s", string(strDeviceSerial), string(strChannel), "stop stream");
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());

    if (strDeviceSerial == NULL)
        return QTSS_BadArgument;

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSRefTableEx::OSRefEx* theDevRef = deviceMap->Resolve(strDeviceSerial);
    if (theDevRef == NULL)//找不到指定设备
        return EASY_ERROR_DEVICE_NOT_FOUND;

    OSRefReleaserEx releaser(deviceMap, strDeviceSerial);
    //走到这说明存在指定设备，则该设备发出停止推流请求
    HTTPSession* pDevSession = static_cast<HTTPSession*>(theDevRef->GetObjectPtr());//获得当前设备回话

    EasyProtocolACK reqreq(MSG_SD_STREAM_STOP_REQ);
    EasyJsonValue headerheader, bodybody;

    headerheader[EASY_TAG_CSEQ] = EasyUtil::ToString(pDevSession->GetCSeq());//注意这个地方不能直接将UINT32->int,因为会造成数据失真
    headerheader[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;

    bodybody[EASY_TAG_SERIAL] = strDeviceSerial;
    bodybody[EASY_TAG_CHANNEL] = strChannel;
    bodybody[EASY_TAG_RESERVE] = strReserve;
    bodybody[EASY_TAG_PROTOCOL] = "";
    bodybody[EASY_TAG_FROM] = sessionId_;
    bodybody[EASY_TAG_TO] = pDevSession->GetSessionID();
    bodybody[EASY_TAG_VIA] = QTSServerInterface::GetServer()->GetCloudServiceNodeID();

    reqreq.SetHead(headerheader);
    reqreq.SetBody(bodybody);

    log = Format("%s-%s %s", string(strDeviceSerial), string(strChannel), "MSG_SD_STREAM_STOP_REQ");
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());
    const string buffer = reqreq.GetMsg();
    pDevSession->PostRequest(buffer);

    //直接对客户端（EasyDarWin)进行正确回应
    EasyProtocolACK rsp(MSG_SC_STOP_STREAM_ACK);
    EasyJsonValue header, body;
    header[EASY_TAG_CSEQ] = EasyUtil::ToString(GetCSeq());
    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    body[EASY_TAG_SERIAL] = strDeviceSerial;
    body[EASY_TAG_CHANNEL] = strChannel;
    body[EASY_TAG_RESERVE] = strReserve;

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}


QTSS_Error HTTPSession::execNetMsgDSPushStreamAck(const char* json)
{
    if (!fAuthenticated)
        return httpUnAuthorized;

    EasyProtocol req(json);

    string strDeviceSerial = req.GetBodyValue(EASY_TAG_SERIAL);
    string strChannel = req.GetBodyValue(EASY_TAG_CHANNEL);
    string strProtocol = req.GetBodyValue(EASY_TAG_PROTOCOL);
    string strReserve = req.GetBodyValue(EASY_TAG_RESERVE);
    string strDssIP = req.GetBodyValue(EASY_TAG_SERVER_IP);
    string strDssPort = req.GetBodyValue(EASY_TAG_SERVER_PORT);
    string strFrom = req.GetBodyValue(EASY_TAG_FROM);
    string strTo = req.GetBodyValue(EASY_TAG_TO);
    string strVia = req.GetBodyValue(EASY_TAG_VIA);

    string strCSeq = req.GetHeaderValue(EASY_TAG_CSEQ);
    string strStateCode = req.GetHeaderValue(EASY_TAG_ERROR_NUM);

    if (strChannel.empty())
        strChannel = "1";
    if (strReserve.empty())
        strReserve = "1";

    OSRefTableEx* sessionMap = QTSServerInterface::GetServer()->GetHTTPSessionMap();
    OSRefTableEx::OSRefEx* sessionRef = sessionMap->Resolve(strTo);
    if (!sessionRef)
        return EASY_ERROR_SESSION_NOT_FOUND;

    OSRefReleaserEx releaser(sessionMap, strTo);
    HTTPSession* httpSession = static_cast<HTTPSession*>(sessionRef->GetObjectPtr());

    if (httpSession->IsLiveSession())
    {
        string service = string("IP=") + strDssIP + ";Port=" + EasyUtil::ToString(httpSession->GetDarwinHTTPPort()) + ";Type=EasyDarwin";

        EasyProtocolACK rsp(MSG_SC_START_STREAM_ACK);
        EasyJsonValue header, body;
        body[EASY_TAG_SERVICE] = service;
        body[EASY_TAG_SERIAL] = strDeviceSerial;
        body[EASY_TAG_CHANNEL] = strChannel;
        body[EASY_TAG_RESERVE] = strReserve;

        header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
        header[EASY_TAG_CSEQ] = strCSeq;
        header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
        header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

        rsp.SetHead(header);
        rsp.SetBody(body);

        string msg = rsp.GetMsg();
        httpSession->PostResponse(msg);
    }

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSGetDeviceListReqRESTful(const char* queryString)//客户端获得设备列表
{

    //if (!fAuthenticated)//没有进行认证请求
    //	return httpUnAuthorized;

    std::string queryTemp;
    if (queryString != NULL)
    {
        queryTemp = EasyUtil::Urldecode(queryString);
    }
    QueryParamList parList(queryTemp);
    const char* chAppType = parList.DoFindCGIValueForParam(EASY_TAG_APP_TYPE);//APPType
    const char* chTerminalType = parList.DoFindCGIValueForParam(EASY_TAG_TERMINAL_TYPE);//TerminalType

    EasyProtocolACK rsp(MSG_SC_DEVICE_LIST_ACK);
    EasyJsonValue header, body;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = 1;
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    set<string> terminalSet;
    if (chTerminalType != NULL)
    {
        string terminalTemp(chTerminalType);

        if (boost::ends_with(terminalTemp, "|"))
        {
            boost::erase_tail(terminalTemp, 1);
        }
        boost::split(terminalSet, terminalTemp, boost::is_any_of("|"), boost::token_compress_on);
    }

    OSMutex* mutexMap = QTSServerInterface::GetServer()->GetDeviceSessionMap()->GetMutex();
    OSHashMap* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap()->GetMap();
    Json::Value* proot = rsp.GetRoot();

    {
        OSMutexLocker lock(mutexMap);
        int iDevNum = 0;

        for (OSHashMap::iterator itRef = deviceMap->begin(); itRef != deviceMap->end(); ++itRef)
        {
            strDevice* deviceInfo = static_cast<HTTPSession*>(itRef->second->GetObjectPtr())->GetDeviceInfo();
            if (!deviceInfo)
                continue;

            if (chAppType != NULL)// AppType fileter
            {
                if (EasyProtocol::GetAppTypeString(deviceInfo->eAppType) != string(chAppType))
                    continue;
            }
            if (chTerminalType != NULL)// TerminateType fileter
            {
                if (terminalSet.find(EasyProtocol::GetTerminalTypeString(deviceInfo->eDeviceType)) == terminalSet.end())
                    continue;
            }

            iDevNum++;

            Json::Value value;
            value[EASY_TAG_SERIAL] = deviceInfo->serial_;//这个地方引起了崩溃,deviceMap里有数据，但是deviceInfo里面数据都是空
            value[EASY_TAG_NAME] = deviceInfo->name_;
            value[EASY_TAG_TAG] = deviceInfo->tag_;
            value[EASY_TAG_APP_TYPE] = EasyProtocol::GetAppTypeString(deviceInfo->eAppType);
            value[EASY_TAG_TERMINAL_TYPE] = EasyProtocol::GetTerminalTypeString(deviceInfo->eDeviceType);
            //如果设备是EasyCamera,则返回设备快照信息
            if (deviceInfo->eAppType == EASY_APP_TYPE_CAMERA)
            {
                value[EASY_TAG_SNAP_URL] = deviceInfo->snapJpgPath_;
            }
            (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_DEVICES].append(value);
        }
        body[EASY_TAG_DEVICE_COUNT] = iDevNum;
    }

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSDeviceListReq(const char* json)//客户端获得设备列表
{
    /*
    if(!fAuthenticated)//没有进行认证请求
    return httpUnAuthorized;
    */
    EasyProtocol req(json);

    EasyProtocolACK rsp(MSG_SC_DEVICE_LIST_ACK);
    EasyJsonValue header, body;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = req.GetHeaderValue(EASY_TAG_CSEQ);
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSMutex* mutexMap = deviceMap->GetMutex();
    OSHashMap* deviceHashMap = deviceMap->GetMap();
    Json::Value* proot = rsp.GetRoot();

    {
        OSMutexLocker lock(mutexMap);
        body[EASY_TAG_DEVICE_COUNT] = deviceMap->GetEleNumInMap();
        for (OSHashMap::iterator itRef = deviceHashMap->begin(); itRef != deviceHashMap->end(); ++itRef)
        {
            Json::Value value;
            strDevice* deviceInfo = static_cast<HTTPSession*>(itRef->second->GetObjectPtr())->GetDeviceInfo();
            if (!deviceInfo)
                continue;

            value[EASY_TAG_SERIAL] = deviceInfo->serial_;
            value[EASY_TAG_NAME] = deviceInfo->name_;
            value[EASY_TAG_TAG] = deviceInfo->tag_;
            value[EASY_TAG_APP_TYPE] = EasyProtocol::GetAppTypeString(deviceInfo->eAppType);
            value[EASY_TAG_TERMINAL_TYPE] = EasyProtocol::GetTerminalTypeString(deviceInfo->eDeviceType);
            //如果设备是EasyCamera,则返回设备快照信息
            if (deviceInfo->eAppType == EASY_APP_TYPE_CAMERA)
            {
                value[EASY_TAG_SNAP_URL] = deviceInfo->snapJpgPath_;
            }
            (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_DEVICES].append(value);
        }
    }

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSGetCameraListReqRESTful(const char* queryString)
{
    /*
        if(!fAuthenticated)//没有进行认证请求
        return httpUnAuthorized;
    */
    if (queryString == NULL)
    {
        return QTSS_BadArgument;
    }

    const string decQueryString = EasyUtil::Urldecode(queryString);

    QueryParamList parList(decQueryString);

    const char* device_serial = parList.DoFindCGIValueForParam(EASY_TAG_L_DEVICE);//获取设备序列号

    if (device_serial == NULL)
        return QTSS_BadArgument;

    EasyProtocolACK rsp(MSG_SC_DEVICE_INFO_ACK);
    EasyJsonValue header, body;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = 1;

    body[EASY_TAG_SERIAL] = device_serial;

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSRefTableEx::OSRefEx* theDevRef = deviceMap->Resolve(device_serial);
    if (theDevRef == NULL)//不存在指定设备
    {
        header[EASY_TAG_ERROR_NUM] = EASY_ERROR_DEVICE_NOT_FOUND;
        header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_DEVICE_NOT_FOUND);
    }
    else//存在指定设备，则获取这个设备的摄像头信息
    {
        OSRefReleaserEx releaser(deviceMap, device_serial);

        header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
        header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

        Json::Value* proot = rsp.GetRoot();
        strDevice* deviceInfo = static_cast<HTTPSession*>(theDevRef->GetObjectPtr())->GetDeviceInfo();
        if (!deviceInfo)
        {
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_DEVICE_NOT_FOUND;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_DEVICE_NOT_FOUND);
        }
        else
        {
            if (deviceInfo->eAppType == EASY_APP_TYPE_CAMERA)
            {
                body[EASY_TAG_SNAP_URL] = deviceInfo->snapJpgPath_;
            }
            else
            {
                body[EASY_TAG_CHANNEL_COUNT] = deviceInfo->channelCount_;
                for (EasyDevices::iterator itCam = deviceInfo->channels_.begin(); itCam != deviceInfo->channels_.end(); ++itCam)
                {
                    Json::Value value;
                    value[EASY_TAG_CHANNEL] = itCam->first;
                    value[EASY_TAG_NAME] = itCam->second.name_;
                    value[EASY_TAG_STATUS] = itCam->second.status_;
                    value[EASY_TAG_SNAP_URL] = itCam->second.snapJpgPath_;
                    (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_CHANNELS].append(value);
                }
            }
        }

    }
    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSCameraListReq(const char* json)
{
    /*
    if(!fAuthenticated)//没有进行认证请求
    return httpUnAuthorized;
    */
    EasyProtocol req(json);
    string strDeviceSerial = req.GetBodyValue(EASY_TAG_SERIAL);

    if (strDeviceSerial.empty())
        return QTSS_BadArgument;

    EasyProtocolACK rsp(MSG_SC_DEVICE_INFO_ACK);
    EasyJsonValue header, body;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = req.GetHeaderValue(EASY_TAG_CSEQ);
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);
    body[EASY_TAG_SERIAL] = strDeviceSerial;

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSRefTableEx::OSRefEx* theDevRef = deviceMap->Resolve(strDeviceSerial);
    if (theDevRef == NULL)//不存在指定设备
    {
        return EASY_ERROR_DEVICE_NOT_FOUND;//交给错误处理中心处理
    }
    //存在指定设备，则获取这个设备的摄像头信息
    OSRefReleaserEx releaser(deviceMap, strDeviceSerial);

    Json::Value* proot = rsp.GetRoot();
    strDevice* deviceInfo = static_cast<HTTPSession*>(theDevRef->GetObjectPtr())->GetDeviceInfo();
    if (!deviceInfo)
        return EASY_ERROR_DEVICE_NOT_FOUND;

    if (deviceInfo->eAppType == EASY_APP_TYPE_CAMERA)
    {
        body[EASY_TAG_SNAP_URL] = deviceInfo->snapJpgPath_;
    }
    else
    {
        body[EASY_TAG_CHANNEL_COUNT] = static_cast<HTTPSession*>(theDevRef->GetObjectPtr())->GetDeviceInfo()->channelCount_;
        for (EasyDevices::iterator itCam = deviceInfo->channels_.begin(); itCam != deviceInfo->channels_.end(); ++itCam)
        {
            Json::Value value;
            value[EASY_TAG_CHANNEL] = itCam->second.channel_;
            value[EASY_TAG_NAME] = itCam->second.name_;
            value[EASY_TAG_STATUS] = itCam->second.status_;
            body[EASY_TAG_SNAP_URL] = itCam->second.snapJpgPath_;
            (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_CHANNELS].append(value);
        }
    }
    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::processRequest()//处理请求
{
    //OSCharArrayDeleter charArrayPathDeleter(theRequestBody);//不要在这删除，因为可能执行多次，仅当对请求的处理完毕后再进行删除

    if (requestBody_ == NULL)//表示没有正确的解析请求，SetUpRequest环节没有解析出数据部分
        return QTSS_NoErr;

    QTSS_Error theErr = QTSS_NoErr;
    int nRspMsg = MSG_SC_EXCEPTION;

    if (request_->GetRequestPath() == NULL || string(request_->GetRequestPath()).empty())
    {
        //消息处理
        EasyProtocol protocol(requestBody_);
        const int nNetMsg = protocol.GetMessageType();
        switch (nNetMsg)
        {
        case MSG_DS_REGISTER_REQ://处理设备上线消息,设备类型包括NVR、摄像头和智能主机
            theErr = execNetMsgDSRegisterReq(requestBody_);
            nRspMsg = MSG_SD_REGISTER_ACK;
            break;
        case MSG_DS_PUSH_STREAM_ACK://设备的开始流回应
            theErr = execNetMsgDSPushStreamAck(requestBody_);
            nRspMsg = MSG_DS_PUSH_STREAM_ACK;//注意，这里实际上是不应该再回应的
            break;
        case MSG_CS_FREE_STREAM_REQ://客户端的停止直播请求
            theErr = execNetMsgCSFreeStreamReq(requestBody_);
            nRspMsg = MSG_SC_FREE_STREAM_ACK;
            break;
        case MSG_DS_STREAM_STOP_ACK://设备对EasyCMS的停止推流回应
            theErr = execNetMsgDSStreamStopAck(requestBody_);
            nRspMsg = MSG_DS_STREAM_STOP_ACK;//注意，这里实际上是不需要在进行回应的
            break;
        case MSG_CS_DEVICE_LIST_REQ://设备列表请求
            theErr = execNetMsgCSDeviceListReq(requestBody_);//add
            nRspMsg = MSG_SC_DEVICE_LIST_ACK;
            break;
        case MSG_CS_DEVICE_INFO_REQ://摄像头列表请求,设备的具体信息
            theErr = execNetMsgCSCameraListReq(requestBody_);//add
            nRspMsg = MSG_SC_DEVICE_INFO_ACK;
            break;
        case MSG_DS_POST_SNAP_REQ://设备快照上传
            theErr = execNetMsgDSPostSnapReq(requestBody_);
            nRspMsg = MSG_SD_POST_SNAP_ACK;
            break;
        case MSG_DS_CONTROL_PTZ_ACK:
            theErr = execNetMsgDSPTZControlAck(requestBody_);
            nRspMsg = MSG_DS_CONTROL_PTZ_ACK;
            break;
        case MSG_DS_CONTROL_PRESET_ACK:
            theErr = execNetMsgDSPresetControlAck(requestBody_);
            nRspMsg = MSG_DS_CONTROL_PRESET_ACK;
            break;
        case MSG_CS_TALKBACK_CONTROL_REQ:
            theErr = execNetMsgCSTalkbackControlReq(requestBody_);
            nRspMsg = MSG_SC_TALKBACK_CONTROL_ACK;
            break;
        case MSG_DS_CONTROL_TALKBACK_ACK:
            theErr = execNetMSGDSTalkbackControlAck(requestBody_);
            nRspMsg = MSG_DS_CONTROL_TALKBACK_ACK;
            break;
        default:
            theErr = execNetMsgErrorReqHandler(httpNotImplemented);
            break;
        }
    }
    else
    {
        const string sRequest(request_->GetRequestPath());

        if (handlerMap_.find(sRequest) != handlerMap_.end())
            theErr = handlerMap_[sRequest](requestBody_);
    }

    //如果不想进入错误自动处理则一定要返回QTSS_NoErr
    if (theErr != QTSS_NoErr)//无论是正确回应还是等待返回都是QTSS_NoErr，出现错误，对错误进行统一回应
    {
        EasyProtocol protocol(requestBody_);

        if (nRspMsg == MSG_SC_EXCEPTION)
        {
            const int nNetMsg = protocol.GetMessageType();
            switch (nNetMsg)
            {
            case MSG_DS_REGISTER_REQ:
                nRspMsg = MSG_SD_REGISTER_ACK;
                break;
            case MSG_CS_FREE_STREAM_REQ:
                nRspMsg = MSG_SC_FREE_STREAM_ACK;
                break;
            default:
                theErr = execNetMsgErrorReqHandler(httpNotImplemented);
                break;
            }
        }

        EasyProtocol req(requestBody_);
        EasyProtocolACK rsp(nRspMsg);
        EasyJsonValue header;
        header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
        header[EASY_TAG_CSEQ] = req.GetHeaderValue(EASY_TAG_CSEQ);

        switch (theErr)
        {
        case QTSS_BadArgument:
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_CLIENT_BAD_REQUEST;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_CLIENT_BAD_REQUEST);
            break;
        case httpUnAuthorized:
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_CLIENT_UNAUTHORIZED;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_CLIENT_UNAUTHORIZED);
            break;
        case QTSS_AttrNameExists:
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_CONFLICT;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_CONFLICT);
            break;
        case EASY_ERROR_DEVICE_NOT_FOUND:
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_DEVICE_NOT_FOUND;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_DEVICE_NOT_FOUND);
            break;
        case EASY_ERROR_SERVICE_NOT_FOUND:
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SERVICE_NOT_FOUND;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SERVICE_NOT_FOUND);
            break;
        case httpRequestTimeout:
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_REQUEST_TIMEOUT;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_REQUEST_TIMEOUT);
            break;
        case EASY_ERROR_SERVER_INTERNAL_ERROR:
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SERVER_INTERNAL_ERROR;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SERVER_INTERNAL_ERROR);
            break;
        case EASY_ERROR_SERVER_NOT_IMPLEMENTED:
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SERVER_NOT_IMPLEMENTED;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SERVER_NOT_IMPLEMENTED);
            break;
        default:
            header[EASY_TAG_ERROR_NUM] = EASY_ERROR_CLIENT_BAD_REQUEST;
            header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_CLIENT_BAD_REQUEST);
            break;
        }

        rsp.SetHead(header);

        const string msg = rsp.GetMsg();
        this->PostResponse(msg);
    }
    return theErr;
}

QTSS_Error HTTPSession::execNetMsgCSPTZControlReqRESTful(const char* queryString)
{
    /*//暂时注释掉，实际上是需要认证的
    if(!fAuthenticated)//没有进行认证请求
    return httpUnAuthorized;
    */

    if (queryString == NULL)
    {
        return QTSS_BadArgument;
    }

    const string decQueryString = EasyUtil::Urldecode(queryString);

    QueryParamList parList(decQueryString);

    const char* chSerial = parList.DoFindCGIValueForParam(EASY_TAG_L_DEVICE);//获取设备序列号
    const char* chChannel = parList.DoFindCGIValueForParam(EASY_TAG_L_CHANNEL);//获取通道
    const char* chProtocol = parList.DoFindCGIValueForParam(EASY_TAG_L_PROTOCOL);//获取通道
    const char* chReserve(parList.DoFindCGIValueForParam(EASY_TAG_L_RESERVE));//获取通道
    const char* chActionType = parList.DoFindCGIValueForParam(EASY_TAG_L_ACTION_TYPE);
    const char* chCmd = parList.DoFindCGIValueForParam(EASY_TAG_L_CMD);
    const char* chSpeed = parList.DoFindCGIValueForParam(EASY_TAG_L_SPEED);

    if (!chSerial || !chProtocol || !chActionType || !chCmd)
        return QTSS_BadArgument;

    //为可选参数填充默认值
    if (!isRightChannel(chChannel))
        chChannel = "1";
    if (chReserve == NULL)
        chReserve = "1";

    std::string log = Format("%s-%s %s %s", string(chSerial), string(chChannel), "ptz", string(chCmd));
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSRefTableEx::OSRefEx* theDevRef = deviceMap->Resolve(chSerial);
    if (theDevRef == NULL)//找不到指定设备
        return EASY_ERROR_DEVICE_NOT_FOUND;

    OSRefReleaserEx releaser(deviceMap, chSerial);
    //走到这说明存在指定设备
    HTTPSession* pDevSession = static_cast<HTTPSession*>(theDevRef->GetObjectPtr());//获得当前设备回话

    EasyProtocolACK reqreq(MSG_SD_CONTROL_PTZ_REQ);
    EasyJsonValue headerheader, bodybody;

    const UInt32 strCSEQ = pDevSession->GetCSeq();
    headerheader[EASY_TAG_CSEQ] = EasyUtil::ToString(strCSEQ);
    headerheader[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;

    string strProtocol(chProtocol);
    string strActionType(chActionType);
    string strCmd(chCmd);
    boost::to_upper(strProtocol);
    boost::to_upper(strActionType);
    boost::to_upper(strCmd);

    bodybody[EASY_TAG_SERIAL] = chSerial;
    bodybody[EASY_TAG_CHANNEL] = chChannel;
    bodybody[EASY_TAG_PROTOCOL] = strProtocol;
    bodybody[EASY_TAG_RESERVE] = chReserve;
    bodybody[EASY_TAG_ACTION_TYPE] = strActionType;
    bodybody[EASY_TAG_CMD] = strCmd;
    bodybody[EASY_TAG_SPEED] = chSpeed;
    bodybody[EASY_TAG_FROM] = sessionId_;
    bodybody[EASY_TAG_TO] = pDevSession->GetSessionID();
    bodybody[EASY_TAG_VIA] = QTSServerInterface::GetServer()->GetCloudServiceNodeID();

    reqreq.SetHead(headerheader);
    reqreq.SetBody(bodybody);

    log = Format("%s-%s %s %s", string(chSerial), string(chChannel), "MSG_SD_CONTROL_PTZ_REQ", string(chCmd));
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());
    const string buffer = reqreq.GetMsg();
    pDevSession->PostRequest(buffer);

    EasyProtocolACK rsp(MSG_SC_PTZ_CONTROL_ACK);
    EasyJsonValue header, body;
    body[EASY_TAG_SERIAL] = chSerial;
    body[EASY_TAG_CHANNEL] = chChannel;
    body[EASY_TAG_PROTOCOL] = strProtocol;
    body[EASY_TAG_RESERVE] = chReserve;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = EasyUtil::ToString(strCSEQ);
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgDSPTZControlAck(const char* json)
{
    //  if (!fAuthenticated)//没有进行认证请求
    //      return httpUnAuthorized;

    //  //对于设备的推流回应是不需要在进行回应的，直接解析找到对应的客户端Session，赋值即可	
    //  EasyProtocol req(json);

    //  string strDeviceSerial = req.GetBodyValue(EASY_TAG_SERIAL);//设备序列号
    //  string strChannel = req.GetBodyValue(EASY_TAG_CHANNEL);//摄像头序列号
    //  string strProtocol = req.GetBodyValue(EASY_TAG_PROTOCOL);//协议,终端仅支持RTSP推送
    //  string strReserve = req.GetBodyValue(EASY_TAG_RESERVE);//流类型
    //  string strFrom = req.GetBodyValue(EASY_TAG_FROM);
    //  string strTo = req.GetBodyValue(EASY_TAG_TO);
    //  string strVia = req.GetBodyValue(EASY_TAG_VIA);

    //  string strCSeq = req.GetHeaderValue(EASY_TAG_CSEQ);//这个是关键字
    //  string strStateCode = req.GetHeaderValue(EASY_TAG_ERROR_NUM);//状态码

    //  if (strChannel.empty())
    //      strChannel = "1";
    //  if (strReserve.empty())
    //      strReserve = "1";

    //  OSRefTableEx* sessionMap = QTSServerInterface::GetServer()->GetHTTPSessionMap();
    //  OSRefTableEx::OSRefEx* sessionRef = sessionMap->Resolve(strTo);
    //  if (sessionRef == NULL)
    //      return EASY_ERROR_SESSION_NOT_FOUND;

    //  OSRefReleaserEx releaser(sessionMap, strTo);
    //  HTTPSession* httpSession = static_cast<HTTPSession*>(sessionRef->GetObjectPtr());

    //  if (httpSession->IsLiveSession())
    //  {
    //      //走到这说明对客户端的正确回应,因为错误回应直接返回。
    //      EasyProtocolACK rsp(MSG_SC_PTZ_CONTROL_ACK);
    //      EasyJsonValue header, body;
    //      body[EASY_TAG_SERIAL] = strDeviceSerial;
    //      body[EASY_TAG_CHANNEL] = strChannel;
    //      body[EASY_TAG_PROTOCOL] = strProtocol;//如果当前已经推流，则返回请求的，否则返回实际推流类型
    //      body[EASY_TAG_RESERVE] = strReserve;//如果当前已经推流，则返回请求的，否则返回实际推流类型

    //      header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    //      header[EASY_TAG_CSEQ] = strCSeq;
    //      header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    //      header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    //      rsp.SetHead(header);
    //      rsp.SetBody(body);
    //      string msg = rsp.GetMsg();
          //httpSession->ProcessEvent(msg, httpResponseType);
    //  }

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSPresetControlReqRESTful(const char* queryString)
{
    /*//暂时注释掉，实际上是需要认证的
    if(!fAuthenticated)//没有进行认证请求
    return httpUnAuthorized;
    */

    if (queryString == NULL)
    {
        return QTSS_BadArgument;
    }

    const string decQueryString = EasyUtil::Urldecode(queryString);

    QueryParamList parList(decQueryString);

    const char* chSerial = parList.DoFindCGIValueForParam(EASY_TAG_L_DEVICE);//获取设备序列号
    const char* chChannel = parList.DoFindCGIValueForParam(EASY_TAG_L_CHANNEL);//获取通道
    const char* chProtocol = parList.DoFindCGIValueForParam(EASY_TAG_L_PROTOCOL);//获取通道
    const char* chReserve = parList.DoFindCGIValueForParam(EASY_TAG_L_RESERVE);//获取通道
    const char* chCmd = parList.DoFindCGIValueForParam(EASY_TAG_L_CMD);
    const char* chPreset = parList.DoFindCGIValueForParam(EASY_TAG_L_PRESET);

    if (!chSerial || !chProtocol || !chCmd)
        return QTSS_BadArgument;

    //为可选参数填充默认值
    if (!isRightChannel(chChannel))
        chChannel = "1";
    if (chReserve == NULL)
        chReserve = "1";

    std::string log = Format("%s-%s %s %s", string(chSerial), string(chChannel), "preset", string(chCmd));
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSRefTableEx::OSRefEx* theDevRef = deviceMap->Resolve(chSerial);
    if (theDevRef == NULL)//找不到指定设备
        return EASY_ERROR_DEVICE_NOT_FOUND;

    OSRefReleaserEx releaser(deviceMap, chSerial);
    //走到这说明存在指定设备
    HTTPSession* pDevSession = static_cast<HTTPSession*>(theDevRef->GetObjectPtr());//获得当前设备回话

    EasyProtocolACK reqreq(MSG_SD_CONTROL_PRESET_REQ);
    EasyJsonValue headerheader, bodybody;

    headerheader[EASY_TAG_CSEQ] = EasyUtil::ToString(pDevSession->GetCSeq());
    headerheader[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;

    bodybody[EASY_TAG_SERIAL] = chSerial;
    bodybody[EASY_TAG_CHANNEL] = chChannel;
    bodybody[EASY_TAG_PROTOCOL] = chProtocol;
    bodybody[EASY_TAG_RESERVE] = chReserve;
    bodybody[EASY_TAG_CMD] = chCmd;
    bodybody[EASY_TAG_PRESET] = chPreset;
    bodybody[EASY_TAG_FROM] = sessionId_;
    bodybody[EASY_TAG_TO] = pDevSession->GetSessionID();
    bodybody[EASY_TAG_VIA] = QTSServerInterface::GetServer()->GetCloudServiceNodeID();

    reqreq.SetHead(headerheader);
    reqreq.SetBody(bodybody);

    log = Format("%s-%s %s %s", string(chSerial), string(chChannel), "MSG_SD_CONTROL_PRESET_REQ", string(chCmd));
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());
    const string buffer = reqreq.GetMsg();
    pDevSession->PostRequest(buffer);

    fTimeoutTask.SetTimeout(3 * 1000);
    fTimeoutTask.RefreshTimeout();

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgDSPresetControlAck(const char* json) const
{
    if (!fAuthenticated)//没有进行认证请求
        return httpUnAuthorized;

    //对于设备的推流回应是不需要在进行回应的，直接解析找到对应的客户端Session，赋值即可	
    EasyProtocol req(json);

    const string strDeviceSerial = req.GetBodyValue(EASY_TAG_SERIAL);//设备序列号
    string strChannel = req.GetBodyValue(EASY_TAG_CHANNEL);//摄像头序列号
    const string strProtocol = req.GetBodyValue(EASY_TAG_PROTOCOL);//协议,终端仅支持RTSP推送
    string strReserve = req.GetBodyValue(EASY_TAG_RESERVE);//流类型
    string strFrom = req.GetBodyValue(EASY_TAG_FROM);
    const string strTo = req.GetBodyValue(EASY_TAG_TO);
    string strVia = req.GetBodyValue(EASY_TAG_VIA);

    const string strCSeq = req.GetHeaderValue(EASY_TAG_CSEQ);//这个是关键字
    string strStateCode = req.GetHeaderValue(EASY_TAG_ERROR_NUM);//状态码

    if (strChannel.empty())
        strChannel = "1";
    if (strReserve.empty())
        strReserve = "1";

    OSRefTableEx* sessionMap = QTSServerInterface::GetServer()->GetHTTPSessionMap();
    OSRefTableEx::OSRefEx* sessionRef = sessionMap->Resolve(strTo);
    if (sessionRef == NULL)
        return EASY_ERROR_SESSION_NOT_FOUND;

    OSRefReleaserEx releaser(sessionMap, strTo);
    HTTPSession* httpSession = static_cast<HTTPSession*>(sessionRef->GetObjectPtr());

    if (httpSession->IsLiveSession())
    {
        //走到这说明对客户端的正确回应,因为错误回应直接返回。
        EasyProtocolACK rsp(MSG_SC_PRESET_CONTROL_ACK);
        EasyJsonValue header, body;
        body[EASY_TAG_SERIAL] = strDeviceSerial;
        body[EASY_TAG_CHANNEL] = strChannel;
        body[EASY_TAG_PROTOCOL] = strProtocol;//如果当前已经推流，则返回请求的，否则返回实际推流类型
        body[EASY_TAG_RESERVE] = strReserve;//如果当前已经推流，则返回请求的，否则返回实际推流类型

        header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
        header[EASY_TAG_CSEQ] = strCSeq;
        header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
        header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

        rsp.SetHead(header);
        rsp.SetBody(body);

        const string msg = rsp.GetMsg();
        httpSession->PostResponse(msg);
    }

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSTalkbackControlReq(const char* json)
{
    //if (!fAuthenticated)//没有进行认证请求
    //	return httpUnAuthorized;

    EasyProtocol req(json);

    const string strDeviceSerial = req.GetBodyValue(EASY_TAG_SERIAL);
    string strChannel = req.GetBodyValue(EASY_TAG_CHANNEL);
    const string strProtocol = req.GetBodyValue(EASY_TAG_PROTOCOL);
    string strReserve = req.GetBodyValue(EASY_TAG_RESERVE);
    const string strCmd = req.GetBodyValue(EASY_TAG_CMD);
    const string strAudioType = req.GetBodyValue(EASY_TAG_AUDIO_TYPE);
    const string strAudioData = req.GetBodyValue(EASY_TAG_AUDIO_DATA);
    const string strPts = req.GetBodyValue(EASY_TAG_PTS);

    string strCSeq = req.GetHeaderValue(EASY_TAG_CSEQ);//这个是关键字

    if (strChannel.empty())
        strChannel = "1";
    if (strReserve.empty())
        strReserve = "1";

    std::string log = Format("%s-%s %s %s", strDeviceSerial, strChannel, "talk", strCmd);
    QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSRefTableEx::OSRefEx* theDevRef = deviceMap->Resolve(strDeviceSerial);
    if (theDevRef == NULL)//找不到指定设备
        return EASY_ERROR_DEVICE_NOT_FOUND;

    OSRefReleaserEx releaser(deviceMap, strDeviceSerial);
    //走到这说明存在指定设备
    HTTPSession* pDevSession = static_cast<HTTPSession*>(theDevRef->GetObjectPtr());//获得当前设备回话

    int errNo;
    std::string errString;
    if (strCmd == "SENDDATA")
    {
        if (!pDevSession->GetTalkbackSession().empty() && pDevSession->GetTalkbackSession() == sessionId_)
        {
            EasyProtocolACK reqreq(MSG_SD_CONTROL_TALKBACK_REQ);
            EasyJsonValue headerheader, bodybody;

            headerheader[EASY_TAG_CSEQ] = EasyUtil::ToString(pDevSession->GetCSeq());//注意这个地方不能直接将UINT32->int,因为会造成数据失真
            headerheader[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;

            bodybody[EASY_TAG_SERIAL] = strDeviceSerial;
            bodybody[EASY_TAG_CHANNEL] = strChannel;
            bodybody[EASY_TAG_PROTOCOL] = strProtocol;
            bodybody[EASY_TAG_RESERVE] = strReserve;
            bodybody[EASY_TAG_CMD] = strCmd;
            bodybody[EASY_TAG_AUDIO_TYPE] = strAudioType;
            bodybody[EASY_TAG_AUDIO_DATA] = strAudioData;
            bodybody[EASY_TAG_PTS] = strPts;
            bodybody[EASY_TAG_FROM] = sessionId_;
            bodybody[EASY_TAG_TO] = pDevSession->GetSessionID();
            bodybody[EASY_TAG_VIA] = QTSServerInterface::GetServer()->GetCloudServiceNodeID();

            reqreq.SetHead(headerheader);
            reqreq.SetBody(bodybody);

            log = Format("%s-%s %s %s", strDeviceSerial, strChannel, "MSG_SD_CONTROL_TALKBACK_REQ", strCmd);
            QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());
            const string buffer = reqreq.GetMsg();
            pDevSession->PostRequest(buffer);

            errNo = EASY_ERROR_SUCCESS_OK;
            errString = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);
        }
        else
        {
            errNo = EASY_ERROR_CLIENT_BAD_REQUEST;
            errString = EasyProtocol::GetErrorString(EASY_ERROR_CLIENT_BAD_REQUEST);
            goto ACK;
        }
    }
    else
    {
        if (strCmd == "START")
        {
            if (pDevSession->GetTalkbackSession().empty())
            {
                pDevSession->SetTalkbackSession(sessionId_);
                errNo = EASY_ERROR_SUCCESS_OK;
                errString = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);
            }
            else if (pDevSession->GetTalkbackSession() == sessionId_)
            {
            }
            else
            {
                errNo = EASY_ERROR_CLIENT_BAD_REQUEST;
                errString = EasyProtocol::GetErrorString(EASY_ERROR_CLIENT_BAD_REQUEST);
                goto ACK;
            }
        }
        else if (strCmd == "STOP")
        {
            if (pDevSession->GetTalkbackSession().empty() || pDevSession->GetTalkbackSession() != sessionId_)
            {
                errNo = EASY_ERROR_CLIENT_BAD_REQUEST;
                errString = EasyProtocol::GetErrorString(EASY_ERROR_CLIENT_BAD_REQUEST);
                goto ACK;
            }

            pDevSession->SetTalkbackSession("");
            errNo = EASY_ERROR_SUCCESS_OK;
            errString = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);
        }

        EasyProtocolACK reqreq(MSG_SD_CONTROL_TALKBACK_REQ);
        EasyJsonValue headerheader, bodybody;

        headerheader[EASY_TAG_CSEQ] = EasyUtil::ToString(pDevSession->GetCSeq());//注意这个地方不能直接将UINT32->int,因为会造成数据失真
        headerheader[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;

        bodybody[EASY_TAG_SERIAL] = strDeviceSerial;
        bodybody[EASY_TAG_CHANNEL] = strChannel;
        bodybody[EASY_TAG_PROTOCOL] = strProtocol;
        bodybody[EASY_TAG_RESERVE] = strReserve;
        bodybody[EASY_TAG_CMD] = strCmd;
        bodybody[EASY_TAG_AUDIO_TYPE] = strAudioType;
        bodybody[EASY_TAG_AUDIO_DATA] = strAudioData;
        bodybody[EASY_TAG_PTS] = strPts;
        bodybody[EASY_TAG_FROM] = sessionId_;
        bodybody[EASY_TAG_TO] = pDevSession->GetSessionID();
        bodybody[EASY_TAG_VIA] = QTSServerInterface::GetServer()->GetCloudServiceNodeID();

        reqreq.SetHead(headerheader);
        reqreq.SetBody(bodybody);

        log = Format("%s-%s %s %s", strDeviceSerial, strChannel, "MSG_SD_CONTROL_TALKBACK_REQ", strCmd);
        QTSServerInterface::LogError(qtssMessageVerbosity, (char*)log.c_str());
        const string buffer = reqreq.GetMsg();
        pDevSession->PostRequest(buffer);
    }

ACK:

    printf("%s\n", strCmd.c_str());

    EasyProtocolACK rsp(MSG_SC_TALKBACK_CONTROL_ACK);
    EasyJsonValue header, body;
    body[EASY_TAG_SERIAL] = strDeviceSerial;
    body[EASY_TAG_CHANNEL] = strChannel;
    body[EASY_TAG_PROTOCOL] = strProtocol;
    body[EASY_TAG_RESERVE] = strReserve;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = EasyUtil::ToString(pDevSession->GetCSeq());
    header[EASY_TAG_ERROR_NUM] = errNo;
    header[EASY_TAG_ERROR_STRING] = errString;

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg, false);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMSGDSTalkbackControlAck(const char* json)
{
    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSGetBaseConfigReqRESTful(const char* queryString)
{
    //if (!fAuthenticated)//没有进行认证请求
    //	return httpUnAuthorized;

    EasyProtocolACK rsp(MSG_SC_SERVER_BASE_CONFIG_ACK);
    EasyJsonValue header, body;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = 1;
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    QTSSCharArrayDeleter wanIP(QTSServerInterface::GetServer()->GetPrefs()->GetServiceWANIP());
    QTSSCharArrayDeleter snapPath(QTSServerInterface::GetServer()->GetPrefs()->GetSnapLocalPath());
    QTSSCharArrayDeleter snapWebPath(QTSServerInterface::GetServer()->GetPrefs()->GetSnapWebPath());

    body[EASY_TAG_CONFIG_SERVICE_WAN_IP] = string(wanIP);
    body[EASY_TAG_CONFIG_SERVICE_LAN_PORT] = QTSServerInterface::GetServer()->GetPrefs()->GetServiceLANPort();
    body[EASY_TAG_CONFIG_SERVICE_WAN_PORT] = QTSServerInterface::GetServer()->GetPrefs()->GetServiceWANPort();
    body[EASY_TAG_CONFIG_SNAP_LOCAL_PATH] = string(snapPath);
    body[EASY_TAG_CONFIG_SNAP_WEB_PATH] = string(snapWebPath);

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSSetBaseConfigReqRESTful(const char* queryString)
{
    //if (!fAuthenticated)//没有进行认证请求
    //	return httpUnAuthorized;

    string queryTemp;
    if (queryString)
    {
        queryTemp = EasyUtil::Urldecode(queryString);
    }

    QueryParamList parList(queryTemp);
    const char* chWanIP = parList.DoFindCGIValueForParam(EASY_TAG_CONFIG_SERVICE_WAN_IP);
    if (chWanIP)
    {
        QTSS_SetValue(QTSServerInterface::GetServer()->GetPrefs(), qtssPrefsServiceWANIPAddr, 0, chWanIP, strlen(chWanIP));
    }

    const char* chHTTPLanPort = parList.DoFindCGIValueForParam(EASY_TAG_CONFIG_SERVICE_LAN_PORT);
    if (chHTTPLanPort)
    {
        UInt16 uHTTPLanPort = atoi(chHTTPLanPort);
        QTSS_SetValue(QTSServerInterface::GetServer()->GetPrefs(), qtssPrefsServiceLANPort, 0, &uHTTPLanPort, sizeof(uHTTPLanPort));
    }

    const char*	chHTTPWanPort = parList.DoFindCGIValueForParam(EASY_TAG_CONFIG_SERVICE_WAN_PORT);
    if (chHTTPWanPort)
    {
        UInt16 uHTTPWanPort = atoi(chHTTPWanPort);
        QTSS_SetValue(QTSServerInterface::GetServer()->GetPrefs(), qtssPrefsServiceWANPort, 0, &uHTTPWanPort, sizeof(uHTTPWanPort));
    }

    const char* chSnapLocalPath = parList.DoFindCGIValueForParam(EASY_TAG_CONFIG_SNAP_LOCAL_PATH);
    if (chSnapLocalPath)
    {
        string snapLocalPath(chSnapLocalPath);
        if (snapLocalPath[snapLocalPath.length() - 1] != '\\')
        {
            snapLocalPath.push_back('\\');
        }
        QTSS_SetValue(QTSServerInterface::GetServer()->GetPrefs(), qtssPrefsSnapLocalPath, 0, snapLocalPath.c_str(), snapLocalPath.size());
    }

    const char* chSnapWebPath = parList.DoFindCGIValueForParam(EASY_TAG_CONFIG_SNAP_WEB_PATH);
    if (chSnapWebPath)
    {
        string snapWebPath(chSnapWebPath);
        if (snapWebPath[snapWebPath.length() - 1] != '\/')
        {
            snapWebPath.push_back('\/');
        }
        QTSS_SetValue(QTSServerInterface::GetServer()->GetPrefs(), qtssPrefsSnapWebPath, 0, snapWebPath.c_str(), snapWebPath.size());
    }

    EasyProtocolACK rsp(MSG_SC_SERVER_SET_BASE_CONFIG_ACK);
    EasyJsonValue header, body;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = 1;
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSGetServerInfoReqRESTful(const char* queryString)
{
    //if (!fAuthenticated)//没有进行认证请求
    //	return httpUnAuthorized;

    EasyProtocolACK rsp(MSG_SC_SERVER_INFO_ACK);
    EasyJsonValue header, body;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = 1;
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    char* serverHeader = NULL;
    (void)QTSS_GetValueAsString(QTSServerInterface::GetServer(), qtssSvrHTTPServerHeader, 0, &serverHeader);
    QTSSCharArrayDeleter theFullPathStrDeleter(serverHeader);
    body[EASY_TAG_SERVER_HEADER] = serverHeader;

    const SInt64 timeNow = OS::Milliseconds();
    SInt64 startupTime = 0;
    UInt32 startupTimeSize = sizeof(startupTime);
    (void)QTSS_GetValue(QTSServerInterface::GetServer(), qtssSvrStartupTime, 0, &startupTime, &startupTimeSize);
    const SInt64 longstTime = (timeNow - startupTime) / 1000;

    unsigned int timeDays = longstTime / (24 * 60 * 60);
    unsigned int timeHours = (longstTime % (24 * 60 * 60)) / (60 * 60);
    unsigned int timeMins = ((longstTime % (24 * 60 * 60)) % (60 * 60)) / 60;
    unsigned int timeSecs = ((longstTime % (24 * 60 * 60)) % (60 * 60)) % 60;

    body[EASY_TAG_SERVER_RUNNING_TIME] = Format("%u Days %u Hours %u Mins %u Secs", timeDays, timeHours, timeMins, timeSecs);

    const UInt32 load = QTSServerInterface::GetServer()->GetNumServiceSessions();
    body[EASY_TAG_LOAD] = EasyUtil::ToString(load);

    body[EASY_TAG_SERVER_HARDWARE] = "x86";
    body[EASY_TAG_SERVER_INTERFACE_VERSION] = "v1";

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

QTSS_Error HTTPSession::execNetMsgCSRestartReqRESTful(const char* queryString)
{
    /*//暂时注释掉，实际上是需要认证的
    if(!fAuthenticated)//没有进行认证请求
    return httpUnAuthorized;
    */

#ifdef WIN32
    ::ExitProcess(0);
#else
    exit(0);
#endif //WIN32
}

QTSS_Error HTTPSession::execNetMsgCSGetUsagesReqRESTful(const char* queryString)
{
    /*//暂时注释掉，实际上是需要认证的
    if(!fAuthenticated)//没有进行认证请求
    return httpUnAuthorized;
    */

    EasyProtocolACK rsp(MSG_SC_SERVER_USAGES_ACK);
    EasyJsonValue header, body;

    header[EASY_TAG_VERSION] = EASY_PROTOCOL_VERSION;
    header[EASY_TAG_CSEQ] = 1;
    header[EASY_TAG_ERROR_NUM] = EASY_ERROR_SUCCESS_OK;
    header[EASY_TAG_ERROR_STRING] = EasyProtocol::GetErrorString(EASY_ERROR_SUCCESS_OK);

    Json::Value* proot = rsp.GetRoot();

    {
        Json::Value value;
        value[EASY_TAG_HTTP_METHOD] = EASY_TAG_HTTP_GET;
        value[EASY_TAG_ACTION] = "GetDeviceList";
        value[EASY_TAG_PARAMETER] = "";
        value[EASY_TAG_EXAMPLE] = "http://ip:port/api/v1/getdevicelist";
        value[EASY_TAG_DESCRIPTION] = "";
        (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_API].append(value);
    }

    {
        Json::Value value;
        value[EASY_TAG_HTTP_METHOD] = EASY_TAG_HTTP_GET;
        value[EASY_TAG_ACTION] = "GetDeviceInfo";
        value[EASY_TAG_PARAMETER] = "device=[Serial]";
        value[EASY_TAG_EXAMPLE] = "http://ip:port/api/v1/getdeviceinfo?device=00100100001";
        value[EASY_TAG_DESCRIPTION] = "";
        (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_API].append(value);
    }

    {
        Json::Value value;
        value[EASY_TAG_HTTP_METHOD] = EASY_TAG_HTTP_GET;
        value[EASY_TAG_ACTION] = "StartDeviceStream";
        value[EASY_TAG_PARAMETER] = "device=[Serial]&channel=[Channel]&reserve=[Reserve]";
        value[EASY_TAG_EXAMPLE] = "http://ip:port/api/v1/startdevicestream?device=001002000001&channel=1&reserve=1";
        value[EASY_TAG_DESCRIPTION] = "";
        (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_API].append(value);
    }

    {
        Json::Value value;
        value[EASY_TAG_HTTP_METHOD] = EASY_TAG_HTTP_GET;
        value[EASY_TAG_ACTION] = "StopDeviceStream";
        value[EASY_TAG_PARAMETER] = "device=[Serial]&channel=[Channel]&reserve=[Reserve]";
        value[EASY_TAG_EXAMPLE] = "http://ip:port/api/v1/stopdevicestream?device=001002000001&channel=1&reserve=1";
        value[EASY_TAG_DESCRIPTION] = "";
        (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_API].append(value);
    }

    {
        Json::Value value;
        value[EASY_TAG_HTTP_METHOD] = EASY_TAG_HTTP_GET;
        value[EASY_TAG_ACTION] = "PTZControl";
        value[EASY_TAG_PARAMETER] = "device=[Serial]&channel=[Channel]&protocol=[ONVIF/SDK]&actiontype=[Continuous/Single]&command=[Stop/Up/Down/Left/Right/Zoomin/Zoomout/Focusin/Focusout/Aperturein/Apertureout]&speed=[Speed]&reserve=[Reserve]";
        value[EASY_TAG_EXAMPLE] = "http://ip:port/api/v1/ptzcontrol?device=001002000001&channel=1&protocol=onvif&actiontype=single&command=down&speed=5&reserve=1";
        value[EASY_TAG_DESCRIPTION] = "";
        (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_API].append(value);
    }

    {
        Json::Value value;
        value[EASY_TAG_HTTP_METHOD] = EASY_TAG_HTTP_GET;
        value[EASY_TAG_ACTION] = "PresetControl";
        value[EASY_TAG_PARAMETER] = "device=[Serial]&channel=[Channel]&protocol=[ONVIF/SDK]&preset=[Preset]&command=[Goto/Set/Remove]";
        value[EASY_TAG_EXAMPLE] = "http://ip:port/api/v1/presetcontrol?device=001001000058&channel=1&command=goto&preset=1&protocol=onvif";
        value[EASY_TAG_DESCRIPTION] = "";
        (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_API].append(value);
    }

    {
        Json::Value value;
        value[EASY_TAG_HTTP_METHOD] = EASY_TAG_HTTP_POST;
        value[EASY_TAG_ACTION] = "MSG_CS_TALKBACK_CONTROL_REQ";
        value[EASY_TAG_PARAMETER] = "";
        value[EASY_TAG_EXAMPLE] = "http://ip:port";
        value[EASY_TAG_DESCRIPTION] = "";
        (*proot)[EASY_TAG_ROOT][EASY_TAG_BODY][EASY_TAG_API].append(value);
    }

    rsp.SetHead(header);
    rsp.SetBody(body);

    const string msg = rsp.GetMsg();
    this->PostResponse(msg);

    return QTSS_NoErr;
}

bool HTTPSession::isRightChannel(const char* channel) const
{
    if (!channel)
    {
        return false;
    }

    try
    {
        const int channelNum = boost::lexical_cast<unsigned int>(channel);
        if (channelNum > 1024)
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    return true;
}


QTSS_Error HTTPSession::snapHandler(const char* json)
{
    Json::Value content;

    if (!json)
    {
        content["code"] = 401;
        content["msg"] = "bad args";

        this->PostResponse(content.toStyledString());

        return QTSS_NoErr;
    }

    string serial;
    unsigned int channel;
    string data;
    try
    {
        Json::Reader reader;
        Json::Value root;
        reader.parse(json, root);

        serial = root["serial"].asString();
        channel = root["channel"].asUInt();
        data = root["data"].asString();
    }
    catch (...)
    {
        content["code"] = 401;
        content["msg"] = "bad args";

        this->PostResponse(content.toStyledString());

        return QTSS_NoErr;
    }

    if (serial.empty() || data.empty())
    {
        content["code"] = 401;
        content["msg"] = "bad args";

        this->PostResponse(content.toStyledString());

        return QTSS_NoErr;
    }

    OSRefTableEx* deviceMap = QTSServerInterface::GetServer()->GetDeviceSessionMap();
    OSRefTableEx::OSRefEx* theDevRef = deviceMap->Resolve(serial);
    if (!theDevRef)
    {
        content["code"] = 404;
        content["msg"] = "no device";

        this->PostResponse(content.toStyledString());

        return QTSS_NoErr;
    }

    OSRefReleaserEx releaser(deviceMap, serial);
    HTTPSession* deviceSession = static_cast<HTTPSession*>(theDevRef->GetObjectPtr());

    std::vector<string> dataVector;
    boost::split(dataVector, data, boost::is_any_of(","), boost::token_compress_on);
    if (dataVector.size() != 2)
    {
        content["code"] = 401;
        content["msg"] = "bad args";

        this->PostResponse(content.toStyledString());

        return QTSS_NoErr;
    }
    string image(dataVector[1]);
    image = EasyUtil::Base64Decode(image.data(), image.size());
    string channelStr = boost::lexical_cast<string>(channel);
    QTSSCharArrayDeleter snapPath(QTSServerInterface::GetServer()->GetPrefs()->GetSnapLocalPath());
    string jpgDir = string(snapPath).append(serial);
    OS::RecursiveMakeDir(const_cast<char*>(jpgDir.c_str()));
#ifdef SAVE_SNAP_BY_TIME
    string jpgPath = Format("%s/%s_%s_%s.%s", jpgDir, device_serial, channelStr, strTime, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
#else
    string jpgPath = Format("%s/%s_%s.%s", jpgDir, serial, channelStr, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
#endif //SAVE_SNAP_BY_TIME

    {
        FILE* snapFile = ::fopen(jpgPath.c_str(), "wb");
        if (snapFile)
        {
            boost::shared_ptr<FILE> fileClose(snapFile, &fclose);
            fwrite(image.data(), 1, image.size(), snapFile);
        }
    }

    QTSSCharArrayDeleter snapWebPath(QTSServerInterface::GetServer()->GetPrefs()->GetSnapWebPath());
#ifdef SAVE_SNAP_BY_TIME
    const string snapURL = Format("%s%s/%s_%s_%s.%s", string(QTSServerInterface::GetServer()->GetPrefs()->GetSnapWebPath()), device_serial,
        device_serial, channelStr, strTime, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
#else
    const string snapURL = Format("%s%s/%s_%s.%s", string(snapWebPath), serial,
        serial, channelStr, EasyProtocol::GetSnapTypeString(EASY_SNAP_TYPE_JPEG));
#endif //SAVE_SNAP_BY_TIME

    deviceSession->setChannelSnap(snapURL, channelStr);

    content["code"] = 0;
    content["msg"] = "success";

    this->PostResponse(content.toStyledString());

    return QTSS_NoErr;
}

void HTTPSession::setChannelSnap(const string& url, const string& channel)
{
    if (!device_)
        return;

    device_->HoldSnapPath(url, channel);
    device_->channels_[channel].status_ = "online";
}

void HTTPSession::unRegDevSession() const
{
    if (fAuthenticated)
    {
        char msgStr[512];
        qtss_snprintf(msgStr, sizeof(msgStr), "Device unregister, Device_serial %s", device_->serial_.c_str());
        QTSServerInterface::LogError(qtssMessageVerbosity, msgStr);

        QTSServerInterface::GetServer()->GetDeviceSessionMap()->UnRegister(device_->serial_);

        QTSS_RoleParams theParams;
        theParams.DeviceInfoParams.serial_ = (char*)device_->serial_.c_str();
        UInt32 numModules = QTSServerInterface::GetNumModulesInRole(QTSSModule::kRedisDelDeviceRole);
        for (UInt32 currentModule = 0; currentModule < numModules;)
        {
            QTSSModule* theModule = QTSServerInterface::GetModule(QTSSModule::kRedisDelDeviceRole, currentModule);
            (void)theModule->CallDispatch(Easy_RedisDelDevice_Role, &theParams);
            break;
        }

        /*QTSS_RoleParams params;
        params.logParams.serial = (char*)device_->serial_.c_str();
        params.logParams.msg = msgStr;
        numModules = QTSServerInterface::GetNumModulesInRole(QTSSModule::kRedisLogRole);
        for (UInt32 currentModule = 0; currentModule < numModules;)
        {
        QTSSModule* theModule = QTSServerInterface::GetModule(QTSSModule::kRedisLogRole, currentModule);
        (void)theModule->CallDispatch(Easy_RedisLog_Role, &params);
        break;
        }*/
    }
}

