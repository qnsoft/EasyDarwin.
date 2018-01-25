/*
    Copyleft (c) 2012-2016 EasyDarwin.ORG.  All rights reserved.
    Github: https://github.com/EasyDarwin
    WEChat: EasyDarwin
    Website: http://www.EasyDarwin.org
*/
/*
    File:       HTTPSessionInterface.cpp
    Contains:   Implementation of HTTPSessionInterface object.
*/

#include "HTTPSessionInterface.h"
#include "QTSServerInterface.h"
#include <errno.h>
#include "EasyUtil.h"

unsigned int	HTTPSessionInterface::sSessionIndexCounter = kFirstHTTPSessionID;

void HTTPSessionInterface::Initialize()
{
}

HTTPSessionInterface::HTTPSessionInterface()
    : Task(),
    fTimeoutTask(NULL, QTSServerInterface::GetServer()->GetPrefs()->GetSessionTimeoutInSecs() * 1000),
    fInputStream(&fSocket),
    fOutputStream(&fSocket, &fTimeoutTask),
    fSessionMutex(),
    fSocket(NULL, Socket::kNonBlockingSocketType),
    fOutputSocketP(&fSocket),
    fInputSocketP(&fSocket),
    //fTerminalType(0),
    fLiveSession(true),
    fObjectHolders(0),
    fRequestBodyLen(-1),
    fAuthenticated(false),
    fCSeq(1)
{
    fTimeoutTask.SetTask(this);
    fSocket.SetTask(this);

    fSessionIndex = ++sSessionIndexCounter;

	sessionId_ = EasyUtil::GetUUID();

    fInputStream.ShowMSG(QTSServerInterface::GetServer()->GetPrefs()->GetMSGDebugPrintfs());
    fOutputStream.ShowMSG(QTSServerInterface::GetServer()->GetPrefs()->GetMSGDebugPrintfs());
}

HTTPSessionInterface::~HTTPSessionInterface()
{
	// If the input socket is != output socket, the input socket was created dynamically
    if (fInputSocketP != fOutputSocketP)
        delete fInputSocketP;
}

void HTTPSessionInterface::DecrementObjectHolderCount()
{

    //#if __Win32__
    //maybe don't need this special case but for now on Win32 we do it the old way since the killEvent code hasn't been verified on Windows.
    this->Signal(Task::kReadEvent);//have the object wakeup in case it can go away.
    atomic_sub(&fObjectHolders, 1);
    //#else
    //    if (0 == atomic_sub(&fObjectHolders, 1))
    //        this->Signal(Task::kKillEvent);
    //#endif

}

QTSS_Error HTTPSessionInterface::Write(void* inBuffer, UInt32 inLength, UInt32* outLenWritten, UInt32 inFlags)
{
    UInt32 sendType = HTTPResponseStream::kDontBuffer;
    if ((inFlags & qtssWriteFlagsBufferData) != 0)
        sendType = HTTPResponseStream::kAlwaysBuffer;

    iovec theVec[2];
    theVec[1].iov_base = static_cast<char*>(inBuffer);
    theVec[1].iov_len = inLength;
    return fOutputStream.WriteV(theVec, 2, inLength, outLenWritten, sendType);
}

QTSS_Error HTTPSessionInterface::WriteV(iovec* inVec, UInt32 inNumVectors, UInt32 inTotalLength, UInt32* outLenWritten)
{
    return fOutputStream.WriteV(inVec, inNumVectors, inTotalLength, outLenWritten, HTTPResponseStream::kDontBuffer);
}

QTSS_Error HTTPSessionInterface::Read(void* ioBuffer, UInt32 inLength, UInt32* outLenRead)
{
    //
    // Don't let callers of this function accidently creep past the end of the
    // request body.  If the request body size isn't known, fRequestBodyLen will be -1

    if (fRequestBodyLen == 0)
        return QTSS_NoMoreData;

    if ((fRequestBodyLen > 0) && (static_cast<SInt32>(inLength) > fRequestBodyLen))
        inLength = fRequestBodyLen;

    UInt32 theLenRead = 0;
    QTSS_Error theErr = fInputStream.Read(ioBuffer, inLength, &theLenRead);

    if (fRequestBodyLen >= 0)
        fRequestBodyLen -= theLenRead;

    if (outLenRead != NULL)
        *outLenRead = theLenRead;

    return theErr;
}

QTSS_Error HTTPSessionInterface::RequestEvent(QTSS_EventType inEventMask)
{
    if (inEventMask & QTSS_ReadableEvent)
        fInputSocketP->RequestEvent(EV_RE);
    if (inEventMask & QTSS_WriteableEvent)
        fOutputSocketP->RequestEvent(EV_WR);

    return QTSS_NoErr;
}

void HTTPSessionInterface::snarfInputSocket(HTTPSessionInterface* fromHTTPSession)
{
    Assert(fromHTTPSession != NULL);
    Assert(fromHTTPSession->fOutputSocketP != NULL);

    fInputStream.SnarfRetreat(fromHTTPSession->fInputStream);

    if (fInputSocketP == fOutputSocketP)
        fInputSocketP = new TCPSocket(this, Socket::kNonBlockingSocketType);
    else
        fInputSocketP->Cleanup();   // if this is a socket replacing an old socket, we need
                                    // to make sure the file descriptor gets closed
    fInputSocketP->SnarfSocket(fromHTTPSession->fSocket);

    // fInputStream, meet your new input socket
    fInputStream.AttachToSocket(fInputSocketP);
}
