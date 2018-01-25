#include "EasyRedisHandler.h"

#include "QTSSMemoryDeleter.h"
#include "Format.h"
#include "Resources.h"
#include "EasyUtil.h"

static UInt32 sRedisHandlerID = 0;

EasyRedisHandler::EasyRedisHandler(const char* ip, UInt16 port, const char* passwd)
	: fQueueElem()
	, fID(sRedisHandlerID++)
	, sIfConSucess(false)
	, sMutex()
	, redisContext_(NULL)
{
	this->SetTaskName("EasyRedisHandler");

	fQueueElem.SetEnclosingObject(this);

	::strcpy(fRedisIP, ip);
	fRedisPort = port;
	::strcpy(fRedisPasswd, passwd);

	this->Signal(Task::kStartEvent);
}

EasyRedisHandler::~EasyRedisHandler()
{
	RedisErrorHandler();
}

SInt64 EasyRedisHandler::Run()
{
	OSMutexLocker locker(&sMutex);

	EventFlags theEvents = this->GetEvents();

	RedisConnect();

	return 0;
}

bool EasyRedisHandler::RedisConnect()
{
	if (sIfConSucess)
		return true;

	bool theRet = false;
	do
	{
		struct timeval timeout = { 2, 0 }; // 2 seconds
		redisContext_ = redisConnectWithTimeout(fRedisIP, fRedisPort, timeout);
		if (!redisContext_ || redisContext_->err)
		{
			if (redisContext_)
			{
				printf("Redis context connect error \n");
			}
			else
			{
				printf("Connection error: can't allocate redis context\n");
			}

			theRet = false;
			break;
		}

		string auth = Format("auth %s", string(fRedisPasswd));
		redisReply* reply = static_cast<redisReply*>(redisCommand(redisContext_, auth.c_str()));

		RedisReplyObjectDeleter replyDeleter(reply);
		if (!reply || string(reply->str) != string("OK"))
		{
			printf("Redis auth error\n");
			theRet = false;
			break;
		}

		theRet = true;
		sIfConSucess = true;

		printf("Connect Redis success\n");

	} while (false);

	if (!theRet && redisContext_)
		RedisErrorHandler();

	return theRet;
}

QTSS_Error EasyRedisHandler::RedisTTL()
{
	OSMutexLocker mutexLock(&sMutex);

	QTSS_Error theRet = QTSS_NoErr;
	if (!RedisConnect())
		return QTSS_NotConnected;

	string server(QTSServerInterface::GetServer()->GetServerName().Ptr);
	string id(QTSServerInterface::GetServer()->GetCloudServiceNodeID());
	UInt32 load = QTSServerInterface::GetServer()->GetNumServiceSessions();

	do
	{
		string expire = Format("expire %s:%s 15", server, id);
		redisReply* reply = static_cast<redisReply*>(redisCommand(redisContext_, expire.c_str()));

		RedisReplyObjectDeleter replyDeleter(reply);
		if (!reply)
		{
			theRet = QTSS_NotConnected;
			break;
		}

		if (reply->integer == 0)
		{
			QTSSCharArrayDeleter wanIP(QTSServerInterface::GetServer()->GetPrefs()->GetServiceWANIP());
			UInt16 cmsPort = QTSServerInterface::GetServer()->GetPrefs()->GetServiceWANPort();
			std::string hmset = Format("hmset %s:%s %s %s %s %hu %s %lu", string(EASY_REDIS_EASYCMS), id, string(EASY_REDIS_IP), string(wanIP),
				string(EASY_REDIS_PORT), cmsPort, string(EASY_REDIS_LOAD), load);
			redisReply* replyHmset = static_cast<redisReply*>(redisCommand(redisContext_, hmset.c_str()));
			RedisReplyObjectDeleter replyHmsetDeleter(replyHmset);
			if (!replyHmset)
			{
				theRet = QTSS_NotConnected;
				break;
			}

			redisReply* replyExpire = static_cast<redisReply*>(redisCommand(redisContext_, expire.c_str()));
			RedisReplyObjectDeleter replyExpireDeleter(replyExpire);
			if (!replyExpire)
			{
				theRet = QTSS_NotConnected;
				break;
			}
		}
		else if (reply->integer == 1)
		{
			string hset = Format("hset %s:%s %s %lu", server, id, string(EASY_REDIS_LOAD), load);
			redisReply* replyHset = static_cast<redisReply*>(redisCommand(redisContext_, hset.c_str()));
			RedisReplyObjectDeleter replyHsetDeleter(replyHset);
			if (!replyHset)
			{
				theRet = QTSS_NotConnected;
				break;
			}
		}

	} while (false);

	if (theRet != QTSS_NoErr)
		RedisErrorHandler();

	return theRet;
}

QTSS_Error EasyRedisHandler::RedisSetDevice(Easy_DeviceInfo_Params* inParams)
{
	OSMutexLocker mutexLock(&sMutex);

	if (!RedisConnect())
		return QTSS_NotConnected;

	if (!inParams->serial_ || string(inParams->serial_).empty())
		return QTSS_BadArgument;

	QTSS_Error theRet = QTSS_NoErr;

	do
	{
		string id(QTSServerInterface::GetServer()->GetCloudServiceNodeID());
		string hmset = Format("hmset %s:%s %s %s %s %s %s %s %s %s", string(EASY_REDIS_DEVICE), string(inParams->serial_),
			string(EASY_REDIS_DEVICE_TYPE), string(inParams->deviceType_), string(EASY_REDIS_TYPE), string(inParams->type_),
			string(EASY_REDIS_CHANNEL), string(inParams->channels_), string(EASY_REDIS_EASYCMS), id,
			string(EASY_REDIS_TOKEN), string(inParams->token_));
		redisReply* reply = static_cast<redisReply*>(redisCommand(redisContext_, hmset.c_str()));
		RedisReplyObjectDeleter replyDeleter(reply);
		if (!reply)
		{
			theRet = QTSS_NotConnected;
			break;
		}

		if (string(reply->str) == string("OK"))
		{
			string expire = Format("expire %s:%s 150", string(EASY_REDIS_DEVICE), string(inParams->serial_));
			redisReply* replyExpire = static_cast<redisReply*>(redisCommand(redisContext_, expire.c_str()));
			RedisReplyObjectDeleter replyExpireDeleter(replyExpire);
			if (!replyExpire)
			{
				theRet = QTSS_NotConnected;
				break;
			}
		}
		else
		{
			theRet = QTSS_RequestFailed;
		}

	} while (false);

	if (theRet != QTSS_NoErr)
		RedisErrorHandler();

	return theRet;
}

QTSS_Error EasyRedisHandler::RedisDelDevice(Easy_DeviceInfo_Params* inParams)
{
	OSMutexLocker mutexLock(&sMutex);

	if (!RedisConnect())
		return QTSS_NotConnected;

	if (!inParams->serial_ || string(inParams->serial_).empty())
		return QTSS_BadArgument;

	QTSS_Error theRet = QTSS_NoErr;
	do
	{
		string del = Format("del %s:%s", string(EASY_REDIS_DEVICE), string(inParams->serial_));
		redisReply* reply = static_cast<redisReply*>(redisCommand(redisContext_, del.c_str()));
		RedisReplyObjectDeleter replyDeleter(reply);

		if (!reply)
		{
			theRet = QTSS_NotConnected;
			break;
		}

		if (reply->integer == 0)
			theRet = QTSS_RequestFailed;

	} while (false);

	if (theRet != QTSS_NoErr)
		RedisErrorHandler();

	return theRet;
}

QTSS_Error EasyRedisHandler::RedisGetAssociatedDarwin(QTSS_GetAssociatedDarwin_Params* inParams)
{
	OSMutexLocker mutexLock(&sMutex);

	if (!RedisConnect())
		return QTSS_NotConnected;

	QTSS_Error theRet = QTSS_NoErr;
	do
	{
		string exists = Format("exists %s:hls/%s-%s", string(EASY_REDIS_LIVE), string(inParams->inSerial), string(inParams->inChannel));
		redisReply* reply = static_cast<redisReply*>(redisCommand(redisContext_, exists.c_str()));
		RedisReplyObjectDeleter replyDeleter(reply);

		if (!reply)
		{
			theRet = QTSS_NotConnected;
			break;
		}

		if (reply->integer == 1)
		{
			string strTemp = Format("hmget %s:hls/%s-%s %s", string(EASY_REDIS_LIVE), string(inParams->inSerial),
				string(inParams->inChannel), string(EASY_REDIS_EASYDARWIN));
			redisReply* replyHmget = static_cast<redisReply*>(redisCommand(redisContext_, strTemp.c_str()));
			RedisReplyObjectDeleter replyHmgetDeleter(replyHmget);
			if (!replyHmget)
			{
				theRet = QTSS_NotConnected;
				break;
			}
			string easydarwin = Format("%s:", string(EASY_REDIS_EASYDARWIN));
			easydarwin += replyHmget->element[0]->str;

			strTemp = Format("hmget %s %s %s %s", easydarwin, string(EASY_REDIS_IP), string(EASY_REDIS_HTTP), string(EASY_REDIS_RTSP));
			redisReply* replyHmgetEasyDarwin = static_cast<redisReply*>(redisCommand(redisContext_, strTemp.c_str()));
			RedisReplyObjectDeleter replyHmgetEasyDarwinDeleter(replyHmgetEasyDarwin);
			if (!replyHmgetEasyDarwin)
			{
				theRet = QTSS_NotConnected;
				break;
			}

			if (replyHmgetEasyDarwin->type == REDIS_REPLY_NIL)
			{
				theRet = QTSS_RequestFailed;
				break;;
			}

			if (replyHmgetEasyDarwin->type == REDIS_REPLY_ARRAY && replyHmgetEasyDarwin->elements == 3)
			{
				bool ok = true;
				for (int i = 0; i < replyHmgetEasyDarwin->elements; ++i)
				{
					if (replyHmgetEasyDarwin->element[i]->type == REDIS_REPLY_NIL)
						ok = ok && false;
				}

				if (ok)
				{
					string ip(replyHmgetEasyDarwin->element[0]->str);
					string httpPort(replyHmgetEasyDarwin->element[1]->str);
					string rtspPort(replyHmgetEasyDarwin->element[2]->str);
					memcpy(inParams->outDssIP, ip.c_str(), ip.size());
					memcpy(inParams->outHTTPPort, httpPort.c_str(), httpPort.size());
					memcpy(inParams->outDssPort, rtspPort.c_str(), rtspPort.size());
					inParams->isOn = true;
				}
				else
				{
					theRet = QTSS_RequestFailed;
					break;
				}
			}
		}
		else
		{
			string keys = Format("keys %s:*", string(EASY_REDIS_EASYDARWIN));
			redisReply* replyKeys = static_cast<redisReply*>(redisCommand(redisContext_, keys.c_str()));
			RedisReplyObjectDeleter replyKeysDeleter(replyKeys);
			if (!replyKeys)
			{
				theRet = QTSS_NotConnected;
				break;
			}

			if (replyKeys->elements > 0)
			{
				int eleIndex = -1, eleLoad = 0;
				string eleIP, eleHTTP, eleRTSP;
				for (size_t i = 0; i < replyKeys->elements; ++i)
				{
					redisReply* replyTemp = replyKeys->element[i];
					if (replyTemp->type == REDIS_REPLY_NIL)
						continue;

					string strTemp = Format("hmget %s %s %s %s %s ", string(replyTemp->str), string(EASY_REDIS_LOAD), string(EASY_REDIS_IP),
						string(EASY_REDIS_HTTP), string(EASY_REDIS_RTSP));
					redisReply* replyHmget = static_cast<redisReply*>(redisCommand(redisContext_, strTemp.c_str()));
					RedisReplyObjectDeleter replyHmgetDeleter(replyHmget);

					if (!replyHmget)
					{
						theRet = QTSS_NotConnected;
						break;
					}

					if (replyHmget->type == REDIS_REPLY_NIL)
						continue;

					redisReply* loadReply = replyHmget->element[0];
					redisReply* ipReply = replyHmget->element[1];
					redisReply* httpReply = replyHmget->element[2];
					redisReply* rtspReply = replyHmget->element[3];

					int load = atoi(loadReply->str);
					string ip(ipReply->str);
					string http(httpReply->str);
					string rtsp(rtspReply->str);

					if (eleIndex == -1)
					{
						eleIndex = i;
						eleLoad = load;
						strncpy(inParams->outDssIP, ip.c_str(), ip.size());
						strncpy(inParams->outHTTPPort, http.c_str(), http.size());
						strncpy(inParams->outDssPort, rtsp.c_str(), rtsp.size());
					}
					else
					{
						if (load < eleLoad)//find better
						{
							eleIndex = i;
							eleLoad = load;
							strncpy(inParams->outDssIP, ip.c_str(), ip.size());
							strncpy(inParams->outHTTPPort, http.c_str(), http.size());
							strncpy(inParams->outDssPort, rtsp.c_str(), rtsp.size());
						}
					}
				}

				if (eleIndex == -1)//no one live
				{
					theRet = QTSS_Unimplemented;
					break;
				}

				inParams->isOn = false;
			}
			else
			{
				theRet = QTSS_Unimplemented;
				break;
			}
		}

	} while (false);

	if (theRet != QTSS_NoErr)
		RedisErrorHandler();

	return theRet;
}

QTSS_Error EasyRedisHandler::RedisLog(QTSS_Log_Params* inParams)
{
	OSMutexLocker mutexLock(&sMutex);

	if (!RedisConnect())
		return QTSS_NotConnected;

	if (!inParams->serial || string(inParams->serial).empty() || !inParams->msg || string(inParams->msg).empty())
		return QTSS_BadArgument;

	QTSS_Error theRet = QTSS_NoErr;
	do
	{
		string value = EasyUtil::Replace(string(inParams->msg), " ", "-");
		string set = Format("lpush Log:%s %s", string(inParams->serial), value);
		redisReply* reply = static_cast<redisReply*>(redisCommand(redisContext_, set.c_str()));
		RedisReplyObjectDeleter replyDeleter(reply);

		if (!reply)
		{
			theRet = QTSS_NotConnected;
			break;
		}

		if (reply->integer == 0)
			theRet = QTSS_RequestFailed;

	} while (false);

	if (theRet != QTSS_NoErr)
		RedisErrorHandler();

	return theRet;
}

void EasyRedisHandler::RedisErrorHandler()
{
	sIfConSucess = false;
	if (redisContext_)
	{
		printf("Connection error: %s\n", redisContext_->errstr);
		redisFree(redisContext_);
	}
	redisContext_ = NULL;
}
