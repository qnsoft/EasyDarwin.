/*
	Copyleft (c) 2012-2016 EasyDarwin.ORG.  All rights reserved.
	Github: https://github.com/EasyDarwin
	WEChat: EasyDarwin
	Website: http://www.EasyDarwin.org
*/
#include "EasyRedisModule.h"

#include "EasyRedisHandler.h"


// STATIC VARIABLES
static QTSS_ModulePrefsObject	modulePrefs = NULL;
static QTSS_PrefsObject			sServerPrefs = NULL;
static QTSS_ServerObject		sServer = NULL;
static OSMutex					sMutex;

// Redis IP
static char*            sRedis_IP = NULL;
static char*            sDefaultRedis_IP_Addr = "127.0.0.1";
// Redis Port
static UInt16			sRedisPort = 6379;
static UInt16			sDefaultRedisPort = 6379;
// Redis password
static char*            sRedisPassword = NULL;
static char*            sDefaultRedisPassword = "EasyDSSEasyDarwinEasyCMSEasyCamera";
// RedisClientPoolSize
static UInt16			sRedisClientPoolSize = 16;
static UInt16			sDefaultRedisClientPoolSize = 16;
// MaxRedisClientPoolSize
static UInt16			sMaxRedisClientPoolSize = 64;
static UInt16			sDefaultMaxRedisClientPoolSize = 64;

static OSQueue			sFreeHandlerQueue;


// FUNCTION PROTOTYPES
static QTSS_Error EasyRedisModuleDispatch(QTSS_Role inRole, QTSS_RoleParamPtr inParamBlock);
static QTSS_Error Register(QTSS_Register_Params* inParams);
static QTSS_Error Initialize(QTSS_Initialize_Params* inParams);
static QTSS_Error RereadPrefs();

static EasyRedisHandler* GetRedisHandler();
static void RedisHandlerReclaim(EasyRedisHandler* handler);

static QTSS_Error RedisTTL();
static QTSS_Error RedisSetDevice(Easy_DeviceInfo_Params* inParams);
static QTSS_Error RedisDelDevice(Easy_DeviceInfo_Params* inParams);
static QTSS_Error RedisGetAssociatedDarwin(QTSS_GetAssociatedDarwin_Params* inParams);
static QTSS_Error RedisLog(QTSS_Log_Params* inParams);

QTSS_Error EasyRedisModule_Main(void* inPrivateArgs)
{
	return _stublibrary_main(inPrivateArgs, EasyRedisModuleDispatch);
}

QTSS_Error EasyRedisModuleDispatch(QTSS_Role inRole, QTSS_RoleParamPtr inParamBlock)
{
	switch (inRole)
	{
	case QTSS_Register_Role:
		return Register(&inParamBlock->regParams);
	case QTSS_Initialize_Role:
		return Initialize(&inParamBlock->initParams);
	case QTSS_RereadPrefs_Role:
		return RereadPrefs();
	case Easy_RedisSetDevice_Role:
		return RedisSetDevice(&inParamBlock->DeviceInfoParams);
	case Easy_RedisDelDevice_Role:
		return RedisDelDevice(&inParamBlock->DeviceInfoParams);
	case Easy_RedisTTL_Role:
		return RedisTTL();
	case Easy_RedisGetEasyDarwin_Role:
		return RedisGetAssociatedDarwin(&inParamBlock->GetAssociatedDarwinParams);
	case Easy_RedisLog_Role:
		return RedisLog(&inParamBlock->logParams);
	default: break;
	}
	return QTSS_NoErr;
}

QTSS_Error Register(QTSS_Register_Params* inParams)
{
	// Do role setup
	(void)QTSS_AddRole(QTSS_Initialize_Role);
	(void)QTSS_AddRole(QTSS_RereadPrefs_Role);
	(void)QTSS_AddRole(Easy_RedisTTL_Role);
	(void)QTSS_AddRole(Easy_RedisSetDevice_Role);
	(void)QTSS_AddRole(Easy_RedisDelDevice_Role);
	(void)QTSS_AddRole(Easy_RedisGetEasyDarwin_Role);
	(void)QTSS_AddRole(Easy_RedisLog_Role);

	static char* sModuleName = "EasyRedisModule";
	::strcpy(inParams->outModuleName, sModuleName);

	return QTSS_NoErr;
}

QTSS_Error Initialize(QTSS_Initialize_Params* inParams)
{
	QTSSModuleUtils::Initialize(inParams->inMessages, inParams->inServer, inParams->inErrorLogStream);
	sServer = inParams->inServer;
	sServerPrefs = inParams->inPrefs;
	modulePrefs = QTSSModuleUtils::GetModulePrefsObject(inParams->inModule);

	RereadPrefs();

	for (UInt32 numPackets = 0; numPackets < 16; numPackets++)
	{
		EasyRedisHandler* handler = new EasyRedisHandler(sRedis_IP, sRedisPort, sRedisPassword);
		sFreeHandlerQueue.EnQueue(&handler->fQueueElem);//put this packet onto the free queue
	}

	//while (fFreeHandlerQueue.GetLength() > 0)
	//{
	//	EasyRedisHandler* handler = (EasyRedisHandler*)fFreeHandlerQueue.DeQueue()->GetEnclosingObject();
	//	delete handler;
	//}

	return QTSS_NoErr;
}

QTSS_Error RereadPrefs()
{
	delete[] sRedis_IP;
	sRedis_IP = QTSSModuleUtils::GetStringAttribute(modulePrefs, "redis_ip", sDefaultRedis_IP_Addr);

	QTSSModuleUtils::GetAttribute(modulePrefs, "redis_port", qtssAttrDataTypeUInt16, &sRedisPort, &sDefaultRedisPort, sizeof(sRedisPort));

	delete[] sRedisPassword;
	sRedisPassword = QTSSModuleUtils::GetStringAttribute(modulePrefs, "redis_password", sDefaultRedisPassword);

	QTSSModuleUtils::GetAttribute(modulePrefs, "redis_client_pool_size", qtssAttrDataTypeUInt16, &sRedisClientPoolSize, &sDefaultRedisClientPoolSize, sizeof(sDefaultRedisClientPoolSize));
	QTSSModuleUtils::GetAttribute(modulePrefs, "max_redis_client_pool_size", qtssAttrDataTypeUInt16, &sMaxRedisClientPoolSize, &sDefaultMaxRedisClientPoolSize, sizeof(sDefaultMaxRedisClientPoolSize));

	return QTSS_NoErr;
}

QTSS_Error RedisTTL()
{
	QTSS_Error theRet = QTSS_Unimplemented;

	EasyRedisHandler* handler = GetRedisHandler();
	if(handler)
	{
		theRet = handler->RedisTTL();
		RedisHandlerReclaim(handler);
	}
	return theRet;
}

QTSS_Error RedisSetDevice(Easy_DeviceInfo_Params* inParams)
{
	QTSS_Error theRet = QTSS_Unimplemented;

	EasyRedisHandler* handler = GetRedisHandler();
	if(handler)
	{
		theRet = handler->RedisSetDevice(inParams);
		RedisHandlerReclaim(handler);
	}
	return theRet;
}

QTSS_Error RedisDelDevice(Easy_DeviceInfo_Params* inParams)
{
	QTSS_Error theRet = QTSS_Unimplemented;

	EasyRedisHandler* handler = GetRedisHandler();
	if(handler)
	{
		theRet = handler->RedisDelDevice(inParams);
		RedisHandlerReclaim(handler);
	}
	return theRet;
}

QTSS_Error RedisGetAssociatedDarwin(QTSS_GetAssociatedDarwin_Params* inParams)
{
	QTSS_Error theRet = QTSS_Unimplemented;

	EasyRedisHandler* handler = GetRedisHandler();
	if(handler)
	{
		theRet = handler->RedisGetAssociatedDarwin(inParams);
		RedisHandlerReclaim(handler);
	}
	return theRet;
}

EasyRedisHandler* GetRedisHandler()
{
	OSMutexLocker locker(&sMutex);
	if (sFreeHandlerQueue.GetLength() == 0)
		//if the port number of this socket is odd, this packet is an RTCP packet.
		return new EasyRedisHandler(sRedis_IP, sRedisPort, sRedisPassword);
	else
		return (EasyRedisHandler*)sFreeHandlerQueue.DeQueue()->GetEnclosingObject();
}

void RedisHandlerReclaim(EasyRedisHandler* handler)
{
	if(handler)
	{
		//printf("RedisHandlerReclaim ID:%d \n", handler->fID);
		if(sFreeHandlerQueue.GetLength() > sMaxRedisClientPoolSize)
			handler->Signal(Task::kKillEvent);
		else
			sFreeHandlerQueue.EnQueue(&handler->fQueueElem);
	}
}

QTSS_Error RedisLog(QTSS_Log_Params* inParams)
{
	QTSS_Error theRet = QTSS_Unimplemented;

	EasyRedisHandler* handler = GetRedisHandler();
	if (handler)
	{
		theRet = handler->RedisLog(inParams);
		RedisHandlerReclaim(handler);
	}

	return theRet;
}