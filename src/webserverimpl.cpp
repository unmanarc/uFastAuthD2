#include "webserverimpl.h"
#include "globals.h"
#include "defs.h"
#include "config.h"

#include <Mantids29/Net_Sockets/socket_tls.h>
#include <Mantids29/Server_MonolithWebAPI/engine.h>
#include <Mantids29/API_Templates/fullauth.h>

#include  <boost/algorithm/string/predicate.hpp>

#include <memory>
#include <sstream>
#include <ostream>
#include <inttypes.h>



// Imported namespaces are shortened and grouped for better readability
using namespace Mantids29;
using namespace Network;
using namespace Network::Sockets;
using namespace Network::Servers;
using namespace Program;
using namespace AUTHSERVER::WEB;

bool WebServerImpl::createWebService()
{
    // Use a shared pointer for better memory management
    auto sockWebListen = std::make_shared<Socket_TLS>();

    // Set the default security level for the socket
    sockWebListen->keys.setSecurityLevel(-1);

    // Retrieve listen port and address from configuration
    uint16_t listenPort = Globals::getConfig_main()->get<uint16_t>("WebService.ListenPort", 40401);
    std::string listenAddr = Globals::getConfig_main()->get<std::string>("WebService.ListenAddr", "0.0.0.0");

    // Load public key from PEM file for TLS
    if (!sockWebListen->keys.loadPublicKeyFromPEMFile(Globals::getConfig_main()->get<std::string>("WebService.CertFile", "snakeoil.crt").c_str()))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Web Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS Web Service Public Key");
        return false;
    }

    // Load private key from PEM file for TLS
    if (!sockWebListen->keys.loadPrivateKeyFromPEMFile(Globals::getConfig_main()->get<std::string>("WebService.KeyFile", "snakeoil.key").c_str()))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Web Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS Web Service Private Key");
        return false;
    }

    // Start listening on the specified address and port
    if (sockWebListen->listenOn(listenPort, listenAddr.c_str(), !Globals::getConfig_main()->get<bool>("WebService.ipv6", false)))
    {
        // Initialize the authentication domains and method handlers
        Authentication::Domains *authDomains = new Authentication::Domains;
        API::MethodsHandler *methodsHandler = new API::MethodsHandler(DB_APPNAME);

        // Add authentication methods
        API::Templates::FullAuth::AddFullAuthMethods(methodsHandler, DB_APPNAME);

        // Add the default domain / auth
        authDomains->addDomain("", Globals::getAuthManager());

        // Create and configure the web server instance
        WebMonolith::Engine *webServer = new WebMonolith::Engine();
        webServer->m_useCSRFToken = false; // No need for CSRF token in a web API
        webServer->m_rpcLog = LOG_RPC;
        webServer->m_authenticator = authDomains;
        webServer->m_callbacks.m_onInitFailed = WebServerImpl::protoInitFail;
        webServer->m_methodsHandler = methodsHandler;
        webServer->setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

        // Use a thread pool or multi-threading based on configuration
        if (Globals::getConfig_main()->get<bool>("WebService.ThreadPool", false))
            webServer->acceptPoolThreaded(sockWebListen, Globals::getConfig_main()->get<uint32_t>("WebService.PoolSize", 10));
        else
            webServer->acceptMultiThreaded(sockWebListen, Globals::getConfig_main()->get<uint32_t>("WebService.MaxThreads", 10000));

        // Log successful web service start
         LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Web Service Listening @%s:%" PRIu16, listenAddr.c_str(), listenPort);
         return true;
     }
     else
     {
         // Log the error if the web service fails to start
         LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Web Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockWebListen->getLastError().c_str());
         return false;
     }
}



/*


using namespace Mantids29::Network::Sockets;
using namespace Mantids29::Program;
using namespace Mantids29::Network::Servers;
using namespace Mantids29::Network;
using namespace Mantids29;
using namespace AUTHSERVER::WEB;

bool WebServerImpl::createWebService()
{
    auto sockWebListen = std::make_shared<Socket_TLS>();

    // Set the SO default security level:
    sockWebListen->keys.setSecurityLevel(-1);

    uint16_t listenPort = Globals::getConfig_main()->get<uint16_t>("WebService.ListenPort",40401);
    std::string listenAddr = Globals::getConfig_main()->get<std::string>("WebService.ListenAddr","0.0.0.0");

    if (!sockWebListen->keys.loadPublicKeyFromPEMFile(  Globals::getConfig_main()->get<std::string>("WebService.CertFile","snakeoil.crt").c_str()  ))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Web Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS Web Service Public Key");
        return false;
    }
    if (!sockWebListen->keys.loadPrivateKeyFromPEMFile( Globals::getConfig_main()->get<std::string>("WebService.KeyFile","snakeoil.key").c_str()  ))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Web Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS Web Service Private Key");
        return false;
    }

    if (sockWebListen->listenOn(listenPort ,listenAddr.c_str(), !Globals::getConfig_main()->get<bool>("WebService.ipv6",false) ))
    {
        Authentication::Domains * authDomains = new Authentication::Domains;
        API::MethodsHandler *methodsHandler = new API::MethodsHandler(DB_APPNAME);

        // Add authentication methods:
        API::Templates::FullAuth::AddFullAuthMethods(methodsHandler,DB_APPNAME);

        // Add the default domain / auth:
        authDomains->addDomain("",Globals::getAuthManager());

        WebMonolith::Engine * webServer = new WebMonolith::Engine();
        // because is a web api, No need to use CSRF token here:
        webServer->m_useCSRFToken = false;
        webServer->m_rpcLog = LOG_RPC;
        webServer->m_authenticator = authDomains;
        webServer->m_callbacks.m_onInitFailed = WebServerImpl::protoInitFail;
        webServer->m_methodsHandler = methodsHandler;
        webServer->setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH),  "a");

        if (Globals::getConfig_main()->get<bool>("WebService.ThreadPool", false))
            webServer->acceptPoolThreaded(sockWebListen, Globals::getConfig_main()->get<uint32_t>("WebService.PoolSize", 10) );
        else
            webServer->acceptMultiThreaded(sockWebListen, Globals::getConfig_main()->get<uint32_t>("WebService.MaxThreads", 10000));

        LOG_APP->log0(__func__,Logs::LEVEL_INFO,  "Web Service Listening @%s:%" PRIu16, listenAddr.c_str(), listenPort);
        return true;
    }
    else
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Web Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockWebListen->getLastError().c_str());
        return false;
    }
}*/

bool WebServerImpl::protoInitFail(void * , Network::Sockets::Socket_Stream_Base * sock, const char * remoteIP, bool )
{
    Socket_TLS * secSocket = (Socket_TLS *)sock;

    for (const auto & i :secSocket->getTLSErrorsAndClear())
    {
        if (!strstr(i.c_str(),"certificate unknown"))
            LOG_APP->log1(__func__, remoteIP,Logs::LEVEL_ERR, "TLS: %s", i.c_str());
    }
    return true;
}


WebServerImpl::WebServerImpl()
{
}


/*
bool WebServerImpl::createWebServer()
{
    auto sockWebListen = std::make_shared<Socket_TLS>();

    // Set the SO default security level:
    sockWebListen->keys.setSecurityLevel(-1);

    uint16_t listenPort = Globals::getConfig_main()->get<uint16_t>("WebServer.ListenPort",40443);
    std::string listenAddr = Globals::getConfig_main()->get<std::string>("WebServer.ListenAddr","0.0.0.0");

    if (!sockWebListen->keys.loadPublicKeyFromPEMFile(  Globals::getConfig_main()->get<std::string>("WebServer.CertFile","snakeoil.crt").c_str()  ))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Web Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS WEB Server Public Key");
        return false;
    }
    if (!sockWebListen->keys.loadPrivateKeyFromPEMFile( Globals::getConfig_main()->get<std::string>("WebServer.KeyFile","snakeoil.key").c_str()  ))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Web Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS WEB Server Private Key");
        return false;
    }

    if (sockWebListen->listenOn(listenPort ,listenAddr.c_str(), !Globals::getConfig_main()->get<bool>("WebServer.ipv6",false) ))
    {
        Authentication::Domains * authDomains = new Authentication::Domains;
        MethodsManager *methodsHandler = new MethodsManager(DB_APPNAME);

        // Add authentication methods for the session:
        RPC::Templates::FullAuth::AddFullAuthMethods(methodsHandler,DB_APPNAME);

        // Add the default domain / auth:
        authDomains->addDomain("",Globals::getAuthManager());

        WebServer * webServer = new WebServer();
        webServer->setRPCLog(LOG_RPC);
        std::string resourcesPath = Globals::getConfig_main()->get<std::string>("WebServer.ResourcesPath",AUTHSERVER_WEBDIR);
        if (!webServer->setDocumentRootPath( resourcesPath ))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error locating web server resources at %s",resourcesPath.c_str() );
            return false;
        }
        webServer->setAuthenticator(authDomains);
        webServer->setMethodManagers(methodsHandler);
        webServer->setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH),  "a");
        webServer->setExtCallBackOnInitFailed(WebServerImpl::protoInitFail);

        if (Globals::getConfig_main()->get<bool>("WebServer.ThreadPool", false))
            webServer->acceptPoolThreaded(sockWebListen, Globals::getConfig_main()->get<uint32_t>("WebServer.PoolSize", 10) );
        else
            webServer->acceptMultiThreaded(sockWebListen, Globals::getConfig_main()->get<uint32_t>("WebServer.MaxThreads", 10000));

        LOG_APP->log0(__func__,Logs::LEVEL_INFO,  "Web Server Listening @%s:%" PRIu16, listenAddr.c_str(), listenPort);
        return true;
    }
    else
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Web Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockWebListen->getLastError().c_str());
        return false;
    }
}*/
