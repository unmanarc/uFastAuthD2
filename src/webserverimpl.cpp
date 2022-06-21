#include "webserverimpl.h"
#include "globals.h"
#include "defs.h"
#include "config.h"

#include <mdz_xrpc_webserver/webserver.h>
#include <mdz_net_sockets/socket_tls.h>
#include <mdz_xrpc_templates/fullauth.h>

#include  <boost/algorithm/string/predicate.hpp>

#include <sstream>
#include <ostream>
#include <inttypes.h>

using namespace Mantids::Application;
using namespace Mantids::RPC::Web;
using namespace Mantids::RPC;
using namespace Mantids;
using namespace AUTHSERVER::WEB;

WebServerImpl::WebServerImpl()
{
}

bool WebServerImpl::createWebServer()
{
    Mantids::Network::TLS::Socket_TLS * sockWebListen = new Mantids::Network::TLS::Socket_TLS;

    uint16_t listenPort = Globals::getConfig_main()->get<uint16_t>("WebServer.ListenPort",40443);
    std::string listenAddr = Globals::getConfig_main()->get<std::string>("WebServer.ListenAddr","0.0.0.0");

    if (!sockWebListen->setTLSPublicKeyPath(  Globals::getConfig_main()->get<std::string>("WebServer.CertFile","snakeoil.crt").c_str()  ))
    {
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Web Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS WEB Server Public Key");
        return false;
    }
    if (!sockWebListen->setTLSPrivateKeyPath( Globals::getConfig_main()->get<std::string>("WebServer.KeyFile","snakeoil.key").c_str()  ))
    {
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Web Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS WEB Server Private Key");
        return false;
    }

    if (sockWebListen->listenOn(listenPort ,listenAddr.c_str(), !Globals::getConfig_main()->get<bool>("WebServer.ipv6",false) ))
    {
        Authentication::Domains * authDomains = new Authentication::Domains;
        MethodsManager *methodsManagers = new MethodsManager(DB_APPNAME);

        // Add methods:
        Mantids::RPC::Templates::FullAuth::AddFullAuthMethods(methodsManagers,DB_APPNAME);

        // Add the default domain / auth:
        authDomains->addDomain("",Globals::getAuthManager());

        WebServer * webServer = new WebServer();
        webServer->setRPCLog(Globals::getRPCLog());
        std::string resourcesPath = Globals::getConfig_main()->get<std::string>("WebServer.ResourcesPath",AUTHSERVER_WEBDIR);
        if (!webServer->setDocumentRootPath( resourcesPath ))
        {
            Globals::getAppLog()->log0(__func__,Logs::LEVEL_CRITICAL, "Error locating web server resources at %s",resourcesPath.c_str() );
            return false;
        }
        webServer->setAuthenticator(authDomains);
        webServer->setMethodManagers(methodsManagers);
        webServer->setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH),  "a");
        webServer->setExtCallBackOnInitFailed(WebServerImpl::protoInitFail);

        if (Globals::getConfig_main()->get<bool>("WebServer.ThreadPool", false))
            webServer->acceptPoolThreaded(sockWebListen, Globals::getConfig_main()->get<uint32_t>("WebServer.PoolSize", 10) );
        else
            webServer->acceptMultiThreaded(sockWebListen, Globals::getConfig_main()->get<uint32_t>("WebServer.MaxThreads", 10000));

        Globals::getAppLog()->log0(__func__,Logs::LEVEL_INFO,  "Web Server Listening @%s:%" PRIu16, listenAddr.c_str(), listenPort);
        return true;
    }
    else
    {
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Web Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockWebListen->getLastError().c_str());
        return false;
    }
}

bool WebServerImpl::protoInitFail(void * , Network::Streams::StreamSocket * sock, const char * remoteIP, bool )
{
    Mantids::Network::TLS::Socket_TLS * secSocket = (Mantids::Network::TLS::Socket_TLS *)sock;

    for (const auto & i :secSocket->getTLSErrorsAndClear())
    {
        if (!strstr(i.c_str(),"certificate unknown"))
            Globals::getAppLog()->log1(__func__, remoteIP,Logs::LEVEL_ERR, "TLS: %s", i.c_str());
    }
    return true;
}
