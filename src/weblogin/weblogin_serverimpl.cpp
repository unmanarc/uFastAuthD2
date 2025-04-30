#include "weblogin_serverimpl.h"
#include <Mantids30/DataFormat_JWT/jwt.h>
#include <Mantids30/Program_Config/jwt.h>
#include "weblogin_authmethods.h"
#include "../globals.h"
#include "../defs.h"
#include "../config.h"

#include <Mantids30/Net_Sockets/socket_tls.h>
#include <Mantids30/Server_RESTfulWebAPI/engine.h>
#include  <boost/algorithm/string/predicate.hpp>

#include <memory>
// #include <sstream>
// #include <ostream>
#include <inttypes.h>

// Imported namespaces are shortened and grouped for better readability
using namespace Mantids30;
using namespace Network;
using namespace Network::Sockets;
using namespace Network::Servers;
using namespace Program;

std::set<std::string> parseCommaSeparatedOrigins(const std::string &input)
{
    std::set<std::string> result;
    std::stringstream ss(input);
    std::string item;
    while (std::getline(ss, item, ','))
    {
        if (!item.empty())
        {
            result.insert(item);
        }
    }
    return result;
}

bool WebLogin_ServerImpl::createService()
{
    // TODO: pasar a mantids config...
    auto config = Globals::getConfig();

    // Use a shared pointer for better memory management
    auto sockWebListen = std::make_shared<Socket_TLS>();

    // Set the default security level for the socket
    sockWebListen->tlsKeys.setSecurityLevel(-1);

    // Retrieve listen port and address from configuration
    uint16_t listenPort = config->get<uint16_t>("WebLoginService.ListenPort", 8443);
    std::string listenAddr = config->get<std::string>("WebLoginService.ListenAddr", "0.0.0.0");

    // Load public key from PEM file for TLS
    if (!sockWebListen->tlsKeys.loadPublicKeyFromPEMFile(config->get<std::string>("WebLoginService.CertFile", "snakeoil.crt").c_str()))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Web Login Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS Web Login Service Public Key");
        return false;
    }

    // Load private key from PEM file for TLS
    if (!sockWebListen->tlsKeys.loadPrivateKeyFromPEMFile(config->get<std::string>("WebLoginService.KeyFile", "snakeoil.key").c_str()))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Web Login Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS Web Login Service Private Key");
        return false;
    }

    // Start listening on the specified address and port
    if (sockWebListen->listenOn(listenPort, listenAddr.c_str(), !config->get<bool>("WebLoginService.IPv6", false)))
    {
        // Create and configure the web server instance
        RESTful::Engine *loginWebServer = new RESTful::Engine();
        // Setup the RPC Log:
        loginWebServer->config.rpcLog = LOG_RPC;

        std::string resourcesPath = config->get<std::string>("WebLoginService.ResourcesPath",AUTHSERVER_WEBDIR);
        if (!loginWebServer->config.setDocumentRootPath( resourcesPath ))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error locating web server resources at %s",resourcesPath.c_str() );
            return false;
        }

        std::string rawOrigins = config->get<std::string>("WebLoginService.IAMOriginDomains", "");
        loginWebServer->config.permittedAPIOrigins = parseCommaSeparatedOrigins(rawOrigins);
        loginWebServer->config.dynamicRequestHandlersByRoute["/login"] = &WebLogin_AuthMethods::handleDynamicRequest;

        // TODO: el JWT va a tener una firma distinta por aplicacion, ya que la app necesita validar esto y no puedes compartir la misma clave con todos (en caso de HS).
        // JWT:
        loginWebServer->config.jwtSigner = Mantids30::ConfigBuilder::JWT::createJWTSigner(LOG_APP, config, "JWT" );
        loginWebServer->config.jwtValidator = Mantids30::ConfigBuilder::JWT::createJWTValidator(LOG_APP, config, "JWT" );

        if (!loginWebServer->config.jwtValidator)
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "We need at least a JWT Validator.");
            return false;
        }

        // Setup the callbacks:
        loginWebServer->callbacks.onProtocolInitializationFailure = WebLogin_ServerImpl::handleProtocolInitializationFailure;
        loginWebServer->callbacks.onClientAcceptTimeoutOccurred = WebLogin_ServerImpl::handleClientAcceptTimeoutOccurred;
        // Setup the methods handler for version 1:
        loginWebServer->methodsHandler[1] = std::make_shared<API::RESTful::MethodsHandler>();
        // Set the software version:
        loginWebServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

        // Add authentication methods
        WebLogin_AuthMethods::addMethods(loginWebServer->methodsHandler[1]);

        // Use a thread pool or multi-threading based on configuration
        if (config->get<bool>("WebLoginService.ThreadPool", false))
            loginWebServer->acceptPoolThreaded(sockWebListen, config->get<uint32_t>("WebLoginService.PoolSize", 10));
        else
            loginWebServer->acceptMultiThreaded(sockWebListen, config->get<uint32_t>("WebLoginService.MaxThreads", 10000));

        // Log successful web service start
         LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Web Login Service Listening @%s:%" PRIu16, listenAddr.c_str(), listenPort);
         return true;
    }
    else
    {
        // Log the error if the web service fails to start
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Web Login Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockWebListen->getLastError().c_str());
        return false;
    }
}

bool WebLogin_ServerImpl::handleProtocolInitializationFailure(void * , std::shared_ptr<Sockets::Socket_Stream_Base> sock )
{
    std::shared_ptr<Socket_TLS> secSocket = std::dynamic_pointer_cast<Socket_TLS>(sock);

    for (const auto & i :secSocket->getTLSErrorsAndClear())
    {
        if (!strstr(i.c_str(),"certificate unknown"))
            LOG_APP->log1(__func__, sock->getRemotePairStr(),Logs::LEVEL_ERR, "TLS: %s", i.c_str());
    }
    return true;
}

bool WebLogin_ServerImpl::handleClientAcceptTimeoutOccurred(void *webServer, std::shared_ptr<Sockets::Socket_Stream_Base> sock)
{
    LOG_APP->log1(__func__, sock->getRemotePairStr(),Logs::LEVEL_ERR, "Web Login Service Timed Out.");
    return true;
}

