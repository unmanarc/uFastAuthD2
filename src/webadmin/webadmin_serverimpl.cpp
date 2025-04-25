#include "webadmin_serverimpl.h"
#include "../config.h"
#include "../defs.h"
#include "../globals.h"
#include "webadmin/webadmin_methods.h"
#include <Mantids30/DataFormat_JWT/jwt.h>
#include <Mantids30/Program_Config/jwt.h>

#include <Mantids30/Net_Sockets/socket_tls.h>
#include <Mantids30/Server_RESTfulWebAPI/engine.h>
#include <boost/algorithm/string/predicate.hpp>

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

bool WebAdmin_ServerImpl::createService()
{
    auto config = Globals::getConfig();

    // Use a shared pointer for better memory management
    auto sockWebListen = std::make_shared<Socket_TLS>();

    // Set the default security level for the socket
    sockWebListen->tlsKeys.setSecurityLevel(-1);

    // Retrieve listen port and address from configuration
    uint16_t listenPort = config->get<uint16_t>("WebAdminService.ListenPort", 9443);
    std::string listenAddr = config->get<std::string>("WebAdminService.ListenAddr", "0.0.0.0");

    // Load public key from PEM file for TLS
    if (!sockWebListen->tlsKeys.loadPublicKeyFromPEMFile(config->get<std::string>("WebAdminService.CertFile", "snakeoil.crt").c_str()))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Web Admin Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS Web Admin Service Public Key");
        return false;
    }

    // Load private key from PEM file for TLS
    if (!sockWebListen->tlsKeys.loadPrivateKeyFromPEMFile(config->get<std::string>("WebAdminService.KeyFile", "snakeoil.key").c_str()))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Web Admin Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS Web Admin Service Private Key");
        return false;
    }

    // Start listening on the specified address and port
    if (sockWebListen->listenOn(listenPort, listenAddr.c_str(), !config->get<bool>("WebAdminService.IPv6", false)))
    {
        // Create and configure the web server instance
        RESTful::Engine *adminWebServer = new RESTful::Engine();
        // Setup the RPC Log:
        adminWebServer->config.rpcLog = LOG_RPC;

        std::string resourcesPath = config->get<std::string>("WebAdminService.ResourcesPath", AUTHSERVER_WEBDIR);
        if (!adminWebServer->config.setDocumentRootPath(resourcesPath))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error locating web server resources at %s", resourcesPath.c_str());
            return false;
        }

      //  adminWebServer->config.dynamicRequestHandlersByRoute["/login"] = &WebAdmin_AuthMethods::handleDynamicRequest;
        // JWT:
        adminWebServer->config.jwtValidator = Mantids30::ConfigBuilder::JWT::createJWTValidator(LOG_APP, config, "JWT");

        if (!adminWebServer->config.jwtValidator)
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "We need a JWT Validator (2).");
            return false;
        }

        // Setup the callbacks:
        adminWebServer->callbacks.onProtocolInitializationFailure = WebAdmin_ServerImpl::handleProtocolInitializationFailure;
        adminWebServer->callbacks.onClientAcceptTimeoutOccurred = WebAdmin_ServerImpl::handleClientAcceptTimeoutOccurred;
        // Setup the methods handler for version 1:
        adminWebServer->methodsHandler[1] = std::make_shared<API::RESTful::MethodsHandler>();
        // Set the software version:
        adminWebServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

        // Add authentication methods
        WebAdmin_Methods::addMethods(adminWebServer->methodsHandler[1]);

        // Use a thread pool or multi-threading based on configuration
        if (config->get<bool>("WebAdminService.ThreadPool", false))
            adminWebServer->acceptPoolThreaded(sockWebListen, config->get<uint32_t>("WebAdminService.PoolSize", 10));
        else
            adminWebServer->acceptMultiThreaded(sockWebListen, config->get<uint32_t>("WebAdminService.MaxThreads", 10000));

        // Log successful web service start
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Web Admin Service Listening @%s:%" PRIu16, listenAddr.c_str(), listenPort);
        return true;
    }
    else
    {
        // Log the error if the web service fails to start
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Web Admin Service @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockWebListen->getLastError().c_str());
        return false;
    }
}

bool WebAdmin_ServerImpl::handleProtocolInitializationFailure(
    void *, std::shared_ptr<Sockets::Socket_Stream_Base> sock)
{
    std::shared_ptr<Socket_TLS> secSocket = std::dynamic_pointer_cast<Socket_TLS>(sock);

    for (const auto &i : secSocket->getTLSErrorsAndClear())
    {
        if (!strstr(i.c_str(), "certificate unknown"))
            LOG_APP->log1(__func__, sock->getRemotePairStr(), Logs::LEVEL_ERR, "TLS: %s", i.c_str());
    }
    return true;
}

bool WebAdmin_ServerImpl::handleClientAcceptTimeoutOccurred(
    void *webServer, std::shared_ptr<Sockets::Socket_Stream_Base> sock)
{
    LOG_APP->log1(__func__, sock->getRemotePairStr(), Logs::LEVEL_ERR, "Web Admin Service Timed Out.");
    return true;
}
