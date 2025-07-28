#include "websessionauthhandler_serverimpl.h"
#include "config.h"
#include "defs.h"
#include "globals.h"
#include "websessionauthhandler_authmethods.h"

#include <Mantids30/Config_Builder/restful_engine.h>
#include <Mantids30/Server_RESTfulWebAPI/engine.h>

#include <boost/algorithm/string/predicate.hpp>
#include <memory>

// Imported namespaces are shortened and grouped for better readability
using namespace Mantids30;
using namespace Network;
using namespace Network::Sockets;
using namespace Network::Servers;
using namespace Program;

bool WebSessionAuthHandler_ServerImpl::createService()
{
    boost::property_tree::ptree *config = Globals::getConfig();

    try
    {
        config = &config->get_child("WebSessionAuthHandlerService");
    }
    catch (boost::property_tree::ptree_error &e)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Configuration error: WebSessionAuthHandlerService not found: %s", e.what());
        return false;
    }

    RESTful::Engine *webSessionAuthHandlerServer = Program::Config::RESTful_Engine::createRESTfulEngine(config, LOG_APP, LOG_RPC, "Web Session Auth Handler", AUTHSERVER_WEBDIR,
                                                                                                        Mantids30::Program::Config::REST_ENGINE_DISABLE_RESOURCES);

    if (!webSessionAuthHandlerServer)
        return false;

    // Set the software version:
    webSessionAuthHandlerServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

    // Setup the methods handler for version 1:
    webSessionAuthHandlerServer->methodsHandler[1] = std::make_shared<API::RESTful::MethodsHandler>();

    // This will validate the JWT, the app should match with this:
    webSessionAuthHandlerServer->config.appName = "IAM";

    // Add authentication methods
    WebSessionAuthHandler_AuthMethods::addMethods(webSessionAuthHandlerServer->methodsHandler[1]);

    webSessionAuthHandlerServer->startInBackground();

    LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Web Session Auth Handler Service Listening @%s", webSessionAuthHandlerServer->getListenerSocket()->getLastBindAddress().c_str());

    return true;
}
