#include "weblogin_serverimpl.h"
#include "config.h"
#include "defs.h"
#include "globals.h"
#include "weblogin_authmethods.h"

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

bool WebLogin_ServerImpl::createService()
{
    boost::property_tree::ptree *config = Globals::getConfig();

    try
    {
        config = &config->get_child("WebLoginService");
    }
    catch (boost::property_tree::ptree_error &e)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Configuration error: WebLoginService not found: %s", e.what());
        return false;
    }

    RESTful::Engine *loginWebServer = Program::Config::RESTful_Engine::createRESTfulEngine(config, LOG_APP, LOG_RPC, "Web Login", AUTHSERVER_WEBDIR, Program::Config::REST_ENGINE_MANDATORY_SSL);

    if (!loginWebServer)
        return false;

    // Handle the login function for APP personalized site:
    loginWebServer->config.dynamicRequestHandlersByRoute["/login"] = {&WebLogin_AuthMethods::handleLoginDynamicRequest, nullptr};

    // Set the software version:
    loginWebServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

    // This will validate the JWT, the app should match with this:
    loginWebServer->config.appName = "IAM";

    // Setup the methods handler for version 1:
    loginWebServer->methodsHandler[1] = std::make_shared<API::RESTful::MethodsHandler>();

    // Add authentication methods
    WebLogin_AuthMethods::addMethods(loginWebServer->methodsHandler[1]);

    loginWebServer->startInBackground();

    LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Web Login Service Listening @%s", loginWebServer->getListenerSocket()->getLastBindAddress().c_str());

    return true;
}
