#include "webadmin_serverimpl.h"
#include "webadmin_methods.h"

#include "config.h"
#include "defs.h"
#include "globals.h"

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

bool WebAdmin_ServerImpl::createService()
{
    boost::property_tree::ptree *config = Globals::getConfig();
    try
    {
        config = &config->get_child("WebAdminService");
    }
    catch (boost::property_tree::ptree_error &e)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Configuration error: WebAdminService not found: %s", e.what());
        return false;
    }

    std::map<std::string, std::string> vars;
    vars["APIKEY"] = Globals::getIdentityManager()->applications->getApplicationAPIKey(DB_APPNAME);

    RESTful::Engine *adminWebServer = Program::Config::RESTful_Engine::createRESTfulEngine(config, LOG_APP, LOG_RPC, "Admin", ADMINSERVER_WEBDIR,
                                                                                           Program::Config::REST_ENGINE_NO_JWT | Program::Config::REST_ENGINE_MANDATORY_SSL, vars);

    if (!adminWebServer)
        return false;

    // JWT:
    adminWebServer->config.jwtValidator = Globals::getIdentityManager()->applications->getAppJWTValidator(DB_APPNAME);
    if (!adminWebServer->config.jwtValidator)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "We need a JWT Validator for the IAM Admin Service (2).");
        return false;
    }

    // This will validate the JWT, the app should match with this:
    adminWebServer->config.appName = "IAM";

    // Set the software version:
    adminWebServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

    // Setup the methods handler for version 1:
    adminWebServer->methodsHandler[1] = std::make_shared<API::RESTful::MethodsHandler>();

    // Add authentication methods
    WebAdmin_Methods::addMethods(adminWebServer->methodsHandler[1]);

    adminWebServer->startInBackground();

    LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Web Admin Service Listening @%s", adminWebServer->getListenerSocket()->getLastBindAddress().c_str());

    return true;
}
