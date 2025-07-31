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

bool JWTDynamicTokenValidatorFunction(const std::string& accessTokenStr, const std::string& xAPIKeyStr, Mantids30::DataFormat::JWT::Token * accessToken)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string appNameStr = identityManager->applications->getApplicationNameByAPIKey(xAPIKeyStr);
    // Now, search the application by the x-api-key:
    if (appNameStr.empty())
    {
        // app key not found...
        LOG_APP->log1(__func__, "", Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided to the dynamic validator. Application not found.");
        return false;
    }

    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(appNameStr);
    std::shared_ptr<Mantids30::DataFormat::JWT> validator = identityManager->applications->getAppJWTValidator(appNameStr);

    return validator->verify(accessTokenStr,accessToken);
}

bool myDynamicOriginValidatorFunction(const std::string& origin, const std::string& xAPIKeyStr)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string appNameStr = identityManager->applications->getApplicationNameByAPIKey(xAPIKeyStr);

    std::list<std::string> origins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appNameStr);

    return std::find(origins.begin(), origins.end(), origin) != origins.end();
}

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

    RESTful::Engine *webSessionAuthHandlerServer = Program::Config::RESTful_Engine::createRESTfulEngine(config, LOG_APP, LOG_RPC, "Web Session Auth Handler", AUTHSERVER_WEBDIR);

    if (!webSessionAuthHandlerServer)
        return false;

    // Set the software version:
    webSessionAuthHandlerServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");


    // Specific JWT Token Validator given an API Key specifying the APP
    webSessionAuthHandlerServer->config.dynamicTokenValidator = JWTDynamicTokenValidatorFunction;

    // Specific origin validator given the Origin: and an API Key specifying the APP
    webSessionAuthHandlerServer->config.dynamicOriginValidator = myDynamicOriginValidatorFunction;

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
