#include "websessionauthhandler_authmethods.h"

#include <Mantids30/DataFormat_JWT/jwt.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Program_Logs/applog.h>
#include <Mantids30/Program_Logs/loglevels.h>
#include <Mantids30/Protocol_HTTP/hdr_cookie.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include <Mantids30/Protocol_HTTP/rsp_status.h>

#include <boost/algorithm/string.hpp>
#include <json/value.h>
#include <string>

#include "../globals.h"
#include "IdentityManager/ds_authentication.h"

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::DataFormat;

void WebSessionAuthHandler_AuthMethods::addMethods(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // AUTHENTICATION FUNCTIONS:

    // Web triggered events:
    methods->addResource(MethodsHandler::POST, "logout", &appLogout, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "refreshAccessToken", &refreshAccessToken, nullptr, SecurityOptions::NO_AUTH, {});
//    methods->addResource(MethodsHandler::POST, "refreshRefresherToken", &refreshRefresherToken, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "callback", &callback, nullptr, SecurityOptions::NO_AUTH, {});
}

bool WebSessionAuthHandler_AuthMethods::validateAPIKey(const std::string &app, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    // Check if the token generation is called within the app context:
    std::string apiKey = request.clientRequest->headers.getOptionValueStringByName("x-api-key");

    // Check if the token generation is called within the app context:
    std::string dbApiKey = identityManager->applications->getApplicationAPIKey(app);

    if (dbApiKey.empty())
    {
        LOG_APP->log2(__func__, request.jwtToken->getSubject(), authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Application '%s' does not exist. Pre-Auth JWT Token signature may be compromised!! Change immediately!", app.c_str());
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), getReasonText(REASON_BAD_PARAMETERS));
        return false;
    }

    if (dbApiKey != apiKey)
    {
        LOG_APP->log2(__func__, request.jwtToken->getSubject(), authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Application '%s' does not match the web application API Key. Attack or misconfiguration?", app.c_str());
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "Not Found.");
        return false;
    }

    return true;
}

json WebSessionAuthHandler_AuthMethods::getAccountDetails(IdentityManager *identityManager, const std::string &accountName)
{
    json accountInfo;

    accountInfo = identityManager->accounts->getAccountDetails(accountName).toJSON();

    return accountInfo;
}

std::string WebSessionAuthHandler_AuthMethods::signApplicationToken(JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties)
{
    std::string appName = JSON_ASSTRING_D(accessToken.getClaim("app"), "");
    auto signingJWT = Globals::getIdentityManager()->applications->getAppJWTSigner(appName);
    if (!signingJWT)
    {
        return std::string();
    }
    return signingJWT->signFromToken(accessToken, false);
}
