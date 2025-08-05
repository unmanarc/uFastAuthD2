#include "Mantids30/Program_Logs/loglevels.h"
#include "weblogin_authmethods.h"
#include "json/value.h"
#include <Mantids30/Helpers/json.h>

#include <algorithm> // std::find
#include <boost/algorithm/string/join.hpp>
#include <json/config.h>

#include "../globals.h"

#include "Tokens/tokensmanager.h"

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;


bool WebLogin_AuthMethods::token_validateRedirectUri(IdentityManager* identityManager, const std::string& app,
    const std::string& redirectURI, const std::string& user, const std::string& ipAddress)
{
    std::list<std::string> redirectURIs = identityManager->applications->listWebLoginRedirectURIsFromApplication(app);
    std::string callbackURI = identityManager->applications->getApplicationCallbackURI(app);

    // Validate if the redirect URI is acceptable by the application.
    if (!redirectURI.empty() && std::find(redirectURIs.begin(), redirectURIs.end(), redirectURI) == redirectURIs.end())
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Invalid return URL '%s': The provided URI does not match any recognized redirect URIs for application '%s'.", redirectURI.c_str(), app.c_str());
        return false;
    }

    if (callbackURI.empty())
    {
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' has not configured a callback URI yet.", app.c_str());
        return false;
    }

    return true;
}

std::string WebLogin_AuthMethods::token_signApplicationJWT(JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties)
{
    std::string appName = JSON_ASSTRING_D(accessToken.getClaim("app"), "");
    std::shared_ptr<JWT> signingJWT = Globals::getIdentityManager()->applications->getAppJWTSigner(appName);
    if (!signingJWT)
    {
        return std::string();
    }
    return signingJWT->signFromToken(accessToken, false);
}

bool WebLogin_AuthMethods::token_createAndSignJWTs(IdentityManager* identityManager, const JWT::Token* jwtToken,
    const std::string& app, const std::string& user, const std::string& redirectURI,
    APIReturn& response)
{
    ApplicationTokenProperties tokenProperties = identityManager->applications->getWebLoginJWTConfigFromApplication(app);

    if (tokenProperties.appName != app)
    {
        LOG_APP->log1(__func__, user, Logs::LEVEL_CRITICAL,
                      "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.", app.c_str());
        return false;
    }

    std::set<uint32_t> authenticatedSlotIdsSet = Mantids30::Helpers::jsonToUInt32Set(jwtToken->getClaim("slotIds"));
    std::string refreshTokenId = Mantids30::Helpers::Random::createRandomString(16);

    JWT::Token accessToken, refreshToken;
    TokensManager::configureRefreshToken(refreshToken, refreshTokenId, user, app, tokenProperties, authenticatedSlotIdsSet);
    TokensManager::configureAccessToken(accessToken, refreshTokenId, user, app, tokenProperties, authenticatedSlotIdsSet);

    (*response.responseJSON())["accessToken"] = token_signApplicationJWT(accessToken, tokenProperties);
    (*response.responseJSON())["refreshToken"] = token_signApplicationJWT(refreshToken, tokenProperties);
    (*response.responseJSON())["redirectURI"] = redirectURI;
    (*response.responseJSON())["callbackURI"] = identityManager->applications->getApplicationCallbackURI(app);

    return true;
}

bool WebLogin_AuthMethods::token_validateJwtClaims(const JWT::Token *jwtToken, const std::string &user, const std::string &ipAddress)
{
    if (jwtToken->getClaim("app") != "IAM" || jwtToken->getClaim("type") != "IAM")
    {
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Token request denied: Invalid or unauthorized token.");
        return false;
    }
    return true;
}

bool WebLogin_AuthMethods::token_validateAuthenticationScheme(IdentityManager *identityManager, const JWT::Token *jwtToken, const std::string &app, const std::string &activity, uint32_t schemeId, const std::string &user, const std::string &ipAddress)
{
    std::set<uint32_t> authenticatedSlotIdsSet = Mantids30::Helpers::jsonToUInt32Set(jwtToken->getClaim("slotIds"));
    std::set<std::string> authenticatedAppsSet = Mantids30::Helpers::jsonToStringSet(jwtToken->getClaim("apps"));

    std::set<uint32_t> schemesInActivity = identityManager->authController->listAuthenticationSchemesForApplicationActivity(app, activity);
    if (schemesInActivity.find(schemeId) == schemesInActivity.end())
    {
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Token request denied: Scheme ID does not match any required schemes for this app/activity.");
        return false;
    }

    std::vector<AuthenticationSchemeUsedSlot> slotsUsedByScheme = identityManager->authController->listAuthenticationSlotsUsedByScheme(schemeId);
    for (const auto &slot : slotsUsedByScheme)
    {
        if (authenticatedSlotIdsSet.find(slot.slotId) == authenticatedSlotIdsSet.end())
        {
            LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_SECURITY_ALERT,
                          "Token request denied: Missing required credential slot id='%d'.", slot.slotId);
            return false;
        }
    }

    return true;
}
bool WebLogin_AuthMethods::token_validateAppAuthorization(IdentityManager* identityManager, const JWT::Token* jwtToken,
    const std::string& app, const std::string& user, const std::string& ipAddress)
{
    std::set<std::string> authenticatedAppsSet = Mantids30::Helpers::jsonToStringSet(jwtToken->getClaim("apps"));
    if (authenticatedAppsSet.find(app) == authenticatedAppsSet.end())
    {
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Token request denied: Unauthorized application '%s' access.", app.c_str());
        return false;
    }
    return true;
}


/*
    This will tranform the current authentication into an APP access...
*/
void WebLogin_AuthMethods::token(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string authenticatedUser = request.jwtToken->getSubject();
    std::string app = JSON_ASSTRING(*request.inputJSON, "app", "");                 // APPNAME
    std::string activity = JSON_ASSTRING(*request.inputJSON, "activity", "");       // APP ACTIVITY NAME.
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 1);             // APP SCHEME ID.
    std::string redirectURI = JSON_ASSTRING(*request.inputJSON, "redirectURI", ""); // APP REDIRECT URI.

    // TODO: implement optional auth...
    // If an user does not have configured that optional value (eg. 2fa value), we should just omit that.

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------     TOKEN VALIDATION       --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    if (!token_validateJwtClaims(request.jwtToken, authenticatedUser, authClientDetails.ipAddress))
    {
        response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------        AUTHENTICATION      --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    // Validate authentication scheme
    if (!token_validateAuthenticationScheme(identityManager, request.jwtToken, app, activity, schemeId, authenticatedUser, authClientDetails.ipAddress))
    {
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
        return;
    }

    // Validate app authorization
    if (!token_validateAppAuthorization(identityManager, request.jwtToken, app, authenticatedUser, authClientDetails.ipAddress))
    {
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(REASON_ACCOUNT_NOT_IN_APP), getReasonText(REASON_ACCOUNT_NOT_IN_APP));
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ---------------------------    ACCOUNT VALIDATIONS   --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    Reason r;
    if (!identityManager->validateAccountForNewAccess(authenticatedUser,app,r,true))
    {
        // This token is not available for retrieving app tokens because the user does not have a valid account with the specified application.
        const char * reasonText = getReasonText(r);
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: User '%s' attempted to obtain an access token for app '%s', but the account is not valid or authorized for this application. Reason: %s.", authenticatedUser.c_str(), app.c_str(), reasonText);
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_INVALID_ACCT", getReasonText(r));
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ---------------------------   REDIRECT VALIDATIONS   --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    if (!token_validateRedirectUri(identityManager, app, redirectURI, authenticatedUser, authClientDetails.ipAddress))
    {
        response.setError(HTTP::Status::S_406_NOT_ACCEPTABLE, "AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), "Invalid Redirect URI");
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------       TOKEN CREATION       --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    // Create and sign tokens
    if (!token_createAndSignJWTs(identityManager, request.jwtToken, app, authenticatedUser, redirectURI, response))
    {
        // Failed to create the token...
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ----------------------       KEEP AUTHENTICATION       ------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    if (JSON_ASBOOL_D(request.jwtToken->getClaim("keepAuthenticated"),false) == false)
    {
        // Discard access cookies upon first use. (Access tokens are short-lived, but should be discarded after the first usage)
        logout(context, response, request, authClientDetails);
    }
}


