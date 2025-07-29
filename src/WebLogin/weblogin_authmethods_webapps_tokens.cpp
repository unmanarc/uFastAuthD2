#include "Mantids30/Program_Logs/loglevels.h"
#include "weblogin_authmethods.h"
#include "json/value.h"
#include <Mantids30/Helpers/json.h>

#include <algorithm> // std::find
#include <boost/algorithm/string/join.hpp>
#include <json/config.h>
#include <optional>

#include "../globals.h"

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

std::optional<JWT::Token> WebLogin_AuthMethods::loadJWTAccessTokenFromPOST(APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();
    auto jsonstrptr = request.clientRequest->getJSONStreamerContent();
    if (!jsonstrptr)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Received invalid or missing JSON content. Cannot proceed with token parsing.");
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_json", "The request body must contain valid JSON content with an 'accessToken' field.");
        return std::nullopt;
    }

    std::string accessTokenStr = JSON_ASSTRING(*jsonstrptr->getValue(), "accessToken", "");

    if (accessTokenStr.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Missing 'accessToken' field in the request. Token parsing aborted.");
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "missing_field", "'accessToken' is a required field in the JSON payload.");
        return std::nullopt;
    }

    JWT::Token accessTokenNoVerified, accessTokenVerified;
    if (!JWT::decodeNoVerify(accessTokenStr, &accessTokenNoVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid JWT format detected in the provided access token.");
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_jwt", "The 'accessToken' must be a valid JWT string.");
        return std::nullopt;
    }

    // Substract the app name from the token.
    std::string appName = JSON_ASSTRING_D(accessTokenNoVerified.getClaim("app"), "");

    // Retrieve the token validator:
    std::shared_ptr<DataFormat::JWT> validator = identityManager->applications->getAppJWTValidator(appName);

    if (!validator)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "No JWT validator found for application name: '%s'.", appName.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_app", "The provided application name in the token is not valid or authorized.");
        return std::nullopt;
    }

    if (!validator->verify(accessTokenStr, &accessTokenVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "JWT token verification failed. Possible tampering detected.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "token_invalid", "The JWT access token is invalid or has been tampered with.");
        return std::nullopt;
    }

    if (!accessTokenVerified.getSubject().empty())
    {
        // Already logged in.
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, accessTokenVerified.getSubject(), authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Application token retrieval attempt denied: Token already issued for this user/application.");
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), getReasonText(REASON_BAD_PARAMETERS));
        return std::nullopt;
    }

    return accessTokenVerified;
}

void WebLogin_AuthMethods::setupAccessTokenCookies(APIReturn &response, JWT::Token accessToken, const ApplicationTokenProperties &tokenProps)
{
    // This cookie is generic for all the application.
    response.cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessToken"].setExpiration(accessToken.getExpirationTime());
    response.cookiesMap["AccessToken"].secure = true;
    response.cookiesMap["AccessToken"].path = "/";
    response.cookiesMap["AccessToken"].httpOnly = true;
    response.cookiesMap["AccessToken"].value = signApplicationToken(accessToken, tokenProps);

    // Max age accessible from JS to indicate when the access token needs to be refreshed.
    response.cookiesMap["AccessTokenMaxAge"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessTokenMaxAge"].setExpiration(accessToken.getExpirationTime());
    response.cookiesMap["AccessTokenMaxAge"].path = "/";
    response.cookiesMap["AccessTokenMaxAge"].secure = true;
    response.cookiesMap["AccessTokenMaxAge"].httpOnly = false;
    response.cookiesMap["AccessTokenMaxAge"].value = std::to_string(accessToken.getExpirationTime() - time(nullptr));
}

void WebLogin_AuthMethods::setupRefreshTokenCookies(APIReturn &response, JWT::Token refreshToken, const ApplicationTokenProperties &tokenProps)
{
    // This cookie is specific to the path of the AUTH API and allows to refresh the access token.
    response.cookiesMap["RefreshToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshToken"].setExpiration(tokenProps.refreshTokenTimeout);
    response.cookiesMap["RefreshToken"].secure = true;
    response.cookiesMap["RefreshToken"].httpOnly = true;
    response.cookiesMap["RefreshToken"].value = signApplicationToken(refreshToken, tokenProps);
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

    if (request.jwtToken->getClaim("app") != "IAM" || request.jwtToken->getClaim("type") != "IAM")
    {
        // This Token is not for this cookie...
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Token request denied: User attempted to inject an invalid token or a token with another purpose.");
        response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------        AUTHENTICATION      --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    std::set<uint32_t> authenticatedSlotIdsSet = Mantids30::Helpers::jsonToUInt32Set(request.jwtToken->getClaim("slotIds"));
    std::set<std::string> authenticatedAppsSet = Mantids30::Helpers::jsonToStringSet(request.jwtToken->getClaim("apps"));

    std::set<uint32_t> schemesInActivity = identityManager->authController->listAuthenticationSchemesForApplicationActivity(app, activity);

    if (schemesInActivity.find(schemeId) == schemesInActivity.end())
    {
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Token request denied: The provided authentication scheme ID does not match any required schemes for the specified application activity.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
        return;
    }

    std::vector<AuthenticationSchemeUsedSlot> slotsUsedByScheme = identityManager->authController->listAuthenticationSlotsUsedByScheme(schemeId);

    for (const auto &slot : slotsUsedByScheme)
    {
        uint32_t slotId = slot.slotId;

        if (authenticatedSlotIdsSet.find(slotId) == authenticatedSlotIdsSet.end())
        {
            // This token is not available for retrieving app tokens...
            LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT,
                          "Token request denied: User attempted to obtain a token without presenting all required credentials.");
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
            return;
        }
    }

    if (authenticatedAppsSet.find(app) == authenticatedAppsSet.end())
    {
        // This token is not available for retrieving app tokens because the app is not in the list of authenticated apps.
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: User attempted to obtain a token for an unauthorized application.");
        // Prevent app enumeration by saying that the account is not on the app (log will help you troubleshoot this).
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(REASON_ACCOUNT_NOT_IN_APP), getReasonText(REASON_ACCOUNT_NOT_IN_APP));
        return;
    }

    if (!identityManager->applications->validateApplicationAccount(app, authenticatedUser))
    {
        // This token is not available for retrieving app tokens because the user does not have a valid account with the specified application.
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: User does not have a valid account with the specified application.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(REASON_ACCOUNT_NOT_IN_APP), getReasonText(REASON_ACCOUNT_NOT_IN_APP));
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ---------------------------   REDIRECT VALIDATIONS   --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////

    std::list<std::string> redirectURIs = identityManager->applications->listWebLoginRedirectURIsFromApplication(app);
    std::string callbackURI = identityManager->applications->getApplicationCallbackURI(app);

    // Validate if the redirect URI is acceptable by the application.
    if (!redirectURI.empty() && std::find(redirectURIs.begin(), redirectURIs.end(), redirectURI) == redirectURIs.end())
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Invalid return URL '%s': The provided URI does not match any recognized redirect URIs for application '%s'.", redirectURI.c_str(), app.c_str());
        response.setError(HTTP::Status::S_406_NOT_ACCEPTABLE, "AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), "Invalid Redirect URI");
        return;
    }

    if (callbackURI.empty())
    {
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' has not configured a callback URI yet.", app.c_str());
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------       TOKEN CREATION       --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    JWT::Token accessToken, refreshToken;

    auto refreshTokenId = Mantids30::Helpers::Random::createRandomString(16);

    // DB Info:
    ApplicationTokenProperties tokenProperties = identityManager->applications->getWebLoginJWTConfigFromApplication(app);
    if (tokenProperties.appName != app)
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_CRITICAL,
                      "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.", app.c_str());
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    configureAccessToken(accessToken, identityManager, refreshTokenId, authenticatedUser, app, tokenProperties, authenticatedSlotIdsSet);
    configureRefreshToken(refreshToken, identityManager, refreshTokenId, authenticatedUser, app, tokenProperties, authenticatedSlotIdsSet);

    // This information the JS will resend as POST to the callback.

    (*response.responseJSON())["accessToken"] = signApplicationToken(accessToken, tokenProperties);
    (*response.responseJSON())["refreshToken"] = signApplicationToken(refreshToken, tokenProperties);
    (*response.responseJSON())["redirectURI"] = redirectURI;

    // you should give all the previous information to the callbackURI, so the callbackURI will "absorb the cookie"
    (*response.responseJSON())["callbackURI"] = callbackURI;

    //  (*response.responseJSON())["expiresIn"] = (Json::UInt64) (accessToken.getExpirationTime() - time(nullptr));

    /*// Configuration parameters:
    IdentityManager *identityManager = Globals::getIdentityManager();

    JWT::Token accessToken, refreshToken;

    std::optional<JWT::Token> currentJWTToken = loadJWTAccessTokenFromPOST(response,request,authClientDetails);
    if (!currentJWTToken)
    {
        return;
    }
    // JWT Info.
    std::string jwtPreAuthUser = JSON_ASSTRING_D(currentJWTToken->getClaim("preAuthUser"), "");
    std::string jwtPreAuthApp = JSON_ASSTRING_D(currentJWTToken->getClaim("app"), "");
    std::set<uint32_t> currentAuthenticatedSlotIds = getSlotIdsFromJSON(currentJWTToken->getClaim("slotIds"));

    if (!validateAPIKey(jwtPreAuthApp, response,request,authClientDetails))
    {
        return;
    }

    // DB Info:
    ApplicationTokenProperties tokenProperties = identityManager->applications->getWebLoginJWTConfigFromApplication(jwtPreAuthApp);
    if ( tokenProperties.appName != jwtPreAuthApp )
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, jwtPreAuthUser, authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.", jwtPreAuthApp.c_str());
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR,"AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    // Validate the token...
    if (!currentJWTToken->hasClaim("isFullyAuthenticated"))
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, jwtPreAuthUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: User attempted to obtain a token without presenting all required credentials.", jwtPreAuthUser.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
        return;
    }

    std::list<std::string> redirectURIs = identityManager->applications->listWebLoginRedirectURIsFromApplication(jwtPreAuthApp);
    std::string redirectURI = request.clientRequest->getVars(HTTP::VARS_POST)->getStringValue(redirectURI);

    // Validate if the redirect URI is acceptable by the application.
    if (!redirectURI.empty() && std::find(redirectURIs.begin(), redirectURIs.end(), redirectURI) == redirectURIs.end())
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, jwtPreAuthUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid return URL '%s': The provided URI does not match any recognized redirect URIs for application '%s'.", redirectURI.c_str(), jwtPreAuthApp.c_str());
        response.setError(HTTP::Status::S_406_NOT_ACCEPTABLE,"AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), getReasonText(REASON_BAD_PARAMETERS));
        return;
    }

    auto refreshTokenId = Mantids30::Helpers::Random::createRandomString(16);

    configureAccessToken(accessToken, identityManager, refreshTokenId, jwtPreAuthUser, jwtPreAuthApp, tokenProperties, currentAuthenticatedSlotIds);
    configureRefreshToken(refreshToken, identityManager, refreshTokenId, jwtPreAuthUser, jwtPreAuthApp, tokenProperties, currentAuthenticatedSlotIds);

    setupAccessTokenCookies(response,accessToken,tokenProperties);
    setupRefreshTokenCookies(response,refreshToken,tokenProperties);

    // Create the proper header for allowing the IAM.
    const auto &permittedOrigins = Globals::getWebLoginServer()->config.permittedLoginOrigins;
    if (!permittedOrigins.empty())
    {
        response.httpExtraHeaders["Access-Control-Allow-Origin"] = boost::algorithm::join(permittedOrigins, ", ");
    }
    else
    {
        // If no origins are specified, don't allow anything... (don't add this header)
    }

    // It's just a POST (no creds...)
    //response.httpExtraHeaders["Access-Control-Allow-Credentials"] = "true";
    response.httpExtraHeaders["Access-Control-Allow-Methods"] = "POST";
    response.httpExtraHeaders["Access-Control-Allow-Headers"] = "Content-Type";

    // Redirect:
    response.httpExtraHeaders["Location"] = redirectURI;
    response.setError( HTTP::Status::S_307_TEMPORARY_REDIRECT, "redirect", "Website redirection." );
    
    // TODO: how to setup the local access token... maybe I should create a new api for it.
    //configureIAMAccessToken(response, request, identityManager, refreshTokenId, jwtPreAuthUser, currentAuthenticatedSlotIds);

    // TODO: guardar los tokens en una db interna para el logout (no hacer ahorita)
  //  (*response.responseJSON())["accessToken"] = signAccessToken(accessToken, tokenProperties, jwtPreAuthApp);
  //..  (*response.responseJSON())["expiresIn"] = (Json::UInt64) (accessToken.getExpirationTime() - time(nullptr));

    // TODO: la información que requiere la APP para operar, es la configuración de los privilegios, los requisitos de 2nd factor para ciertos privilegios\
*/
}

void WebLogin_AuthMethods::tempMFAToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    // INPUTS...
    /* std::string password = JSON_ASSTRING(*request.inputJSON, "password", "");
    std::string authMode = JSON_ASSTRING(*request.inputJSON, "authMode", "");
    std::string challengeSalt = JSON_ASSTRING(*request.inputJSON, "challengeSalt", "");
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);
    std::string appName = JSON_ASSTRING(*request.inputJSON, "app", "");

    // TODO: multi-slots input.
    IdentityManager *identityManager = Globals::getIdentityManager();
    JWT::Token tempMFAToken;

    // JWT Info.
    std::string jwtAccountName = request.jwtToken->getSubject();
    std::set<uint32_t> currentAuthenticatedSlotIds;
    // Don't get the previous tokens
    //= getSlotIdsFromJSON(request.jwtToken->getClaim("slotIds"));

    // DB Info:
    auto tokenProperties = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName);

    // Check JWT APP Signature capabilities...
    if (!JWT::isAlgorithmSupported(tokenProperties.tokenType))
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, jwtAccountName, authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "The application '%s' is configured with an unsupported or invalid signing algorithm.", appName.c_str());

        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR,"AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    Reason reason = REASON_INTERNAL_ERROR;
    if (!validateAccountForNewToken(identityManager, jwtAccountName, reason, appName, true))
    {
        LOG_APP->log2(__func__, jwtAccountName, authClientDetails.ipAddress, Logs::LEVEL_WARN, "The account '%s' can't create a new temporal the access token for the application '%s'.", jwtAccountName.c_str(), appName.c_str());

        response.setError(HTTP::Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(reason), getReasonText(reason));
        return;
    }

    // The token is valid here...
    auto authRetCode = identityManager->authController->authenticateCredential(authClientDetails, jwtAccountName, password, slotId, getAuthModeFromString(authMode), challengeSalt);
    bool statusOk = IS_PASSWORD_AUTHENTICATED(authRetCode) && authRetCode != REASON_EXPIRED_PASSWORD;

    LOG_APP->log2(__func__, jwtAccountName, authClientDetails.ipAddress, authRetCode ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO, "Account Temporal Authorization Result: %" PRIu32 " - %s, for application %s", authRetCode, response.getErrorString().c_str(), appName.c_str());

    if (!statusOk)
    {
        response.setError(HTTP::Status::S_401_UNAUTHORIZED,"AUTH_ERR_"+std::to_string(authRetCode), getReasonText(authRetCode) );
    }
    else
    {
        // Authentication Factor Validated and not expired. (if expired, you should renew it before keep using it)
        currentAuthenticatedSlotIds.insert(slotId);
        configureAccessToken(tempMFAToken, identityManager, request.jwtToken->getJwtId(), jwtAccountName, appName, tokenProperties, currentAuthenticatedSlotIds);
        auto expectedExpirationTime = time(nullptr) + tokenProperties.tempMFATokenTimeout;
        auto accountExpirationTime = identityManager->accounts->getAccountExpirationTime(jwtAccountName);
        tempMFAToken.setExpirationTime(accountExpirationTime < expectedExpirationTime ? accountExpirationTime : expectedExpirationTime);
        (*response.responseJSON())["tempMFAToken"] = signApplicationToken(tempMFAToken, tokenProperties);
    }*/
}
