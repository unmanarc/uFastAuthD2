#include "Mantids30/Program_Logs/loglevels.h"
#include "Mantids30/Protocol_HTTP/httpv1_base.h"
#include "Tokens/tokensmanager.h"
#include "websessionauthhandler_authmethods.h"
#include "json/value.h"
#include <Mantids30/Helpers/json.h>

#include <boost/algorithm/string/join.hpp>
#include <json/config.h>
#include <optional>

#include "../globals.h"
#include "Tokens/tokensmanager.h"

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

std::optional<JWT::Token> WebSessionAuthHandler_AuthMethods::loadJWTAccessTokenFromPOST(APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
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

void WebSessionAuthHandler_AuthMethods::setupAccessTokenCookies(APIReturn &response, JWT::Token accessToken, const ApplicationTokenProperties &tokenProps)
{
    setupCookie(response, "AccessToken", accessToken.getExpirationTime(), true, JSON_ASSTRING(tokenProps.tokensConfiguration["accessToken"],"path","/"), true, signApplicationToken(accessToken, tokenProps));
    //setupMaxAgeCookie(response, "AccessTokenMaxAge", accessToken.getExpirationTime());
}

void WebSessionAuthHandler_AuthMethods::setupRefreshTokenCookies(APIReturn &response, JWT::Token refreshToken, const ApplicationTokenProperties &tokenProps)
{
    setupCookie(response, "RefreshToken", refreshToken.getExpirationTime(), true, JSON_ASSTRING(tokenProps.tokensConfiguration["refreshToken"],"path","/auth"), true, signApplicationToken(refreshToken, tokenProps));
}
/*
void WebSessionAuthHandler_AuthMethods::setupAccessTokenCookies(APIReturn &response, std::string accessToken, const time_t &timeout)
{
    IdentityManager *identityManager = Globals::getIdentityManager();
    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(refreshTokenApp);

    setupCookie(response, "AccessToken", timeout, true, "/", true, accessToken);
    setupMaxAgeCookie(response, "AccessTokenMaxAge", timeout);
}

void WebSessionAuthHandler_AuthMethods::setupRefreshTokenCookies(APIReturn &response, std::string refreshToken, const time_t &timeout)
{
    setupCookie(response, "RefreshToken", timeout, true, "/", true, refreshToken);
}*/

void WebSessionAuthHandler_AuthMethods::setupCookie(APIReturn &response, const std::string &name, time_t expirationTime, bool secure, const std::string &path, bool httpOnly, const std::string &value)
{
    response.cookiesMap[name] = HTTP::Headers::Cookie();
    response.cookiesMap[name].setExpiration(expirationTime);
    response.cookiesMap[name].secure = secure;
    response.cookiesMap[name].path = path;
    response.cookiesMap[name].httpOnly = httpOnly;
    response.cookiesMap[name].value = value;
}

/*
void WebSessionAuthHandler_AuthMethods::setupMaxAgeCookie(APIReturn &response, const std::string &name, time_t expirationTime)
{
    setupCookie(response, name, expirationTime, true, "/", false, std::to_string(expirationTime - time(nullptr)));
}*/

void WebSessionAuthHandler_AuthMethods::refreshAccessToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string refreshTokenStr = request.clientRequest->getCookies()->getSubVar("RefreshToken");

    // ----------    decode no verify the Refresh Token and take the app name    -----------

    if (refreshTokenStr.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token cookie is missing or empty.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_refresher", "Invalid Refresh Token");
        return;
    }

    // Validate the refresh token
    JWT::Token refreshTokenNoVerified;

    if (!JWT::decodeNoVerify(refreshTokenStr, &refreshTokenNoVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid JWT format detected in the provided access token.");
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_jwt", "The 'accessToken' must be a valid JWT string.");
        return;
    }

    // Extract application from the refresh token
    const auto &refreshTokenApp = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("app"), "");
    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(refreshTokenApp);

    if (refreshTokenApp.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token contains invalid or missing claims.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresher Token");
        return;
    }

    if (tokenProps.appName != refreshTokenApp)
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.",
                      refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    // ----------   validate the header API Key    -----------
    if (!validateAPIKey(refreshTokenApp, response, request, authClientDetails))
    {
        return;
    }

    // --------- validate the refresh token itself (that is signed with the application keys) --------
    JWT::Token refreshTokenVerified;

    std::shared_ptr<JWT> validator = identityManager->applications->getAppJWTValidator(refreshTokenApp);

    if (!validator)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "No JWT validator found for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_app", "Application not configured");
        return;
    }

    if (!validator->verify(refreshTokenStr, &refreshTokenVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Failed to verify refresh token for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresh Token");
        return;
    }

    const std::string &refreshTokenUser = refreshTokenVerified.getSubject();

    // --------- create a new access token (like in the token function) -----------
    std::set<uint32_t> currentAuthenticatedSlotIds;
    Json::Value jSlotIds = refreshTokenVerified.getClaim("slotIds");
    if (!jSlotIds.isNull() && jSlotIds.isArray())
    {
        for (const auto &slotIdNode : jSlotIds)
        {
            const uint32_t slotId = JSON_ASUINT_D(slotIdNode, 0xFFFFFFFF);
            currentAuthenticatedSlotIds.insert(slotId);
        }
    }

    JWT::Token newAccessToken;
    TokensManager::configureAccessToken(newAccessToken, refreshTokenVerified.getJwtId(), refreshTokenUser, refreshTokenApp, tokenProps,
                         currentAuthenticatedSlotIds); // Assuming these variables are accessible here

    // --------- return as cookie, and create the max age cookie too, don't do anything else. ------------
    // Update cookies with new tokens
    setupAccessTokenCookies(response, newAccessToken, tokenProps);
}

void WebSessionAuthHandler_AuthMethods::appLogout(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string refreshTokenStr = request.clientRequest->getCookies()->getSubVar("RefreshToken");
    // ----------   prevent CSRF here. because this cookie is strict, won't exist on CSRF calls...   -----------
    if (refreshTokenStr.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Refresh token cookie is missing or empty during logout. Maybe not logged in?");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_refresher", "Invalid Refresh Token");
        return;
    }

    // if ok, clear everything!:
    response.cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessToken"].setAsTransientCookie();
    response.cookiesMap["AccessToken"].value = "";
    response.cookiesMap["AccessToken"].path = "/";

/*    response.cookiesMap["AccessTokenMaxAge"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessTokenMaxAge"].setAsTransientCookie();
    response.cookiesMap["AccessTokenMaxAge"].path = "/";
    response.cookiesMap["AccessTokenMaxAge"].value = "";*/

    response.cookiesMap["RefreshToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshToken"].setAsTransientCookie();
    response.cookiesMap["RefreshToken"].value = "";
}

void WebSessionAuthHandler_AuthMethods::callback(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    // HTTP CLIENT VARS:
    std::string accessTokenStr = request.clientRequest->getVars(HTTP::VARS_POST)->getStringValue("ACCESSTOKEN");
    std::string refreshTokenStr = request.clientRequest->getVars(HTTP::VARS_POST)->getStringValue("REFRESHTOKEN");
    std::string redirectURIStr = request.clientRequest->getVars(HTTP::VARS_POST)->getStringValue("REDIRECTURI");
    std::string xAPIKeyStr = request.clientRequest->getHeaderOption("x-api-key");

    // VARS:
    std::string appNameStr = identityManager->applications->getApplicationNameByAPIKey(xAPIKeyStr);

    // Now, search the application by the x-api-key:
    if (appNameStr.empty())
    {
        // app key not found...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided. Application not found.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized.");
        return;
    }

    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(appNameStr);
    std::shared_ptr<JWT> validator = identityManager->applications->getAppJWTValidator(appNameStr);

    JWT::Token accessToken, refreshToken;

    // Verify that the tokens are valid, if not, don't return the tokens.
    bool accessTokenValid = validator->verify(accessTokenStr, &accessToken);
    bool refreshTokenValid = validator->verify(refreshTokenStr, &refreshToken);

    if (!accessTokenValid || !refreshTokenValid)
    {
        std::string logMessage = "Invalid JWT token(s) provided.";
        if (!accessTokenValid)
        {
            logMessage += " Access Token verification failed.";
        }
        if (!refreshTokenValid)
        {
            logMessage += " Refresh Token verification failed.";
        }
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, logMessage.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "The provided access or refresh token is invalid.");
        return;
    }

    // Verify the redirection... (VERY IMPORTANT)
    std::list<std::string> redirectURLS = identityManager->applications->listWebLoginRedirectURIsFromApplication(appNameStr);

    if (std::find(redirectURLS.begin(), redirectURLS.end(), redirectURIStr) == redirectURLS.end())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Redirect URI '%s' is not allowed for application '%s'.", redirectURIStr.c_str(), appNameStr.c_str());
        response.setError(HTTP::Status::S_403_FORBIDDEN, "invalid_redirect_uri", "The requested redirect URI is not authorized.");
        return;
    }

    setupAccessTokenCookies(response, accessToken, tokenProps);
    setupRefreshTokenCookies(response, refreshToken, tokenProps);

    // Redirect:
    response.redirectURL = redirectURIStr;
}

void WebSessionAuthHandler_AuthMethods::refreshRefresherToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string refreshTokenStr = request.clientRequest->getCookies()->getSubVar("RefreshToken");

    // ----------    decode no verify the Refresh Token and take the app name    -----------

    if (refreshTokenStr.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token cookie is missing or empty.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_refresher", "Invalid Refresh Token");
        return;
    }

    // Validate the refresh token
    JWT::Token refreshTokenNoVerified;

    if (!JWT::decodeNoVerify(refreshTokenStr, &refreshTokenNoVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid JWT format detected in the provided access token.");
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_jwt", "The 'accessToken' must be a valid JWT string.");
        return;
    }

    // Extract application from the refresh token
    const auto &refreshTokenApp = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("app"), "");
    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(refreshTokenApp);

    if (refreshTokenApp.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token contains invalid or missing claims.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresher Token");
        return;
    }

    if (tokenProps.appName != refreshTokenApp)
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.",
                      refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    if (!tokenProps.allowRefreshTokenRenovation)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token renovation not allowed for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_403_FORBIDDEN, "refresh_denied", "Renovation of refresh tokens is disabled");
        return;
    }

    // ----------   validate the header API Key    -----------
    if (!validateAPIKey(refreshTokenApp, response, request, authClientDetails))
    {
        return;
    }

    // --------- validate the refresh token itself (that is signed with the application keys) --------
    JWT::Token refreshTokenVerified;

    auto validator = identityManager->applications->getAppJWTValidator(refreshTokenApp);

    if (!validator)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "No JWT validator found for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_app", "Application not configured");
        return;
    }

    if (!validator->verify(refreshTokenStr, &refreshTokenVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Failed to verify refresh token for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresh Token");
        return;
    }

    // TODO: check if the refresh the refresh token is available by the app configuration
    // The token is valid here...
    // TODO: invalidar todos los tokens viejos que su parent sea este refresher...
    // TODO: guardar los tokens en una db interna para el logout (no hacer ahorita)

    auto refreshTokenId = Mantids30::Helpers::Random::createRandomString(16);

    auto tokenHalfLifeSeconds = (refreshTokenVerified.getExpirationTime() - refreshTokenVerified.getIssuedAt()) / 2;
    auto tokenHalfLifePoint = refreshTokenVerified.getIssuedAt() + tokenHalfLifeSeconds;

    if (time(nullptr) <= tokenHalfLifePoint)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Refresh token hast not past its half-life and cannot be refreshed.");
        response.setError(HTTP::Status::S_406_NOT_ACCEPTABLE, "unrefresheable_token", "The refresh token is not refresheable yet.");
        return;
    }

    const auto &refreshTokenUser = refreshTokenVerified.getSubject();

    // --------- create a new access token (like in the token function) -----------
    std::set<uint32_t> currentAuthenticatedSlotIds;
    Json::Value jSlotIds = refreshTokenVerified.getClaim("slotIds");
    if (!jSlotIds.isNull() && jSlotIds.isArray())
    {
        for (const auto &slotIdNode : jSlotIds)
        {
            const uint32_t slotId = JSON_ASUINT_D(slotIdNode, 0xFFFFFFFF);
            currentAuthenticatedSlotIds.insert(slotId);
        }
    }

    JWT::Token newRefreshToken;
    TokensManager::configureRefreshToken(newRefreshToken, refreshTokenId, refreshTokenUser, refreshTokenApp, tokenProps, currentAuthenticatedSlotIds);
    setupRefreshTokenCookies(response, newRefreshToken, tokenProps);
}
