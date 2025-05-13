#include "json/value.h"
#include <Mantids30/Helpers/json.h>
#include "Mantids30/Program_Logs/loglevels.h"
#include "weblogin_authmethods.h"

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

std::optional<JWT::Token> WebLogin_AuthMethods::loadJWTAccessTokenFromPOST(
    APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
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
        LOG_APP->log2(__func__, accessTokenVerified.getSubject(), authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Application token retrieval attempt denied: Token already issued for this user/application.");
        response.setError(HTTP::Status::S_400_BAD_REQUEST,"AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), getReasonText(REASON_BAD_PARAMETERS));
        return std::nullopt;
    }

    return accessTokenVerified;
}

void WebLogin_AuthMethods::setupAccessTokenCookies(
    APIReturn &response, JWT::Token accessToken, const ApplicationTokenProperties &tokenProps)
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

void WebLogin_AuthMethods::setupRefreshTokenCookies(
    APIReturn &response, JWT::Token refreshToken, const ApplicationTokenProperties &tokenProps)
{
    // This cookie is specific to the path of the AUTH API and allows to refresh the access token.
    response.cookiesMap["RefreshToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshToken"].setExpiration( tokenProps.refreshTokenTimeout );
    response.cookiesMap["RefreshToken"].secure = true;
    response.cookiesMap["RefreshToken"].httpOnly = true;
    response.cookiesMap["RefreshToken"].value = signApplicationToken(refreshToken, tokenProps);
}

/** \brief Validates an access token provided via POST request from an IAM proxy for web applications.
 *
 * This function is specifically designed to handle authentication requests forwarded by an Identity and Access Management (IAM) proxy used in web applications.
 * The primary role of this function is to validate the provided API key and JWT access token, ensuring they adhere to security standards and are appropriately authorized for use.
 *
 * Upon successful validation, the function generates two distinct tokens: a short-lived AccessToken and a long-lived RefresherToken.
 *
 * These serve different purposes within the application's authentication framework:
 *
 * 1. **AccessToken**:       Created with broad scope across the entire site,
 *                           this token enables seamless user authentication across all pages and services of the web application.
 *                           It is designed to be short-lived to minimize exposure in case of leakage.
 *
 * 2. **RefresherToken**:    Limited in scope to the specific proxy endpoint responsible for authentication,
 *                           this token allows users to obtain new AccessTokens without re-authenticating each time,
 *                           enhancing user experience while maintaining security through restricted access.
 *
 * 3. **AccessTokenMaxAge**: This provides a mechanism for client-side JavaScript to determine when the current AccessToken is nearing expiration,
 *                           enabling proactive renewal of the token via the RefresherToken before it becomes invalid.
 *
 * All cookies associated with these tokens are configured with `SameSite=Strict` by default. This configuration ensures that cookies are only sent in first-party contexts,
 * effectively mitigating risks related to Cross-Site Request Forgery (CSRF) attacks. Such measures align with best practices for securing web applications and maintaining user trust.
 *
 * @param context Not used.
 * @param response Reference to the APIReturn object where errors/statuses are set.
 * @param request Contains incoming HTTP request parameters including JSON payload.
 * @param authClientDetails Holds client details (e.g., IP address) for logging/security purposes.
 */
void WebLogin_AuthMethods::token(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    // Configuration parameters:
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
/*
    // TODO: guardar los tokens en una db interna para el logout (no hacer ahorita)
    (*response.responseJSON())["accessToken"] = signAccessToken(accessToken, tokenProperties, jwtPreAuthApp);
    (*response.responseJSON())["expiresIn"] = (Json::UInt64) (accessToken.getExpirationTime() - time(nullptr));
*/
    // TODO: la información que requiere la APP para operar, es la configuración de los privilegios, los requisitos de 2nd factor para ciertos privilegios
}

void WebLogin_AuthMethods::refreshAccessToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
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
    const auto& refreshTokenApp = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("app"), "");
    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(refreshTokenApp);

    if (refreshTokenApp.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token contains invalid or missing claims.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED,"invalid_token", "Invalid Refresher Token");
        return;
    }

    if (tokenProps.appName != refreshTokenApp)
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR,"AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    // ----------   validate the header API Key    -----------
    if (!validateAPIKey(refreshTokenApp, response,request,authClientDetails))
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

    if (!validator->verify( refreshTokenStr, &refreshTokenVerified ))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Failed to verify refresh token for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED,"invalid_token", "Invalid Refresh Token");
        return;
    }

    const auto& refreshTokenUser = refreshTokenVerified.getSubject();


    // --------- create a new access token (like in the token function) -----------
    std::set<uint32_t> currentAuthenticatedSlotIds;
    Json::Value jSlotIds = refreshTokenVerified.getClaim("slotIds");
    if (!jSlotIds.isNull() && jSlotIds.isArray())
    {
        for (const auto& slotIdNode : jSlotIds)
        {
            const uint32_t slotId = JSON_ASUINT_D(slotIdNode,0xFFFFFFFF);
            currentAuthenticatedSlotIds.insert(slotId);
        }
    }

    JWT::Token newAccessToken;
    configureAccessToken(newAccessToken, identityManager, refreshTokenVerified.getJwtId(), refreshTokenUser, refreshTokenApp, tokenProps, currentAuthenticatedSlotIds); // Assuming these variables are accessible here

    // --------- return as cookie, and create the max age cookie too, don't do anything else. ------------
    // Update cookies with new tokens
    setupAccessTokenCookies(response,newAccessToken,tokenProps);

}

void WebLogin_AuthMethods::appLogout(
    void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
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

    response.cookiesMap["AccessTokenMaxAge"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessTokenMaxAge"].setAsTransientCookie();
    response.cookiesMap["AccessTokenMaxAge"].path = "/";
    response.cookiesMap["AccessTokenMaxAge"].value = "";

    response.cookiesMap["RefreshToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshToken"].setAsTransientCookie();
    response.cookiesMap["RefreshToken"].value = "";
}

void WebLogin_AuthMethods::refreshRefresherToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
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
    const auto& refreshTokenApp = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("app"), "");
    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(refreshTokenApp);

    if (refreshTokenApp.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token contains invalid or missing claims.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED,"invalid_token", "Invalid Refresher Token");
        return;
    }

    if (tokenProps.appName != refreshTokenApp)
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR,"AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    if (!tokenProps.allowRefreshTokenRenovation)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token renovation not allowed for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_403_FORBIDDEN, "refresh_denied", "Renovation of refresh tokens is disabled");
        return;
    }

    // ----------   validate the header API Key    -----------
    if (!validateAPIKey(refreshTokenApp, response,request,authClientDetails))
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

    if (!validator->verify( refreshTokenStr, &refreshTokenVerified ))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Failed to verify refresh token for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED,"invalid_token", "Invalid Refresh Token");
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


    const auto& refreshTokenUser = refreshTokenVerified.getSubject();

    // --------- create a new access token (like in the token function) -----------
    std::set<uint32_t> currentAuthenticatedSlotIds;
    Json::Value jSlotIds = refreshTokenVerified.getClaim("slotIds");
    if (!jSlotIds.isNull() && jSlotIds.isArray())
    {
        for (const auto& slotIdNode : jSlotIds)
        {
            const uint32_t slotId = JSON_ASUINT_D(slotIdNode,0xFFFFFFFF);
            currentAuthenticatedSlotIds.insert(slotId);
        }
    }

    JWT::Token newRefreshToken;
    configureRefreshToken(newRefreshToken, identityManager, refreshTokenId, refreshTokenUser, refreshTokenApp, tokenProps, currentAuthenticatedSlotIds);
    setupRefreshTokenCookies(response,newRefreshToken,tokenProps);
}




void WebLogin_AuthMethods::tempMFAToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
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

