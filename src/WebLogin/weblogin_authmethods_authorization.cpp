#include "IdentityManager/ds_authentication.h"
#include "Mantids30/Program_Logs/loglevels.h"
#include "Tokens/tokensmanager.h"
#include "weblogin_authmethods.h"
#include <Mantids30/Helpers/json.h>

#include "../globals.h"

#include <cstdint>
#include <inttypes.h>
#include <json/config.h>
#include <memory>
#include <string>

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;
using namespace Mantids30::DataFormat;

// Validate user and get authorization flow:
void WebLogin_AuthMethods::preAuthorize(void *context, APIReturn &response, const API::RESTful::RequestParameters &request, ClientDetails &authClientDetails)
{
    // Environment:
    JWT::Token token;
    IdentityManager *identityManager = Globals::getIdentityManager();

    //  Configuration parameters:
    auto config = Globals::getConfig();
    uint32_t loginAuthenticationTimeout = config->get<uint32_t>("WebLoginService.AuthenticationTimeout", 300);

    // Input parameters:
    std::string app = JSON_ASSTRING(*request.inputJSON, "app", "");                 // APPNAME.
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", ""); // ACCOUNT ID.
    std::string activity = JSON_ASSTRING(*request.inputJSON, "activity", "");       // APP ACTIVITY NAME.

    if (!identityManager->applications->doesApplicationExist(app))
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "Invalid Application");
        return;
    }

    (*response.responseJSON()) = identityManager->authController->getApplicableAuthenticationSchemesForAccount(app, activity, accountName);
    (*response.responseJSON())["loginAuthenticationTimeout"] = loginAuthenticationTimeout;
}

bool validateIAMAccessTokenCookieProperties(const RequestParameters &request, WebLogin_AuthMethods::APIReturn &response, JWT::Token *token, const std::string &accountName, const std::string &appName)
{
    std::string cookieAccessTokenStr = request.clientRequest->getCookie("AccessToken");

    if (!cookieAccessTokenStr.empty())
    {
        if (!request.jwtValidator->verify(cookieAccessTokenStr, token))
        {
            // Failed to load the intermediary...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
            return false;
        }
        if (token->getClaim("app") != "IAM" || token->getClaim("type") != "IAM")
        {
            // This Token is not for this cookie...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
            return false;
        }
        if (token->getSubject() != accountName)
        {
            // This Token is not for this cookie... (other username... logout first please!)
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
            return false;
        }

        if (token->getClaim("apps").isMember(appName))
        {
            // Already authenticated within this APP...
            response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
            return false;
        }
    }
    return true;
}

bool validateAndDecodeBearerAccessTokenProperties(const RequestParameters &request, WebLogin_AuthMethods::APIReturn &response, JWT::Token *oldIntermediateAuthToken, std::string *accountName,
                                                  bool *isFullyAuthenticated, std::shared_ptr<AppAuthExtras> authContext)
{
    std::string oldIntermediateAuthTokenStr = request.clientRequest->getAuthorizationBearer();

    // Validate the token
    if (!oldIntermediateAuthTokenStr.empty())
    {
        if (!request.jwtValidator->verify(oldIntermediateAuthTokenStr, oldIntermediateAuthToken))
        {
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
            return false;
        }
    }

    // Extract JWT Signed Parameters:
    *accountName = JSON_ASSTRING_D(oldIntermediateAuthToken->getClaim("preAuthUser"), "");
    *isFullyAuthenticated = JSON_ASBOOL_D(oldIntermediateAuthToken->getClaim("isFullyAuthenticated"), false);
    authContext->fillFromTokenClaims(oldIntermediateAuthToken->getAllClaimsAsJSON());
    return true;
}

bool setupNewIntermediateAuthToken(const RequestParameters &request, Mantids30::API::APIReturn &response, IdentityManager *identityManager, std::shared_ptr<AppAuthExtras> authContext,
                                   const std::vector<AuthenticationSchemeUsedSlot> &authSlots, const time_t &oldIntermediateTokenExpirationTime, const std::string &accountName)
{
    // Retrieve configuration parameters from global settings.
    auto config = Globals::getConfig();
    uint32_t loginAuthenticationTimeout = config->get<uint32_t>("WebLoginService.AuthenticationTimeout", 300);
    JWT::Token newIntermediateAuthToken;

    if (authContext->currentSlotPosition == 0)
    {
        newIntermediateAuthToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));
        newIntermediateAuthToken.setExpirationTime(time(nullptr) + loginAuthenticationTimeout);
    }
    else
    {
        newIntermediateAuthToken.setExpirationTime(oldIntermediateTokenExpirationTime);
    }

    newIntermediateAuthToken.setIssuedAt(time(nullptr));
    newIntermediateAuthToken.setNotBefore(time(nullptr) - 30);
    newIntermediateAuthToken.addClaim("app", authContext->appName);
    newIntermediateAuthToken.addClaim("preAuthUser", accountName);
    newIntermediateAuthToken.addClaim("slotSchemeHash", authContext->slotSchemeHash);
    newIntermediateAuthToken.addClaim("schemeId", authContext->schemeId);
    newIntermediateAuthToken.addClaim("keepAuthenticated", authContext->keepAuthenticated);

    if (authContext->currentSlotPosition == authSlots.size() - 1)
    {
        // Report that it's fully authenticated (all slots id's from the scheme were authenticated OK).
        newIntermediateAuthToken.addClaim("isFullyAuthenticated", true);

        // Create a Json::Value array to store slot IDs
        Json::Value slotIds(Json::arrayValue);
        for (const auto &slot : authSlots)
        {
            slotIds.append((Json::UInt) slot.slotId);
        }

        newIntermediateAuthToken.addClaim("slotIds", slotIds);
        newIntermediateAuthToken.addClaim("type", "intermediate");

        JWT::Token cookieAccessToken;
        // Obtained accountName and appName in the POST Token (if exist) should match the decoded bearer token:
        if (!validateIAMAccessTokenCookieProperties(request, response, &cookieAccessToken, accountName, authContext->appName))
        {
            return false;
        }

        // Set the IAM Access Token into the Cookie...
        TokensManager::setIAMAccessTokenCookie(response, request, newIntermediateAuthToken, cookieAccessToken,
                                               authContext->keepAuthenticated,              // Keep authenticated will use the current authentication proccess
                                               newIntermediateAuthToken.getExpirationTime() // Get current JWT expiration time (if keep autneticated is false)
        );

        (*response.responseJSON())["isFullyAuthenticated"] = true;
    }
    else
    {
        (*response.responseJSON())["isFullyAuthenticated"] = false;

        newIntermediateAuthToken.addClaim("isFullyAuthenticated", false);
        newIntermediateAuthToken.addClaim("currentSlotPosition", authContext->currentSlotPosition + 1);

        // We can give the credential public data for the next credential:
        Credential publicData = identityManager->authController->getAccountCredentialPublicData(accountName, authSlots[authContext->currentSlotPosition + 1].slotId);

        (*response.responseJSON())["credentialPublicData"] = publicData.toJSON(identityManager->authController->getAuthenticationPolicy());
        (*response.responseJSON())["intermediateToken"] = request.jwtSigner->signFromToken(newIntermediateAuthToken, false);
    }
    return true;
}

// Validate credential:
void WebLogin_AuthMethods::authorize(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &clientDetails)
{
    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();
    // Vector to store the authentication slots used by a particular scheme.
    std::vector<AuthenticationSchemeUsedSlot> authSlots;

    std::shared_ptr<AppAuthExtras> authContext = std::make_shared<AppAuthExtras>();
    // IMPORTANT NOTE:
    // In this case, the JWT Token will come via bearer header.

    JWT::Token oldIntermediateAuthToken;
    std::string accountName;
    bool isFullyAuthenticated;

    // Decode the bearer intermediate token...
    if (!validateAndDecodeBearerAccessTokenProperties(request, response, &oldIntermediateAuthToken, &accountName, &isFullyAuthenticated, authContext))
    {
        return;
    }

    // Using the first slot where the intermediate token does not exist:
    if (oldIntermediateAuthToken.getJwtId().empty())
    {
        // When there is no token, override initial token parameters with the input parameters...
        accountName = JSON_ASSTRING(*request.inputJSON, "preAuthUser", "");
        authContext->fillFromInitialJSONPOST(*request.inputJSON);
    }

    if (authContext->currentSlotPosition == std::numeric_limits<uint32_t>::max() || isFullyAuthenticated || request.clientRequest->getCookie("AccessToken") != "")
    {
        // You don´t need to authorize anything else! it's already authenticated.
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(REASON_BAD_PASSWORD), getReasonText(REASON_BAD_PASSWORD));
        return;
    }

    authSlots = identityManager->authController->listAuthenticationSlotsUsedByScheme(authContext->schemeId);

    if (authSlots.size() <= authContext->currentSlotPosition)
    {
        throw std::runtime_error("This should not be happening. maybe someone manipulated the JWT, change your key soon!!!");
    }

    Reason authRetCode = identityManager->authController->authenticateCredential(clientDetails, accountName, JSON_ASSTRING(*request.inputJSON, "password", ""),
                                                                                 authSlots.at(authContext->currentSlotPosition).slotId,
                                                                                 getAuthModeFromString(JSON_ASSTRING(*request.inputJSON, "authMode", "MODE_PLAIN")),
                                                                                 JSON_ASSTRING(*request.inputJSON, "challengeSalt", ""), authContext);

    LOG_APP->log2(__func__, accountName, clientDetails.ipAddress, authRetCode ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                  "Account Authorization Result: %" PRIu32 " - %s, for application '%s', scheme '%" PRIu32 "' and slotId[%" PRIu32 "] '%" PRIu32 "'", authRetCode, getReasonText(authRetCode),
                  authContext->appName.c_str(), authContext->schemeId, authContext->currentSlotPosition, authSlots[authContext->currentSlotPosition].slotId);

    if (IS_PASSWORD_AUTHENTICATED(authRetCode))
    {
        if (!setupNewIntermediateAuthToken(request, response, identityManager, authContext, authSlots, oldIntermediateAuthToken.getExpirationTime(), accountName))
        {
            // Invalid Cookie...
            authRetCode = REASON_BAD_PARAMETERS;
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(authRetCode), getReasonText(authRetCode));
        }
    }
    else
    {
        if (authRetCode == REASON_ACCOUNT_NOT_IN_APP)
        {
            // Prevent user/app enumeration:
            authRetCode = REASON_BAD_PASSWORD;
        }

        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(authRetCode), getReasonText(authRetCode));
    }

    LOG_APP->log2(__func__, accountName, clientDetails.ipAddress, response.getHTTPResponseCode() != HTTP::Status::S_200_OK ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO, "R/%03" PRIu16 ": %s",
                  static_cast<uint16_t>(response.getHTTPResponseCode()), request.clientRequest->getURI().c_str());
}
