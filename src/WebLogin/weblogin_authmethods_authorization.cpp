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

bool WebLogin_AuthMethods::areAllSlotIdsAuthenticated(const std::set<uint32_t> &currentAuthenticatedSlotIds, const std::map<uint32_t, std::string> &accountAuthenticationSlotsUsedForLogin)
{
    for (const auto &r : accountAuthenticationSlotsUsedForLogin)
    {
        if (currentAuthenticatedSlotIds.find(r.first) == currentAuthenticatedSlotIds.end())
        {
            return false;
        }
    }
    return true;
}

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

// Validate credential:
void WebLogin_AuthMethods::authorize(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &clientDetails)
{
    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();
    // Vector to store the authentication slots used by a particular scheme.
    std::vector<AuthenticationSchemeUsedSlot> authSlots;
    // Retrieve configuration parameters from global settings.
    auto config = Globals::getConfig();

    uint32_t loginAuthenticationTimeout = config->get<uint32_t>("WebLoginService.AuthenticationTimeout", 300);

    std::shared_ptr<AppAuthExtras> authContext = std::make_shared<AppAuthExtras>();

    // IMPORTANT NOTE:
    // In this case, the JWT Token will come via bearer header.
    std::string oldIntermediateAuthTokenStr = request.clientRequest->getAuthorizationBearer();
    std::string cookieAccessTokenStr = request.clientRequest->getCookie("AccessToken");

    JWT::Token oldIntermediateAuthToken, cookieAccessToken;

    if (!oldIntermediateAuthTokenStr.empty())
    {
        if (!request.jwtValidator->verify(oldIntermediateAuthTokenStr, &oldIntermediateAuthToken))
        {
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
            return;
        }
    }

    // JWT Signed Parameters:
    std::string accountName = JSON_ASSTRING_D(oldIntermediateAuthToken.getClaim("preAuthUser"), "");
    bool isFullyAuthenticated = JSON_ASBOOL_D(oldIntermediateAuthToken.getClaim("isFullyAuthenticated"), false);
    authContext->appName = JSON_ASSTRING_D(oldIntermediateAuthToken.getClaim("app"), "");
    authContext->slotSchemeHash = JSON_ASSTRING_D(oldIntermediateAuthToken.getClaim("slotSchemeHash"), "");
    authContext->schemeId = JSON_ASUINT_D(oldIntermediateAuthToken.getClaim("schemeId"), UINT32_MAX);
    authContext->keepAuthenticated = JSON_ASBOOL_D(oldIntermediateAuthToken.getClaim("keepAuthenticated"), false);
    authContext->currentSlotPosition = JSON_ASUINT_D(oldIntermediateAuthToken.getClaim("currentSlotPosition"), UINT32_MAX);
    std::string jwtTokenId = oldIntermediateAuthToken.getJwtId();

    if (!cookieAccessTokenStr.empty())
    {
        if (!request.jwtValidator->verify(cookieAccessTokenStr, &cookieAccessToken))
        {
            // Failed to load the intermediary...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
            return;
        }
        if (cookieAccessToken.getClaim("app") != "IAM" || cookieAccessToken.getClaim("type") != "IAM")
        {
            // This Token is not for this cookie...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
            return;
        }
        if (cookieAccessToken.getSubject() != accountName)
        {
            // This Token is not for this cookie... (other username... logout first please!)
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
            return;
        }

        if (cookieAccessToken.getClaim("apps").isMember(authContext->appName))
        {
            // Already authenticated with this APP...
            response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
            return;
        }
    }

    // Using the first slot:
    if (jwtTokenId.empty())
    {
        // When there is no token, override initial token parameters with the input parameters...
        accountName = JSON_ASSTRING(*request.inputJSON, "preAuthUser", "");
        authContext->keepAuthenticated = JSON_ASBOOL(*request.inputJSON, "keepAuthenticated", false);
        authContext->appName = JSON_ASSTRING(*request.inputJSON, "app", "");
        authContext->schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", UINT32_MAX);
        authContext->currentSlotPosition = 0;
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
        // Set the new JWT here.
        JWT::Token newIntermediateAuthToken;

        if (authContext->currentSlotPosition == 0)
        {
            newIntermediateAuthToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));
            newIntermediateAuthToken.setExpirationTime(time(nullptr) + loginAuthenticationTimeout);
        }
        else
        {
            newIntermediateAuthToken.setExpirationTime(oldIntermediateAuthToken.getExpirationTime());
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

            TokensManager::setIAMAccessToken(response, request, newIntermediateAuthToken, cookieAccessToken,
                                             authContext->keepAuthenticated, // Keep authenticated will use the current authentication proccess
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
    }
    else
    {
        if (authRetCode == REASON_ACCOUNT_NOT_IN_APP)
        {
            // Prevent user/app enumeration:
            authRetCode = REASON_BAD_PASSWORD;
            //  response.setFullStatus(IS_PASSWORD_AUTHENTICATED(authRetCode),IS_PASSWORD_AUTHENTICATED(authRetCode)?Status::S_200_OK : Status::S_401_UNAUTHORIZED, (uint32_t) authRetCode, getReasonText(authRetCode));
        }

        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(authRetCode), getReasonText(authRetCode));
    }

    LOG_APP->log2(__func__, accountName, clientDetails.ipAddress, response.getHTTPResponseCode() != HTTP::Status::S_200_OK ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO, "R/%03" PRIu16 ": %s",
                  static_cast<uint16_t>(response.getHTTPResponseCode()), request.clientRequest->getURI().c_str());
}

// TODO: - detect multiple logins and block when disallowed.
