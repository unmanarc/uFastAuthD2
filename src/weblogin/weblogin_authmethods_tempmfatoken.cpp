#include "weblogin_authmethods.h"

#include "../globals.h"
#include <string>

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;
using namespace Mantids30::Network::Protocols::HTTP;

// TODO: esto no esta revisado ...

void WebLogin_AuthMethods::tempMFAToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    // INPUTS...
    std::string password = JSON_ASSTRING(*request.inputJSON, "password", "");
    std::string authMode = JSON_ASSTRING(*request.inputJSON, "authMode", "");
    std::string challengeSalt = JSON_ASSTRING(*request.inputJSON, "challengeSalt", "");
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);
    std::string appName = JSON_ASSTRING(*request.inputJSON, "app", "");

    // TODO: multi-slots input.
    IdentityManager *identityManager = Globals::getIdentityManager();
    DataFormat::JWT::Token tempMFAToken;

    // JWT Info.
    std::string jwtUserId = request.jwtToken->getSubject();
    std::set<uint32_t> currentAuthenticatedSlotIds;
    // Don't get the previous tokens
    //= getSlotIdsFromJSON(request.jwtToken->getClaim("slotIds"));

    // DB Info:
    auto tokenProperties = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName);

    // Check JWT APP Signature capabilities...
    if (!DataFormat::JWT::isAlgorithmSupported(tokenProperties.tokenType))
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, jwtUserId, authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "The application '%s' is configured with an unsupported or invalid signing algorithm.", appName.c_str());

        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    Reason reason = REASON_INTERNAL_ERROR;
    if (!validateAccountForNewToken(identityManager, jwtUserId, reason, appName, true))
    {
        LOG_APP->log2(__func__, jwtUserId, authClientDetails.ipAddress, Logs::LEVEL_WARN, "The account '%s' can't create a new temporal the access token for the application '%s'.", jwtUserId.c_str(), appName.c_str());

        response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(reason), getReasonText(reason));
        return;
    }

    // The token is valid here...
    auto authRetCode = identityManager->authController->authenticateCredential(authClientDetails, jwtUserId, password, slotId, getAuthModeFromString(authMode), challengeSalt);
    bool statusOk = IS_PASSWORD_AUTHENTICATED(authRetCode) && authRetCode != REASON_EXPIRED_PASSWORD;

    LOG_APP->log2(__func__, jwtUserId, authClientDetails.ipAddress, authRetCode ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO, "Account Temporal Authorization Result: %" PRIu32 " - %s, for application %s", authRetCode, response.getErrorString().c_str(), appName.c_str());

    if (!statusOk)
    {
        response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_"+std::to_string(authRetCode), getReasonText(authRetCode) );
    }
    else
    {
        // Authentication Factor Validated and not expired. (if expired, you should renew it before keep using it)
        currentAuthenticatedSlotIds.insert(slotId);
        configureAccessToken(tempMFAToken, identityManager, request.jwtToken->getJwtId(), jwtUserId, appName, tokenProperties, currentAuthenticatedSlotIds);
        auto expectedExpirationTime = time(nullptr) + tokenProperties.tempMFATokenTimeout;
        auto accountExpirationTime = identityManager->users->getAccountExpirationTime(jwtUserId);
        tempMFAToken.setExpirationTime(accountExpirationTime < expectedExpirationTime ? accountExpirationTime : expectedExpirationTime);
        (*response.responseJSON())["tempMFAToken"] = signAccessToken(tempMFAToken, tokenProperties, appName);
    }
}

