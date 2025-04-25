#include "IdentityManager/ds_authentication.h"
#include "Mantids30/Helpers/json.h"
#include "Mantids30/Program_Logs/loglevels.h"
#include "weblogin_authmethods.h"

#include "../globals.h"
#include <cstdint>
#include <memory>
#include <string>

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;

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

// Validate credential:
void WebLogin_AuthMethods::authorize(void *context,
                                     APIReturn &response,
                                     const Mantids30::API::RESTful::RequestParameters &request,
                                     Mantids30::Sessions::ClientDetails &clientDetails)
{
    // Environment:
    IdentityManager *identityManager = Globals::getIdentityManager();
    std::vector<AuthenticationSchemeUsedSlot> authSlots;

    // Configuration parameters:
    auto config = Globals::getConfig();
    uint32_t loginAuthenticationTimeout = config->get<uint32_t>("WebLoginService.AuthenticationTimeout", 300);

    std::shared_ptr<AppAuthExtras> authContext = std::make_shared<AppAuthExtras>();


    // JWT Signed Parameters:
    std::string accountName          = JSON_ASSTRING_D(request.jwtToken->getClaim("preAuthUser"), "");
    authContext->appName             = JSON_ASSTRING_D(request.jwtToken->getClaim("applicationName"), "");
    authContext->slotSchemeHash      = JSON_ASSTRING_D(request.jwtToken->getClaim("slotSchemeHash"), "");
    authContext->schemeId            = JSON_ASUINT_D(request.jwtToken->getClaim("schemeId"), UINT32_MAX);
    authContext->currentSlotPosition = JSON_ASUINT_D(request.jwtToken->getClaim("currentSlotPosition"), UINT32_MAX);
    std::string jwtTokenId           = request.jwtToken->getJwtId();

    // Using the first slot:
    if (jwtTokenId.empty())
    {
        // When there is no token, override initial token parameters with the input parameters...
        accountName = JSON_ASSTRING(*request.inputJSON, "preAuthUser", "");
        authContext->appName = JSON_ASSTRING(*request.inputJSON, "applicationName", "");
        authContext->schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", UINT32_MAX);
        authContext->currentSlotPosition = 0;
    }

    if (authContext->currentSlotPosition == std::numeric_limits<uint32_t>::max())
    {
        // You don´t need to authorize anything else!
        response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(REASON_BAD_PASSWORD), getReasonText(REASON_BAD_PASSWORD));
        return;
    }

    authSlots = identityManager->authController->listAuthenticationSlotsUsedByScheme(authContext->schemeId);

    if ( authSlots.size() <= authContext->currentSlotPosition )
    {
        throw std::runtime_error("This should not be happening. maybe someone manipulated the JWT, change your key soon!!!");
    }

    Reason authRetCode = identityManager->authController->authenticateCredential(
                                                            clientDetails,
                                                            accountName,
                                                            JSON_ASSTRING(*request.inputJSON, "password", ""),
                                                            authSlots.at(authContext->currentSlotPosition).slotId,
                                                            getAuthModeFromString(JSON_ASSTRING(*request.inputJSON, "authMode", "MODE_PLAIN")),
                                                            JSON_ASSTRING(*request.inputJSON, "challengeSalt", ""),
                                                            authContext);


    LOG_APP->log2(__func__,
                  accountName,
                  clientDetails.ipAddress,
                  authRetCode ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                  "Account Authorization Result: %" PRIu32 " - %s, for application '%s', scheme '%" PRIu32 "' and slotId[%" PRIu32 "] '%" PRIu32 "'",
                  authRetCode,
                  (*response.outputPayload())["statusMessage"].asCString(),
                  authContext->appName.c_str(),
                  authContext->schemeId,
                  authContext->currentSlotPosition,
                  authSlots[authContext->currentSlotPosition].slotId
                  );

    if (IS_PASSWORD_AUTHENTICATED(authRetCode))
    {

        // Set the new JWT here.
        DataFormat::JWT::Token outgoingToken;

        if (authContext->currentSlotPosition == 0)
        {
            outgoingToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));
            outgoingToken.setExpirationTime(time(nullptr) + loginAuthenticationTimeout);
        }
        else
        {
            outgoingToken.setExpirationTime( request.jwtToken->getExpirationTime() );
        }

        outgoingToken.setIssuedAt(time(nullptr));
        outgoingToken.setNotBefore(time(nullptr) - 30);

        outgoingToken.addClaim("applicationName", authContext->appName);
        outgoingToken.addClaim("preAuthUser", accountName);
        outgoingToken.addClaim("slotSchemeHash", authContext->slotSchemeHash);
        outgoingToken.addClaim("schemeId", authContext->schemeId);

        if ( authContext->currentSlotPosition == authSlots.size()-1 )
        {
            outgoingToken.addClaim("isFullyAuthenticated", true);
            (*response.outputPayload())["isFullyAuthenticated"] = true;
        }
        else
        {
            (*response.outputPayload())["isFullyAuthenticated"] = false;
            outgoingToken.addClaim("isFullyAuthenticated", false);
            outgoingToken.addClaim("currentSlotPosition", authContext->currentSlotPosition+1);

            // We can give the credential public data for the next credential:
            Credential publicData = identityManager->authController->getAccountCredentialPublicData(accountName,authContext->currentSlotPosition+1);
            (*response.outputPayload())["credentialPublicData"] = publicData.toJSON( identityManager->authController->getAuthenticationPolicy() );

        }
        response.cookiesMap["AuthToken"] = Headers::Cookie();
        response.cookiesMap["AuthToken"].secure = true;
        response.cookiesMap["AuthToken"].httpOnly = true;
        response.cookiesMap["AuthToken"].setExpirationFromNow(loginAuthenticationTimeout); // 2min expiration...
        response.cookiesMap["AuthToken"].value = request.jwtSigner->signFromToken(outgoingToken, false);
    }
    else
    {
        if ( authRetCode == REASON_ACCOUNT_NOT_IN_APP )
        {
            // Prevent user/app enumeration:
            authRetCode = REASON_BAD_PASSWORD;
          //  response.setFullStatus(IS_PASSWORD_AUTHENTICATED(authRetCode),IS_PASSWORD_AUTHENTICATED(authRetCode)?Status::S_200_OK : Status::S_401_UNAUTHORIZED, (uint32_t) authRetCode, getReasonText(authRetCode));
        }

        response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(authRetCode), getReasonText(authRetCode));
    }
}


// TODO: - detect multiple logins and block when disallowed.
//       - detect if already logged to the application



















/*
    if ( !identityManager->applications->validateApplicationAccount( appName, accountName ) )
    {
        // Expecting the first scheme ID.
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_WARN, "App:'%s' not registered for user:'%s'.", appName.c_str(), accountName.c_str());
        prepareAuthenticationErrorResponse(response,  REASON_EXPIRED, Mantids30::Network::Protocols::HTTP::Status::S_401_UNAUTHORIZED);
        // TODO: clear the jwt to prevent the jwt reutilization? revocarlo?
        return;
    }

    std::vector<AuthenticationSchemeUsedSlot> authSlots = identityManager->authController->listAuthenticationSlotsUsedByScheme(schemeId);

    // huh, no auth slots? better to answer invalid password.
    if (authSlots.empty())
    {
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_WARN, "No authentication slots for scheme id:'%" PRIu32 "'.", schemeId);
        prepareAuthenticationErrorResponse(response,  REASON_UNAUTHENTICATED, Mantids30::Network::Protocols::HTTP::Status::S_401_UNAUTHORIZED);
        return;
    }

    if (jwtTokenId.empty())
    {
        // no authentication yet.
        // Use the first slot:
        currentSlotPosition = 0;
        slotSchemeHash = Helpers::Crypto::calcSHA256(authSlotsToJSON( authSlots ).toStyledString());
    }
    else
    {
        if (slotSchemeHash != Helpers::Crypto::calcSHA256(authSlotsToJSON( authSlots ).toStyledString()))
        {
            LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_WARN, "Scheme id '%" PRIu32 "' changed during the authentication, aborting.", schemeId);
            prepareAuthenticationErrorResponse(response,  REASON_UNAUTHENTICATED, Mantids30::Network::Protocols::HTTP::Status::S_401_UNAUTHORIZED);
            return;
        }
    }

    if (currentSlotPosition>=authSlots.size())
    {
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Slot position '%" PRIu32 "' hacked on scheme id: '%" PRIu32 "'.", currentSlotPosition, schemeId);
        prepareAuthenticationErrorResponse(response,  REASON_UNAUTHENTICATED, Mantids30::Network::Protocols::HTTP::Status::S_401_UNAUTHORIZED);
        return;
    }

    // Now here we authenticate the credential...
    Reason authRetCode = identityManager->authController->authenticateCredential( authClientDetails,
                                                                                 accountName,
                                                                                 JSON_ASSTRING(*request.inputJSON, "password", ""),
                                                                                 authSlots.at(currentSlotPosition).slotId,
                                                                                 getAuthModeFromString(JSON_ASSTRING(*request.inputJSON, "authMode", "MODE_PLAIN")),
                                                                                JSON_ASSTRING(*request.inputJSON, "challengeSalt", ""));
*/


/*
    std::string password = JSON_ASSTRING(*request.inputJSON, "password", "");
    std::string authMode = JSON_ASSTRING(*request.inputJSON, "authMode", "");
    std::string challengeSalt = JSON_ASSTRING(*request.inputJSON, "challengeSalt", "");

    //uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    bool clearedForAuthentication = false;

    // There are two modes... the first authentication (zero), or the indexed authentication (n)
    if (slotId == 0)
    {
        // Ok... authenticate is cleared to be used with the first entry...
        clearedForAuthentication = true;
        token.setJwtId(Mantids30::Helpers::Random::createRandomString(16));


    }
    else
    {
        // The password SlotId is NOT zero. This is a subsequent authentication.

        // The username is the username used in the JWT (not the provided input)
        accountName = jwtUser;
//        appName = jwtAppName;
        token.setJwtId(tokenId);

        // it should be pre-authenticated...
        if (currentAuthenticatedSlotIds.find(0) != currentAuthenticatedSlotIds.end())
        {
            clearedForAuthentication = true;
        }
        else
        {
            // Otherwise, will not be pre-authed, and you can't try to login with next slotIds. (not cleared).
            LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Can't authenticate slotId=%" PRIu32 " - for application %s without authenticating slotId=0 first", appName.c_str());
            prepareAuthenticationErrorResponse(response,  REASON_PASSWORD_INDEX_NOTFOUND, Mantids30::Network::Protocols::HTTP::Status::S_401_UNAUTHORIZED);
            return;
        }
    }

    response.setSuccess(false);

    if (clearedForAuthentication)
    {
        std::map<uint32_t, std::string> accountAuthenticationSlotsRequiredForLogin;
        auto authRetCode = identityManager->authController->authenticateCredential(appName,
                                                                                   authClientDetails,
                                                                                   username,
                                                                                   password,
                                                                                   slotId,
                                                                                   getAuthModeFromString(authMode),
                                                                                   challengeSalt,
                                                                                   &accountAuthenticationSlotsRequiredForLogin);

        response.setFullStatus(IS_PASSWORD_AUTHENTICATED(authRetCode), (uint32_t) authRetCode, getReasonText(authRetCode));

        (*response.outputPayload())["isFullyAuthenticated"] = false;

        int i = 0;
        for (const auto &v : accountAuthenticationSlotsRequiredForLogin)
        {
            (*response.outputPayload())["accountAuthenticationSlotsRequiredForLogin"][i]["slotId"] = v.first;
            (*response.outputPayload())["accountAuthenticationSlotsRequiredForLogin"][i]["txt"] = v.second;
            i++;
        }

        LOG_APP->log2(__func__,
                      accountName,
                      authClientDetails.ipAddress,
                      authRetCode ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                      "Account Authorization Result: %" PRIu32 " - %s, for application %s",
                      authRetCode,
                      (*response.outputPayload())["statusMessage"].asCString(),
                      JSON_ASSTRING_D(request.jwtToken->getClaim("applicationName"), "").c_str());

        if (IS_PASSWORD_AUTHENTICATED(authRetCode))
        {
            // Password Authenticated... Include...
            currentAuthenticatedSlotIds.insert(slotId);
            if (authRetCode == REASON_EXPIRED_PASSWORD)
            {
                currentExpiredSlotIds.insert(slotId);
            }

            if (areAllSlotIdsAuthenticated(currentAuthenticatedSlotIds, accountAuthenticationSlotsRequiredForLogin))
            {
                // Login completed. Get the full token using /token.
                token.addClaim("isFullyAuthenticated", true);
                (*response.outputPayload())["isFullyAuthenticated"] = true;
            }

        }
    }*/
