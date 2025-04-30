#include "IdentityManager/ds_authentication.h"
#include <Mantids30/Helpers/json.h>
#include "Mantids30/Program_Logs/loglevels.h"
#include "weblogin_authmethods.h"

#include "../globals.h"
#include <json/config.h>
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
    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();
    // Vector to store the authentication slots used by a particular scheme.
    std::vector<AuthenticationSchemeUsedSlot> authSlots;
    // Retrieve configuration parameters from global settings.
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
                  response.getErrorString().c_str(),
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
            // Report that it's fully authenticated (all slots id's from the scheme were authenticated OK).
            outgoingToken.addClaim("isFullyAuthenticated", true);

            // Create a Json::Value array to store slot IDs
            Json::Value slotIds(Json::arrayValue);
            for(const auto& slot : authSlots)
            {
                slotIds.append((Json::UInt)slot.slotId);
            }
            outgoingToken.addClaim("slotIds", slotIds);

            (*response.responseJSON())["isFullyAuthenticated"] = true;
        }
        else
        {
            (*response.responseJSON())["isFullyAuthenticated"] = false;
            outgoingToken.addClaim("isFullyAuthenticated", false);
            outgoingToken.addClaim("currentSlotPosition", authContext->currentSlotPosition+1);

            // We can give the credential public data for the next credential:
            Credential publicData = identityManager->authController->getAccountCredentialPublicData(accountName,authSlots[authContext->currentSlotPosition+1].slotId);
            (*response.responseJSON())["credentialPublicData"] = publicData.toJSON( identityManager->authController->getAuthenticationPolicy() );

        }
        response.cookiesMap["AccessToken"] = Headers::Cookie();
        response.cookiesMap["AccessToken"].secure = true;
        response.cookiesMap["AccessToken"].httpOnly = true;
        response.cookiesMap["AccessToken"].setExpirationFromNow(loginAuthenticationTimeout); // 2min expiration...
        response.cookiesMap["AccessToken"].value = request.jwtSigner->signFromToken(outgoingToken, false);
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











