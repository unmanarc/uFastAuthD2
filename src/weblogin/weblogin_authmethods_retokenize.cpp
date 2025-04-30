#include "IdentityManager/ds_authentication.h"
#include "weblogin_authmethods.h"

#include <Mantids30/Helpers/json.h>
#include <json/config.h>
// #include <algorithm> // std::find

#include "../globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;

// Get the application token...
void WebLogin_AuthMethods::retokenize(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    // Configuration parameters:
    IdentityManager *identityManager = Globals::getIdentityManager();

    // JSON Input.
    std::string appName = JSON_ASSTRING(*request.inputJSON, "app", "");
    std::string redirectURI = JSON_ASSTRING(*request.inputJSON, "redirectURI", "");

    // JWT Info.
    std::string accountName = request.jwtToken->getSubject();
    Json::Value jAuthenticatedSlotIds = request.jwtToken->getClaim("slotIds");
    std::string tokenType = JSON_ASSTRING_D(request.jwtToken->getClaim("type"),"");

    // Validate the refresher token...
    if (!request.jwtToken->hasClaim("type"))
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Trying to retokenize without being fully logged in (1).");
        response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
        return;
    }

    if (tokenType!="refresher")
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Trying to retokenize without being fully logged in (2).");
        response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
        return;
    }

    if (accountName.empty())
    {
        // Already logged in.
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Trying to retokenize without being fully logged in (3).");
        response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
        return;
    }

    // Validate that the user belongs to the application.
    if ( ! identityManager->applications->validateApplicationAccount( appName, accountName )  )
    {
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Unauthorized access attempt: User is not associated with the application '%s'.", appName.c_str());
        response.setError(Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(REASON_ACCOUNT_NOT_IN_APP), getReasonText(REASON_ACCOUNT_NOT_IN_APP));
        return;
    }

    // Admitted APP redirect URI's
    std::list<std::string> redirectURIs = identityManager->applications->listWebLoginRedirectURIsFromApplication(appName);

    // Verify if the URI is not in the list.
    if (!redirectURI.empty() && std::find(redirectURIs.begin(), redirectURIs.end(), redirectURI) == redirectURIs.end())
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid return URL '%s': The provided URI does not match any recognized redirect URIs for application '%s'.", redirectURI.c_str(), appName.c_str());
        response.setError(Status::S_403_FORBIDDEN,"AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), getReasonText(REASON_BAD_PARAMETERS));
        return;
    }

    std::set<uint32_t>  schemes = identityManager->authController->listAuthenticationSchemesForApplicationActivity( appName, "LOGIN" );

    // Iterate over each scheme to check required slots
    for (const auto& schemeId : schemes)
    {
        std::vector<AuthenticationSchemeUsedSlot> requiredSlots = identityManager->authController->listAuthenticationSlotsUsedByScheme(schemeId);

        // Retrieve and verify authentication slots required by each scheme. 
        std::set<uint32_t> requiredSlotsIds, authenticatedSlotsIdsSet;
        for ( auto & slot : requiredSlots )
        {
            requiredSlotsIds.insert(slot.slotId);
        }

        // Check if all required slots are present in the authenticated slots
        if ( !jAuthenticatedSlotIds.isNull() && jAuthenticatedSlotIds.isArray() )
        {
            for (const auto& slot : jAuthenticatedSlotIds)
            {
                authenticatedSlotsIdsSet.insert(slot.asUInt());
            }
        }

        // Remove authenticated slots from the required set.
        for ( const auto & slotId : authenticatedSlotsIdsSet)
        {
            requiredSlotsIds.erase(slotId);
        }

        // If the scheme is fully authenticated, deliver the token to the application.
        if (requiredSlotsIds.empty())
        {
            // Great, we can deliver the app token here because the application is configured...

            // Get the token properties:
            auto tokenProperties = identityManager->applications->getWebLoginJWTConfigFromApplication(appName);

            if (!DataFormat::JWT::isAlgorithmSupported(tokenProperties.tokenType))
            {
                // This token is not available for retrieving app tokens...
                LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.", appName.c_str());
                response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
                return;
            }

            DataFormat::JWT::Token accessToken;
            configureAccessToken(accessToken, identityManager, request.jwtToken->getJwtId(), accountName, appName, tokenProperties, authenticatedSlotsIdsSet);

            (*response.responseJSON())["accessToken"] = signAccessToken(accessToken, tokenProperties, appName);
            (*response.responseJSON())["callbackURI"] = identityManager->applications->getAuthCallbackURIFromApplication(appName);
            (*response.responseJSON())["expiresIn"] = (Json::UInt64) (accessToken.getExpirationTime() - time(nullptr));

            return;
        }
    }

    // If none of the schemes have required slots met
    LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Authenticated slots are not enough to trigger any valid authentication scheme found for application '%s'.", appName.c_str());
    response.setError(Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
    return;
}
