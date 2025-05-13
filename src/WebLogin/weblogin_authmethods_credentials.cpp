#include "weblogin_authmethods.h"

#include "../globals.h"

#include <inttypes.h>

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

void WebLogin_AuthMethods::accountCredentialPublicData(
    void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();
    auto accountName = request.jwtToken->getSubject();
    auto slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    if (identityManager->applications->validateApplicationAccount(JSON_ASSTRING_D(request.jwtToken->getClaim("app"), ""), accountName))
    {
        auto v = identityManager->authController->getAccountCredentialPublicData(accountName, slotId);
        (*response.responseJSON()) = v.toJSON(identityManager->authController->getAuthenticationPolicy());
    }
}




void WebLogin_AuthMethods::listCredentials(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    // JWT INPUTS:
    std::string jwtAccountName = request.jwtToken->getSubject();
    std::string app = JSON_ASSTRING_D(request.jwtToken->getClaim("app"),"");
    std::map<uint32_t, Credential> r;

    if (identityManager->applications->validateApplicationAccount(app, jwtAccountName))
    {
        // PROCESS DATA:
        r = identityManager->authController->getAccountAllCredentialsPublicData(jwtAccountName);
        for (const auto &publicData : r)
        {

            (*response.responseJSON())[std::to_string(publicData.first)] = publicData.second.toJSON(identityManager->authController->getAuthenticationPolicy());
        }
    }

    if (r.empty())
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR,"no_credentials","No detected credentials");
    // RETURN...
}


void WebLogin_AuthMethods::changeCredential(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    // JWT INPUTS:
    std::string jwtAccountName = request.jwtToken->getSubject();

    // JSON INPUTS:
    std::string appName = JSON_ASSTRING_D(request.jwtToken->getClaim("app"), ""); // Logged in in some app...
    std::string oldPassword = JSON_ASSTRING(*request.inputJSON, "oldPassword", "");
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);
    std::string authMode = JSON_ASSTRING(*request.inputJSON, "authMode", "");
    std::string challengeSalt = JSON_ASSTRING(*request.inputJSON, "challengeSalt", "");

    Credential newCredential = Credential::createFromJSON((*request.inputJSON)["newCredential"]);
    // ACTION:
    bool changed = false;

    if (identityManager->applications->validateApplicationAccount(appName, jwtAccountName))
    {
        //const std::string &accountName, uint32_t slotId, const std::string &sCurrentPassword, const Credential &passwordData, const Sessions::ClientDetails &clientInfo, Mode authMode, const std::string &challengeSalt)
        if (identityManager->authController->changeAccountAuthenticatedCredential(jwtAccountName, slotId, oldPassword, newCredential, authClientDetails, getAuthModeFromString(authMode), challengeSalt))
        {
            changed = true;
            // response with 200.
        }
        else
        {
            response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR,"unexpected_error", "Failed.");
        }
    }
    else
    {
        response.setError(HTTP::Status::S_401_UNAUTHORIZED,"unauthorized", "The account does not belong to the application");
    }

    LOG_APP->log2(__func__, request.jwtToken->getSubject(), authClientDetails.ipAddress, changed ? Logs::LEVEL_INFO : Logs::LEVEL_WARN, "Account Change Authentication Result: %" PRIu8, changed ? 1 : 0);
    // RETURN...
}
