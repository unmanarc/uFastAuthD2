#include "weblogin_authmethods.h"

#include "../globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;

void WebLogin_AuthMethods::getApplicationAuthCallbackURI(
    void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();


    // JWT INPUTS:
    std::string jwtUserId = request.jwtToken->getSubject();

    // JSON INPUTS:
    std::string appName = JSON_ASSTRING(*request.inputJSON,"app", "");
    std::string callbackURI = identityManager->applications->getAuthCallbackURIFromApplication(appName);

    // We need a callback URL.
    if ( callbackURI.empty() )
    {
        response.setError( Status::S_500_INTERNAL_SERVER_ERROR,"unexpected_error", "Invalid APP or not configured.");
        return;
    }

    std::list<std::string> redirectURIs = identityManager->applications->listWebLoginRedirectURIsFromApplication(appName);
    std::string redirectURI = JSON_ASSTRING(*request.inputJSON, "redirectURI", "");

    // Check if the value is not in the list.
    if (!redirectURI.empty() && std::find(redirectURIs.begin(), redirectURIs.end(), redirectURI) == redirectURIs.end())
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, jwtUserId, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid return URL '%s': The provided URI does not match any recognized redirect URIs for application '%s'.", redirectURI.c_str(), appName.c_str());
        response.setError(Status::S_406_NOT_ACCEPTABLE,"AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), getReasonText(REASON_BAD_PARAMETERS));
        return;
    }


    (*response.outputPayload())["callbackURI"] = callbackURI;
}
