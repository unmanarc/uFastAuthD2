#include "weblogin_authmethods.h"

#include "../globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;



void WebLogin_AuthMethods::listCredentials(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    // JWT INPUTS:
    std::string jwtUserId = request.jwtToken->getSubject();
    std::string app = JSON_ASSTRING_D(request.jwtToken->getClaim("app"),"");
    std::map<uint32_t, Credential> r;

    if (identityManager->applications->validateApplicationAccount(app, jwtUserId))
    {
        // PROCESS DATA:
        r = identityManager->authController->getAccountAllCredentialsPublicData(jwtUserId);
        for (const auto &publicData : r)
        {

            (*response.outputPayload())[std::to_string(publicData.first)] = publicData.second.toJSON(identityManager->authController->getAuthenticationPolicy());
        }
    }

    if (r.empty())
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"no_credentials","No detected credentials");
    // RETURN...
}
