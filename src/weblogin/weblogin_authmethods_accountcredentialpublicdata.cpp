#include "weblogin_authmethods.h"

#include "../globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;


void WebLogin_AuthMethods::accountCredentialPublicData(
    void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();
    auto user = request.jwtToken->getSubject();
    auto slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    if (identityManager->applications->validateApplicationAccount(JSON_ASSTRING_D(request.jwtToken->getClaim("app"), ""), user))
    {
        auto v = identityManager->authController->getAccountCredentialPublicData(user, slotId);
        (*response.responseJSON()) = v.toJSON(identityManager->authController->getAuthenticationPolicy());
    }
}


