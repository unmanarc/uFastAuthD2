#include <Mantids30/Helpers/json.h>
#include "weblogin_authmethods.h"

#include "../globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;

// Validate user and get auth:
void WebLogin_AuthMethods::preAuthorize(void *context,
                                     APIReturn &response,
                                     const Mantids30::API::RESTful::RequestParameters &request,
                                     Mantids30::Sessions::ClientDetails &authClientDetails)
{
    // Environment:
    DataFormat::JWT::Token token;
    IdentityManager *identityManager = Globals::getIdentityManager();

    //  Configuration parameters:
    auto config = Globals::getConfig();
    uint32_t loginAuthenticationTimeout = config->get<uint32_t>("WebLoginService.AuthenticationTimeout", 300);

    // Input parameters:
    std::string app = JSON_ASSTRING(*request.inputJSON, "app", "");           // APPNAME.
    std::string username = JSON_ASSTRING(*request.inputJSON, "accountName", ""); // USER.
    std::string activity = JSON_ASSTRING(*request.inputJSON, "activity", ""); // APP ACTIVITY NAME.

    if ( ! identityManager->applications->doesApplicationExist(app) )
    {
        response.setError( Status::S_404_NOT_FOUND,"not_found", "Invalid Application");
        return;
    }

    (*response.responseJSON()) = identityManager->authController->getApplicableAuthenticationSchemesForUser(app,activity,username);
    (*response.responseJSON())["loginAuthenticationTimeout"] = loginAuthenticationTimeout;
}
