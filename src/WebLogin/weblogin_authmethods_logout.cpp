#include <Mantids30/Helpers/json.h>
#include "weblogin_authmethods.h"

using namespace Mantids30;
using namespace API::RESTful;
using namespace Network::Protocols;

// Get the application token...

void WebLogin_AuthMethods::logout(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    response.cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessToken"].setAsTransientCookie();
    response.cookiesMap["AccessToken"].value = "";

    response.cookiesMap["loggedIn"] = HTTP::Headers::Cookie();
    response.cookiesMap["loggedIn"].setAsTransientCookie();
    response.cookiesMap["loggedIn"].path = "/";
    response.cookiesMap["loggedIn"].value = "";
}
