#include "defs.h"
#include "weblogin_authmethods.h"

#include "../globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;


void WebLogin_AuthMethods::refreshRefresherToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    // INPUT DATA:
   /* std::string appName = DB_APPNAME;
    // JWT Info.
    if (retrieveAndValidateAccessTokenFromInputData(request, appName) && retrieveAndValidateAppOrigin(request.clientRequest, appName,USING_HEADER_ORIGIN))
    {
        IdentityManager *identityManager = Globals::getIdentityManager();

        // JWT Info.
        std::string jwtUserId = request.jwtToken->getSubject();
        std::set<uint32_t> currentAuthenticatedSlotIds = getSlotIdsFromJSON(request.jwtToken->getClaim("slotIds"));

        Reason reason = REASON_INTERNAL_ERROR;
        if (!validateAccountForNewToken(identityManager, jwtUserId, reason, "", false))
        {
            // This token is not available for retrieving app tokens...
            LOG_APP->log2(__func__, jwtUserId, authClientDetails.ipAddress, Logs::LEVEL_WARN, "The account '%s' can't refresh the refresh token.", jwtUserId.c_str());
            prepareAuthenticationErrorResponse(response,  reason, Mantids30::Network::Protocols::HTTP::Status::S_401_UNAUTHORIZED);
            return;
        }

        // The token is valid here...
        // TODO: invalidar todos los tokens viejos que su parent sea este refresher...
        // TODO: guardar los tokens en una db interna para el logout (no hacer ahorita)

        auto refreshTokenId = Mantids30::Helpers::Random::createRandomString(16);

        auto tokenHalfLifeSeconds = (request.jwtToken->getExpirationTime() - request.jwtToken->getIssuedAt()) / 2;
        auto tokenHalfLifePoint = request.jwtToken->getIssuedAt() + tokenHalfLifeSeconds;

        if (time(nullptr) > tokenHalfLifePoint)
        {
            configureRefresherToken(response, request, identityManager, refreshTokenId, jwtUserId, currentAuthenticatedSlotIds);
            response.setSuccess(true);
        }
        else
        {
            response.setSuccess(false);
            // don't refresh this token (not needed)...
        }
        return;
    }*/

    // TODO: fix / check
    response.setError( Status::S_401_UNAUTHORIZED,"unauthorized", "Invalid Access Token");
}
