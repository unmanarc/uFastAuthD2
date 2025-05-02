#include <Mantids30/Helpers/json.h>
#include "weblogin_authmethods.h"

#include <json/config.h>
#include <algorithm> // std::find

#include "../globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;

// Get the application token...
void WebLogin_AuthMethods::token(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    // Configuration parameters:
    IdentityManager *identityManager = Globals::getIdentityManager();
    DataFormat::JWT::Token accessToken, refreshToken;

    if (!request.jwtToken->getSubject().empty())
    {
        // Already logged in.
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, request.jwtToken->getSubject(), authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Application token retrieval attempt denied: Token already issued for this user/application.");
        response.setError(Status::S_400_BAD_REQUEST,"AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), getReasonText(REASON_BAD_PARAMETERS));
        return;
    }

    // JWT Info.
    std::string jwtPreAuthUser = JSON_ASSTRING_D(request.jwtToken->getClaim("preAuthUser"), "");
    std::string jwtPreAuthApp = JSON_ASSTRING_D(request.jwtToken->getClaim("applicationName"), "");
    std::set<uint32_t> currentAuthenticatedSlotIds = getSlotIdsFromJSON(request.jwtToken->getClaim("slotIds"));

    // DB Info:
    auto tokenProperties = identityManager->applications->getWebLoginJWTConfigFromApplication(jwtPreAuthApp);

    if (!DataFormat::JWT::isAlgorithmSupported(tokenProperties.tokenType))
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, jwtPreAuthUser, authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.", jwtPreAuthApp.c_str());
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"AUTH_ERR_" + std::to_string(REASON_INTERNAL_ERROR), getReasonText(REASON_INTERNAL_ERROR));
        return;
    }

    // Validate the token...
    if (!request.jwtToken->hasClaim("isFullyAuthenticated"))
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, jwtPreAuthUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: User attempted to obtain a token without presenting all required credentials.", jwtPreAuthUser.c_str());
        response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(REASON_UNAUTHENTICATED), getReasonText(REASON_UNAUTHENTICATED));
        return;
    }

    std::list<std::string> redirectURIs = identityManager->applications->listWebLoginRedirectURIsFromApplication(jwtPreAuthApp);
    std::string redirectURI = JSON_ASSTRING(*request.inputJSON, "redirectURI", "");
    // Verificar si el valor no está en la lista
    if (!redirectURI.empty() && std::find(redirectURIs.begin(), redirectURIs.end(), redirectURI) == redirectURIs.end())
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, jwtPreAuthUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid return URL '%s': The provided URI does not match any recognized redirect URIs for application '%s'.", redirectURI.c_str(), jwtPreAuthApp.c_str());
        response.setError(Status::S_406_NOT_ACCEPTABLE,"AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), getReasonText(REASON_BAD_PARAMETERS));
        return;
    }

    auto refreshTokenId = Mantids30::Helpers::Random::createRandomString(16);

    configureAccessToken(accessToken, identityManager, refreshTokenId, jwtPreAuthUser, jwtPreAuthApp, tokenProperties, currentAuthenticatedSlotIds);
    configureRefresherToken(response, request, identityManager, refreshTokenId, jwtPreAuthUser, currentAuthenticatedSlotIds);

    // TODO: guardar los tokens en una db interna para el logout (no hacer ahorita)
    (*response.responseJSON())["accessToken"] = signAccessToken(accessToken, tokenProperties, jwtPreAuthApp);
    (*response.responseJSON())["callbackURI"] = identityManager->applications->getAuthCallbackURIFromApplication(jwtPreAuthApp);
    (*response.responseJSON())["expiresIn"] = (Json::UInt64) (accessToken.getExpirationTime() - time(nullptr));

    // TODO: la información que requiere la APP para operar, es la configuración de los privilegios, los requisitos de 2nd factor para ciertos privilegios
    /**
     * La app en sí conoce sus privilegios... pero no sabe que privilegios cuenta el usuario
     * entonces si, hay que entregar (esta en el token) que privilegios tiene el usuario
     *
     * lo que ocurre es que de vez en cuando un privilegio de la app solo se puede adquirir cuando se desactiva un slotIds específico (hay que modificar la db para esto)
     * entonces... sería como una especie de privilegio que si tiene el usuario (por ejemplo, hacer transferencias), pero requiere un id específico (privilegio->pass slotId requerido?)
     *
     *
     * great aaron, lo que hicimos fue app activities, en este caso, una persona logeada
    */
}

