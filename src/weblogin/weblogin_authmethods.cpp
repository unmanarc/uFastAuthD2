#include "weblogin_authmethods.h"

#include <Mantids30/Program_Logs/applog.h>
#include <Mantids30/DataFormat_JWT/jwt.h>
#include <Mantids30/Protocol_HTTP/hdr_cookie.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Program_Logs/loglevels.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include <Mantids30/Protocol_HTTP/rsp_status.h>

#include <boost/algorithm/string.hpp>
#include <inttypes.h>
#include <json/value.h>
#include <string>

#include "../globals.h"
#include "logindirectorymanager.h"
#include "IdentityManager/ds_authentication.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;

std::regex WebLogin_AuthMethods::originPattern = std::regex("^(https?://[^/]+)");

void WebLogin_AuthMethods::addMethods(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // AUTHENTICATION FUNCTIONS:

    // The Login does not need previous authentication:
    methods->addResource(MethodsHandler::POST, "preAuthorize", &preAuthorize, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "authorize", &authorize, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "token", &token, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "logout", &logout, nullptr, SecurityOptions::NO_AUTH, {});

    // Account registration:
    methods->addResource(MethodsHandler::POST, "registerAccount", &registerAccount, nullptr, SecurityOptions::NO_AUTH, {});

    // When requested by an external webste, no CSRF challenge could be sent by an external website... So your access token will be used to authenticate the refreshal...
    // In this premise, the refresher cookie is not know by your website (so if your website leaks the data),
    //   will not leak the master authentication cookie (refresher token) that can go to any application under your name.
    //   so... with this accessToken, you can renew, but what if the accessToken is compromised? well...
    //   the only thing you want to do is to limit the amount of time of that access...
    //   then... we should implement some kind of anti-CSRF, tokens are discarded because they are in the same domain of the access token (the browser)
    //   and... what you can do is: to validate the origin/referer.

    // Post-authenticated API:
    methods->addResource(MethodsHandler::POST, "retokenize", &retokenize, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    methods->addResource(MethodsHandler::POST, "getApplicationAuthCallbackURI", &getApplicationAuthCallbackURI, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});

    methods->addResource(MethodsHandler::POST, "refreshAccessToken", &refreshAccessToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    methods->addResource(MethodsHandler::POST, "refreshRefresherToken", &refreshRefresherToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    // The change credential dialog/html needs to send the CSRF challenge:
    methods->addResource(MethodsHandler::POST, "changeCredential", &changeCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    methods->addResource(MethodsHandler::POST, "listCredentials", &listCredentials, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    methods->addResource(MethodsHandler::POST, "accountCredentialPublicData", &accountCredentialPublicData, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});

    // Temporal tokens are also given trough an intermediate window...
    methods->addResource(MethodsHandler::POST, "tempMFAToken", &tempMFAToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    //    methods->addResource("addAccount",{&addAccount,auth});
}

std::set<uint32_t> WebLogin_AuthMethods::getSlotIdsFromJSON(const json &input)
{
    std::set<uint32_t> slotIds;
    for (auto &element : input)
    {
        if (element.isUInt())
            slotIds.insert(element.asUInt());
        else
        {
            // This is an unexpected scenario where an unauthorized user has manipulated the token. The application should immediately terminate for security reasons.
            throw std::invalid_argument("Possible security event detected! The JWT input contains an invalid element. I recommend you to change the JWT keys and figure out how the keys has been leaked...");
        }
    }
    return slotIds;
}

json WebLogin_AuthMethods::getAccountDetails(IdentityManager *identityManager, const std::string &userId)
{
    json accountInfo;

    accountInfo = identityManager->users->getAccountDetails(userId).toJSON();

    return accountInfo;
}

void WebLogin_AuthMethods::configureAccessToken(
    Mantids30::DataFormat::JWT::Token &accessToken, IdentityManager *identityManager, const std::string &refreshTokenId, const std::string &jwtUserId, const std::string &appName, const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds)
{
    auto tokenId = Mantids30::Helpers::Random::createRandomString(16);
    accessToken.setSubject(jwtUserId);
    accessToken.setIssuedAt(time(nullptr));
    auto expectedExpirationTime = time(nullptr) + tokenProperties.accessTokenTimeout;
    auto accountExpirationTime = identityManager->users->getAccountExpirationTime(jwtUserId);

    if (accountExpirationTime==0 || accountExpirationTime>=expectedExpirationTime)
    {
        // We can safely use the expected token expiration time
        accessToken.setExpirationTime(expectedExpirationTime);
    }
    else
    {
        // The account expires before, so the tokens need to expire before:
        accessToken.setExpirationTime(accountExpirationTime);
    }

    accessToken.setNotBefore(time(nullptr) - 30);
    accessToken.addClaim("sessionInactivityTimeout", tokenProperties.sessionInactivityTimeout);
    accessToken.addClaim("slotIds", Mantids30::Helpers::setToJSON(slotIds));
    accessToken.setJwtId(tokenId);
    accessToken.addClaim("parentTokenId", refreshTokenId);
    accessToken.addClaim("app", appName);

    // Get the user permissions if needed for this application...
    if (tokenProperties.includeApplicationPermissionsInToken)
    {
        auto x = identityManager->authController->getAccountUsableApplicationPermissions(jwtUserId);
        for (const auto &i : x)
        {
            if (i.appName == appName)
            {
                accessToken.addPermission(i.permissionId);
            }
        }
    }
    // Get the user basic info if needed for this application...
    if (tokenProperties.includeBasicUserInfoInToken)
    {
        accessToken.addClaim("accountInfo", getAccountDetails(identityManager, jwtUserId));
    }

    if (identityManager->users->getAccountFlags(jwtUserId).superuser)
        accessToken.addClaim("isAdmin", true);
}

void WebLogin_AuthMethods::configureRefresherToken(APIReturn &response,
                                                   const RequestParameters &request,
                                                   IdentityManager *identityManager,
                                                   const std::string &refreshTokenId,
                                                   const std::string &userId,
                                                   const std::set<uint32_t> &currentAuthenticatedSlotIds)
{
 //   json *jOutput = response.body->getValue();

    // TODO: multi-app login, si ya estabas logeado con otra app, entonces debes fusionar los tokens...

    DataFormat::JWT::Token refresherToken;
    auto accountExpirationTime = identityManager->users->getAccountExpirationTime(userId);
    uint32_t expectedRefresherTokenTimeoutTime = time(nullptr) + Globals::getConfig()->get<uint32_t>("WebLoginService.RefreshTokenTimeout", 2592000);

    refresherToken.setSubject(userId);
    refresherToken.setIssuedAt(time(nullptr));
    refresherToken.setExpirationTime((accountExpirationTime < expectedRefresherTokenTimeoutTime && accountExpirationTime!=0) ? accountExpirationTime : expectedRefresherTokenTimeoutTime);
    refresherToken.setNotBefore(time(nullptr) - 30);
    refresherToken.addClaim("slotIds", Mantids30::Helpers::setToJSON(currentAuthenticatedSlotIds));
    refresherToken.addClaim("type", "refresher");
    refresherToken.setJwtId(refreshTokenId);

    std::string sAuthToken = request.jwtSigner->signFromToken(refresherToken, false);

    // Keep the auth refresher token here:
    response.cookiesMap["AccessToken"] = Headers::Cookie();
    response.cookiesMap["AccessToken"].setExpiration( refresherToken.getExpirationTime() );
    response.cookiesMap["AccessToken"].secure = true;
    response.cookiesMap["AccessToken"].httpOnly = true;
    response.cookiesMap["AccessToken"].value = sAuthToken ;

    response.cookiesMap["loggedIn"] = Headers::Cookie();
    response.cookiesMap["loggedIn"].setExpiration( refresherToken.getExpirationTime() );
    response.cookiesMap["loggedIn"].secure = true;
    response.cookiesMap["loggedIn"].httpOnly = false;
    response.cookiesMap["loggedIn"].path= "/";
    response.cookiesMap["loggedIn"].value = std::to_string(refresherToken.getExpirationTime()) ;
}

bool WebLogin_AuthMethods::validateAccountForNewToken(IdentityManager *identityManager, const std::string &jwtUserId, Reason &reason, const std::string &appName, bool checkValidAppAccount)
{
    // First, check if the account is disabled, unconfirmed, or expired.

    auto accountFlags = identityManager->users->getAccountFlags(jwtUserId);

    if (!accountFlags.enabled)
    {
        reason = Reason::REASON_DISABLED_ACCOUNT;
        return false;
    }
    else if (!accountFlags.confirmed)
    {
        reason = Reason::REASON_UNCONFIRMED_ACCOUNT;
        return false;
    }
    else if (identityManager->users->isAccountExpired(jwtUserId))
    {
        reason = Reason::REASON_EXPIRED_ACCOUNT;
        return false;
    }

    // If checkValidAppAccount is true, check if the account is valid for the specified application.
    if (checkValidAppAccount && !identityManager->applications->validateApplicationAccount(appName, jwtUserId))
    {
        reason = Reason::REASON_BAD_ACCOUNT;
        return false;
    }

    // If all checks pass, the account is valid for refreshing the token.
    return true;
}
std::string WebLogin_AuthMethods::signAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties, const std::string &appName)
{
    DataFormat::JWT::AlgorithmDetails algorithmDetails(tokenProperties.tokenType.c_str());
    DataFormat::JWT jwtAccessSigner(algorithmDetails.algorithm);
    auto signingKey = Globals::getIdentityManager()->applications->getWebLoginJWTSigningKeyForApplication(appName);

    if (algorithmDetails.isUsingHMAC)
    {
        jwtAccessSigner.setSharedSecret(signingKey);
    }
    else
    {
        jwtAccessSigner.setPrivateSecret(signingKey);
    }

    return jwtAccessSigner.signFromToken(accessToken, false);
}

Status::eRetCode WebLogin_AuthMethods::handleDynamicRequest(const std::string &appName, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response)
{
    std::string page;
    auto status = Globals::getLoginDirManager()->retrieveFile(appName, page);
    bool originValidated = retrieveAndValidateAppOrigin(request, appName,USING_HEADER_REFERER);
    auto currentOrigin = request->getHeaderOption("Origin");

    if (status != LoginDirectoryManager::ErrorCode::SUCCESS)
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_WARN, "Failed to obtain the HTML for application '%s': %s", appName.c_str(), LoginDirectoryManager::getErrorMessage(status).c_str());
        return Status::S_404_NOT_FOUND;
    }

    if (!originValidated)
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_SECURITY_ALERT, "Not allowed origin '%s' for application '%s'", currentOrigin.c_str(), appName.c_str());

        return Status::S_403_FORBIDDEN;
    }

    LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_INFO, "HTML Login for application '%s' requested from '%s'", appName.c_str(), currentOrigin.c_str());

    response->content.writer()->writeString(page);
    response->setContentType("text/html");

    return Status::S_200_OK;
}
bool WebLogin_AuthMethods::retrieveAndValidateAppOrigin(Mantids30::Network::Protocols::HTTP::HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource)
{
    auto origins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appName);

    std::string currentOrigin;
    if (originSource == USING_HEADER_ORIGIN)
    {
        currentOrigin = request->getHeaderOption("Origin");
    }
    else if (originSource == USING_HEADER_REFERER)
    {
        std::string referer = request->getHeaderOption("Referer");
        std::smatch matches;
        if (std::regex_search(referer, matches, originPattern) && matches.size() > 1)
        {
            currentOrigin = matches[1].str(); // Extrae solo la parte del dominio y el esquema.
        }
    }

    // Validate the origin...
    bool originValidated = false;
    for (const auto &origin : origins)
    {
        if (currentOrigin == origin)
        {
            originValidated = true;
            break;
        }
    }
    return originValidated;
}

// TODO: entregar una tabla de los slotIds que requiere una permission específico...
// TODO: block my account (and temporary external link to do so in case of account compromise)
// TODO: mail o mensaje de "ha sido logeado"
// TODO: default return url?
// TODO: hacer servicio que permita identificar tokens invalidados (o servicio de redistribución de estos en real time)
// TODO: hacer servicio de personalizacion de la app por usuario en bg... (la app podra consultar y modificar via una api parametros extra del usuario)
// TODO: la app no tiene porque manejar el token de refresh, podría ir en un cookie sobre el dominio del IAM?, como hacemos para que la app pueda refrescar este token? cuando sea mayor a 1/2 del tiempo de vida? (puede solicitarlo cada 1hr por ejemplo y que esta app se encargue de refrescarlo)
// TODO: poner el account expiration date dentro del token
// TODO: puede ser que el refresher no quieras dejarlo refrescarse a si mismo y obligar a reautenticar cada cierto tiempo?...
// TODO: implementación de "remember me"
// TODO: geolocalizacion en el login? (LOWPRIO)
// TODO: account personalization image. (LOWPRIO)
// TODO: directory personalization... (LOWPRIO)
// TODO: mensaje a cuenta... (LOWPRIO)
// TODO: API REST para recibir archivos... (no todo es JSON)
// TODO: list current logins
// TODO: list brief login history
// TODO: logout...
// TODO: redirecciones de regreso
// TODO: opción de una sesión por usuario (en la app)
// TODO: implement navigator fingerprint security as a claim (including ip address)...
// TODO: logearse en sitio web desde una app de celular que escanee un QR code...
