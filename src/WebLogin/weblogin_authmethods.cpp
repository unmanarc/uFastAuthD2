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
#include <json/value.h>
#include <string>

#include "../globals.h"
#include "logindirectorymanager.h"
#include "IdentityManager/ds_authentication.h"

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::DataFormat;

std::regex WebLogin_AuthMethods::originPattern = std::regex("^(https?://[^/]+)");

void WebLogin_AuthMethods::addMethods(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // AUTHENTICATION FUNCTIONS:

    // Web triggered events:
    methods->addResource(MethodsHandler::POST, "webapp/auth/logout", &appLogout, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "webapp/auth/token", &token, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "webapp/auth/refreshAccessToken", &refreshAccessToken, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "webapp/auth/refreshRefresherToken", &refreshRefresherToken, nullptr, SecurityOptions::NO_AUTH, {});

    // TODO: cuando requiere REQUIRE_JWT_COOKIE_AUTH implica que necesita validar que la aplicación sea la correcta (configurada)

    // The Login does not need previous authentication:
    methods->addResource(MethodsHandler::POST, "preAuthorize", &preAuthorize,   nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "authorize",    &authorize,      nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "logout",       &logout,         nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});

    // Account registration:
    //methods->addResource(MethodsHandler::POST, "registerAccount", &registerAccount, nullptr, SecurityOptions::NO_AUTH, {});

    // When requested by an external webste, no CSRF challenge could be sent by an external website... So your access token will be used to authenticate the refreshal...
    // In this premise, the refresher cookie is not know by your website (so if your website leaks the data),
    //   will not leak the master authentication cookie (refresher token) that can go to any application under your name.
    //   so... with this accessToken, you can renew, but what if the accessToken is compromised? well...
    //   the only thing you want to do is to limit the amount of time of that access...
    //   then... we should implement some kind of anti-CSRF, tokens are discarded because they are in the same domain of the access token (the browser)
    //   and... what you can do is: to validate the origin/referer.

    // Post-authenticated API:
    //methods->addResource(MethodsHandler::POST, "retokenize", &retokenize, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    // The change credential dialog/html needs to send the CSRF challenge:
    methods->addResource(MethodsHandler::POST, "changeCredential", &changeCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    methods->addResource(MethodsHandler::POST, "listCredentials", &listCredentials, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    methods->addResource(MethodsHandler::POST, "accountCredentialPublicData", &accountCredentialPublicData, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});

    // Temporal tokens are also given trough an intermediate window...
    //methods->addResource(MethodsHandler::POST, "tempMFAToken", &tempMFAToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {});
    //    methods->addResource("addAccount",{&addAccount,auth});
}

bool WebLogin_AuthMethods::validateAPIKey(
    const std::string &app, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Sessions::ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    // Check if the token generation is called within the app context:
    std::string apiKey = request.clientRequest->headers.getOptionValueStringByName("x-api-key");

    // Check if the token generation is called within the app context:
    std::string dbApiKey = identityManager->applications->getApplicationAPIKey(app);

    if (dbApiKey.empty())
    {
        LOG_APP->log2(__func__, request.jwtToken->getSubject(), authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Application '%s' does not exist. Pre-Auth JWT Token signature may be compromised!! Change immediately!", app.c_str());
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(REASON_BAD_PARAMETERS), getReasonText(REASON_BAD_PARAMETERS));
        return false;
    }

    if (dbApiKey != apiKey)
    {
        LOG_APP->log2(__func__, request.jwtToken->getSubject(), authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Application '%s' does not match the web application API Key. Attack or misconfiguration?", app.c_str());
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "Not Found.");
        return false;
    }

    return true;
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

json WebLogin_AuthMethods::getAccountDetails(IdentityManager *identityManager, const std::string &accountName)
{
    json accountInfo;

    accountInfo = identityManager->accounts->getAccountDetails(accountName).toJSON();

    return accountInfo;
}

void WebLogin_AuthMethods::configureAccessToken(
    JWT::Token &accessToken, IdentityManager *identityManager, const std::string &refreshTokenId, const std::string &jwtAccountName, const std::string &appName, const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds)
{
    auto tokenId = Mantids30::Helpers::Random::createRandomString(16);
    accessToken.setSubject(jwtAccountName);
    accessToken.setIssuedAt(time(nullptr));
    auto expectedExpirationTime = time(nullptr) + tokenProperties.accessTokenTimeout;
    auto accountExpirationTime = identityManager->accounts->getAccountExpirationTime(jwtAccountName);

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
    if (tokenProperties.includeApplicationPermissions)
    {
        auto x = identityManager->authController->getAccountUsableApplicationPermissions(jwtAccountName);
        for (const auto &i : x)
        {
            if (i.appName == appName)
            {
                accessToken.addPermission(i.permissionId);
            }
        }
    }
    // Get the user basic info if needed for this application...
    if (tokenProperties.includeBasicAccountInfo)
    {
        accessToken.addClaim("accountInfo", getAccountDetails(identityManager, jwtAccountName));
    }

    if (identityManager->accounts->getAccountFlags(jwtAccountName).admin)
        accessToken.addClaim("isAdmin", true);
}

void WebLogin_AuthMethods::configureRefreshToken(
    JWT::Token &refreshToken, IdentityManager *identityManager, const std::string &refreshTokenId, const std::string &jwtAccountName, const std::string &appName, const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds)
{
    refreshToken.setSubject(jwtAccountName);
    refreshToken.setIssuedAt(time(nullptr));

    auto expectedExpirationTime = time(nullptr) + tokenProperties.refreshTokenTimeout;
    auto accountExpirationTime = identityManager->accounts->getAccountExpirationTime(jwtAccountName);

    if (accountExpirationTime==0 || accountExpirationTime>=expectedExpirationTime)
    {
        // We can safely use the expected token expiration time
        refreshToken.setExpirationTime(expectedExpirationTime);
    }
    else
    {
        // The account expires before, so the tokens need to expire before:
        refreshToken.setExpirationTime(accountExpirationTime);
    }

    refreshToken.setNotBefore(time(nullptr) - 30);
    refreshToken.addClaim("slotIds", Mantids30::Helpers::setToJSON(slotIds));
    refreshToken.setJwtId(refreshTokenId);
    refreshToken.addClaim("app", appName);
    refreshToken.addClaim("refresher", true);
}

void WebLogin_AuthMethods::configureIAMAccessToken(APIReturn &response,
                                                   const RequestParameters &request,
                                                   IdentityManager *identityManager,
                                                   const std::string &refreshTokenId,
                                                   const std::string &accountName,
                                                   const std::set<uint32_t> &currentAuthenticatedSlotIds)
{
 //   json *jOutput = response.body->getValue();

    // TODO: multi-app login, si ya estabas logeado con otra app, entonces debes fusionar los tokens...

    JWT::Token refresherToken;
    auto accountExpirationTime = identityManager->accounts->getAccountExpirationTime(accountName);
    uint32_t expectedRefresherTokenTimeoutTime = time(nullptr) + Globals::getConfig()->get<uint32_t>("WebLoginService.RefreshTokenTimeout", 2592000);

    refresherToken.setSubject(accountName);
    refresherToken.setIssuedAt(time(nullptr));
    refresherToken.setExpirationTime((accountExpirationTime < expectedRefresherTokenTimeoutTime && accountExpirationTime!=0) ? accountExpirationTime : expectedRefresherTokenTimeoutTime);
    refresherToken.setNotBefore(time(nullptr) - 30);
    refresherToken.addClaim("slotIds", Mantids30::Helpers::setToJSON(currentAuthenticatedSlotIds));
    refresherToken.addClaim("type", "refresher");
    refresherToken.setJwtId(refreshTokenId);

    std::string sAuthToken = request.jwtSigner->signFromToken(refresherToken, false);

    // Keep the auth refresher token here:
    response.cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessToken"].setExpiration( refresherToken.getExpirationTime() );
    response.cookiesMap["AccessToken"].secure = true;
    response.cookiesMap["AccessToken"].httpOnly = true;
    response.cookiesMap["AccessToken"].value = sAuthToken ;

    response.cookiesMap["loggedIn"] = HTTP::Headers::Cookie();
    response.cookiesMap["loggedIn"].setExpiration( refresherToken.getExpirationTime() );
    response.cookiesMap["loggedIn"].secure = true;
    response.cookiesMap["loggedIn"].httpOnly = false;
    response.cookiesMap["loggedIn"].path= "/";
    response.cookiesMap["loggedIn"].value = std::to_string(refresherToken.getExpirationTime()) ;
}

bool WebLogin_AuthMethods::validateAccountForNewToken(IdentityManager *identityManager, const std::string &jwtAccountName, Reason &reason, const std::string &appName, bool checkValidAppAccount)
{
    // First, check if the account is disabled, unconfirmed, or expired.

    auto accountFlags = identityManager->accounts->getAccountFlags(jwtAccountName);

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
    else if (identityManager->accounts->isAccountExpired(jwtAccountName))
    {
        reason = Reason::REASON_EXPIRED_ACCOUNT;
        return false;
    }

    // If checkValidAppAccount is true, check if the account is valid for the specified application.
    if (checkValidAppAccount && !identityManager->applications->validateApplicationAccount(appName, jwtAccountName))
    {
        reason = Reason::REASON_BAD_ACCOUNT;
        return false;
    }

    // If all checks pass, the account is valid for refreshing the token.
    return true;
}

std::string WebLogin_AuthMethods::signApplicationToken(JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties)
{
    std::string appName = JSON_ASSTRING_D(accessToken.getClaim("app"),"");
    auto signingJWT = Globals::getIdentityManager()->applications->getAppJWTSigner(appName);
    if (!signingJWT)
    {
        return std::string();
    }
    return signingJWT->signFromToken(accessToken, false);
}


// Handle personalized login forms:
HTTP::Status::Codes WebLogin_AuthMethods::handleLoginDynamicRequest(const std::string &appName, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response, std::shared_ptr<void>)
{
    std::string page;
    auto status = Globals::getLoginDirManager()->retrieveFile(appName, page);
    bool originValidated = retrieveAndValidateAppOrigin(request, appName,USING_HEADER_REFERER);
    auto currentOrigin = request->getHeaderOption("Origin");


    if (!originValidated)
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_SECURITY_ALERT, "Not allowed origin '%s' for application '%s'", currentOrigin.c_str(), appName.c_str());

        return HTTP::Status::S_403_FORBIDDEN;
    }

    if (status != LoginDirectoryManager::ErrorCode::SUCCESS)
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_WARN, "Failed to obtain the HTML for application '%s': %s", appName.c_str(), LoginDirectoryManager::getErrorMessage(status).c_str());
        return HTTP::Status::S_404_NOT_FOUND;
    }


    LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_INFO, "HTML Login for application '%s' requested from '%s'", appName.c_str(), currentOrigin.c_str());

    response->content.writer()->writeString(page);
    response->setContentType("text/html");

    return HTTP::Status::S_200_OK;
}
/*

// Handle the retokenization HTML.
HTTP::Status::Codes WebLogin_AuthMethods::handleRetokenizeHTMLDynamicRequest(
    const std::string &internalPath, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response, std::shared_ptr<void>)
{
    // TODO: security: sanitize appName in DB, so you can't use escapes in the HTML ;)


    // scheme:

    //     webapp -> ( https://IAM/retokenizeHTML/?app=... ) via iframe (checking the origin on destination, it's a valid app+origin?)
    //     HTML( https://IAM/retokenizeHTML/?app=... ) -> https://IAM/api/v1/retokenize via AJAX returning back the app callback endpoint.
    //     HTML( https://IAM/retokenizeHTML/?app=... ) -> app callback endpoint (eg. webapp/api/auth/callback) via FORM POST injecting the token
    //     webapp/api/auth/callback called with #retokenize won't go anywhere (maybe must close the parent iframe to prevent anything)

    //     TODO: what if retokenization fails and not logged in... must redirect to the auth size (maybe using a floating window on this case?)


    // GET Input.
    std::string appName = request->getVars(HTTP::VARS_GET)->getTValue<std::string>("app","");

    // Origin.
    bool originValidated = retrieveAndValidateAppOrigin(request, appName,USING_HEADER_REFERER);

    // Current Origin
    auto currentOrigin = request->getHeaderOption("Origin");

    // Validate origin:
    if (!originValidated)
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_SECURITY_ALERT, "Not allowed origin '%s' for application '%s' during retokenization", currentOrigin.c_str(), appName.c_str());

        return HTTP::Status::S_403_FORBIDDEN;
    }

    return retokenizeUsingJS(response,appName);
}
*/

bool WebLogin_AuthMethods::retrieveAndValidateAppOrigin(HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource)
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

HTTP::Status::Codes WebLogin_AuthMethods::retokenizeUsingJS(HTTPv1_Base::Response *response, const std::string &appName)
{
    response->content.getStreamableObj()->strPrintf(
R"(<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Retokenize</title>
    <script src="/assets/js/jquery.min.js"></script>
</head>
<body>
    <script>
        // Create and send the form:
        function createAndSubmitRedirectForm(actionUrl, data, method = 'POST') {
            const form = document.createElement('form');
            form.method = method;
            form.action = actionUrl;
            Object.entries(data).forEach(([name, value]) => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = name;
                input.value = value;
                form.appendChild(input);
            });
            document.body.appendChild(form);
            form.submit();
        }

        // AJAX Logic:
        $(window).on('load', function() {
            $.ajax({
                url: "/api/v1/retokenize",
                type: "POST",
                contentType: "application/json",
                data: JSON.stringify({
                    redirectURI: "",
                    app: "%s"
                }),
                success: function (response) {
                    createAndSubmitRedirectForm(response.callbackURI, {
                        accessToken: response.accessToken,
                        expiresIn: response.expiresIn,
                        redirectURI: "#retokenize"
                    }, 'POST');
                },
                error: function(xhr, status, error) {
                    console.error("Error during AJAX:", error);
                }
            });
        });
    </script>
</body>
</html>)", appName.c_str());
    return HTTP::Status::S_200_OK;
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
