#include "webadmin_methods_applications.h"

#include <Mantids30/Program_Logs/applog.h>
#include "../globals.h"
#include "defs.h"


using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols::HTTP;


void WebAdminMethods_Applications::addMethods_Applications(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // Applications
  methods->addResource(MethodsHandler::GET, "getApplicationInfo", &getApplicationInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::POST, "addApplication", &addApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_CREATE"});
  methods->addResource(MethodsHandler::POST, "removeApplication", &removeApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_DELETE"});
  methods->addResource(MethodsHandler::GET, "doesApplicationExist", &doesApplicationExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::GET, "getApplicationDescription", &getApplicationDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::POST, "updateApplicationDescription", &updateApplicationDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::POST, "updateApplicationAPIKey", &updateApplicationAPIKey, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::GET, "listApplications", &listApplications, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::GET, "validateApplicationOwner", &validateApplicationOwner, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::GET, "validateApplicationAccount", &validateApplicationAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::GET, "listApplicationOwners", &listApplicationOwners, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::GET, "listApplicationAccounts", &listApplicationAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::GET, "listAccountApplications", &listAccountApplications, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::POST, "addAccountToApplication", &addAccountToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::POST, "removeAccountFromApplication", &removeAccountFromApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::POST, "addApplicationOwner", &addApplicationOwner, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::POST, "removeApplicationOwner", &removeApplicationOwner, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::GET, "searchApplications", &searchApplications, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::POST, "modifyWebLoginJWTConfigForApplication", &modifyWebLoginJWTConfigForApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::GET, "getWebLoginJWTConfigFromApplication", &getWebLoginJWTConfigFromApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::POST, "setWebLoginJWTSigningKeyForApplication", &setWebLoginJWTSigningKeyForApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::GET, "getWebLoginJWTSigningKeyForApplication", &getWebLoginJWTSigningKeyForApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::POST, "addWebLoginRedirectURIToApplication", &addWebLoginRedirectURIToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::POST, "removeWebLoginRedirectURIToApplication", &removeWebLoginRedirectURIToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::GET, "listWebLoginRedirectURIsFromApplication", &listWebLoginRedirectURIsFromApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
  methods->addResource(MethodsHandler::POST, "addWebLoginOriginURLToApplication", &addWebLoginOriginURLToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::POST, "removeWebLoginOriginURLToApplication", &removeWebLoginOriginURLToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
  methods->addResource(MethodsHandler::GET, "listWebLoginOriginUrlsFromApplication", &listWebLoginOriginUrlsFromApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
}

void WebAdminMethods_Applications::addApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->addApplication(   JSON_ASSTRING(*request.inputJSON,"appName",""),
                                                                        JSON_ASSTRING(*request.inputJSON,"description",""),
                                                                        JSON_ASSTRING(*request.inputJSON,"appKey",""),
                                                                        request.jwtToken->getSubject()
                                                                     ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
        return;
    }
    return ;
}

void WebAdminMethods_Applications::removeApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON,"appName","");

    if (appName == DB_APPNAME)
    {
        response.setError(Status::S_400_BAD_REQUEST,"invalid_request","Can't remove the IAM application");
        return;
    }

    if (!Globals::getIdentityManager()->applications->removeApplication(appName))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
        return;
    }
}

void WebAdminMethods_Applications::doesApplicationExist(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->doesApplicationExist( JSON_ASSTRING(*request.inputJSON,"appName","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
        return;
    }
}

void WebAdminMethods_Applications::getApplicationDescription(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->applications->getApplicationDescription( JSON_ASSTRING(*request.inputJSON,"appName",""));
}
/*
void WebAdminMethods_Applications::getApplicationAPIKey(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    payloadOut["appKey"] = Globals::getIdentityManager()->getApplicationAPIKey( JSON_ASSTRING(*request.inputJSON,"appName",""));
    return payloadOut;
}
*/
void WebAdminMethods_Applications::getApplicationInfo(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    json payloadOut;
    std::string appName = JSON_ASSTRING(*request.inputJSON,"appName","");
    payloadOut["description"] = Globals::getIdentityManager()->applications->getApplicationDescription( appName );

    // Get associated permission...
    auto attrList = Globals::getIdentityManager()->authController->listApplicationPermissions(appName);
    int i=0;
    for ( const auto & permission : attrList )
    {
        payloadOut["permissions"][i]["id"] = permission.permissionId;
        payloadOut["permissions"][i]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(permission);
        i++;
    }

    // Get associated direct accounts...
    auto acctList = Globals::getIdentityManager()->applications->listApplicationAccounts(appName);
    i=0;
    for ( const auto & acct : acctList )
    {
        auto getAccountDetails = Globals::getIdentityManager()->users->getAccountDetails(acct);
        payloadOut["accounts"][i]["name"] = acct;
/*        payloadOut["accounts"][i]["description"] = getAccountDetails.description;
        payloadOut["accounts"][i]["givenName"] = getAccountDetails.givenName;
        payloadOut["accounts"][i]["lastName"] = getAccountDetails.lastName;*/
        i++;
    }

    (*response.responseJSON()) = payloadOut;
}

void WebAdminMethods_Applications::updateApplicationDescription(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->updateApplicationDescription( JSON_ASSTRING(*request.inputJSON,"appName",""), JSON_ASSTRING(*request.inputJSON,"description","") ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::updateApplicationAPIKey(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->updateApplicationAPIKey( JSON_ASSTRING(*request.inputJSON,"appName",""), JSON_ASSTRING(*request.inputJSON,"appKey","") ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::listApplications(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->applications->listApplications());
}

void WebAdminMethods_Applications::validateApplicationOwner(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->validateApplicationOwner( JSON_ASSTRING(*request.inputJSON,"appName",""), JSON_ASSTRING(*request.inputJSON,"accountName","") ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::validateApplicationAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->validateApplicationAccount( JSON_ASSTRING(*request.inputJSON,"appName",""), JSON_ASSTRING(*request.inputJSON,"accountName","") ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::listApplicationOwners(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->applications->listApplicationOwners( JSON_ASSTRING(*request.inputJSON,"applicationName","")));
}

void WebAdminMethods_Applications::listApplicationAccounts(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->applications->listApplicationAccounts( JSON_ASSTRING(*request.inputJSON,"applicationName","")));
}

void WebAdminMethods_Applications::listAccountApplications(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->applications->listAccountApplications( JSON_ASSTRING(*request.inputJSON,"accountName","")));
}

void WebAdminMethods_Applications::addAccountToApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->addAccountToApplication( JSON_ASSTRING(*request.inputJSON,"appName",""), JSON_ASSTRING(*request.inputJSON,"accountName","") ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::removeAccountFromApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->removeAccountFromApplication( JSON_ASSTRING(*request.inputJSON,"appName",""), JSON_ASSTRING(*request.inputJSON,"accountName","") ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::addApplicationOwner(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->addApplicationOwner( JSON_ASSTRING(*request.inputJSON,"appName",""), JSON_ASSTRING(*request.inputJSON,"accountName","") ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::removeApplicationOwner(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->removeApplicationOwner( JSON_ASSTRING(*request.inputJSON,"appName",""), JSON_ASSTRING(*request.inputJSON,"accountName","") ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::searchApplications(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    json x;
    int i=0;
    for (const auto & strVal : Globals::getIdentityManager()->applications->searchApplications(
             JSON_ASSTRING(*request.inputJSON,"searchWords",""),
             JSON_ASUINT64(*request.inputJSON,"limit",0),
             JSON_ASUINT64(*request.inputJSON,"offset",0)
             ))
    {
        x[i]["appCreator"] = strVal.appCreator;
        x[i]["appName"] = strVal.applicationName;
        x[i]["description"] = strVal.description;
        i++;
    }
    (*response.responseJSON()) = x;
}

void WebAdminMethods_Applications::addWebLoginRedirectURIToApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->addWebLoginRedirectURIToApplication(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "loginRedirectURI", "")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::removeWebLoginRedirectURIToApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->removeWebLoginRedirectURIToApplication(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "loginRedirectURI", "")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::listWebLoginRedirectURIsFromApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::listToJSON(Globals::getIdentityManager()->applications->listWebLoginRedirectURIsFromApplication(JSON_ASSTRING(*request.inputJSON, "appName", "")));
}

void WebAdminMethods_Applications::addWebLoginOriginURLToApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->addWebLoginOriginURLToApplication(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "originUrl", "")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::removeWebLoginOriginURLToApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->removeWebLoginOriginURLToApplication(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "originUrl", "")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::listWebLoginOriginUrlsFromApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    (*response.responseJSON()) = Helpers::listToJSON(Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(JSON_ASSTRING(*request.inputJSON, "appName", "")));
}

void WebAdminMethods_Applications::modifyWebLoginJWTConfigForApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    ApplicationTokenProperties tokenInfo;

    tokenInfo.appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    tokenInfo.accessTokenTimeout = (*request.inputJSON)["accessTokenTimeout"].asUInt();
    tokenInfo.tempMFATokenTimeout = (*request.inputJSON)["tempMFATokenTimeout"].asUInt();
    tokenInfo.sessionInactivityTimeout = (*request.inputJSON)["sessionInactivityTimeout"].asUInt();
    tokenInfo.tokenType = JSON_ASSTRING(*request.inputJSON, "tokenType", "");
    tokenInfo.includeApplicationPermissionsInToken = (*request.inputJSON)["includeApplicationPermissionsInToken"].asBool();
    tokenInfo.includeBasicUserInfoInToken = (*request.inputJSON)["includeBasicUserInfoInToken"].asBool();
    tokenInfo.maintainRevocationAndLogoutInfo = (*request.inputJSON)["maintainRevocationAndLogoutInfo"].asBool();

    if (!Globals::getIdentityManager()->applications->modifyWebLoginJWTConfigForApplication(tokenInfo))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
        return;
    }
}


void WebAdminMethods_Applications::getWebLoginJWTConfigFromApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    json payloadOut;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    ApplicationTokenProperties tokenInfo = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName);
    payloadOut["appName"] = tokenInfo.appName;
    payloadOut["accessTokenTimeout"] = tokenInfo.accessTokenTimeout;
    // ... [Continúa agregando el resto de campos de tokenInfo al payloadOut] ...

    (*response.responseJSON()) = payloadOut;
}


void WebAdminMethods_Applications::setWebLoginJWTSigningKeyForApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string signingKey = JSON_ASSTRING(*request.inputJSON, "signingKey", "");

    if (!Globals::getIdentityManager()->applications->setWebLoginJWTSigningKeyForApplication(appName, signingKey))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}


void WebAdminMethods_Applications::getWebLoginJWTSigningKeyForApplication(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string signingKey = Globals::getIdentityManager()->applications->getWebLoginJWTSigningKeyForApplication(appName);
    (*response.responseJSON()) = signingKey;
}
