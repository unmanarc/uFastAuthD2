#include "webadmin_methods_accounts.h"

#include "webadmin_methods.h"

#include <Mantids30/Program_Logs/applog.h>
#include "IdentityManager/ds_authentication.h"

#include "../globals.h"
#include <regex>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols::HTTP;

void WebAdminMethods_Accounts::addMethods_Accounts(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // Accounts
    methods->addResource(MethodsHandler::POST, "addAccount", &addAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_MODIFY"});
    methods->addResource(MethodsHandler::POST, "changeAccountExpiration", &changeAccountExpiration, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_MODIFY"});
    methods->addResource(MethodsHandler::POST, "changeCredential", &changeCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_PWDDCHANGE"});
    methods->addResource(MethodsHandler::POST, "confirmAccount", &confirmAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_MODIFY"});
    methods->addResource(MethodsHandler::POST, "disableAccount", &disableAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_DISABLE"});
    methods->addResource(MethodsHandler::GET, "doesAccountExist", &doesAccountExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountBlockToken", &getAccountBlockToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_MODIFY"});
    methods->addResource(MethodsHandler::GET, "getAccountDirectApplicationPermissions", &getAccountDirectApplicationPermissions, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountDetails", &getAccountDetails, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountExpirationTime", &getAccountExpirationTime, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountFlags", &getAccountFlags, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountInfo", &getAccountInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountLastLogin", &getAccountLastLogin, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountRoles", &getAccountRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountUsableApplicationPermissions", &getAccountUsableApplicationPermissions, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "isAccountExpired", &isAccountExpired, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::GET, "listAccounts", &listAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::POST, "removeAccount", &removeAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_DELETE"});
    methods->addResource(MethodsHandler::POST, "resetBadAttemptsOnCredential", &resetBadAttemptsOnCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_MODIFY"});
    methods->addResource(MethodsHandler::GET, "searchAccounts", &searchAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::POST, "updateAccountInfo", &updateAccountInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_MODIFY"});
    methods->addResource(MethodsHandler::POST, "updateAccountRoles", &updateAccountRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_MODIFY"});
    methods->addResource(MethodsHandler::GET, "validateAccountApplicationPermission", &validateAccountApplicationPermission, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_READ"});
    methods->addResource(MethodsHandler::POST, "blockAccountUsingToken", &blockAccountUsingToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"USER_MODIFY"});
}

void WebAdminMethods_Accounts::addAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    std::string accountName = JSON_ASSTRING(*request.inputJSON,"accountName","");

    if (Globals::getIdentityManager()->users->doesAccountExist(accountName))
    {
        response.setError(Status::S_406_NOT_ACCEPTABLE,"unacceptable_request","Account Already Exist");
        return;
    }

    if (accountName.empty())
    {
        response.setError(Status::S_400_BAD_REQUEST,"invalid_request","Account Name is Empty");
        return;
    }

    std::regex accountNameExpr("[a-zA-Z0-9]+");
    if(!regex_match(accountName,accountNameExpr))
    {
        response.setError(Status::S_400_BAD_REQUEST,"invalid_request","Account name have invalid characters");
        return;
    }

    // Create Expired SSHA256 password (require change)
    /*  AccountCreationDetails getAccountDetails;
    getAccountDetails.description = JSON_ASSTRING(*request.inputJSON,"description","");
    getAccountDetails.email = JSON_ASSTRING(*request.inputJSON,"mail","");
    getAccountDetails.extraData = JSON_ASSTRING(*request.inputJSON,"extraData","");
    getAccountDetails.givenName = JSON_ASSTRING(*request.inputJSON,"givenName","");
    getAccountDetails.lastName = JSON_ASSTRING(*request.inputJSON,"lastName","");*/

    AccountFlags accountFlags;
    accountFlags.fromJSON(request.inputJSON);

    if (
        !Globals::getIdentityManager()->users->addAccount(
            accountName,
            JSON_ASUINT64(*request.inputJSON,"expirationDate",0),
            accountFlags,
            request.jwtToken->getSubject()
            ))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error","Failed to add the new account. Check if user already exists");
        return;
    }

    Credential newCredentialData = Credential::createFromJSON(JSON_ASSTRING(*request.inputJSON,"tempCredential",""));
    uint32_t slotId = JSON_ASUINT(*request.inputJSON,"slotId",0);

    if (!Globals::getIdentityManager()->authController->changeCredential(accountName,newCredentialData,slotId))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error","Failed to change the credential on the new user.");
        return;
    }

    // TODO: que pasa si cambiamos el slot de credenciales mientras hacemos esta operacion?
    //       creo que lo mejor es que solo se puedan cambiar los esquemas de acceso en un modo "super safe" en donde esté apagado el servidor IAM web,
    //       solo se admita una conexion admin y ya... de ese modo no habrá race condition en esta cosa...
}

void WebAdminMethods_Accounts::changeAccountExpiration(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->users->changeAccountExpiration(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASUINT64(*request.inputJSON,"expiration",0)))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::changeCredential(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    Credential credentialData;
    credentialData.fromJSON((*request.inputJSON)["credentialData"]);
    if (!Globals::getIdentityManager()->authController->changeCredential(JSON_ASSTRING(*request.inputJSON,"accountName",""),  credentialData, JSON_ASUINT(*request.inputJSON,"slotId",0)))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::confirmAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->users->disableAccount(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASBOOL(*request.inputJSON,"disabled",false)))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::disableAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->users->disableAccount(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASBOOL(*request.inputJSON,"disabled",false)))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::doesAccountExist(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->users->doesAccountExist(JSON_ASSTRING(*request.inputJSON,"accountName","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::getAccountBlockToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = Globals::getIdentityManager()->users->getAccountBlockToken(JSON_ASSTRING(*request.inputJSON,"accountName",""));
}

void WebAdminMethods_Accounts::getAccountDirectApplicationPermissions(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = WebAdmin_Methods::permissionListToJSON(Globals::getIdentityManager()->authController->getAccountDirectApplicationPermissions(JSON_ASSTRING(*request.inputJSON,"accountName","")));
}

void WebAdminMethods_Accounts::getAccountDetails(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    auto getAccountDetails = Globals::getIdentityManager()->users->getAccountDetails(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
    // Llenar el payloadOut con los detalles de la cuenta
    (*response.outputPayload()) = getAccountDetails.toJSON();
}

void WebAdminMethods_Accounts::getAccountExpirationTime(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = Json::Int64(Globals::getIdentityManager()->users->getAccountExpirationTime(JSON_ASSTRING(*request.inputJSON,"accountName","")));
}

void WebAdminMethods_Accounts::getAccountFlags(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = Globals::getIdentityManager()->users->getAccountFlags(JSON_ASSTRING(*request.inputJSON,"accountName","")).toJSON();
}

void WebAdminMethods_Accounts::getAccountInfo(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    getAccountDetails(context, response,  request,authClientDetails);

    int i=0;
    auto getAccountRoles = Globals::getIdentityManager()->users->getAccountRoles(JSON_ASSTRING(*request.inputJSON,"accountName",""));
    for (const auto & roleName : getAccountRoles)
    {
        (*response.outputPayload())["roles"][i]["name"] = roleName;
        // TODO: optimize:
        (*response.outputPayload())["roles"][i]["description"] = Globals::getIdentityManager()->roles->getRoleDescription(roleName);
        i++;
    }

    i=0;
    for (const auto & roleName : Globals::getIdentityManager()->roles->getRolesList())
    {
        if (getAccountRoles.find(roleName)==getAccountRoles.end())
        {
            (*response.outputPayload())["rolesLeft"][i]["name"] = roleName;
            (*response.outputPayload())["rolesLeft"][i]["description"] = Globals::getIdentityManager()->roles->getRoleDescription(roleName);
            i++;
        }
    }

    auto directPermissions = Globals::getIdentityManager()->authController->getAccountDirectApplicationPermissions(JSON_ASSTRING(*request.inputJSON,"accountName",""));
    auto usablePermissions = Globals::getIdentityManager()->authController->getAccountUsableApplicationPermissions(JSON_ASSTRING(*request.inputJSON,"accountName",""));

    auto listAccountApplications = Globals::getIdentityManager()->applications->listAccountApplications(JSON_ASSTRING(*request.inputJSON,"accountName",""));
    i=0;
    for (const auto & applicationName : listAccountApplications)
    {
        (*response.outputPayload())["applications"][i]["name"] = applicationName;
        // TODO: optimize:
        (*response.outputPayload())["applications"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(applicationName);

        int j=0;
        for (const auto & directApplicationPermission : directPermissions)
        {
            if (directApplicationPermission.appName == applicationName)
            {
                (*response.outputPayload())["applications"][i]["directPermissions"][j]["id"] = directApplicationPermission.permissionId;
                (*response.outputPayload())["applications"][i]["directPermissions"][j]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(directApplicationPermission);
                j++;
            }
        }

        j=0;
        for (const auto & permission : Globals::getIdentityManager()->authController->listApplicationPermissions(applicationName))
        {
            if (directPermissions.find(permission)==directPermissions.end())
            {
                (*response.outputPayload())["applications"][i]["directPermissionsLeft"][j]["id"] = permission.permissionId;
                (*response.outputPayload())["applications"][i]["directPermissionsLeft"][j]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(permission);
                j++;
            }
        }

        j=0;
        for (const auto & usablePermission : usablePermissions)
        {
            if (usablePermission.appName == applicationName)
            {
                (*response.outputPayload())["applications"][i]["usablePermissions"][j]["id"] = usablePermission.permissionId;
                (*response.outputPayload())["applications"][i]["usablePermissions"][j]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(usablePermission);
                j++;
            }
        }
        i++;
    }


    i=0;

    for (const auto & applicationName : Globals::getIdentityManager()->applications->listApplications())
    {
        if ( listAccountApplications.find(applicationName) == listAccountApplications.end()  )
        {
            (*response.outputPayload())["applicationsLeft"][i]["name"] = applicationName;
            (*response.outputPayload())["applicationsLeft"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(applicationName);
            i++;
        }
    }


}

void WebAdminMethods_Accounts::getAccountLastLogin(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = Globals::getIdentityManager()->authController->getAccountLastLogin(JSON_ASSTRING(*request.inputJSON,"accountName",""));
}

void WebAdminMethods_Accounts::getAccountRoles(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = Helpers::setToJSON(Globals::getIdentityManager()->users->getAccountRoles(JSON_ASSTRING(*request.inputJSON,"accountName","")));
}

void WebAdminMethods_Accounts::getAccountUsableApplicationPermissions(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = WebAdmin_Methods::permissionListToJSON(Globals::getIdentityManager()->authController->getAccountUsableApplicationPermissions(JSON_ASSTRING(*request.inputJSON,"accountName","")));
}

void WebAdminMethods_Accounts::isAccountExpired(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = Globals::getIdentityManager()->users->isAccountExpired(JSON_ASSTRING(*request.inputJSON,"accountName",""));
}

void WebAdminMethods_Accounts::listAccounts(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = Helpers::setToJSON(Globals::getIdentityManager()->users->listAccounts());
}

void WebAdminMethods_Accounts::removeAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->users->removeAccount(JSON_ASSTRING(*request.inputJSON,"accountName","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::resetBadAttemptsOnCredential(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    Globals::getIdentityManager()->authController->resetBadAttemptsOnCredential(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASUINT(*request.inputJSON, "slotId", 0));
}

void WebAdminMethods_Accounts::searchAccounts(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    json x;
    int i=0;
    for (const auto & strVal : Globals::getIdentityManager()->users->searchAccounts(
             JSON_ASSTRING(*request.inputJSON,"searchWords",""),
             JSON_ASUINT64(*request.inputJSON,"limit",0),
             JSON_ASUINT64(*request.inputJSON,"offset",0)
             ))
    {
        x[i] = strVal.toJSON();
        i++;
    }
    (*response.outputPayload()) = x;
}

void WebAdminMethods_Accounts::updateAccountInfo(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    AccountFlags accountFlags;
    accountFlags.fromJSON(request.inputJSON);
    // TODO: set account details granularly...
    if (!Globals::getIdentityManager()->users->changeAccountFlags(JSON_ASSTRING(*request.inputJSON,"accountName",""), accountFlags))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }

    /*  Globals::getIdentityManager()->users->changeAccountDescription(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"description","")) &&
        Globals::getIdentityManager()->users->changeAccoungGivenName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"givenName","")) &&
        Globals::getIdentityManager()->users->changeAccountLastName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"lastName","")) &&
        Globals::getIdentityManager()->users->changeAccountEmail(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"email","")) &&
        Globals::getIdentityManager()->users->changeAccountExtraData(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"extraData","")) &&*/


}

/*
void WebAdminMethods_Accounts::changeAccountDescription(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->users->changeAccountDescription(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"description",""));
}

void WebAdminMethods_Accounts::changeAccoungGivenName(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->users->changeAccoungGivenName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"givenName",""));
}

void WebAdminMethods_Accounts::changeAccountLastName(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->users->changeAccountLastName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"lastName",""));
}

void WebAdminMethods_Accounts::changeAccountEmail(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->users->changeAccountEmail(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"email",""));
}

void WebAdminMethods_Accounts::changeAccountExtraData(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->users->changeAccountExtraData(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"extraData",""));
}*/

void WebAdminMethods_Accounts::updateAccountRoles(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    std::set<std::string> roleSet;

    if (!(*request.inputJSON)["roles"].isArray())
    {
        response.setError(Status::S_400_BAD_REQUEST,"invalid_request","Invalid Parameters");
        return;
    }

    for ( size_t i=0; i<(*request.inputJSON)["roles"].size();i++ )
    {
        roleSet.insert((*request.inputJSON)["roles"][(int)i].asString());
    }

    if (!Globals::getIdentityManager()->users->updateAccountRoles(JSON_ASSTRING(*request.inputJSON,"accountName",""), roleSet))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
        return;
    }
}

void WebAdminMethods_Accounts::validateAccountApplicationPermission(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.outputPayload()) = Globals::getIdentityManager()->authController->validateAccountApplicationPermission(JSON_ASSTRING(*request.inputJSON,"accountName",""),  {JSON_ASSTRING(*request.inputJSON,"appName",""),JSON_ASSTRING(*request.inputJSON,"id","")});
}

void WebAdminMethods_Accounts::blockAccountUsingToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->users->blockAccountUsingToken(JSON_ASSTRING(*request.inputJSON,"accountName",""),  JSON_ASSTRING(*request.inputJSON,"blockToken","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}



std::map<std::string, std::string> WebAdminMethods_Accounts::jsonToMap(const json &jValue)
{
    std::map<std::string, std::string> r;
    for (const std::string &memberName : jValue.getMemberNames())
    {
        if (jValue[memberName].isString())
            r[memberName] = JSON_ASSTRING(jValue, memberName, "");
    }
    return r;
}

