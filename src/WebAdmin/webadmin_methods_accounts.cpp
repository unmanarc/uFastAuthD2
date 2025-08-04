#include "webadmin_methods_accounts.h"

#include "webadmin_methods.h"

#include "IdentityManager/ds_authentication.h"
#include <Mantids30/Program_Logs/applog.h>

#include "../globals.h"
#include <regex>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols;

void WebAdminMethods_Accounts::addMethods_Accounts(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // Accounts
    methods->addResource(MethodsHandler::POST, "addAccount", &addAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::POST, "changeAccountExpiration", &changeAccountExpiration, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::POST, "changeCredential", &changeCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_PWDDCHANGE"});
    methods->addResource(MethodsHandler::POST, "confirmAccount", &confirmAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::POST, "disableAccount", &disableAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_DISABLE"});
    methods->addResource(MethodsHandler::GET, "doesAccountExist", &doesAccountExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountBlockToken", &getAccountBlockToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::GET, "getAccountDirectApplicationPermissions", &getAccountDirectApplicationPermissions, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountDetails", &getAccountDetails, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountExpirationTime", &getAccountExpirationTime, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountFlags", &getAccountFlags, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountInfo", &getAccountInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountLastAccess", &getAccountLastAccess, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountRoles", &getAccountRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountUsableApplicationPermissions", &getAccountUsableApplicationPermissions, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "isAccountExpired", &isAccountExpired, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "listAccounts", &listAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::POST, "removeAccount", &removeAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_DELETE"});
    methods->addResource(MethodsHandler::POST, "resetBadAttemptsOnCredential", &resetBadAttemptsOnCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::GET, "searchAccounts", &searchAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::POST, "updateAccountInfo", &updateAccountInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::POST, "updateAccountRoles", &updateAccountRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::GET, "validateAccountApplicationPermission", &validateAccountApplicationPermission, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::POST, "blockAccountUsingToken", &blockAccountUsingToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
}

void WebAdminMethods_Accounts::addAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (Globals::getIdentityManager()->accounts->doesAccountExist(accountName))
    {
        response.setError(HTTP::Status::S_406_NOT_ACCEPTABLE, "unacceptable_request", "Account Already Exist");
        return;
    }

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return;
    }

    std::regex accountNameExpr("[a-zA-Z0-9]+");
    if (!regex_match(accountName, accountNameExpr))
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name have invalid characters");
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

    if (!Globals::getIdentityManager()->accounts->addAccount(accountName, JSON_ASUINT64(*request.inputJSON, "expirationDate", 0), accountFlags, request.jwtToken->getSubject()))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the new account. Check if user already exists");
        return;
    }

    Credential newCredentialData = Credential::createFromJSON(JSON_ASSTRING(*request.inputJSON, "tempCredential", ""));
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    if (!Globals::getIdentityManager()->authController->changeCredential(accountName, newCredentialData, slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change the credential on the new user.");
        return;
    }

    // TODO: que pasa si cambiamos el slot de credenciales mientras hacemos esta operacion?
    //       creo que lo mejor es que solo se puedan cambiar los esquemas de acceso en un modo "super safe" en donde esté apagado el servidor IAM web,
    //       solo se admita una conexion admin y ya... de ese modo no habrá race condition en esta cosa...
}

void WebAdminMethods_Accounts::changeAccountExpiration(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->changeAccountExpiration(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASUINT64(*request.inputJSON, "expiration", 0)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::changeCredential(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    Credential credentialData;
    credentialData.fromJSON((*request.inputJSON)["credentialData"]);
    if (!Globals::getIdentityManager()->authController->changeCredential(JSON_ASSTRING(*request.inputJSON, "accountName", ""), credentialData, JSON_ASUINT(*request.inputJSON, "slotId", 0)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::confirmAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->disableAccount(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASBOOL(*request.inputJSON, "disabled", false)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::disableAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->disableAccount(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASBOOL(*request.inputJSON, "disabled", false)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::doesAccountExist(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->doesAccountExist(JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::getAccountBlockToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->getAccountBlockToken(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
}

void WebAdminMethods_Accounts::getAccountDirectApplicationPermissions(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Methods::permissionListToJSON(
        Globals::getIdentityManager()->authController->getAccountDirectApplicationPermissions(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

void WebAdminMethods_Accounts::getAccountDetails(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    auto getAccountDetails = Globals::getIdentityManager()->accounts->getAccountDetails(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
    // Llenar el payloadOut con los detalles de la cuenta
    (*response.responseJSON()) = getAccountDetails.toJSON();
}

void WebAdminMethods_Accounts::getAccountExpirationTime(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Json::Int64(Globals::getIdentityManager()->accounts->getAccountExpirationTime(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

void WebAdminMethods_Accounts::getAccountFlags(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->getAccountFlags(JSON_ASSTRING(*request.inputJSON, "accountName", "")).toJSON();
}

void WebAdminMethods_Accounts::getAccountInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    getAccountDetails(context, response, request, authClientDetails);

    int i = 0;
    auto getAccountRoles = Globals::getIdentityManager()->accounts->getAccountRoles(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
    for (const auto &roleName : getAccountRoles)
    {
        (*response.responseJSON())["roles"][i]["name"] = roleName;
        // TODO: optimize:
        (*response.responseJSON())["roles"][i]["description"] = Globals::getIdentityManager()->roles->getRoleDescription(roleName);
        i++;
    }

    i = 0;
    for (const auto &roleName : Globals::getIdentityManager()->roles->getRolesList())
    {
        if (getAccountRoles.find(roleName) == getAccountRoles.end())
        {
            (*response.responseJSON())["rolesLeft"][i]["name"] = roleName;
            (*response.responseJSON())["rolesLeft"][i]["description"] = Globals::getIdentityManager()->roles->getRoleDescription(roleName);
            i++;
        }
    }

    auto directPermissions = Globals::getIdentityManager()->authController->getAccountDirectApplicationPermissions(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
    auto usablePermissions = Globals::getIdentityManager()->authController->getAccountUsableApplicationPermissions(JSON_ASSTRING(*request.inputJSON, "accountName", ""));

    auto listAccountApplications = Globals::getIdentityManager()->applications->listAccountApplications(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
    i = 0;
    for (const auto &applicationName : listAccountApplications)
    {
        (*response.responseJSON())["applications"][i]["name"] = applicationName;
        // TODO: optimize:
        (*response.responseJSON())["applications"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(applicationName);

        int j = 0;
        for (const auto &directApplicationPermission : directPermissions)
        {
            if (directApplicationPermission.appName == applicationName)
            {
                (*response.responseJSON())["applications"][i]["directPermissions"][j]["id"] = directApplicationPermission.permissionId;
                (*response.responseJSON())["applications"][i]["directPermissions"][j]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(
                    directApplicationPermission);
                j++;
            }
        }

        j = 0;
        for (const auto &permission : Globals::getIdentityManager()->authController->listApplicationPermissions(applicationName))
        {
            if (directPermissions.find(permission) == directPermissions.end())
            {
                (*response.responseJSON())["applications"][i]["directPermissionsLeft"][j]["id"] = permission.permissionId;
                (*response.responseJSON())["applications"][i]["directPermissionsLeft"][j]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(
                    permission);
                j++;
            }
        }

        j = 0;
        for (const auto &usablePermission : usablePermissions)
        {
            if (usablePermission.appName == applicationName)
            {
                (*response.responseJSON())["applications"][i]["usablePermissions"][j]["id"] = usablePermission.permissionId;
                (*response.responseJSON())["applications"][i]["usablePermissions"][j]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(
                    usablePermission);
                j++;
            }
        }
        i++;
    }

    i = 0;

    for (const auto &applicationName : Globals::getIdentityManager()->applications->listApplications())
    {
        if (listAccountApplications.find(applicationName) == listAccountApplications.end())
        {
            (*response.responseJSON())["applicationsLeft"][i]["name"] = applicationName;
            (*response.responseJSON())["applicationsLeft"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(applicationName);
            i++;
        }
    }
}

void WebAdminMethods_Accounts::getAccountLastAccess(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->getAccountLastAccess(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
}

void WebAdminMethods_Accounts::getAccountRoles(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->accounts->getAccountRoles(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

void WebAdminMethods_Accounts::getAccountUsableApplicationPermissions(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Methods::permissionListToJSON(
        Globals::getIdentityManager()->authController->getAccountUsableApplicationPermissions(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

void WebAdminMethods_Accounts::isAccountExpired(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->isAccountExpired(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
}

void WebAdminMethods_Accounts::listAccounts(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->accounts->listAccounts());
}

void WebAdminMethods_Accounts::removeAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->removeAccount(JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::resetBadAttemptsOnCredential(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    Globals::getIdentityManager()->authController->resetBadAttemptsOnCredential(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASUINT(*request.inputJSON, "slotId", 0));
}

void WebAdminMethods_Accounts::searchAccounts(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    json x;
    int i = 0;
    for (const auto &strVal : Globals::getIdentityManager()->accounts->searchAccounts(JSON_ASSTRING(*request.inputJSON, "searchWords", ""), JSON_ASUINT64(*request.inputJSON, "limit", 0),
                                                                                      JSON_ASUINT64(*request.inputJSON, "offset", 0)))
    {
        x[i] = strVal.toJSON();
        i++;
    }
    (*response.responseJSON()) = x;
}

void WebAdminMethods_Accounts::updateAccountInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    AccountFlags accountFlags;
    accountFlags.fromJSON(request.inputJSON);
    // TODO: set account details granularly...
    if (!Globals::getIdentityManager()->accounts->changeAccountFlags(JSON_ASSTRING(*request.inputJSON, "accountName", ""), accountFlags))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }

    /*  Globals::getIdentityManager()->accounts->changeAccountDescription(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"description","")) &&
        Globals::getIdentityManager()->accounts->changeAccoungGivenName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"givenName","")) &&
        Globals::getIdentityManager()->accounts->changeAccountLastName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"lastName","")) &&
        Globals::getIdentityManager()->accounts->changeAccountEmail(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"email","")) &&
        Globals::getIdentityManager()->accounts->changeAccountExtraData(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"extraData","")) &&*/
}

/*
void WebAdminMethods_Accounts::changeAccountDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountDescription(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"description",""));
}

void WebAdminMethods_Accounts::changeAccoungGivenName(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccoungGivenName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"givenName",""));
}

void WebAdminMethods_Accounts::changeAccountLastName(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountLastName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"lastName",""));
}

void WebAdminMethods_Accounts::changeAccountEmail(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountEmail(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"email",""));
}

void WebAdminMethods_Accounts::changeAccountExtraData(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountExtraData(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"extraData",""));
}*/

void WebAdminMethods_Accounts::updateAccountRoles(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::set<std::string> roleSet;

    if (!(*request.inputJSON)["roles"].isArray())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Invalid Parameters");
        return;
    }

    for (size_t i = 0; i < (*request.inputJSON)["roles"].size(); i++)
    {
        roleSet.insert((*request.inputJSON)["roles"][(int) i].asString());
    }

    if (!Globals::getIdentityManager()->accounts->updateAccountRoles(JSON_ASSTRING(*request.inputJSON, "accountName", ""), roleSet))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
        return;
    }
}

void WebAdminMethods_Accounts::validateAccountApplicationPermission(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->validateAccountApplicationPermission(JSON_ASSTRING(*request.inputJSON, "accountName", ""),
                                                                                                                     {JSON_ASSTRING(*request.inputJSON, "appName", ""),
                                                                                                                      JSON_ASSTRING(*request.inputJSON, "id", "")});
}

void WebAdminMethods_Accounts::blockAccountUsingToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->blockAccountUsingToken(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASSTRING(*request.inputJSON, "blockToken", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
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
