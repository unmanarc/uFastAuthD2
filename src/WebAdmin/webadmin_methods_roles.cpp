#include "webadmin_methods_roles.h"

#include "../globals.h"
#include <Mantids30/Program_Logs/applog.h>

#include "webadmin_methods.h"

using namespace Mantids30::Program;
using namespace Mantids30;

using namespace Mantids30::Network::Protocols;

void WebAdminMethods_Roles::addMethods_Roles(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // Roles
    methods->addResource(MethodsHandler::POST, "addRole", &addRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_CREATE"});
    methods->addResource(MethodsHandler::POST, "removeRole", &removeRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_DELETE"});
    methods->addResource(MethodsHandler::POST, "addAccountToRole", &addAccountToRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeAccountFromRole", &removeAccountFromRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_MODIFY"});
    methods->addResource(MethodsHandler::POST, "updateRoleDescription", &updateRoleDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_MODIFY"});
    methods->addResource(MethodsHandler::GET, "doesRoleExist", &doesRoleExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "validateApplicationPermissionOnRole", &validateApplicationPermissionOnRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleDescription", &getRoleDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "getRolesList", &getRolesList, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleApplicationPermissions", &getRoleApplicationPermissions, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleAccounts", &getRoleAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "searchRoles", &searchRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleInfo", &getRoleInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
}

void WebAdminMethods_Roles::addRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->roles->addRole(JSON_ASSTRING(*request.inputJSON, "roleName", ""), JSON_ASSTRING(*request.inputJSON, "getRoleDescription", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Roles::removeRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->roles->removeRole(JSON_ASSTRING(*request.inputJSON, "roleName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Roles::doesRoleExist(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->roles->doesRoleExist(JSON_ASSTRING(*request.inputJSON, "roleName", ""));
}

void WebAdminMethods_Roles::addAccountToRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->roles->addAccountToRole(JSON_ASSTRING(*request.inputJSON, "roleName", ""), JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Roles::removeAccountFromRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->roles->removeAccountFromRole(JSON_ASSTRING(*request.inputJSON, "roleName", ""), JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Roles::updateRoleDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->roles->updateRoleDescription(JSON_ASSTRING(*request.inputJSON, "roleName", ""), JSON_ASSTRING(*request.inputJSON, "getRoleDescription", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Roles::validateApplicationPermissionOnRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->validateApplicationPermissionOnRole(JSON_ASSTRING(*request.inputJSON, "roleName", ""),
                                                                                                                    {JSON_ASSTRING(*request.inputJSON, "appName", ""),
                                                                                                                     JSON_ASSTRING(*request.inputJSON, "id", "")});
}

void WebAdminMethods_Roles::getRoleDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->roles->getRoleDescription(JSON_ASSTRING(*request.inputJSON, "roleName", ""));
}

void WebAdminMethods_Roles::getRolesList(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->roles->getRolesList());
}

void WebAdminMethods_Roles::getRoleApplicationPermissions(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Methods::permissionListToJSON(Globals::getIdentityManager()->authController->getRoleApplicationPermissions(JSON_ASSTRING(*request.inputJSON, "roleName", "")));
}

void WebAdminMethods_Roles::getRoleAccounts(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->roles->getRoleAccounts(JSON_ASSTRING(*request.inputJSON, "roleName", "")));
}

void WebAdminMethods_Roles::searchRoles(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    json x;
    int i = 0;
    for (const auto &strVal : Globals::getIdentityManager()->roles->searchRoles(JSON_ASSTRING(*request.inputJSON, "searchWords", ""), JSON_ASUINT64(*request.inputJSON, "limit", 0),
                                                                                JSON_ASUINT64(*request.inputJSON, "offset", 0)))
    {
        x[i]["description"] = strVal.description;
        x[i]["roleName"] = strVal.roleName;
        i++;
    }
    (*response.responseJSON()) = x;
}

void WebAdminMethods_Roles::getRoleInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    // TODO: optimize:

    json payloadOut;
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");

    payloadOut["description"] = Globals::getIdentityManager()->roles->getRoleDescription(roleName);

    int i = 0;
    auto roleAccounts = Globals::getIdentityManager()->roles->getRoleAccounts(roleName);

    for (const auto &accountName : roleAccounts)
    {
        auto getAccountDetails = Globals::getIdentityManager()->accounts->getAccountDetails(accountName);
        payloadOut["accounts"][i]["name"] = accountName;
        /*        payloadOut["accounts"][i]["description"] = getAccountDetails.description;
        payloadOut["accounts"][i]["lastName"] = getAccountDetails.lastName;
        payloadOut["accounts"][i]["givenName"] = getAccountDetails.givenName;*/

        i++;
    }

    auto directPermissions = Globals::getIdentityManager()->authController->getRoleApplicationPermissions(roleName);

    i = 0;
    std::set<std::string> applications;
    for (const auto &permission : directPermissions)
    {
        if (applications.find(permission.appName) != applications.end())
            continue; // This application has been already mapped.

        applications.insert(permission.appName);
        payloadOut["applications"][i]["name"] = permission.appName;
        payloadOut["applications"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(permission.appName);

        // Take the active application permissions for this role:
        int x = 0;
        for (const auto &permission2 : directPermissions)
        {
            if (permission.appName == permission2.appName)
            {
                payloadOut["applications"][i]["permissions"][x]["id"] = permission.permissionId;
                payloadOut["applications"][i]["permissions"][x]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(permission);
                x++;
            }
        }
        // Take the unused application permissions for this role:

        x = 0;
        for (const ApplicationPermission &permission3 : Globals::getIdentityManager()->authController->listApplicationPermissions(permission.appName))
        {
            if (directPermissions.find(permission3) == directPermissions.end())
            {
                payloadOut["applications"][i]["permissionsLeft"][x]["id"] = permission3.permissionId;
                payloadOut["applications"][i]["permissionsLeft"][x]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(permission3);
                x++;
            }
        }

        i++;
    }

    i = 0;
    // put full application list:

    auto leftApplicationList = Globals::getIdentityManager()->applications->listApplications();

    for (const auto &appName : Globals::getIdentityManager()->applications->listApplications())
    {
        if (!WebAdmin_Methods::iPermissionsLeftListForRole(appName, roleName).empty())
        {
            payloadOut["leftApplicationsList"][i]["name"] = appName;
            payloadOut["leftApplicationsList"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(appName);
            i++;
        }
    }

    (*response.responseJSON()) = payloadOut;
}
