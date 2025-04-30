#include "webadmin_methods_applicationspermissions.h"

#include <Mantids30/Program_Logs/applog.h>
#include "webadmin_methods.h"
#include "../globals.h"
#include "defs.h"

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols::HTTP;


void WebAdminMethods_ApplicationsPermissions::addMethods_Permissions(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // Application Permissions

   methods->addResource(MethodsHandler::POST, "addApplicationPermission", &addApplicationPermission, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "removeApplicationPermission", &removeApplicationPermission, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "addApplicationPermissionToRole", &addApplicationPermissionToRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "removeApplicationPermissionFromRole", &removeApplicationPermissionFromRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "addApplicationPermissionToAccount", &addApplicationPermissionToAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "removeApplicationPermissionFromAccount", &removeApplicationPermissionFromAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "updateApplicationPermissionDescription", &updateApplicationPermissionDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::GET, "getApplicationPermissionDescription", &getApplicationPermissionDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "listApplicationPermissions", &listApplicationPermissions, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "getApplicationPermissionsForRole", &getApplicationPermissionsForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "listAccountsOnApplicationPermission", &listAccountsOnApplicationPermission, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "searchApplicationPermissions", &searchApplicationPermissions, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "permissionsLeftListForRole", &permissionsLeftListForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::POST, "addApplicationPermission", &addApplicationPermission, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "removeApplicationPermission", &removeApplicationPermission, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "addApplicationPermissionToRole", &addApplicationPermissionToRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "removeApplicationPermissionFromRole", &removeApplicationPermissionFromRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "addApplicationPermissionToAccount", &addApplicationPermissionToAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "removeApplicationPermissionFromAccount", &removeApplicationPermissionFromAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::POST, "updateApplicationPermissionDescription", &updateApplicationPermissionDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
   methods->addResource(MethodsHandler::GET, "getApplicationPermissionDescription", &getApplicationPermissionDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "listApplicationPermissions", &listApplicationPermissions, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "getApplicationPermissionsForRole", &getApplicationPermissionsForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "listAccountsOnApplicationPermission", &listAccountsOnApplicationPermission, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "searchApplicationPermissions", &searchApplicationPermissions, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
   methods->addResource(MethodsHandler::GET, "permissionsLeftListForRole", &permissionsLeftListForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
}

void WebAdminMethods_ApplicationsPermissions::addApplicationPermission(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON,"appName","");

    // Don't modify permissions from our directory.
    if ( appName == DB_APPNAME )
    {
        response.setError(Status::S_400_BAD_REQUEST,"invalid_request","Can't add application permission to the IAM");
        return;
    }

    if (!Globals::getIdentityManager()->authController->addApplicationPermission({appName,JSON_ASSTRING(*request.inputJSON,"id","")},
                                                                                 JSON_ASSTRING(*request.inputJSON,"description","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsPermissions::removeApplicationPermission(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON,"appName","");

    // Don't modify permissions from our directory.
    if ( appName == DB_APPNAME )
    {
        response.setError(Status::S_400_BAD_REQUEST,"invalid_request","Can't remove application permission to the IAM");
        return;
    }

    if (!Globals::getIdentityManager()->authController->removeApplicationPermission( {appName,JSON_ASSTRING(*request.inputJSON,"id","")}))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsPermissions::addApplicationPermissionToRole(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->authController->addApplicationPermissionToRole( {JSON_ASSTRING(*request.inputJSON,"appName",""),JSON_ASSTRING(*request.inputJSON,"id","")},JSON_ASSTRING(*request.inputJSON,"roleName","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsPermissions::removeApplicationPermissionFromRole(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->authController->removeApplicationPermissionFromRole( {JSON_ASSTRING(*request.inputJSON,"appName",""),JSON_ASSTRING(*request.inputJSON,"id","")},JSON_ASSTRING(*request.inputJSON,"roleName","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsPermissions::addApplicationPermissionToAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->authController->addApplicationPermissionToAccount( {JSON_ASSTRING(*request.inputJSON,"appName",""),JSON_ASSTRING(*request.inputJSON,"id","")},JSON_ASSTRING(*request.inputJSON,"accountName","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsPermissions::removeApplicationPermissionFromAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->authController->removeApplicationPermissionFromAccount( {JSON_ASSTRING(*request.inputJSON,"appName",""),JSON_ASSTRING(*request.inputJSON,"id","")},JSON_ASSTRING(*request.inputJSON,"accountName","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsPermissions::updateApplicationPermissionDescription(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON,"appName","");

    // Don't modify permissions from our directory.
    if ( appName == DB_APPNAME )
    {
        response.setError(Status::S_400_BAD_REQUEST,"invalid_request","Can't update application permission to the IAM");
    }

    if (!Globals::getIdentityManager()->authController->removeApplicationPermissionFromAccount( {appName,JSON_ASSTRING(*request.inputJSON,"id","")},JSON_ASSTRING(*request.inputJSON,"getApplicationPermissionDescription","")))
    {
        response.setError(Status::S_500_INTERNAL_SERVER_ERROR,"internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsPermissions::listApplicationPermissions(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Methods::permissionListToJSON(Globals::getIdentityManager()->authController->listApplicationPermissions(JSON_ASSTRING(*request.inputJSON,"appName","")));
}

void WebAdminMethods_ApplicationsPermissions::getApplicationPermissionsForRole(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->authController->getApplicationPermissionsForRole( {JSON_ASSTRING(*request.inputJSON,"appName",""),JSON_ASSTRING(*request.inputJSON,"id","")}));
}

void WebAdminMethods_ApplicationsPermissions::listAccountsOnApplicationPermission(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->authController->listAccountsOnApplicationPermission( {JSON_ASSTRING(*request.inputJSON,"appName",""),JSON_ASSTRING(*request.inputJSON,"id","")}));
}

void WebAdminMethods_ApplicationsPermissions::getApplicationPermissionDescription(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->getApplicationPermissionDescription({JSON_ASSTRING(*request.inputJSON,"appName",""),JSON_ASSTRING(*request.inputJSON,"id","")});
}

void WebAdminMethods_ApplicationsPermissions::searchApplicationPermissions(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    json payloadOut;

    int i=0;
    for (const auto & strVal : Globals::getIdentityManager()->authController->searchApplicationPermissions(
             JSON_ASSTRING(*request.inputJSON,"appName",""),
             JSON_ASSTRING(*request.inputJSON,"searchWords",""),
             JSON_ASUINT64(*request.inputJSON,"limit",0),
             JSON_ASUINT64(*request.inputJSON,"offset",0)
             ))
    {
        payloadOut[i]["id"] = strVal.permissionId;
        payloadOut[i]["description"] = strVal.description;
        i++;
    }
    (*response.responseJSON()) = payloadOut;
}

void WebAdminMethods_ApplicationsPermissions::permissionsLeftListForRole(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    auto permissionsLeft = WebAdmin_Methods::iPermissionsLeftListForRole(JSON_ASSTRING(*request.inputJSON,"appName",""),JSON_ASSTRING(*request.inputJSON,"roleName",""));
    (*response.responseJSON()) = WebAdmin_Methods::permissionListToJSON(permissionsLeft);
}

