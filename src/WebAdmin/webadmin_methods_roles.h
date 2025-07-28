#pragma once

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdminMethods_Roles
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addMethods_Roles(std::shared_ptr<MethodsHandler> methods);

    static void addRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void doesRoleExist(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void addAccountToRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeAccountFromRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void updateRoleDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void validateApplicationPermissionOnRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void getRoleDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void getRolesList(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void getRoleApplicationPermissions(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void getRoleAccounts(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void searchRoles(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void getRoleInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
};
