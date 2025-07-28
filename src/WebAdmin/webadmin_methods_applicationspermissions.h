#pragma once

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdminMethods_ApplicationsPermissions
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addMethods_Permissions(std::shared_ptr<MethodsHandler> methods);

    static void addApplicationPermission(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeApplicationPermission(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void addApplicationPermissionToRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeApplicationPermissionFromRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void addApplicationPermissionToAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeApplicationPermissionFromAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void updateApplicationPermissionDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void listApplicationPermissions(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void getApplicationPermissionsForRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void listAccountsOnApplicationPermission(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void searchApplicationPermissions(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void permissionsLeftListForRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void getApplicationPermissionDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
};
