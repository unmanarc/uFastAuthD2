#pragma once


#include "IdentityManager/credentialvalidator.h"

#include "webadmin/webadmin_methods_accounts.h"
#include "webadmin/webadmin_methods_applications.h"
#include "webadmin/webadmin_methods_applicationspermissions.h"
#include "webadmin/webadmin_methods_roles.h"
#include <json/json.h>

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

// TODO: remover fastrpc3 de este proyecto.

// This template is for FastRPC
class WebAdmin_Methods : private WebAdminMethods_Accounts, private WebAdminMethods_Applications,
 private WebAdminMethods_ApplicationsPermissions, private WebAdminMethods_Roles
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;

    /**
     * @brief addMethods Add selected/reduced/filtered set of login authentication methods as server functions to the fastrpc connection for remote web applications
     * @param auth authentication manager (with full access to the authentication interface)
     * @param methods RPC engine to expose the methods
     */
    static void addMethods(std::shared_ptr<MethodsHandler> methods);

    // Helpers:
    static json permissionListToJSON(const std::set<ApplicationPermission> &permissions);
    static std::set<ApplicationPermission> iPermissionsLeftListForRole(const std::string &appName, const std::string &roleName);



};

