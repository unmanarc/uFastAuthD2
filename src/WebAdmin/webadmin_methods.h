#pragma once


#include "IdentityManager/credentialvalidator.h"

#include "WebAdmin/webadmin_methods_accounts.h"
#include "WebAdmin/webadmin_methods_applications.h"
#include "WebAdmin/webadmin_methods_applicationspermissions.h"
#include "WebAdmin/webadmin_methods_roles.h"
#include <json/json.h>

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdmin_Methods : private WebAdminMethods_Accounts, private WebAdminMethods_Applications,
 private WebAdminMethods_ApplicationsPermissions, private WebAdminMethods_Roles
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The MethodsHandler to which the authentication methods will be added.
    */
    static void addMethods(std::shared_ptr<MethodsHandler> methods);

    // Helpers:
    static json permissionListToJSON(const std::set<ApplicationPermission> &permissions);
    static std::set<ApplicationPermission> iPermissionsLeftListForRole(const std::string &appName, const std::string &roleName);




};

