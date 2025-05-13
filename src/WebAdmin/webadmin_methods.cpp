#include "webadmin_methods.h"
#include "../globals.h"

using namespace Mantids30;

void WebAdmin_Methods::addMethods(std::shared_ptr<MethodsHandler> methods)
{
    addMethods_Accounts(methods);
    addMethods_Permissions(methods);
    addMethods_Applications(methods);
    addMethods_Roles(methods);
}

json WebAdmin_Methods::permissionListToJSON(const std::set<ApplicationPermission> &permissions)
{
    json x;
    int i = 0;
    for (const auto &permission : permissions)
    {
        x[i]["appName"] = permission.appName;
        x[i]["id"] = permission.permissionId;
        x[i++]["description"] = Globals::getIdentityManager()->authController->getApplicationPermissionDescription(permission);
    }
    return x;
}

std::set<ApplicationPermission> WebAdmin_Methods::iPermissionsLeftListForRole(const std::string &appName, const std::string &roleName)
{
    auto permissionsLeft = Globals::getIdentityManager()->authController->listApplicationPermissions(appName);
    auto rolePermissions = Globals::getIdentityManager()->authController->getRoleApplicationPermissions(roleName);

    for (const auto &rolePermission : rolePermissions)
    {
        permissionsLeft.erase(rolePermission);
    }
    return permissionsLeft;
}
