#include "identitymanager_db.h"
#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint64.h>

using namespace Mantids30;
using namespace Mantids30::Memory;
using namespace Mantids30::Database;

bool IdentityManager_DB::AuthController_DB::addApplicationPermission(const ApplicationPermission & applicationPermission, const std::string &sDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("INSERT INTO iam_applicationPermissions (`f_appName`,`permissionId`,`description`) VALUES(:appName,:permissionId,:description);",
                               {
                                   {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                   {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)},
                                   {":description",MAKE_VAR(STRING,sDescription)}
                               });
}

bool IdentityManager_DB::AuthController_DB::removeApplicationPermission(const ApplicationPermission & applicationPermission)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("DELETE FROM iam_applicationPermissions WHERE `permissionId`=:permissionId and `f_appName`=:appName;",
                               {
                                   {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                   {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)}
                               });
}

bool IdentityManager_DB::AuthController_DB::doesApplicationPermissionExist(const ApplicationPermission & applicationPermission)
{
    bool ret = false;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `description` FROM iam_applicationPermissions WHERE `permissionId`=:permissionId and `f_appName`=:appName LIMIT 1;",
                                          {
                                              {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                              {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)}
                                          },
                                          { });
    if (i->getResultsOK() && i->query->step())
    {
        ret = true;
    }
    return ret;
}

bool IdentityManager_DB::AuthController_DB::addApplicationPermissionToRole(const ApplicationPermission & applicationPermission, const std::string &roleName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    return _parent->m_sqlConnector->query("INSERT INTO iam_applicationPermissionsAtRole (`f_appName`,`f_permissionId`,`f_roleName`) VALUES(:appName,:permissionId,:roleName);",
                               {
                                   {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                   {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)},
                                   {":roleName",MAKE_VAR(STRING,roleName)}
                               });
}

bool IdentityManager_DB::AuthController_DB::removeApplicationPermissionFromRole(const ApplicationPermission & applicationPermission, const std::string &roleName, bool lock)
{
    bool ret = false;
    if (lock) _parent->m_mutex.lock();
    ret = _parent->m_sqlConnector->query("DELETE FROM iam_applicationPermissionsAtRole WHERE `f_permissionId`=:permissionId and `f_appName`=:appName AND `f_roleName`=:roleName;",
                              {
                                  {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                  {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)},
                                  {":roleName",MAKE_VAR(STRING,roleName)}
                              });
    if (lock) _parent->m_mutex.unlock();
    return ret;
}

bool IdentityManager_DB::AuthController_DB::addApplicationPermissionToAccount(const ApplicationPermission & applicationPermission, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("INSERT INTO iam_applicationPermissionsAtAccount (`f_appName`,`f_permissionId`,`f_userName`) VALUES(:appName,:permissionId,:userName);",
                               {
                                   {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                   {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)},
                                   {":userName",MAKE_VAR(STRING,accountName)}
                               });
}

bool IdentityManager_DB::AuthController_DB::removeApplicationPermissionFromAccount(const ApplicationPermission & applicationPermission, const std::string &accountName, bool lock)
{
    bool ret = false;
    if (lock) _parent->m_mutex.lock();
    ret = _parent->m_sqlConnector->query("DELETE FROM iam_applicationPermissionsAtAccount WHERE `f_permissionId`=:permissionId AND `f_appName`=:appName AND `f_userName`=:userName;",
                              {
                                  {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                  {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)},
                                  {":userName",MAKE_VAR(STRING,accountName)}
                              });
    if (lock) _parent->m_mutex.unlock();
    return ret;
}

bool IdentityManager_DB::AuthController_DB::updateApplicationPermissionDescription(const ApplicationPermission & applicationPermission, const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("UPDATE iam_applicationPermissions SET `description`=:description WHERE `permissionId`=:permissionId AND `f_appName`=:appName;",
                               {
                                   {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                   {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)},
                                   {":description",MAKE_VAR(STRING,description)}
                               });
}

std::string IdentityManager_DB::AuthController_DB::getApplicationPermissionDescription(const ApplicationPermission & applicationPermission)
{
    std::string ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING description;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `description` FROM iam_applicationPermissions WHERE `permissionId`=:permissionId AND `f_appName`=:appName LIMIT 1;",
                                          {
                                              {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                              {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)}
                                          },
                                          { &description });
    if (i->getResultsOK() && i->query->step())
    {
        return description.getValue();
    }
    return "";
}

std::set<ApplicationPermission> IdentityManager_DB::AuthController_DB::listApplicationPermissions(const std::string & applicationName)
{
    std::set<ApplicationPermission> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING sAppName,sPermissionId;

    std::string sqlQuery = "SELECT `f_appName`,`permissionId` FROM iam_applicationPermissions;";
    if (!applicationName.empty())
        sqlQuery = "SELECT `f_appName`,`permissionId` FROM iam_applicationPermissions WHERE `f_appName`=:appName;";

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect(sqlQuery,
                                          { {":appName", MAKE_VAR(STRING,applicationName)} },
                                          { &sAppName,&sPermissionId });
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert({sAppName.getValue(),sPermissionId.getValue()});
    }
    return ret;
}

std::set<std::string> IdentityManager_DB::AuthController_DB::getApplicationPermissionsForRole(const ApplicationPermission & applicationPermission, bool lock)
{
    std::set<std::string> ret;
    if (lock) _parent->m_mutex.lockShared();

    Abstract::STRING roleName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam_applicationPermissionsAtRole WHERE `f_permissionId`=:permissionId AND `f_appName`=:appName;",
                                          {
                                              {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                              {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)}
                                          },
                                          { &roleName });
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(roleName.getValue());
    }
    
    if (lock) _parent->m_mutex.unlockShared();
    return ret;
}

std::set<std::string> IdentityManager_DB::AuthController_DB::listAccountsOnApplicationPermission(const ApplicationPermission & applicationPermission, bool lock)
{
    std::set<std::string> ret;
    if (lock) _parent->m_mutex.lockShared();


    Abstract::STRING accountName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_userName` FROM iam_applicationPermissionsAtAccount WHERE `f_permissionId`=:permissionId AND `f_appName`=:appName;",
                                          {
                                              {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                              {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)}
                                          },
                                          { &accountName });
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(accountName.getValue());
    }
    
    if (lock) _parent->m_mutex.unlockShared();
    return ret;
}

std::list<ApplicationPermissionDetails> IdentityManager_DB::AuthController_DB::searchApplicationPermissions(const std::string &appName, std::string sSearchWords, uint64_t limit, uint64_t offset)
{
    std::list<ApplicationPermissionDetails> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING permissionId,description;

    std::string sSqlQuery = "SELECT `permissionId`,`description` FROM iam_applications WHERE `f_appName`=:APPNAME";

    if (!sSearchWords.empty())
    {
        sSearchWords = '%' + sSearchWords + '%';
        sSqlQuery+=" AND (`applicationName` LIKE :SEARCHWORDS OR `appDescription` LIKE :SEARCHWORDS)";
    }

    if (limit)
        sSqlQuery+=" LIMIT :LIMIT OFFSET :OFFSET";

    sSqlQuery+=";";

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect(sSqlQuery,
                                          {
                                              {":APPNAME",MAKE_VAR(STRING,appName)},
                                              {":SEARCHWORDS",MAKE_VAR(STRING,sSearchWords)},
                                              {":LIMIT",MAKE_VAR(UINT64,limit)},
                                              {":OFFSET",MAKE_VAR(UINT64,offset)}
                                          },
                                          { &permissionId, &description });
    while (i->getResultsOK() && i->query->step())
    {
        ApplicationPermissionDetails rDetail;

        rDetail.description = description.getValue();
        rDetail.permissionId = permissionId.getValue();

        ret.push_back(rDetail);
    }

    return ret;
}

bool IdentityManager_DB::AuthController_DB::validateAccountDirectApplicationPermission(const std::string &accountName, const ApplicationPermission & applicationPermission)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_userName` FROM iam_applicationPermissionsAtAccount WHERE `f_permissionId`=:permissionId AND `f_userName`=:userName AND `f_appName`=:appName;",
                                          { {":permissionId",MAKE_VAR(STRING,applicationPermission.permissionId)},
                                            {":appName",MAKE_VAR(STRING,applicationPermission.appName)},
                                            {":userName",MAKE_VAR(STRING,accountName)}
                                          },
                                          { });
    return (i->getResultsOK() && i->query->step());
}
