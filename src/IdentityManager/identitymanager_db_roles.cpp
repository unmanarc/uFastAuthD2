#include "identitymanager_db.h"
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Threads/lock_shared.h>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

bool IdentityManager_DB::Roles_DB::addRole(const std::string &roleName, const std::string &roleDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("INSERT INTO iam.roles (`roleName`,`roleDescription`) VALUES(:roleName,:roleDescription);",
                                          {{":roleName", MAKE_VAR(STRING, roleName)}, {":roleDescription", MAKE_VAR(STRING, roleDescription)}});
}

bool IdentityManager_DB::Roles_DB::removeRole(const std::string &roleName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("DELETE FROM iam.roles WHERE `roleName`=:roleName;", {{":roleName", MAKE_VAR(STRING, roleName)}});
}

bool IdentityManager_DB::Roles_DB::doesRoleExist(const std::string &roleName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `roleName` FROM iam.roles WHERE `roleName`=:roleName;", {{":roleName", MAKE_VAR(STRING, roleName)}}, {});
    return (i->getResultsOK()) && i->query->step();
}

bool IdentityManager_DB::Roles_DB::addAccountToRole(const std::string &roleName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("INSERT INTO iam.rolesAccounts (`f_roleName`,`f_accountName`) VALUES(:roleName,:accountName);",
                                          {{":roleName", MAKE_VAR(STRING, roleName)}, {":accountName", MAKE_VAR(STRING, accountName)}});
}

bool IdentityManager_DB::Roles_DB::removeAccountFromRole(const std::string &roleName, const std::string &accountName, bool lock)
{
    bool ret = false;
    if (lock)
        _parent->m_mutex.lock();
    ret = _parent->m_sqlConnector->query("DELETE FROM iam.rolesAccounts WHERE `f_roleName`=:roleName AND `f_accountName`=:accountName;",
                                         {{":roleName", MAKE_VAR(STRING, roleName)}, {":accountName", MAKE_VAR(STRING, accountName)}});

    if (lock)
        _parent->m_mutex.unlock();
    return ret;
}

bool IdentityManager_DB::Roles_DB::updateRoleDescription(const std::string &roleName, const std::string &roleDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("UPDATE iam.roles SET `roleDescription`=:roleDescription WHERE `roleName`=:roleName;",
                                          {{":roleName", MAKE_VAR(STRING, roleName)}, {":roleDescription", MAKE_VAR(STRING, roleDescription)}});
}

std::string IdentityManager_DB::Roles_DB::getRoleDescription(const std::string &roleName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING roleDescription;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `roleDescription` FROM iam.roles WHERE `roleName`=:roleName LIMIT 1;",
                                                                                      {{":roleName", MAKE_VAR(STRING, roleName)}}, {&roleDescription});
    if (i->getResultsOK() && i->query->step())
    {
        return roleDescription.getValue();
    }
    return "";
}

std::set<std::string> IdentityManager_DB::Roles_DB::getRolesList()
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING roleName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `roleName` FROM iam.roles;", {}, {&roleName});
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(roleName.getValue());
    }
    return ret;
}

std::set<std::string> IdentityManager_DB::Roles_DB::getRoleAccounts(const std::string &roleName, bool lock)
{
    std::set<std::string> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING accountName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_accountName` FROM iam.rolesAccounts WHERE `f_roleName`=:roleName;",
                                                                                      {{":roleName", MAKE_VAR(STRING, roleName)}}, {&accountName});
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(accountName.getValue());
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}

std::list<RoleDetails> IdentityManager_DB::Roles_DB::searchRoles(std::string sSearchWords, size_t limit, size_t offset)
{
    std::list<RoleDetails> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING roleName, description;

    std::string sSqlQuery = "SELECT `roleName`,`roleDescription` FROM iam.roles";

    if (!sSearchWords.empty())
    {
        sSearchWords = '%' + sSearchWords + '%';
        sSqlQuery += " WHERE (`roleName` LIKE :SEARCHWORDS OR `roleDescription` LIKE :SEARCHWORDS)";
    }

    if (limit)
        sSqlQuery += " LIMIT :LIMIT OFFSET :OFFSET";

    sSqlQuery += ";";

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect(sSqlQuery,
                                                                                      {{":SEARCHWORDS", MAKE_VAR(STRING, sSearchWords)},
                                                                                       {":LIMIT", MAKE_VAR(UINT64, limit)},
                                                                                       {":OFFSET", MAKE_VAR(UINT64, offset)}},
                                                                                      {&roleName, &description});
    while (i->getResultsOK() && i->query->step())
    {
        RoleDetails rDetail;

        rDetail.description = description.getValue();
        rDetail.roleName = roleName.getValue();

        ret.push_back(rDetail);
    }

    return ret;
}
