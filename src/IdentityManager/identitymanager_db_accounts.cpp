#include "IdentityManager/identitymanager.h"
#include "identitymanager_db.h"


#include <regex>
#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>

using namespace Mantids30;
using namespace Mantids30::Memory;
using namespace Mantids30::Database;

bool IdentityManager_DB::Users_DB::addAccount(const std::string &accountName, time_t expirationDate, const AccountFlags &accountFlags, const std::string &sCreatorAccountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool r = _parent->m_sqlConnector->query("INSERT INTO iam_accounts (`userName`,`isSuperuser`,`isEnabled`,`isBlocked`,`expiration`,`isAccountConfirmed`,`creator`) "
                                                       "VALUES(:userName,:superuser ,:enabled, :blocked ,:expiration ,:confirmed ,:creator);",
                               {
                                   {":userName",MAKE_VAR(STRING,accountName)},
                                   {":superuser",MAKE_VAR(BOOL,accountFlags.superuser)},
                                   {":enabled",MAKE_VAR(BOOL,accountFlags.enabled)},
                                   {":blocked",MAKE_VAR(BOOL,accountFlags.blocked)},
                                   {":expiration",MAKE_VAR(DATETIME,expirationDate)},
                                   {":confirmed",MAKE_VAR(BOOL,accountFlags.confirmed)},
                                             {":creator", sCreatorAccountName.empty() ? MAKE_NULL_VAR /* null */ : MAKE_VAR(STRING,sCreatorAccountName)}
                               }
                                            );


    if (r)
    {
        // Now create the activation token...
        r =            _parent->m_sqlConnector->query("INSERT INTO iam_accountsActivationToken (`f_userName`,`confirmationToken`) "
                                           "VALUES(:account,:confirmationToken);",
                                           {
                                               {":account",MAKE_VAR(STRING,accountName)},
                                               {":confirmationToken",MAKE_VAR(STRING,_parent->authController->genRandomConfirmationToken())}
                                           }
                                           );
        if (r)
        {
            // Now create the credential... but!!... the credential should be a valid subset from an authentication mode...

        }
    }

    return r;

}

bool IdentityManager_DB::Users_DB::removeAccount(const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (isThereAnotherSuperUser(accountName))
    {
        return _parent->m_sqlConnector->query("DELETE FROM iam_accounts WHERE `userName`=:userName;",
                                   {
                                       {":userName",MAKE_VAR(STRING,accountName)}
                                   });
    }
    return false;
}

bool IdentityManager_DB::Users_DB::doesAccountExist(const std::string &accountName)
{
    bool ret = false;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `isEnabled` FROM iam_accounts WHERE `userName`=:userName LIMIT 1;",
                                          {{":userName",MAKE_VAR(STRING,accountName)}},
                                          { });
    if (i->getResultsOK() && i->query->step())
    {
        ret = true;
    }
    return ret;
}

bool IdentityManager_DB::Users_DB::disableAccount(const std::string &accountName, bool disabled)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (disabled==true && !isThereAnotherSuperUser(accountName))
    {
        return false;
    }

    return _parent->m_sqlConnector->query("UPDATE iam_accounts SET `isEnabled`=:enabled WHERE `userName`=:userName;",
                               {
                                   {":enabled",MAKE_VAR(BOOL,!disabled)},
                                   {":userName",MAKE_VAR(STRING,accountName)}
                               });
}

bool IdentityManager_DB::Users_DB::confirmAccount(const std::string &accountName, const std::string &confirmationToken)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    Abstract::STRING token;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `confirmationToken` FROM iam_accountsActivationToken WHERE `f_userName`=:userName LIMIT 1;",
                                          { {":userName",MAKE_VAR(STRING,accountName)} },
                                          { &token });

    if (i->getResultsOK() && i->query->step())
    {
        if (!token.getValue().empty() && token.getValue() == confirmationToken)
        {
            return _parent->m_sqlConnector->query("UPDATE iam_accounts SET `isAccountConfirmed`='1' WHERE `userName`=:userName;",
                                       {
                                           {":userName",MAKE_VAR(STRING,accountName)}
                                       });
        }
    }
    return false;
}

bool IdentityManager_DB::Users_DB::changeAccountExpiration(const std::string &accountName, time_t expiration)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    return _parent->m_sqlConnector->query("UPDATE iam_accounts SET `expiration`=:expiration WHERE `userName`=:userName;",
                               {
                                   {":expiration",MAKE_VAR(DATETIME,expiration)},
                                   {":userName",MAKE_VAR(STRING,accountName)}
                               });
}

AccountFlags IdentityManager_DB::Users_DB::getAccountFlags(const std::string &accountName)
{
    AccountFlags r;

    Abstract::BOOL enabled,confirmed,superuser;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `isEnabled`,`isAccountConfirmed`,`isSuperuser` FROM iam_accounts WHERE `userName`=:userName LIMIT 1;",
                                          { {":userName",MAKE_VAR(STRING,accountName)} },
                                          { &enabled,&confirmed,&superuser});

    if (i->getResultsOK() && i->query->step())
    {
        r.enabled = enabled.getValue();
        r.confirmed = confirmed.getValue();
        r.superuser = superuser.getValue();
    }


    return r;
}

bool IdentityManager_DB::Users_DB::updateAccountRoles(const std::string &accountName, const std::set<std::string> &roleSet)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->query("DELETE FROM iam_rolesAccounts WHERE `f_userName`=:userName;",
    {
        {":userName",MAKE_VAR(STRING,accountName)}
    }))
        return false;

    for (const auto & role : roleSet)
    {
        if (!_parent->m_sqlConnector->query("INSERT INTO iam_rolesAccounts (`f_roleName`,`f_userName`) VALUES(:roleName,:userName);",
        {
            {":roleName",MAKE_VAR(STRING,role)},
            {":userName",MAKE_VAR(STRING,accountName)}
        }))
        return false;
    }
    return true;
}

bool IdentityManager_DB::Users_DB::changeAccountFlags(const std::string &accountName, const AccountFlags &accountFlags)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if ((accountFlags.confirmed==false || accountFlags.enabled==false || accountFlags.superuser==false) && !isThereAnotherSuperUser(accountName))
    {
        return false;
    }

    return _parent->m_sqlConnector->query("UPDATE iam_accounts SET `isEnabled`=:enabled,`isAccountConfirmed`=:confirmed,`isSuperuser`=:superuser WHERE `userName`=:userName;",
                               {
                                   {":enabled",MAKE_VAR(BOOL,accountFlags.enabled)},
                                   {":confirmed",MAKE_VAR(BOOL,accountFlags.confirmed)},
                                   {":superuser",MAKE_VAR(BOOL,accountFlags.superuser)},
                                   {":userName",MAKE_VAR(STRING,accountName)}
                               });
}

AccountDetails IdentityManager_DB::Users_DB::getAccountDetails(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // Definir las variables para capturar los valores de la base de datos
    Abstract::STRING creator;
    Abstract::BOOL isSuperuser, isEnabled, isAccountConfirmed;
    Abstract::DATETIME creation, expiration;

    auto allFields = listAccountDetailFields();
    bool accountExist = false;
    AccountDetails details;

    {
        std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `isSuperuser`,`creation`, `creator`, `expiration`, `isEnabled`, `isAccountConfirmed` "
                                                                                 "FROM iam_accounts WHERE `userName`=:userName LIMIT 1;",
                                                                                 {{":userName", MAKE_VAR(STRING,accountName)}},
                                                                                 {&isSuperuser, &creation, &creator, &expiration, &isEnabled, &isAccountConfirmed});

        if (i->getResultsOK() && i->query->step())
        {
            details.accountName = accountName;
            details.creator = creator.getValue();
            details.accountFlags.superuser = isSuperuser.getValue();
            details.accountFlags.enabled = isEnabled.getValue();
            details.accountFlags.confirmed = isAccountConfirmed.getValue();
            details.expirationDate = expiration.getValue();
            details.creationDate = creation.getValue();
            details.expired = std::time(nullptr) > details.expirationDate;
            accountExist = true;
        }
    }

    if (accountExist)
    {
        details.fieldValues = getAccountDetailValues(accountName, ACCOUNT_DETAILS_ALL);

        for (auto &i : details.fieldValues)
        {
            if (allFields.find(i.first) != allFields.end())
                details.fields[i.first] = allFields[i.first];
        }
    }

    return details;
}

time_t IdentityManager_DB::Users_DB::getAccountExpirationTime(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::DATETIME expiration;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `expiration` FROM iam_accounts WHERE `userName`=:userName LIMIT 1;",
                                          { {":userName",MAKE_VAR(STRING,accountName)} },
                                          { &expiration });
    if (i->getResultsOK() && i->query->step())
    {
        return expiration.getValue();
    }
    // If can't get this data, the account is expired:
    return 1;
}

time_t IdentityManager_DB::Users_DB::getAccountCreationTime(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::DATETIME creation;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect(
        "SELECT `creation` FROM iam_accounts WHERE `userName`=:userName LIMIT 1;",
        { {":userName", MAKE_VAR(STRING,accountName)} },
        { &creation }
        );

    if (i->getResultsOK() && i->query->step())
    {
        return creation.getValue(); // Asegúrate de convertir a `time_t` si es necesario
    }

    return std::numeric_limits<time_t>::max();
}
/*
std::list<AccountDetails> IdentityManager_DB::Users_DB::searchAccounts(std::string sSearchWords, uint64_t limit, uint64_t offset)
{
    std::list<AccountDetails> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountName;
    Abstract::BOOL superuser,enabled,confirmed;
    Abstract::DATETIME expiration;

    std::string sSqlQuery = "SELECT `userName`,`isSuperuser`,`isEnabled`,`expiration`,`isAccountConfirmed` FROM iam_accounts";

    if (!sSearchWords.empty())
    {
        sSearchWords = '%' + sSearchWords + '%';
        // TODO: this is the previous implementation, but now has to be compatible with the new database model
        //sSqlQuery+=" WHERE (`userName` LIKE :SEARCHWORDS OR `givenName` LIKE :SEARCHWORDS OR `lastName` LIKE :SEARCHWORDS OR `email` LIKE :SEARCHWORDS OR `description` LIKE :SEARCHWORDS)";
    }

    if (limit)
        sSqlQuery+=" LIMIT :LIMIT OFFSET :OFFSET";

    sSqlQuery+=";";

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect(sSqlQuery,
                                          {
                                              {":SEARCHWORDS",MAKE_VAR(STRING,sSearchWords)},
                                              {":LIMIT",MAKE_VAR(UINT64,limit)},
                                              {":OFFSET",MAKE_VAR(UINT64,offset)}
                                          },
                                          { &accountName, &superuser, &enabled, &expiration, &confirmed });
    while (i->getResultsOK() && i->query->step())
    {
        AccountDetails rDetail;

        rDetail.accountFlags.confirmed = confirmed.getValue();
        rDetail.accountFlags.enabled = enabled.getValue();
        rDetail.accountFlags.superuser = superuser.getValue();
        rDetail.expired = !expiration.getValue()?false:expiration.getValue()<time(nullptr);
        rDetail.accountName = accountName.getValue();
        rDetail.fieldValues = getAccountDetailValues(accountName.getValue(), ACCOUNT_DETAILS_SEARCH);

        auto allFields = listAccountDetailFields();
        for (auto &i : rDetail.fieldValues)
        {
            if (allFields.find(i.first) != allFields.end())
                rDetail.fields[i.first] = allFields[i.first];
        }

        ret.push_back(rDetail);
    }

    return ret;
}*/


std::list<AccountDetails> IdentityManager_DB::Users_DB::searchAccounts(std::string sSearchWords, uint64_t limit, uint64_t offset)
{
    std::list<AccountDetails> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountName;
    Abstract::BOOL superuser, enabled, confirmed;
    Abstract::DATETIME expiration;

    std::string sSqlQuery = "SELECT DISTINCT va.`userName`, va.`isSuperuser`, va.`isEnabled`, va.`expiration`, va.`isAccountConfirmed` FROM iam_accounts va";

    if (!sSearchWords.empty())
    {
        sSearchWords = '%' + sSearchWords + '%';
        sSqlQuery += " JOIN iam_accountDetailValues vadv ON va.`userName` = vadv.`f_username`";
        sSqlQuery += " JOIN iam_accountDetailFields vadf ON vadv.`f_fieldName` = vadf.`fieldName`";
        sSqlQuery += " WHERE vadf.`includeInSearch` = 1 AND vadv.`value` LIKE :SEARCHWORDS";
    }

    if (limit)
    {
        sSqlQuery += " LIMIT :LIMIT OFFSET :OFFSET";
    }

    sSqlQuery += ";";

    auto allFields = listAccountDetailFields();

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect(
        sSqlQuery,
        {
            {":SEARCHWORDS", MAKE_VAR(STRING,sSearchWords)},
            {":LIMIT", MAKE_VAR(UINT64,limit)},
            {":OFFSET", MAKE_VAR(UINT64,offset)}
        },
        { &accountName, &superuser, &enabled, &expiration, &confirmed }
        );

    while (i->getResultsOK() && i->query->step())
    {
        AccountDetails rDetail;

        rDetail.accountFlags.confirmed = confirmed.getValue();
        rDetail.accountFlags.enabled = enabled.getValue();
        rDetail.accountFlags.superuser = superuser.getValue();
        rDetail.expired = !expiration.getValue() ? false : expiration.getValue() < time(nullptr);
        rDetail.accountName = accountName.getValue();
        rDetail.fieldValues = getAccountDetailValues(accountName.getValue(), ACCOUNT_DETAILS_SEARCH);

        for (auto &i : rDetail.fieldValues)
        {
            if (allFields.find(i.first) != allFields.end())
                rDetail.fields[i.first] = allFields[i.first];
        }

        ret.push_back(rDetail);
    }

    return ret;
}






std::set<std::string> IdentityManager_DB::Users_DB::listAccounts()
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `userName` FROM iam_accounts;",
                                          { },
                                          { &accountName });
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(accountName.getValue());
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::Users_DB::getAccountRoles(const std::string &accountName, bool lock)
{
    std::set<std::string> ret;
    if (lock) _parent->m_mutex.lockShared();

    Abstract::STRING role;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam_rolesAccounts WHERE `f_userName`=:userName;",
                                          { {":userName",MAKE_VAR(STRING,accountName)} },
                                          { &role });
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(role.getValue());
    }
    
    if (lock) _parent->m_mutex.unlockShared();
    return ret;
}

bool IdentityManager_DB::Users_DB::hasSuperUserAccount()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `isSuperuser` FROM iam_accounts WHERE `isSuperuser`=:superuser LIMIT 1;",
                                          { {":superuser",MAKE_VAR(BOOL,true)} },
                                          { });

    if (i->getResultsOK() && i->query->step())
        return true;

    return false;
}

bool IdentityManager_DB::Users_DB::isThereAnotherSuperUser(const std::string &accountName)
{
    // Check if there is any superuser acount beside this "to be deleted" account...
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `isEnabled` FROM iam_accounts WHERE `userName`!=:userName and `isSuperuser`=:superUser and `isEnabled`=:enabled and `isAccountConfirmed`=:confirmed LIMIT 1;",
                                          {
                                              {":userName",MAKE_VAR(STRING,accountName)},
                                              {":superUser",MAKE_VAR(BOOL,true)},
                                              {":enabled",MAKE_VAR(BOOL,true)},
                                              {":confirmed",MAKE_VAR(BOOL,true)}
                                          },
                                          { });

    if (i->getResultsOK() && i->query->step())
        return true;
    return false;

}



int32_t IdentityManager_DB::Users_DB::getAccountBlockTokenNoRenew(const std::string &accountName, std::string &token)
{
    auto authenticationPolicy = _parent->authController->getAuthenticationPolicy();
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING blockToken;
    Abstract::DATETIME lastAccess;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `blockToken`,`lastAccess` FROM iam_accountsBlockToken WHERE `f_userName`=:userName;", {{":userName", MAKE_VAR(STRING,accountName)}}, {&blockToken, &lastAccess});
    if (i->getResultsOK() && i->query->step())
    {
        if (lastAccess.getValue() + authenticationPolicy.blockTokenTimeout > time(nullptr))
        {
            token = blockToken.getValue();
            return 0;
        }
        return -1;
    }
    return -2;
}

void IdentityManager_DB::Users_DB::removeBlockToken(const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    _parent->m_sqlConnector->query("DELETE FROM iam_accountsBlockToken WHERE `f_userName`=:userName;", {{":userName", MAKE_VAR(STRING,accountName)}});
}

void IdentityManager_DB::Users_DB::updateOrCreateBlockToken(const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    if (!_parent->m_sqlConnector->query("UPDATE iam_accountsBlockToken SET `lastAccess`=CURRENT_TIMESTAMP WHERE `f_userName`=:userName;", {{":userName", MAKE_VAR(STRING,accountName)}}))
    {
        _parent->m_sqlConnector->query("INSERT INTO iam_accountsBlockToken (`f_userName`,`blockToken`) VALUES(:account,:blockToken);", {{":account", MAKE_VAR(STRING,accountName)}, {":blockToken", MAKE_VAR(STRING,_parent->authController->genRandomConfirmationToken())}});
    }
}

std::string IdentityManager_DB::Users_DB::getAccountBlockToken(const std::string &accountName)
{
    std::string token;
    int32_t i = getAccountBlockTokenNoRenew(accountName, token);
    if (i == 0)
    {
        // Update the registry last access here...
        updateOrCreateBlockToken(accountName);
        return token;
    }
    else if (i == -1)
    {
        // Expired, remove the previous one create a new one...
        removeBlockToken(accountName);
        updateOrCreateBlockToken(accountName);
    }
    else if (i == -2)
    {
        // No registry... Create a new one...
        updateOrCreateBlockToken(accountName);
    }
    i = getAccountBlockTokenNoRenew(accountName, token);
    if (i == 0)
    {
        return token;
    }

    return "";
}

bool IdentityManager_DB::Users_DB::blockAccountUsingToken(const std::string &accountName, const std::string &blockToken)
{
    std::string dbBlockToken;
    if (getAccountBlockTokenNoRenew(accountName, dbBlockToken) == 0)
    {
        if (dbBlockToken == blockToken)
        {
            // everything in place to block this account:
            return disableAccount(accountName);
        }
    }
    return false;
}

bool IdentityManager_DB::Users_DB::addAccountDetailField(const std::string &fieldName, const AccountDetailField & details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->query("INSERT INTO iam_accountDetailFields (`fieldName`, `fieldDescription`, `fieldRegexpValidator`, `fieldType`, `isOptionalField`, `includeInSearch`, `includeInToken`, `includeInColumnView`)"
                                        " VALUES (:fieldName, :fieldDescription, :fieldRegexpValidator, :fieldType, :isOptionalField, :includeInSearch,:includeInToken, :includeInColumnView);",
                                        {
                                            {":fieldName", MAKE_VAR(STRING,fieldName)},
                                            {":fieldDescription", MAKE_VAR(STRING,details.description)},
                                            {":fieldRegexpValidator", MAKE_VAR(STRING,details.regexpValidator)},
                                            {":fieldType", MAKE_VAR(STRING,details.fieldType)},
                                            {":isOptionalField", MAKE_VAR(BOOL,details.isOptionalField)},
                                            {":includeInSearch", MAKE_VAR(BOOL,details.includeInSearch)},
                                            {":includeInToken", MAKE_VAR(BOOL,details.includeInToken)},
                                            {":includeInColumnView", MAKE_VAR(BOOL,details.includeInColumnView)}
                                        }))
    {
        return false;
    }

    return true;
}

bool IdentityManager_DB::Users_DB::removeAccountDetailField(const std::string &fieldName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->query("DELETE FROM iam_accountDetailFields WHERE `fieldName` = :fieldName;",
                                        {
                                            {":fieldName", MAKE_VAR(STRING,fieldName)}
                                        }))
    {
        return false;
    }

    return true;
}

std::map<std::string, AccountDetailField> IdentityManager_DB::Users_DB::listAccountDetailFields()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<std::string, AccountDetailField> fieldMap;

    // Variables para capturar valores de la base de datos
    Abstract::STRING fieldName, fieldDescription, fieldRegexpValidator, fieldType;
    Abstract::BOOL isOptionalField, includeInSearch, includeInColumnView, includeInToken;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect(
        "SELECT `fieldName`, `fieldDescription`, `fieldRegexpValidator`, `fieldType`, `isOptionalField`, `includeInSearch`, `includeInColumnView` FROM `iam_accountDetailFields`;",
        {},
        {&fieldName, &fieldDescription, &fieldRegexpValidator, &fieldType, &isOptionalField, &includeInSearch, &includeInColumnView}
        );

    if (i->getResultsOK())
    {
        while (i->query->step())
        {
            AccountDetailField field;
            field.description = fieldDescription.getValue();
            field.regexpValidator = fieldRegexpValidator.getValue();
            field.fieldType = fieldType.getValue();
            field.isOptionalField = isOptionalField.getValue();
            field.includeInSearch = includeInSearch.getValue();
            field.includeInToken = includeInToken.getValue();
            field.includeInColumnView = includeInColumnView.getValue();

            fieldMap[fieldName.getValue()] = field;
        }
    }

    return fieldMap;
}



bool IdentityManager_DB::Users_DB::changeAccountDetails(const std::string &accountName, const std::map<std::string, std::string> &fieldsValues, bool resetAllValues)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (resetAllValues)
    {
        // Delete all values for the specified account
        _parent->m_sqlConnector->query("DELETE FROM iam_accountDetailValues WHERE `f_username` = :userName;",
                                       {{":userName", MAKE_VAR(STRING,accountName)}});
    }
    else
    {
        // Delete only specified fields for the account
        for (const auto &field : fieldsValues)
        {
            _parent->m_sqlConnector->query("DELETE FROM iam_accountDetailValues WHERE `f_username` = :userName AND `f_fieldName` = :fieldName;",
                                           {{":userName", MAKE_VAR(STRING,accountName)},
                                            {":fieldName", MAKE_VAR(STRING,field.first)}});
        }
    }

    // Insert new values
    for (const auto& field : fieldsValues)
    {
        // Validate field value against regex from iam_accountDetailFields
        Abstract::STRING regex;
        if (_parent->m_sqlConnector->qSelect("SELECT `fieldRegexpValidator` FROM iam_accountDetailFields WHERE `fieldName` = :fieldName;",
                                             { {":fieldName", MAKE_VAR(STRING,field.first)} },
                                             { &regex })->getResultsOK())
        {
            std::regex reg(regex.getValue());
            if (!std::regex_match(field.second, reg))
            {
                // The value does not match the regex
                return false;
            }
        }

        // Inserting the validated value
        if (!_parent->m_sqlConnector->query("INSERT INTO iam_accountDetailValues (`f_username`, `f_fieldName`, `value`) VALUES(:userName, :fieldName, :value);",
                                            { {":userName", MAKE_VAR(STRING,accountName)},
                                             {":fieldName", MAKE_VAR(STRING,field.first)},
                                             {":value", MAKE_VAR(STRING,field.second)} }))
        {
            return false;
        }
    }

    return true;
}

bool IdentityManager_DB::Users_DB::removeAccountDetail(const std::string &accountName, const std::string &fieldName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("DELETE FROM iam_accountDetailValues WHERE `f_username` = :userName AND `f_fieldName` = :fieldName;",
                                   {{":userName", MAKE_VAR(STRING,accountName)},
                                           {":fieldName", MAKE_VAR(STRING,fieldName)}});
}

std::map<std::string, std::string> IdentityManager_DB::Users_DB::getAccountDetailValues(const std::string &accountName, const AccountDetailsToShow &detailsToShow)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<std::string, std::string> detailValues;

    Abstract::STRING fieldName, value;

    std::string query = "SELECT vadv.`f_fieldName`, vadv.`value` FROM iam_accountDetailValues vadv JOIN iam_accountDetailFields vadf ON vadv.`f_fieldName` = vadf.`fieldName` WHERE vadv.`f_username` = :userName";

    switch (detailsToShow)
    {
    case ACCOUNT_DETAILS_SEARCH:
        query += " AND vadf.`includeInSearch` = 1";
        break;
    case ACCOUNT_DETAILS_COLUMNVIEW:
        query += " AND vadf.`includeInColumnView` = 1";
        break;
    case ACCOUNT_DETAILS_TOKEN:
        query += " AND vadf.`includeInToken` = 1";
        break;
    case ACCOUNT_DETAILS_ALL:
    default:
        // no additional filter for ALL
        break;
    }

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect(
        query,
        { {":userName", MAKE_VAR(STRING,accountName)} },
        { &fieldName, &value }
        );

    if (i->getResultsOK())
    {
        while (i->query->step())
        {
            detailValues[fieldName.getValue()] = value.getValue();
        }
    }

    return detailValues;
}
