#include "identitymanager_db.h"

#include <Mantids30/Threads/lock_shared.h>
#include <limits>

#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

Credential IdentityManager_DB::AuthController_DB::retrieveCredential(const std::string &accountName, const uint32_t &slotId, bool *accountFound, bool *authSlotFound)
{
    Credential ret;
    *authSlotFound = false;
    *accountFound = false;

    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 badAttempts;
    Abstract::BOOL forcedExpiration;
    Abstract::DATETIME expiration;
    Abstract::STRING salt, hash;

    *accountFound = _parent->accounts->doesAccountExist(accountName);

    if (!*accountFound)
        return ret;

    auto authSlots = listAuthenticationSlots();

    if (authSlots.find(slotId) != authSlots.end())
    {
        ret.slotDetails = authSlots[slotId];
    }
    else
    {
        // Bad...
        return ret;
    }

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `forcedExpiration`,`expiration`,`badAttempts`,`salt`,`hash` FROM iam_accountCredentials "
                                                                                      "WHERE `f_accountName`=:accountName AND `f_AuthSlotId`=:slotId LIMIT 1;",
                                                                                      {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}},
                                                                                      {&forcedExpiration, &expiration, &badAttempts, &salt, &hash});

    if (i->getResultsOK() && i->query->step())
    {
        *authSlotFound = true;
        ret.forceExpiration = forcedExpiration.getValue();
        ret.expirationTimestamp = expiration.getValue();
        ret.badAttempts = badAttempts.getValue();
        Mantids30::Helpers::Encoders::fromHex(salt.getValue(), ret.ssalt, 4);
        ret.hash = hash.getValue();
    }
    return ret;
}

bool IdentityManager_DB::AuthController_DB::validateApplicationPermissionOnRole(const std::string &roleName, const ApplicationPermission &permission, bool lock)
{
    bool ret = false;
    if (lock)
        _parent->m_mutex.lockShared();

    std::shared_ptr<SQLConnector::QueryInstance> i
        = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam_applicationPermissionsAtRole WHERE `f_permissionId`=:permissionId AND `f_appName`=:appName AND `f_roleName`=:roleName;",
                                           {{":permissionId", MAKE_VAR(STRING, permission.permissionId)}, {":appName", MAKE_VAR(STRING, permission.appName)}, {":roleName", MAKE_VAR(STRING, roleName)}},
                                           {});
    ret = (i->getResultsOK()) && i->query->step();

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}

std::set<ApplicationPermission> IdentityManager_DB::AuthController_DB::getRoleApplicationPermissions(const std::string &roleName, bool lock)
{
    std::set<ApplicationPermission> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING sAppName, sPermissionName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_appName`,`f_permissionId` FROM iam_applicationPermissionsAtRole WHERE `f_roleName`=:roleName;",
                                                                                      {{":roleName", MAKE_VAR(STRING, roleName)}}, {&sAppName, &sPermissionName});
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert({sAppName.getValue(), sPermissionName.getValue()});
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}

bool IdentityManager_DB::AuthController_DB::changeCredential(const std::string &accountName, Credential passwordData, uint32_t slotId)
{
    auto authSlots = listAuthenticationSlots();

    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (authSlots.find(slotId) == authSlots.end())
    {
        // Bad, slot id not found...
        return false;
    }

    if (!authSlots[slotId].isCompatible(passwordData.slotDetails))
    {
        // Bad slotId function...
        return false;
    }

    if (passwordData.expirationTimestamp == 1)
    {
        passwordData.expirationTimestamp = time(nullptr) + authSlots[slotId].defaultExpirationSeconds;
    }

    // TODO: evitar un cambio de password si no estas autenticado en una sesión...
    // TODO: strength validator.

    // Destroy (if exist).
    _parent->m_sqlConnector->query("DELETE FROM iam_accountCredentials WHERE `f_accountName`=:accountName and `f_AuthSlotId`=:slotId",
                                   {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}});

    return _parent->m_sqlConnector->query("INSERT INTO iam_accountCredentials "
                                          "(`f_AuthSlotId`,`f_accountName`,`hash`,`expiration`,`salt`,`forcedExpiration`,`usedstrengthJSONValidator`) "
                                          "VALUES"
                                          "(:slotId,:account,:hash,:expiration,:salt,:forcedExpiration,:usedValidator);",
                                          {{":slotId", MAKE_VAR(UINT32, slotId)},
                                           {":account", MAKE_VAR(STRING, accountName)},
                                           {":hash", MAKE_VAR(STRING, passwordData.hash)},
                                           {":expiration", MAKE_VAR(DATETIME, passwordData.expirationTimestamp)},
                                           {":salt", MAKE_VAR(STRING, Mantids30::Helpers::Encoders::toHex(passwordData.ssalt, 4))},
                                           {":forcedExpiration", MAKE_VAR(BOOL, passwordData.forceExpiration)},
                                           {":usedValidator", MAKE_VAR(STRING, authSlots[slotId].strengthJSONValidator)}});

    //                                              {":passwordFunction",MAKE_VAR(UINT32,passwordData.passwordFunction)},
    //                                               {":totp2FAStepsToleranceWindow",MAKE_VAR(UINT32,passwordData.totp2FAStepsToleranceWindow)}
}

std::string IdentityManager_DB::AuthController_DB::getAccountConfirmationToken(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING token;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT confirmationToken FROM iam_accountsActivationToken WHERE `f_accountName`=:accountName LIMIT 1;",
                                                                                      {{":accountName", MAKE_VAR(STRING, accountName)}}, {&token});
    if (i->getResultsOK() && i->query->step())
    {
        return token.getValue();
    }
    return "";
}

void IdentityManager_DB::AuthController_DB::updateAccountLastLogin(const std::string &accountName, const uint32_t &slotId, const ClientDetails &clientDetails)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Intenta actualizar primero
    bool updated = _parent->m_sqlConnector->query("UPDATE iam_accountsLastLog SET `lastLogin`=CURRENT_TIMESTAMP WHERE `f_accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}});

    // Si no se actualizó ningún registro, entonces inserta uno nuevo
    if (!updated)
    {
        _parent->m_sqlConnector->query("INSERT INTO iam_accountsLastLog(`f_accountName`, `lastLogin`) VALUES (:accountName, CURRENT_TIMESTAMP);", {{":accountName", MAKE_VAR(STRING, accountName)}});
    }

    // Insertar en el registro de inicios de sesión
    _parent->m_sqlConnector->query("INSERT INTO iam_accountAuthLog(`f_accountName`, `f_AuthSlotId`, `loginDateTime`, `loginIP`, `loginTLSCN`, `loginUserAgent`, `loginExtraData`) "
                                   "VALUES (:accountName, :slotId, :date, :loginIP, :loginTLSCN, :loginUserAgent, :loginExtraData);",
                                   {{":accountName", MAKE_VAR(STRING, accountName)},
                                    {":slotId", MAKE_VAR(UINT32, slotId)},
                                    {":date", MAKE_VAR(DATETIME, time(nullptr))},
                                    {":loginIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
                                    {":loginTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
                                    {":loginUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
                                    {":loginExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

time_t IdentityManager_DB::AuthController_DB::getAccountLastLogin(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    {
        Abstract::DATETIME lastLogin;
        std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `lastLogin` FROM iam_accountsLastLog WHERE `f_accountName`=:accountName LIMIT 1;",
                                                                                          {{":accountName", MAKE_VAR(STRING, accountName)}}, {&lastLogin});

        if (i->getResultsOK() && i->query->step())
        {
            return lastLogin.getValue(); // Asegúrate de convertir a `time_t` si es necesario
        }
    }

    // no account? time_t max value...
    return std::numeric_limits<time_t>::max();
}

std::set<uint32_t> IdentityManager_DB::AuthController_DB::listUsedAuthenticationSlotsOnAccount(const std::string &accountName)
{
    std::set<uint32_t> r;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 slotId;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_AuthSlotId` FROM iam_accountCredentials WHERE `f_accountName`=:f_accountName;",
                                                                                      {{":f_accountName", MAKE_VAR(STRING, accountName)}}, {&slotId});

    while (i->getResultsOK() && i->query->step())
    {
        r.insert(slotId.getValue());
    }

    return r;
}

uint32_t IdentityManager_DB::AuthController_DB::addNewAuthenticationSlot(const AuthenticationSlotDetails &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    auto i = _parent->m_sqlConnector->qInsert("INSERT INTO iam_authenticationSlots (`description`,`function`,`defaultExpirationSeconds`,`strengthJSONValidator`) "
                                              "VALUES(:description,:function,:defaultExpirationSeconds,:strengthJSONValidator);",
                                              {{":description", MAKE_VAR(STRING, details.description)},
                                               {":function", MAKE_VAR(UINT32, details.passwordFunction)},
                                               {":defaultExpirationSeconds", MAKE_VAR(UINT32, details.defaultExpirationSeconds)},
                                               {":totp2FAStepsToleranceWindow", MAKE_VAR(UINT32, details.totp2FAStepsToleranceWindow)},
                                               {":strengthJSONValidator", MAKE_VAR(STRING, details.strengthJSONValidator)}});
    if (!i->getResultsOK())
        return UINT32_MAX;

    return i->query->getLastInsertRowID();
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationSlot(const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("DELETE FROM iam_authenticationSlots WHERE `slotId`=:slotId;", {{":slotId", MAKE_VAR(UINT32, slotId)}});
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationSlotDetails(const uint32_t &slotId, const AuthenticationSlotDetails &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update...
    return _parent->m_sqlConnector->query("UPDATE iam_authenticationSlots SET "
                                          "`description` = :description, "
                                          "`function` = :function, "
                                          "`defaultExpirationSeconds` = :defaultExpirationSeconds, "
                                          "`totp2FAStepsToleranceWindow` = :totp2FAStepsToleranceWindow, "
                                          "`strengthJSONValidator` = :strengthJSONValidator "
                                          "WHERE `slotId` = :slotId;",
                                          {{":slotId", MAKE_VAR(UINT32, slotId)},
                                           {":description", MAKE_VAR(STRING, details.description)},
                                           {":function", MAKE_VAR(UINT32, details.passwordFunction)},
                                           {":defaultExpirationSeconds", MAKE_VAR(UINT32, details.defaultExpirationSeconds)},
                                           {":totp2FAStepsToleranceWindow", MAKE_VAR(UINT32, details.totp2FAStepsToleranceWindow)},
                                           {":strengthJSONValidator", MAKE_VAR(STRING, details.strengthJSONValidator)}});
}

std::map<uint32_t, AuthenticationSlotDetails> IdentityManager_DB::AuthController_DB::listAuthenticationSlots()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<uint32_t, AuthenticationSlotDetails> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSlotId;
    Abstract::STRING sDescription;
    Abstract::UINT32 uFunction;
    Abstract::UINT32 uDefaultExpirationSeconds;
    Abstract::STRING sStrengthJSONValidator;
    Abstract::UINT32 uTotp2FAStepsToleranceWindow;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector
                                                         ->qSelect("SELECT `slotId`, `description`, `function`, `defaultExpirationSeconds`, `strengthJSONValidator`,`totp2FAStepsToleranceWindow` "
                                                                   "FROM iam_authenticationSlots;",
                                                                   {}, {&uSlotId, &sDescription, &uFunction, &uDefaultExpirationSeconds, &sStrengthJSONValidator, &uTotp2FAStepsToleranceWindow});

    // Iterate:
    while (i->getResultsOK() && i->query->step())
    {
        // Build AuthenticationSlotDetails and insert it to the maps
        ret.insert({uSlotId.getValue(), AuthenticationSlotDetails(sDescription.getValue(), (HashFunction) uFunction.getValue(), sStrengthJSONValidator.getValue(), uDefaultExpirationSeconds.getValue(),
                                                                  uTotp2FAStepsToleranceWindow.getValue())});
    }

    return ret;
}

uint32_t IdentityManager_DB::AuthController_DB::addAuthenticationScheme(const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    auto i = _parent->m_sqlConnector->qInsert("INSERT INTO iam_authenticationSchemes (`description`) VALUES(:description);", {{":description", MAKE_VAR(STRING, description)}});
    if (!i->getResultsOK())
        return UINT32_MAX;

    return i->query->getLastInsertRowID();
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationScheme(const uint32_t &schemeId, const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update...
    return _parent->m_sqlConnector->query("UPDATE iam_authenticationSchemes SET "
                                          "`description` = :description "
                                          "WHERE `schemeId` = :schemeId;",
                                          {{":schemeId", MAKE_VAR(UINT32, schemeId)}, {":description", MAKE_VAR(STRING, description)}});
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationScheme(const uint32_t &schemeId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("DELETE FROM iam_authenticationSchemes WHERE `schemeId`=:schemeId;", {{":schemeId", MAKE_VAR(UINT32, schemeId)}});
}

std::map<uint32_t, std::string> IdentityManager_DB::AuthController_DB::listAuthenticationSchemes()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<uint32_t, std::string> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSlotId;
    Abstract::STRING sDescription;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `schemeId`, `description` FROM iam_authenticationSchemes;", {}, {&uSlotId, &sDescription});

    // Iterate:
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert({uSlotId.getValue(), sDescription.getValue()});
    }

    return ret;
}

uint32_t IdentityManager_DB::AuthController_DB::getApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // Temporal variable to store the result
    Abstract::UINT32 uDefaultSchemeId;

    // Query to get the default scheme ID for the application activity
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector
                                                         ->qSelect("SELECT `defaultSchemeId` FROM iam_applicationActivities WHERE `f_appName`=:appName AND `activityName`=:activityName;",
                                                                   {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}}, {&uDefaultSchemeId});

    // Check if a result is available
    if (i->getResultsOK() && i->query->step())
    {
        return uDefaultSchemeId.getValue();
    }

    // Return UINT32_MAX if no default scheme is set
    return UINT32_MAX;
}

bool IdentityManager_DB::AuthController_DB::setApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName, const uint32_t &schemeId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update the default scheme ID for the specified application activity
    return _parent->m_sqlConnector->query("UPDATE iam_applicationActivities SET `defaultSchemeId`=:schemeId WHERE `f_appName`=:appName AND `activityName`=:activityName;",
                                          {{":schemeId", MAKE_VAR(UINT32, schemeId)}, {":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}});
}

std::set<uint32_t> IdentityManager_DB::AuthController_DB::listAuthenticationSchemesForApplicationActivity(const std::string &appName, const std::string &activityName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::set<uint32_t> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSchemeId;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector
                                                         ->qSelect("SELECT `f_schemeId` FROM iam_applicationActivitiesAuthSchemes WHERE `f_appName`=:appName AND `f_activityName`=:activityName;",
                                                                   {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}}, {&uSchemeId});

    // Iterate:
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(uSchemeId.getValue());
    }

    return ret;
}

bool IdentityManager_DB::AuthController_DB::addAuthenticationSchemesToApplicationActivity(const std::string &appName, const std::string &activityName, const uint32_t &schemeId)
{
    // Acquire a write lock since we are modifying the database
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Execute the query using direct parameter passing...
    return _parent->m_sqlConnector->query("INSERT INTO iam_applicationActivitiesAuthSchemes (`f_appName`, `f_activityName`, `f_schemeId`) "
                                          "VALUES (:appName, :activityName, :schemeId);",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}, {":schemeId", MAKE_VAR(UINT32, schemeId)}});
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationSchemeFromApplicationActivity(const std::string &appName, const std::string &activityName, const uint32_t &schemeId)
{
    // Acquire a write lock since we are modifying the database
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Execute the query with direct parameter passing
    return _parent->m_sqlConnector->query("DELETE FROM iam_applicationActivitiesAuthSchemes "
                                          "WHERE `f_appName` = :appName AND `f_activityName` = :activityName AND `f_schemeId` = :schemeId;",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}, {":schemeId", MAKE_VAR(UINT32, schemeId)}});
}

std::vector<AuthenticationSchemeUsedSlot> IdentityManager_DB::AuthController_DB::listAuthenticationSlotsUsedByScheme(const uint32_t &schemeId)
{
    std::vector<AuthenticationSchemeUsedSlot> slotsList;
    auto allAuthSlots = listAuthenticationSlots();

    // Acquire a read lock for thread-safe read operation
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 uSlotId;
    Abstract::UINT32 uOrderPriority;
    Abstract::BOOL uOptional;

    // Prepare the SQL SELECT statement to fetch slot details by schemeId
    std::string sql = "SELECT `f_slotId`, `orderPriority`, `optional` "
                      "FROM `iam_authenticationSchemeUsedSlots` "
                      "WHERE `f_schemeId` = :schemeId "
                      "ORDER BY `orderPriority` ASC;"; // Assuming you want to order by priority

    // Execute the query with direct parameter passing
    std::shared_ptr<SQLConnector::QueryInstance> queryInstance = _parent->m_sqlConnector->qSelect(sql, {{":schemeId", MAKE_VAR(UINT32, schemeId)}}, {&uSlotId, &uOrderPriority, &uOptional});

    // Assuming queryInstance->query provides a way to iterate over results and bind columns to variables

    while (queryInstance->getResultsOK() && queryInstance->query->step())
    {
        uint32_t slotId = uSlotId.getValue(), orderPriority = uOrderPriority.getValue();
        bool optional = uOptional.getValue();

        // Add the fetched slot details to the list
        if (allAuthSlots.find(slotId) != allAuthSlots.end())
            slotsList.push_back(AuthenticationSchemeUsedSlot{slotId, orderPriority, optional, allAuthSlots[slotId]});
    }

    return slotsList;
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationSlotUsedByScheme(const uint32_t &schemeId, const std::list<AuthenticationSchemeUsedSlot> &slotsUsedByScheme)
{
    // Acquire a write lock for thread-safe database modification
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Remove existing slots for the scheme
    std::string deleteSql = "DELETE FROM `iam_authenticationSchemeUsedSlots` WHERE `f_schemeId` = :schemeId;";
    if (!_parent->m_sqlConnector->query(deleteSql, {{":schemeId", MAKE_VAR(UINT32, schemeId)}}))
    {
        return false; // If deletion fails, return false
    }

    // Repopulate the table with new slots
    for (const auto &slot : slotsUsedByScheme)
    {
        std::string insertSql = "INSERT INTO `iam_authenticationSchemeUsedSlots` (`f_schemeId`, `f_slotId`, `orderPriority`, `optional`) VALUES (:schemeId, "
                                ":slotId, :orderPriority, :optional);";
        if (!_parent->m_sqlConnector->query(insertSql, {{":schemeId", MAKE_VAR(UINT32, schemeId)},
                                                        {":slotId", MAKE_VAR(UINT32, slot.slotId)},
                                                        {":orderPriority", MAKE_VAR(UINT32, slot.orderPriority)},
                                                        {":optional", MAKE_VAR(BOOL, slot.optional)}}))
        {
            // If any insert fails, there's limited context here to handle rollback or partial success scenarios
            return false;
        }
    }

    return true; // Return true if deletion and all insert operations succeed
}

void IdentityManager_DB::AuthController_DB::resetBadAttemptsOnCredential(const std::string &accountName, const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    _parent->m_sqlConnector->query("UPDATE iam_accountCredentials SET `badAttempts`='0' WHERE `f_accountName`=:accountName and `f_AuthSlotId`=:slotId;",
                                   {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}});
}

void IdentityManager_DB::AuthController_DB::incrementBadAttemptsOnCredential(const std::string &accountName, const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    _parent->m_sqlConnector->query("UPDATE iam_accountCredentials SET `badAttempts`=`badAttempts`+1  WHERE `f_accountName`=:accountName and `f_AuthSlotId`=:slotId;",
                                   {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}});
}

std::set<ApplicationPermission> IdentityManager_DB::AuthController_DB::getAccountDirectApplicationPermissions(const std::string &accountName, bool lock)
{
    std::set<ApplicationPermission> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING appName, permission;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector
                                                         ->qSelect("SELECT `f_appName`,`f_permissionId` FROM iam_applicationPermissionsAtAccount WHERE `f_accountName`=:accountName;",
                                                                   {{":accountName", MAKE_VAR(STRING, accountName)}}, {&appName, &permission});
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert({appName.getValue(), permission.getValue()});
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}
