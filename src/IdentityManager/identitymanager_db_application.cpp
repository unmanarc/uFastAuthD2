#include "identitymanager_db.h"
#include <Mantids30/Helpers/encoders.h>

#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30::Helpers;
using namespace Mantids30;

bool IdentityManager_DB::Applications_DB::addApplication(const std::string &appName, const std::string &applicationDescription, const std::string &apiKey, const std::string &sOwnerAccountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Insert into iam_applications.
    bool appInsertSuccess = _parent->m_sqlConnector
                                ->query("INSERT INTO iam_applications (`appName`, `f_appCreator`, `appDescription`, `apiKey`) VALUES (:appName, :appCreator, :description, :apiKey);",
                                        {
                                            {":appName", MAKE_VAR(STRING, appName)},
                                            {":appCreator", MAKE_VAR(STRING, sOwnerAccountName)},
                                            {":description", MAKE_VAR(STRING, applicationDescription)},
                                            {":apiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))},
                                        });

    // If the insertion is successful, insert another row default values into iam_applicationsJWTTokenConfig.
    if (appInsertSuccess)
    {
        std::string randomSecret = Mantids30::Helpers::Random::createRandomString(64);
        bool tokenInsertSuccess = _parent->m_sqlConnector->query("INSERT INTO iam_applicationsJWTTokenConfig (`f_appName`, `accessTokenSigningKey`, `accessTokenValidationKey`) "
                                                                 "VALUES (:appName, :signingKey, :validationKey);",
                                                                 {
                                                                  {":appName", MAKE_VAR(STRING, appName)},
                                                                  {":signingKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(randomSecret, 0x8A376C54D999F187))},
                                                                  {":validationKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(randomSecret, 0x8A376C54D999F187))}
                                                                 });
        return tokenInsertSuccess;
    }
    else
    {
        return false;
    }
}

bool IdentityManager_DB::Applications_DB::removeApplication(const std::string &appName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("DELETE FROM iam_applications WHERE `appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}});
}

bool IdentityManager_DB::Applications_DB::doesApplicationExist(const std::string &appName)
{
    bool ret = false;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `appDescription` FROM iam_applications WHERE `appName`=:appName LIMIT 1;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {});
    if (i->getResultsOK() && i->query->step())
    {
        ret = true;
    }
    return ret;
}

std::string IdentityManager_DB::Applications_DB::getApplicationDescription(const std::string &appName)
{
    std::string ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING description;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `appDescription` FROM iam_applications WHERE `appName`=:appName LIMIT 1;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {&description});
    if (i->getResultsOK() && i->query->step())
    {
        return description.getValue();
    }
    return "";
}

std::string IdentityManager_DB::Applications_DB::getApplicationAPIKey(const std::string &appName)
{
    std::string ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING apiKey;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `apiKey` FROM iam_applications WHERE `appName`=:appName LIMIT 1;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {&apiKey});
    if (i->getResultsOK() && i->query->step())
    {
        return Encoders::decodeFromBase64Obf(apiKey.getValue());
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::updateApplicationAPIKey(const std::string &appName, const std::string &apiKey)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("UPDATE iam_applications SET `apiKey`=:apiKey WHERE `appName`=:appName;",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":apiKey", MAKE_VAR(STRING, Abstract::STRING(Encoders::encodeToBase64Obf(apiKey)))}});
}

bool IdentityManager_DB::Applications_DB::updateApplicationDescription(const std::string &appName, const std::string &applicationDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("UPDATE iam_applications SET `appDescription`=:description WHERE `appName`=:appName;",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":description", MAKE_VAR(STRING, applicationDescription)}});
}

std::string IdentityManager_DB::Applications_DB::getApplicationNameByAPIKey(const std::string &apiKey)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING appName;
    std::shared_ptr<SQLConnector::QueryInstance> queryResult = _parent->m_sqlConnector->qSelect("SELECT `appName` FROM iam_applications WHERE `apiKey` = :encodedApiKey LIMIT 1;",
                                                                                                {
                                                                                                    {":encodedApiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))},
                                                                                                },
                                                                                                {&appName});
    if (queryResult->getResultsOK() && queryResult->query->step())
    {
        return appName.getValue();
    }
    return "";
}

std::set<std::string> IdentityManager_DB::Applications_DB::listApplications()
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING sAppName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `appName` FROM iam_applications;", {}, {&sAppName});
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(sAppName.getValue());
    }
    return ret;
}

bool IdentityManager_DB::Applications_DB::validateApplicationOwner(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::shared_ptr<SQLConnector::QueryInstance> i
        = _parent->m_sqlConnector->qSelect("SELECT `f_applicationManaged` FROM iam_applicationManagers WHERE `f_accountNameManager`=:accountName AND `f_applicationManaged`=:appName;",
                                           {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}}, {});
    return (i->getResultsOK() && i->query->step());
}

bool IdentityManager_DB::Applications_DB::validateApplicationAccount(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_appName` FROM iam_applicationAccounts WHERE `f_accountName`=:accountName AND `f_appName`=:appName;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}}, {});
    return (i->getResultsOK() && i->query->step());
}

std::set<std::string> IdentityManager_DB::Applications_DB::listApplicationOwners(const std::string &appName)
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_accountNameManager` FROM iam_applicationManagers WHERE `f_applicationManaged`=:appName;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {&accountName});
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(accountName.getValue());
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::Applications_DB::listApplicationAccounts(const std::string &appName)
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_accountName` FROM iam_applicationAccounts WHERE `f_appName`=:appName;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {&accountName});
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(accountName.getValue());
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::Applications_DB::listAccountApplications(const std::string &accountName)
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING applicationName;
    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `f_appName` FROM iam_applicationAccounts WHERE `f_accountName`=:accountName;",
                                                                                      {{":accountName", MAKE_VAR(STRING, accountName)}}, {&applicationName});
    while (i->getResultsOK() && i->query->step())
    {
        ret.insert(applicationName.getValue());
    }

    return ret;
}

bool IdentityManager_DB::Applications_DB::addAccountToApplication(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("INSERT INTO iam_applicationAccounts (`f_accountName`,`f_appName`) VALUES(:accountName,:appName);",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}});
}

bool IdentityManager_DB::Applications_DB::removeAccountFromApplication(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool ret = false;
    ret = _parent->m_sqlConnector->query("DELETE FROM iam_applicationAccounts WHERE `f_appName`=:appName AND `f_accountName`=:accountName;",
                                         {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}});
    return ret;
}

bool IdentityManager_DB::Applications_DB::addApplicationOwner(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("INSERT INTO iam_applicationManagers (`f_accountNameManager`,`f_applicationManaged`) VALUES(:accountName,:appName);",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}});
}

bool IdentityManager_DB::Applications_DB::removeApplicationOwner(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool ret = false;
    ret = _parent->m_sqlConnector->query("DELETE FROM iam_applicationManagers WHERE `f_applicationManaged`=:appName AND `f_accountNameManager`=:accountName;",
                                         {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}});
    return ret;
}

std::list<ApplicationDetails> IdentityManager_DB::Applications_DB::searchApplications(std::string sSearchWords, size_t limit, size_t offset)
{
    std::list<ApplicationDetails> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING applicationName, appCreator, description;

    std::string sSqlQuery = "SELECT `appName`,`f_appCreator`,`appDescription` FROM iam_applications";

    if (!sSearchWords.empty())
    {
        sSearchWords = '%' + sSearchWords + '%';
        sSqlQuery += " WHERE (`appName` LIKE :SEARCHWORDS OR `appDescription` LIKE :SEARCHWORDS)";
    }

    if (limit)
        sSqlQuery += " LIMIT :LIMIT OFFSET :OFFSET";

    sSqlQuery += ";";

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect(sSqlQuery,
                                                                                      {{":SEARCHWORDS", MAKE_VAR(STRING, sSearchWords)},
                                                                                       {":LIMIT", MAKE_VAR(UINT64, limit)},
                                                                                       {":OFFSET", MAKE_VAR(UINT64, offset)}},
                                                                                      {&applicationName, &appCreator, &description});
    while (i->getResultsOK() && i->query->step())
    {
        ApplicationDetails rDetail;

        rDetail.appCreator = appCreator.getValue();
        rDetail.description = description.getValue();
        rDetail.applicationName = applicationName.getValue();

        ret.push_back(rDetail);
    }

    return ret;
}

bool IdentityManager_DB::Applications_DB::addWebLoginRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("INSERT INTO iam_applicationsWebloginRedirectURIs (`f_appName`, `loginRedirectURI`) VALUES (:appName, :loginRedirectURI);",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
}

bool IdentityManager_DB::Applications_DB::removeWebLoginRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("DELETE FROM iam_applicationsWebloginRedirectURIs WHERE `f_appName`=:appName AND `loginRedirectURI`=:loginRedirectURI;",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
}

std::list<std::string> IdentityManager_DB::Applications_DB::listWebLoginRedirectURIsFromApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING loginRedirectURI;
    std::list<std::string> redirectURIs;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `loginRedirectURI` FROM iam_applicationsWebloginRedirectURIs WHERE `f_appName`=:appName;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {&loginRedirectURI});
    while (i->getResultsOK() && i->query->step())
    {
        redirectURIs.push_back(loginRedirectURI.getValue());
    }
    return redirectURIs;
}

bool IdentityManager_DB::Applications_DB::setApplicationWebLoginCallbackURI(const std::string &appName, const std::string &callbackURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool ret = false;

    // Delete existing callback URI for the application if it exists
    _parent->m_sqlConnector->query("DELETE FROM iam_applicationsLoginCallbackURI WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}});

    // Insert new callback URI
    ret = _parent->m_sqlConnector->query("INSERT INTO iam_applicationsLoginCallbackURI (`f_appName`, `callbackURI`) VALUES (:appName, :callbackURI);",
                                         {{":appName", MAKE_VAR(STRING, appName)}, {":callbackURI", MAKE_VAR(STRING, callbackURI)}});

    return ret;
}
std::string IdentityManager_DB::Applications_DB::getApplicationCallbackURI(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING callbackURI;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `callbackURI` FROM iam_applicationsLoginCallbackURI WHERE `f_appName`=:appName LIMIT 1;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {&callbackURI});
    if (i->getResultsOK() && i->query->step())
    {
        return callbackURI.getValue();
    }

    // Return an empty string if no callback URI is found
    return "";
}

bool IdentityManager_DB::Applications_DB::addWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("INSERT INTO iam_applicationsWebloginOrigins (`f_appName`, `originUrl`) VALUES (:appName, :originUrl);",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":originUrl", MAKE_VAR(STRING, originUrl)}});
}

bool IdentityManager_DB::Applications_DB::removeWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("DELETE FROM iam_applicationsWebloginOrigins WHERE `f_appName`=:appName AND `originUrl`=:originUrl;",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":originUrl", MAKE_VAR(STRING, originUrl)}});
}

std::list<std::string> IdentityManager_DB::Applications_DB::listWebLoginOriginUrlsFromApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING originUrl;
    std::list<std::string> originUrls;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `originUrl` FROM iam_applicationsWebloginOrigins WHERE `f_appName`=:appName;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {&originUrl});
    while (i->getResultsOK() && i->query->step())
    {
        originUrls.push_back(originUrl.getValue());
    }
    return originUrls;
}

bool IdentityManager_DB::Applications_DB::modifyWebLoginJWTConfigForApplication(const ApplicationTokenProperties &tokenInfo)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("UPDATE iam_applicationsJWTTokenConfig SET "
                                          "tempMFATokenTimeout=:tempMFATokenTimeout, sessionInactivityTimeout=:sessionInactivityTimeout, "
                                          "tokenType=:tokenType, includeApplicationPermissions=:includeApplicationPermissions, "
                                          "includeBasicAccountInfo=:includeBasicAccountInfo, allowRefreshTokenRenovation=:allowRefreshTokenRenovation, "
                                          "tokensConfigJSON=:tokensConfigJSON, "
                                          "maintainRevocationAndLogoutInfo=:maintainRevocationAndLogoutInfo WHERE f_appName=:appName;",
                                          {{":appName", MAKE_VAR(STRING, tokenInfo.appName)},
                                           {":tempMFATokenTimeout", MAKE_VAR(UINT32, tokenInfo.tempMFATokenTimeout)},
                                           {":sessionInactivityTimeout", MAKE_VAR(UINT32, tokenInfo.sessionInactivityTimeout)},
                                           {":tokenType", MAKE_VAR(STRING, tokenInfo.tokenType)},
                                           {":includeApplicationPermissions", MAKE_VAR(BOOL, tokenInfo.includeApplicationPermissions)},
                                           {":includeBasicAccountInfo", MAKE_VAR(BOOL, tokenInfo.includeBasicAccountInfo)},
                                           {":allowRefreshTokenRenovation", MAKE_VAR(BOOL, tokenInfo.allowRefreshTokenRenovation)},
                                           {":allowRefreshTokenRenovation", MAKE_VAR(BOOL, tokenInfo.allowRefreshTokenRenovation)},
                                           {":tokensConfigJSON", MAKE_VAR(STRING, tokenInfo.tokensConfiguration.toStyledString())},
                                           {":maintainRevocationAndLogoutInfo", MAKE_VAR(BOOL, tokenInfo.maintainRevocationAndLogoutInfo)}});
}

ApplicationTokenProperties IdentityManager_DB::Applications_DB::getWebLoginJWTConfigFromApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    ApplicationTokenProperties tokenInfo;
    tokenInfo.appName = appName;

    // Define las variables para capturar los valores de la base de datos.
    Abstract::UINT32 tempMFATokenTimeout, sessionInactivityTimeout;
    Abstract::STRING tokenType,tokensConfigJSON;
    Abstract::BOOL includeApplicationPermissions, includeBasicAccountInfo, maintainRevocationAndLogoutInfo, allowRefreshTokenRenovation;

    std::shared_ptr<SQLConnector::QueryInstance> i
        = _parent->m_sqlConnector->qSelect("SELECT allowRefreshTokenRenovation,tempMFATokenTimeout, sessionInactivityTimeout, tokenType, "
                                           "includeApplicationPermissions, includeBasicAccountInfo, maintainRevocationAndLogoutInfo, tokensConfigJSON "
                                           "FROM iam_applicationsJWTTokenConfig "
                                           "WHERE f_appName=:appName;",
                                           {{":appName", MAKE_VAR(STRING, appName)}},
                                           {&allowRefreshTokenRenovation, &tempMFATokenTimeout, &sessionInactivityTimeout, &tokenType,
                                            &includeApplicationPermissions, &includeBasicAccountInfo, &maintainRevocationAndLogoutInfo,&tokensConfigJSON });
    if (i->getResultsOK() && i->query->step())
    {
        tokenInfo.tempMFATokenTimeout = tempMFATokenTimeout.getValue();
        tokenInfo.sessionInactivityTimeout = sessionInactivityTimeout.getValue();
        tokenInfo.tokenType = tokenType.getValue();
        tokenInfo.includeApplicationPermissions = includeApplicationPermissions.getValue();
        tokenInfo.includeBasicAccountInfo = includeBasicAccountInfo.getValue();
        tokenInfo.maintainRevocationAndLogoutInfo = maintainRevocationAndLogoutInfo.getValue();
        tokenInfo.allowRefreshTokenRenovation = allowRefreshTokenRenovation.getValue();
        Mantids30::Helpers::JSONReader2 reader;
        reader.parse( tokensConfigJSON.getValue(), tokenInfo.tokensConfiguration );
    }
    return tokenInfo;
}

bool IdentityManager_DB::Applications_DB::setWebLoginJWTSigningKeyForApplication(const std::string &appName, const std::string &signingKey)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("UPDATE iam_applicationsJWTTokenConfig SET accessTokenSigningKey=:signingKey WHERE f_appName=:appName;",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":signingKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(signingKey, 0x8A376C54D999F187))}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginJWTSigningKeyForApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING signingKey;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT accessTokenSigningKey FROM iam_applicationsJWTTokenConfig WHERE f_appName=:appName;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {&signingKey});
    if (i->getResultsOK() && i->query->step())
    {
        // SBO... -.- (protect your .db file)
        return Helpers::Encoders::decodeFromBase64Obf(signingKey.getValue(), 0x8A376C54D999F187);
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::setWebLoginJWTValidationKeyForApplication(const std::string &appName, const std::string &validationKey)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->query("UPDATE iam_applicationsJWTTokenConfig SET accessTokenValidationKey=:validationKey WHERE f_appName=:appName;",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":validationKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(validationKey, 0x8A376C54D999F187))}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginJWTValidationKeyForApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING validationKey;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT accessTokenValidationKey FROM iam_applicationsJWTTokenConfig WHERE f_appName=:appName;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)}}, {&validationKey});
    if (i->getResultsOK() && i->query->step())
    {
        return Helpers::Encoders::decodeFromBase64Obf(validationKey.getValue(), 0x8A376C54D999F187);
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::setApplicationActivities(const std::string &appName, const std::map<std::string, ActivityData> &activities)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Get the current activities from the database
    std::set<std::string> currentActivities;
    Abstract::STRING activityName;

    {
        std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector->qSelect("SELECT `activityName` FROM iam_applicationActivities WHERE `f_appName` = :appName;",
                                                                                          {{":appName", MAKE_VAR(STRING, appName)}}, {&activityName});

        if (i->getResultsOK())
        {
            while (i->query->step())
            {
                currentActivities.insert(activityName.getValue());
            }
        }
        else
        {
            return false;
        }
    }

    // Remove the activities not present in the new map.
    for (const auto &currentActivity : currentActivities)
    {
        if (activities.find(currentActivity) == activities.end())
        {
            if (!_parent->m_sqlConnector->query("DELETE FROM iam_applicationActivities WHERE `f_appName` = :appName AND `activityName` = :activityName;",
                                                {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, currentActivity)}}))
            {
                return false;
            }
        }
    }

    // Update or insert the activity...
    for (const auto &activity : activities)
    {
        if (currentActivities.find(activity.first) != currentActivities.end())
        {
            // Update it (
            if (!_parent->m_sqlConnector->query("UPDATE iam_applicationActivities "
                                                "SET `description` = :description, `parentActivity` = :parentActivity "
                                                "WHERE `f_appName` = :appName AND `activityName` = :activityName;",
                                                {{":description", MAKE_VAR(STRING, activity.second.description)},
                                                 {":parentActivity", MAKE_VAR(STRING, activity.second.parentActivity)},
                                                 {":appName", MAKE_VAR(STRING, appName)},
                                                 {":activityName", MAKE_VAR(STRING, activity.first)}}))
            {
                return false;
            }
        }
        else
        {
            // Insert the new activity
            if (!_parent->m_sqlConnector->query("INSERT INTO iam_applicationActivities (`f_appName`, `activityName`, `parentActivity`, `description`) "
                                                "VALUES(:appName, :activityName, :parentActivity, :description);",
                                                {{":appName", MAKE_VAR(STRING, appName)},
                                                 {":activityName", MAKE_VAR(STRING, activity.first)},
                                                 {":parentActivity", MAKE_VAR(STRING, activity.second.parentActivity)},
                                                 {":description", MAKE_VAR(STRING, activity.second.description)}}))
            {
                return false;
            }
        }
    }

    return true;
}

bool IdentityManager_DB::Applications_DB::removeApplicationActivities(const std::string &appName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Delete all activities for the specified application
    if (!_parent->m_sqlConnector->query("DELETE FROM iam_applicationActivities WHERE `f_appName` = :appName;", {{":appName", MAKE_VAR(STRING, appName)}}))
    {
        return false;
    }

    return true;
}

std::map<std::string, IdentityManager::Applications::ActivityData> IdentityManager_DB::Applications_DB::listApplicationActivities(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING name, description, parentActivity;
    std::map<std::string, IdentityManager::Applications::ActivityData> activities;

    std::shared_ptr<SQLConnector::QueryInstance> i = _parent->m_sqlConnector
                                                         ->qSelect("SELECT `activityName`, `parentActivity`, `description` FROM iam_applicationActivities WHERE `f_appName`=:appName;",
                                                                   {{":appName", MAKE_VAR(STRING, appName)}}, {&name, &parentActivity, &description});
    while (i->getResultsOK() && i->query->step())
    {
        activities[name.toString()] = {.description = description.toString(), .parentActivity = parentActivity.toString()};
    }
    return activities;
}
