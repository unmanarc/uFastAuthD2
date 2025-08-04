#include "identitymanager_db.h"
#include "globals.h"

using namespace Mantids30::Program;
using namespace Mantids30;

IdentityManager_DB::IdentityManager_DB(Mantids30::Database::SQLConnector *_SQLDirConnection)
{
    applications = new Applications_DB(this);
    accounts = new Accounts_DB(this);
    roles = new Roles_DB(this);
    authController = new AuthController_DB(this);

    m_sqlConnector = _SQLDirConnection;
}

bool IdentityManager_DB::initializeDatabase()
{
    const std::vector<std::string_view> sqlStatements = {
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accounts` (
                                             `accountName`              VARCHAR(256)    NOT NULL,
                                             `creation`              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `creator`               VARCHAR(256)    DEFAULT NULL,
                                             `expiration`            DATETIME        NOT NULL,
                                             `isAdmin`           BOOLEAN         NOT NULL,
                                             `isEnabled`             BOOLEAN         NOT NULL,
                                             `isBlocked`             BOOLEAN         NOT NULL,
                                             `isAccountConfirmed`    BOOLEAN         NOT NULL,
                                             PRIMARY KEY(`accountName`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountDetailFields` (
                                             `fieldName`             VARCHAR(256)   NOT NULL,
                                             `fieldDescription`      VARCHAR(4096)  NOT NULL,
                                             `fieldRegexpValidator`  TEXT           DEFAULT NULL,
                                             `fieldType`             VARCHAR(256)   NOT NULL DEFAULT 'TEXTLINE',
                                             `isOptionalField`       BOOLEAN        NOT NULL DEFAULT TRUE,
                                             `includeInSearch`       BOOLEAN        NOT NULL DEFAULT FALSE,
                                             `includeInColumnView`   BOOLEAN        NOT NULL DEFAULT FALSE,
                                             `includeInToken`        BOOLEAN        NOT NULL DEFAULT FALSE,
                                              PRIMARY KEY(`fieldName`)
                                                                        );
                                       )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountDetailValues` (
                                              `f_accountName`           VARCHAR(256)  NOT NULL,
                                              `f_fieldName`             VARCHAR(256)  NOT NULL,
                                              `value`                   TEXT DEFAULT NULL,
                                              `lastUpdate`              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                              FOREIGN KEY(`f_accountName`)   REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                              PRIMARY KEY(`f_accountName`,`f_fieldName`)
                                                                        );
                                       )",

        R"(CREATE TABLE IF NOT EXISTS `iam`.`applications` (
                                             `appName`               VARCHAR(256)  NOT NULL,
                                             `f_appCreator`          VARCHAR(256)  NOT NULL,
                                             `appDescription`        VARCHAR(4096) NOT NULL,
                                             `apiKey`                VARCHAR(512)  NOT NULL,
                                              FOREIGN KEY(`f_appCreator`)   REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                              PRIMARY KEY(`appName`)
                                              UNIQUE(`apiKey`)
                                                                        );
                                    )",       
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationsWebloginRedirectURIs` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `loginRedirectURI`        VARCHAR(4096) NOT NULL,
                                              FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE
                                              PRIMARY KEY(`f_appName`,`loginRedirectURI`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationsLoginCallbackURI` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `callbackURI`           VARCHAR(4096) NOT NULL,
                                              FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE,
                                              PRIMARY KEY(`f_appName`,`callbackURI`)
                                              UNIQUE(`f_appName`)
                     );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationActivities` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `activityName`          VARCHAR(256)  NOT NULL,
                                             `parentActivity`        VARCHAR(256)  NOT NULL,
                                             `description`           VARCHAR(4096) NOT NULL,
                                             `defaultSchemeId` INTEGER DEFAULT NULL,
                                              FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE
                                              PRIMARY KEY(`f_appName`,`activityName`)
                     );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationsWebloginOrigins` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `originUrl`              VARCHAR(2048) NOT NULL,
                                             FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE
                                             PRIMARY KEY(`f_appName`,`originUrl`)
                                                                        );
                                        )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationsJWTTokenConfig` (
                                            `f_appName`                       VARCHAR(256)    NOT NULL,
                                            `tempMFATokenTimeout`             BIGINT UNSIGNED NOT NULL DEFAULT '30',
                                            `sessionInactivityTimeout`        BIGINT UNSIGNED NOT NULL DEFAULT '180',
                                            `tokenType`                       VARCHAR(20)     NOT NULL DEFAULT 'HS256',
                                            `accessTokenSigningKey`           TEXT DEFAULT NULL,
                                            `accessTokenValidationKey`        TEXT DEFAULT NULL,
                                            `tokensConfigJSON`              TEXT NOT NULL DEFAULT '{ "accessToken" : {"path" : "/", "timeout" : 300},"refreshToken" : {"path" : "/auth", "timeout" : 2592000} }',
                                            `includeApplicationPermissions`   BOOLEAN NOT NULL DEFAULT TRUE,
                                            `includeBasicAccountInfo`         BOOLEAN NOT NULL DEFAULT TRUE,
                                            `maintainRevocationAndLogoutInfo` BOOLEAN NOT NULL DEFAULT FALSE,
                                            `allowRefreshTokenRenovation`     BOOLEAN NOT NULL DEFAULT TRUE,
                                            FOREIGN KEY (`f_appName`) REFERENCES applications(`appName`) ON DELETE CASCADE,
                                            PRIMARY KEY (`f_appName`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationPermissions` (
                                             `f_appName`               VARCHAR(256) NOT NULL,
                                             `permissionId`            VARCHAR(256) NOT NULL,
                                             `description`     VARCHAR(4096),
                                             PRIMARY KEY(`f_appName`,`permissionId`),
                                             FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationManagers` (
                                             `f_accountNameManager`       VARCHAR(256)    NOT NULL,
                                             `f_applicationManaged`       VARCHAR(256)    NOT NULL,
                                             PRIMARY KEY(`f_accountNameManager`,`f_applicationManaged`),
                                             FOREIGN KEY(`f_accountNameManager`)       REFERENCES accounts(`accountName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_applicationManaged`)    REFERENCES applications(`appName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationAccounts` (
                                             `f_accountName`       VARCHAR(256)    NOT NULL,
                                             `f_appName`           VARCHAR(256)    NOT NULL,
                                             PRIMARY KEY(`f_accountName`,`f_appName`),
                                             FOREIGN KEY(`f_accountName`) REFERENCES accounts(`accountName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_appName`)  REFERENCES applications(`appName`) ON DELETE CASCADE
                                                                        );
                                    )",

        R"(CREATE TABLE IF NOT EXISTS `iam`.`authenticationSchemes` (
                                            `schemeId`          INTEGER PRIMARY KEY AUTOINCREMENT,
                                            `description`       VARCHAR(4096) NOT NULL
                     );     )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationActivitiesAuthSchemes` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `f_activityName`        VARCHAR(256)  NOT NULL,
                                             `f_schemeId`            INTEGER       NOT NULL,
                                              FOREIGN KEY(`f_appName`,`f_activityName`)   REFERENCES applicationActivities(`f_appName`,`activityName`) ON DELETE CASCADE
                                              FOREIGN KEY(`f_schemeId`) REFERENCES authenticationSchemes(`schemeId`) ON DELETE CASCADE,
                                              PRIMARY KEY(`f_appName`,`f_activityName`,`f_schemeId`)
                     );    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`authenticationSlots` (
                                             `slotId`                        INTEGER PRIMARY KEY AUTOINCREMENT,
                                             `description`                   VARCHAR(4096) NOT NULL,
                                             `function`                      INTEGER       DEFAULT 0,
                                             `defaultExpirationSeconds`      INTEGER       DEFAULT 0,
                                             `strengthJSONValidator`         TEXT          NOT NULL,
                                             `totp2FAStepsToleranceWindow`  INTEGER         DEFAULT 0
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`authenticationSchemeUsedSlots` (
                                            `f_schemeId`             INTEGER        NOT NULL,
                                            `f_slotId`               INTEGER        NOT NULL,
                                            `orderPriority`          INTEGER        NOT NULL,
                                            `optional`               BOOLEAN        NOT NULL,
                                             FOREIGN KEY(`f_schemeId`) REFERENCES authenticationSchemes(`schemeId`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_slotId`) REFERENCES authenticationSlots(`slotId`) ON DELETE CASCADE,
                                             PRIMARY KEY(`f_schemeId`,`f_slotId`)
                     );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountManagers` (
                                             `f_accountNameManager`     VARCHAR(256)    NOT NULL,
                                             `f_accountName_managed`    VARCHAR(256)    NOT NULL,
                                             PRIMARY KEY(`f_accountNameManager`,`f_accountName_managed`),
                                             FOREIGN KEY(`f_accountNameManager`)   REFERENCES accounts(`accountName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_accountName_managed`)  REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountsActivationToken` (
                                             `f_accountName`            VARCHAR(256) NOT NULL,
                                             `confirmationToken`     VARCHAR(256) NOT NULL,
                                             PRIMARY KEY(`f_accountName`),
                                             FOREIGN KEY(`f_accountName`) REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountsBlockToken` (
                                             `f_accountName`            VARCHAR(256) NOT NULL,
                                             `blockToken`            VARCHAR(256) NOT NULL,
                                             `lastAccess`            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             PRIMARY KEY(`f_accountName`),
                                             FOREIGN KEY(`f_accountName`) REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountCredentials` (
                                             `f_AuthSlotId`                 INTEGER         NOT NULL,
                                             `f_accountName`                   VARCHAR(256)    NOT NULL,
                                             `hash`                         VARCHAR(256)    NOT NULL,
                                             `expiration`                   DATETIME        DEFAULT NULL,
                                             `salt`                         VARCHAR(256)            ,
                                             `forcedExpiration`             BOOLEAN         DEFAULT 0,
                                             `badAttempts`                  INTEGER         DEFAULT 0,
                                             `usedstrengthJSONValidator`    TEXT          NOT NULL,
                                             PRIMARY KEY(`f_AuthSlotId`,`f_accountName`),
                                             FOREIGN KEY(`f_AuthSlotId`)      REFERENCES authenticationSlots(`slotId`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_accountName`)        REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`roles` (
                                             `roleName`             VARCHAR(256) NOT NULL,
                                             `roleDescription`           VARCHAR(4096),
                                             PRIMARY KEY(`roleName`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`rolesAccounts` (
                                             `f_roleName`               VARCHAR(256) NOT NULL,
                                             `f_accountName`            VARCHAR(256) NOT NULL,
                                             FOREIGN KEY(`f_roleName`)        REFERENCES roles(`roleName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_accountName`)     REFERENCES accounts(`accountName`) ON DELETE CASCADE,
                                             UNIQUE (`f_roleName`, `f_accountName`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationPermissionsAtRole` (
                                             `f_appName`            VARCHAR(256) NOT NULL,
                                             `f_permissionId`       VARCHAR(256) NOT NULL,
                                             `f_roleName`           VARCHAR(256) NOT NULL,
                                             FOREIGN KEY(`f_appName`,`f_permissionId`) REFERENCES applicationPermissions(`f_appName`,`permissionId`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_roleName`)              REFERENCES roles(`roleName`) ON DELETE CASCADE,
                                             UNIQUE (`f_appName`, `f_permissionId`, `f_roleName`) );
                                    )",       
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationPermissionsAtAccount` (
                                              `f_appName`                VARCHAR(256) NOT NULL,
                                              `f_permissionId`           VARCHAR(256) NOT NULL,
                                              `f_accountName`            VARCHAR(256) NOT NULL,
                                              FOREIGN KEY(`f_appName`,`f_permissionId`) REFERENCES applicationPermissions(`f_appName`,`permissionId`) ON DELETE CASCADE,
                                              FOREIGN KEY(`f_accountName`, `f_appName`) REFERENCES applicationAccounts(`f_accountName`, `f_appName`) ON DELETE CASCADE,
                                              UNIQUE (`f_appName`, `f_permissionId`, `f_accountName`)
                                                                        );
                                    )",
        // LOGS:
        R"(CREATE TABLE IF NOT EXISTS `logs`.`accountsLastAccess` (
                                              `f_accountName`            VARCHAR(256)  NOT NULL,
                                              `lastLogin`             DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                              PRIMARY KEY(`f_accountName`)
                                                                        );
                                       )",
        "CREATE INDEX IF NOT EXISTS `logs`.idx_lastAccess_accountName ON accountsLastAccess (f_accountName);",
        R"(CREATE TABLE IF NOT EXISTS `logs`.`accountAuthLog` (
                                             `f_accountName`        VARCHAR(256)    NOT NULL,
                                             `f_AuthSlotId`      INTEGER         NOT NULL,
                                             `loginDateTime`     DATETIME        NOT NULL,
                                             `loginIP`           VARCHAR(64)     NOT NULL,
                                             `loginTLSCN`        VARCHAR(1024)   NOT NULL,
                                             `loginUserAgent`    VARCHAR(4096)   NOT NULL,
                                             `loginExtraData`    VARCHAR(4096)   NOT NULL);
                                    )",

        "CREATE INDEX IF NOT EXISTS `logs`.idx_logs_accountName ON accountAuthLog (f_accountName);",
        "CREATE INDEX IF NOT EXISTS `logs`.idx_logs_authSlotID ON accountAuthLog (f_AuthSlotId);",
        "CREATE INDEX IF NOT EXISTS `logs`.idx_logs_dateTime ON accountAuthLog (loginDateTime);",
        "CREATE INDEX IF NOT EXISTS `logs`.idx_logs_loginIP ON accountAuthLog (loginIP);"
    };

    // Not using this....
    // FOREIGN KEY(`f_accountName`)   REFERENCES iam.accounts(`accountName`) ON DELETE CASCADE
    // FOREIGN KEY(`f_AuthSlotId`)    REFERENCES iam.authenticationSlots(`slotId`) ON DELETE CASCADE
    // FOREIGN KEY(`f_accountName`)       REFERENCES iam.accounts(`accountName`) ON DELETE CASCADE

    bool success = true;
    for (const auto &sql : sqlStatements)
    {
        if (!m_sqlConnector->query(sql.data()))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Failed to execute SQL: '%s'", std::string(sql).c_str());
            success = false;
            break;
        }
    }

    return success;
}

std::list<std::string> IdentityManager_DB::getSqlErrorList() const
{
    return m_sqlErrorList;
}

void IdentityManager_DB::clearSQLErrorList()
{
    m_sqlErrorList.clear();
}
