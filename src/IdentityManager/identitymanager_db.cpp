#include "identitymanager_db.h"
#include "IdentityManager/ds_authentication.h"

#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_bool.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _WIN32
#include <pwd.h>
#endif


using namespace Mantids30;


/*
 *
 * // This is the new schema:
 * TODO: borrar isLoginRequired / LoginRequired... (crear una app que sea unified login y no se pueda borrar)
 *          poner lo de los metodos de autenticacion en una nueva clase llamada authController...
 *          crear un nuevo scheme que se llame simple login...

 *          implementar esto en la interfaz rpc y en ufastauthd2...
 * TODO: blocked account (functions to block the account)
 * TODO: reaccionar a blocked como si fuese enabled
// Authentication Schemes...
// This is generic for any scheme... (by example: 0: password, 1: 2fa token, 2: sms)

// TODO: las tamperproof se utilizan para evitar ataques de superposición...
// todo: obtain last connection info...

// Account rename?

        // TODO: admin no se puede borrar (solo deshabilitar).

// // Required if the user has configured it (by example, token)

// each account can configure any slot...
REQUIRED_AT_LOGIN
// Applications...

Ideas de comercialización:

    - Usar una DB mas robusta (ej. sql server, postgresql)
    - Proveer el servicio en la nube ya hardenizado
    - Proveer un mecanismo de copia remota del directorio incremental (Integrity)
    - Soporte del fabricante
    - Alternativas de integración con whatsapp por ejemplo...
    - Migracion de datos
    - Conectividad con directorio activo...
*/

IdentityManager_DB::IdentityManager_DB(Mantids30::Database::SQLConnector *_SQLDirConnection)
{
    applications = new Applications_DB(this);
    users = new Users_DB(this);
    roles = new Roles_DB(this);
    authController = new AuthController_DB(this);

    m_sqlConnector = _SQLDirConnection;
}

bool IdentityManager_DB::initializeDatabase()
{
    if (!m_sqlConnector->dbTableExist("iam_applicationPermissionsAtAccount"))
    {
        bool r =
            m_sqlConnector->query(R"(CREATE TABLE `iam_accounts` (
                                             `userName`              VARCHAR(256)    NOT NULL,
                                             `creation`              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `creator`               VARCHAR(256)    DEFAULT NULL,
                                             `expiration`            DATETIME        NOT NULL,
                                             `isSuperuser`           BOOLEAN         NOT NULL,
                                             `isEnabled`             BOOLEAN         NOT NULL,
                                             `isBlocked`             BOOLEAN         NOT NULL,
                                             `isAccountConfirmed`    BOOLEAN         NOT NULL,
                                             PRIMARY KEY(`userName`)
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_accountsLastLog` (
                                              `f_username`            VARCHAR(256)  NOT NULL,
                                              `lastLogin`             DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                              FOREIGN KEY(`f_username`)   REFERENCES iam_accounts(`userName`) ON DELETE CASCADE
                                              PRIMARY KEY(`f_username`)
                                                                        );
                                       )") &&

                 m_sqlConnector->query(R"(CREATE TABLE `iam_accountDetailFields` (
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
                                       )") &&

                 m_sqlConnector->query(R"(CREATE TABLE `iam_accountDetailValues` (
                                              `f_username`              VARCHAR(256)  NOT NULL,
                                              `f_fieldName`             VARCHAR(256)  NOT NULL,
                                              `value`                   TEXT DEFAULT NULL,
                                              `lastUpdate`              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                              FOREIGN KEY(`f_username`)   REFERENCES iam_accounts(`userName`) ON DELETE CASCADE
                                              PRIMARY KEY(`f_username`,`f_fieldName`)
                                                                        );
                                       )") &&

                 m_sqlConnector->query(R"(CREATE TABLE `iam_applications` (
                                             `appName`               VARCHAR(256)  NOT NULL,
                                             `f_appCreator`          VARCHAR(256)  NOT NULL,
                                             `appDescription`        VARCHAR(4096) NOT NULL,
                                             `apiKey`                VARCHAR(512)  NOT NULL,
                                              FOREIGN KEY(`f_appCreator`)   REFERENCES iam_accounts(`userName`) ON DELETE CASCADE
                                                  PRIMARY KEY(`appName`)
                     );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_applicationsWebloginRedirectURIs` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `loginRedirectURI`        VARCHAR(4096) NOT NULL,
                                              FOREIGN KEY(`f_appName`)   REFERENCES iam_applications(`appName`) ON DELETE CASCADE
                                                  PRIMARY KEY(`f_appName`,`loginRedirectURI`)
                     );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_applicationActivities` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `activityName`          VARCHAR(256)  NOT NULL,
                                             `parentActivity`        VARCHAR(256)  NOT NULL,
                                             `description`           VARCHAR(4096) NOT NULL,
                                             `defaultSchemeId` INTEGER DEFAULT NULL,
                                              FOREIGN KEY(`f_appName`)   REFERENCES iam_applications(`appName`) ON DELETE CASCADE
                                                  PRIMARY KEY(`f_appName`,`activityName`)
                     );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_applicationsWebloginOrigins` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `originUrl`              VARCHAR(2048) NOT NULL,
                                             FOREIGN KEY(`f_appName`)   REFERENCES iam_applications(`appName`) ON DELETE CASCADE
                                             PRIMARY KEY(`f_appName`,`originUrl`)
                                                                        );
                                        )") &&
                 m_sqlConnector->query(R"(
                                        CREATE TABLE `iam_applicationsJWTTokenConfig` (
                                            `f_appName`                       VARCHAR(256)    NOT NULL,
                                            `accessTokenTimeout`              BIGINT UNSIGNED NOT NULL DEFAULT '300',
                                            `tempMFATokenTimeout`             BIGINT UNSIGNED NOT NULL DEFAULT '30',
                                            `sessionInactivityTimeout`        BIGINT UNSIGNED NOT NULL DEFAULT '180',
                                            `tokenType`                       VARCHAR(20)     NOT NULL DEFAULT 'HS256',
                                            `accessTokenSigningKey`           TEXT DEFAULT NULL,
                                            `accessTokenValidationKey`        TEXT DEFAULT NULL,
                                            `includeApplicationPermissionsInToken`     BOOLEAN NOT NULL DEFAULT TRUE,
                                            `includeBasicUserInfoInToken`     BOOLEAN NOT NULL DEFAULT TRUE,
                                            `maintainRevocationAndLogoutInfo` BOOLEAN NOT NULL DEFAULT FALSE,
                                            FOREIGN KEY (`f_appName`) REFERENCES iam_applications(`appName`) ON DELETE CASCADE,
                                            PRIMARY KEY (`f_appName`)
                                                                        );
                                    )") &&

                 m_sqlConnector->query(R"(CREATE TABLE `iam_applicationPermissions` (
                                             `f_appName`             VARCHAR(256) NOT NULL,
                                             `permissionId`            VARCHAR(256) NOT NULL,
                                             `description`     VARCHAR(4096),
                                             PRIMARY KEY(`f_appName`,`permissionId`),
                                             FOREIGN KEY(`f_appName`)   REFERENCES iam_applications(`appName`) ON DELETE CASCADE
                                                                        );
                                    )") &&

                 m_sqlConnector->query(R"(CREATE TABLE `iam_applicationManagers` (
                                             `f_userNameManager`       VARCHAR(256)    NOT NULL,
                                             `f_applicationManaged`    VARCHAR(256)    NOT NULL,
                                             PRIMARY KEY(`f_userNameManager`,`f_applicationManaged`),
                                             FOREIGN KEY(`f_userNameManager`)       REFERENCES iam_accounts(`userName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_applicationManaged`)    REFERENCES iam_applications(`appName`) ON DELETE CASCADE
                                                                        );
                                    )") &&

                 m_sqlConnector->query(R"(CREATE TABLE `iam_applicationUsers` (
                                             `f_userName`       VARCHAR(256)    NOT NULL,
                                             `f_appName`        VARCHAR(256)    NOT NULL,
                                             PRIMARY KEY(`f_userName`,`f_appName`),
                                             FOREIGN KEY(`f_userName`) REFERENCES iam_accounts(`userName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_appName`)  REFERENCES iam_applications(`appName`) ON DELETE CASCADE
                                                                        );
                                    )") &&

                  m_sqlConnector->query(R"(CREATE TABLE `iam_authenticationSchemes` (
                                            `schemeId`          INTEGER PRIMARY KEY AUTOINCREMENT,
                                            `description`       VARCHAR(4096) NOT NULL
                     );     )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_applicationActivitiesAuthSchemes` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `f_activityName`        VARCHAR(256)  NOT NULL,
                                             `f_schemeId`            INTEGER       NOT NULL,
                                              FOREIGN KEY(`f_appName`,`f_activityName`)   REFERENCES iam_applicationActivities(`f_appName`,`activityName`) ON DELETE CASCADE
                                              FOREIGN KEY(`f_schemeId`) REFERENCES iam_authenticationSchemes(`schemeId`) ON DELETE CASCADE,
                                              PRIMARY KEY(`f_appName`,`f_activityName`,`f_schemeId`)
                     );    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_authenticationSlots` (
                                             `slotId`                        INTEGER PRIMARY KEY AUTOINCREMENT,
                                             `description`                   VARCHAR(4096) NOT NULL,
                                             `function`                      INTEGER       DEFAULT 0,
                                             `defaultExpirationSeconds`      INTEGER       DEFAULT 0,
                                             `strengthJSONValidator`         TEXT          NOT NULL,
                                             `totp2FAStepsToleranceWindow`  INTEGER         DEFAULT 0
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_authenticationSchemeUsedSlots` (
                                            `f_schemeId`             INTEGER        NOT NULL,
                                            `f_slotId`               INTEGER        NOT NULL,
                                            `orderPriority`          INTEGER        NOT NULL,
                                            `optional`               BOOLEAN        NOT NULL,
                                             FOREIGN KEY(`f_schemeId`) REFERENCES iam_authenticationSchemes(`schemeId`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_slotId`) REFERENCES iam_authenticationSlots(`slotId`) ON DELETE CASCADE,
                                             PRIMARY KEY(`f_schemeId`,`f_slotId`)
                     );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_accountAuthLog` (
                                             `f_userName`        VARCHAR(256)    NOT NULL,
                                             `f_AuthSlotId`      INTEGER         NOT NULL,
                                             `loginDateTime`     DATETIME        NOT NULL,
                                             `loginIP`           VARCHAR(64)     NOT NULL,
                                             `loginTLSCN`        VARCHAR(1024)   NOT NULL,
                                             `loginUserAgent`    VARCHAR(4096)   NOT NULL,
                                             `loginExtraData`    VARCHAR(4096)   NOT NULL,
                                             FOREIGN KEY(`f_AuthSlotId`)    REFERENCES iam_authenticationSlots(`slotId`) ON DELETE CASCADE
                                             FOREIGN KEY(`f_userName`)       REFERENCES iam_accounts(`userName`) ON DELETE CASCADE
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_accountManagers` (
                                             `f_userNameManager`     VARCHAR(256)    NOT NULL,
                                             `f_userName_managed`    VARCHAR(256)    NOT NULL,
                                             PRIMARY KEY(`f_userNameManager`,`f_userName_managed`),
                                             FOREIGN KEY(`f_userNameManager`)   REFERENCES iam_accounts(`userName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_userName_managed`)  REFERENCES iam_accounts(`userName`) ON DELETE CASCADE
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_accountsActivationToken` (
                                             `f_userName`            VARCHAR(256) NOT NULL,
                                             `confirmationToken`     VARCHAR(256) NOT NULL,
                                             PRIMARY KEY(`f_userName`),
                                             FOREIGN KEY(`f_userName`) REFERENCES iam_accounts(`userName`) ON DELETE CASCADE
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_accountsBlockToken` (
                                             `f_userName`            VARCHAR(256) NOT NULL,
                                             `blockToken`            VARCHAR(256) NOT NULL,
                                             `lastAccess`            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             PRIMARY KEY(`f_userName`),
                                             FOREIGN KEY(`f_userName`) REFERENCES iam_accounts(`userName`) ON DELETE CASCADE
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_accountCredentials` (
                                             `f_AuthSlotId`                 INTEGER         NOT NULL,
                                             `f_userName`                   VARCHAR(256)    NOT NULL,
                                             `hash`                         VARCHAR(256)    NOT NULL,
                                             `expiration`                   DATETIME        DEFAULT NULL,
                                             `salt`                         VARCHAR(256)            ,
                                             `forcedExpiration`             BOOLEAN         DEFAULT 0,
                                             `badAttempts`                  INTEGER         DEFAULT 0,
                                             `usedstrengthJSONValidator`    TEXT          NOT NULL,
                                             PRIMARY KEY(`f_AuthSlotId`,`f_userName`),
                                             FOREIGN KEY(`f_AuthSlotId`)      REFERENCES iam_authenticationSlots(`slotId`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_userName`)        REFERENCES iam_accounts(`userName`) ON DELETE CASCADE
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_roles` (
                                             `roleName`             VARCHAR(256) NOT NULL,
                                             `roleDescription`           VARCHAR(4096),
                                             PRIMARY KEY(`roleName`)
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_rolesAccounts` (
                                             `f_roleName`           VARCHAR(256) NOT NULL,
                                             `f_userName`            VARCHAR(256) NOT NULL,
                                             FOREIGN KEY(`f_roleName`)      REFERENCES iam_roles(`roleName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_userName`)       REFERENCES iam_accounts(`userName`) ON DELETE CASCADE
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_applicationPermissionsAtRole` (
                                             `f_appName`            VARCHAR(256) NOT NULL,
                                             `f_permissionId`       VARCHAR(256) NOT NULL,
                                             `f_roleName`           VARCHAR(256) NOT NULL,
                                             FOREIGN KEY(`f_appName`,`f_permissionId`) REFERENCES iam_applicationPermissions(`f_appName`,`permissionId`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_roleName`)              REFERENCES iam_roles(`roleName`) ON DELETE CASCADE
                                                                        );
                                    )") &&
                 m_sqlConnector->query(R"(CREATE TABLE `iam_applicationPermissionsAtAccount` (
                                              `f_appName`             VARCHAR(256) NOT NULL,
                                              `f_permissionId`          VARCHAR(256) NOT NULL,
                                              `f_userName`            VARCHAR(256) NOT NULL,
                                              FOREIGN KEY(`f_appName`,`f_permissionId`) REFERENCES iam_applicationPermissions(`f_appName`,`permissionId`) ON DELETE CASCADE,
                                              FOREIGN KEY(`f_userName`, `f_appName`) REFERENCES iam_applicationUsers(`f_userName`, `f_appName`) ON DELETE CASCADE
                                                                        );
                                    )") &&
                // TODO: check if this needs different implementation across different databases, by now this works on SQLite3
                 m_sqlConnector->query(R"(CREATE UNIQUE INDEX `idx_roles_accounts` ON `iam_rolesAccounts` (`f_roleName` ,`f_userName`);)"
                                       ) &&
                 m_sqlConnector->query(R"(CREATE UNIQUE INDEX `idx_permissions_roles` ON `iam_applicationPermissionsAtRole` (`f_appName`,`f_permissionId`,`f_roleName` );)"
                                       ) &&
                 m_sqlConnector->query(R"(CREATE UNIQUE INDEX `idx_permissions_accounts` ON `iam_applicationPermissionsAtAccount` (`f_appName`,`f_permissionId`,`f_userName`);)"
                                       );

        return r;
    }
    return true;
}

std::list<std::string> IdentityManager_DB::getSqlErrorList() const
{
    return m_sqlErrorList;
}

void IdentityManager_DB::clearSQLErrorList()
{
    m_sqlErrorList.clear();
}
