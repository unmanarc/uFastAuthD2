#pragma once

#include "identitymanager.h"
#include <Mantids30/DB/sqlconnector.h>


class IdentityManager_DB : public IdentityManager
{
public:
    // Open authentication system:
    IdentityManager_DB(Mantids30::Database::SQLConnector *_SQLDirConnection);
    bool initializeDatabase() override;

    class Users_DB : public Users
    {
    public:
        Users_DB(IdentityManager_DB *parent) : Users (parent)
        {
            _parent = parent;
        }
        virtual ~Users_DB() {
        }


        /////////////////////////////////////////////////////////////////////////////////
        // account:
        bool addAccount(        const std::string & accountName,
                        time_t expirationDate = 0, // Note: use 1 to create an expired account.
                        const AccountFlags & accountFlags = {true,true,false,false},
                        const std::string & sCreatorAccountName = "") override;

        bool removeAccount(const std::string & accountName) override;
        bool doesAccountExist(const std::string & accountName) override;
        bool disableAccount(const std::string & accountName, bool disabled = true) override;
        bool confirmAccount(const std::string & accountName, const std::string & confirmationToken) override;
        bool changeAccountExpiration(const std::string & accountName, time_t expiration = 0) override;
        AccountFlags getAccountFlags(const std::string & accountName) override;
        bool updateAccountRoles( const std::string & accountName, const std::set<std::string> & roleSet ) override;
        bool changeAccountFlags(const std::string & accountName,const AccountFlags & accountFlags) override;
        AccountDetails getAccountDetails(const std::string & accountName) override;
        time_t getAccountExpirationTime(const std::string & accountName) override;
        time_t getAccountCreationTime(const std::string & accountName) override;

        std::list<AccountDetails> searchAccounts(std::string sSearchWords, uint64_t limit=0, uint64_t offset=0) override;
        std::set<std::string> listAccounts() override;
        std::set<std::string> getAccountRoles(const std::string & accountName, bool lock = true) override;

        bool hasSuperUserAccount() override;

        int32_t getAccountBlockTokenNoRenew(const std::string &accountName, std::string &token);
        void removeBlockToken(const std::string &accountName);
        void updateOrCreateBlockToken(const std::string &accountName);
        std::string getAccountBlockToken(const std::string &accountName) override;
        bool blockAccountUsingToken(const std::string &accountName, const std::string &blockToken) override;


        // Account Details
        bool addAccountDetailField(const std::string &fieldName, const AccountDetailField & details) override;
        bool removeAccountDetailField(const std::string &fieldName) override;
        std::map<std::string, AccountDetailField> listAccountDetailFields() override;
        bool changeAccountDetails( const std::string &accountName, const std::map<std::string,std::string> & fieldsValues, bool resetAllValues = false ) override;
        bool removeAccountDetail(const std::string &accountName, const std::string &fieldName) override;

        std::map<std::string, std::string> getAccountDetailValues(const std::string &accountName, const AccountDetailsToShow & detailsToShow = ACCOUNT_DETAILS_ALL) override;

    private:
        bool isThereAnotherSuperUser(const std::string &accountName);
        IdentityManager_DB *_parent;
    };
    class Roles_DB : public Roles
    {
    public:
        Roles_DB(IdentityManager_DB *parent)
            : Roles()
        {
            _parent = parent;
        }
        virtual ~Roles_DB() {}

        /////////////////////////////////////////////////////////////////////////////////
        // role:
        bool addRole(const std::string & roleName, const std::string & roleDescription) override;
        bool removeRole(const std::string & roleName) override;
        bool doesRoleExist(const std::string & roleName) override;
        bool addAccountToRole(const std::string & roleName, const std::string & accountName) override;
        bool removeAccountFromRole(const std::string & roleName, const std::string & accountName, bool lock = true) override;
        bool updateRoleDescription(const std::string & roleName, const std::string & roleDescription) override;
        std::string getRoleDescription(const std::string & roleName) override;
        std::set<std::string> getRolesList() override;
        std::set<std::string> getRoleAccounts(const std::string & roleName, bool lock = true) override;
        std::list<RoleDetails> searchRoles(std::string sSearchWords, uint64_t limit=0, uint64_t offset=0) override;

    private:
        IdentityManager_DB *_parent;
    };
    class AuthController_DB : public AuthController
    {
    protected:
        Credential retrieveCredential(const std::string &accountName, const uint32_t &slotId, bool * accountFound, bool * authSlotFound) override;
    private:
        IdentityManager_DB *_parent;
    public:
        AuthController_DB(IdentityManager_DB *parent)   : AuthController(parent)
        {
            _parent = parent;
        }

        std::set<ApplicationPermission> getAccountDirectApplicationPermissions(const std::string & accountName, bool lock = true) override;

        bool validateApplicationPermissionOnRole(const std::string &roleName, const ApplicationPermission &permission, bool lock = true) override;
        std::set<ApplicationPermission> getRoleApplicationPermissions(const std::string & roleName, bool lock = true) override;

        /////////////////////////////////////////////////////////////////////////////////
        // application permissions:
        bool addApplicationPermission(const ApplicationPermission &applicationPermission, const std::string &description) override;
        bool removeApplicationPermission(const ApplicationPermission &applicationPermission) override;
        bool doesApplicationPermissionExist(const ApplicationPermission &applicationPermission) override;
        bool addApplicationPermissionToRole(const ApplicationPermission &applicationPermission, const std::string &roleName) override;
        bool removeApplicationPermissionFromRole(const ApplicationPermission &applicationPermission, const std::string &roleName, bool lock = true) override;
        bool addApplicationPermissionToAccount(const ApplicationPermission &applicationPermission, const std::string &accountName) override;
        bool removeApplicationPermissionFromAccount(const ApplicationPermission &applicationPermission, const std::string &accountName, bool lock = true) override;
        bool updateApplicationPermissionDescription(const ApplicationPermission &applicationPermission, const std::string &description) override;
        std::string getApplicationPermissionDescription(const ApplicationPermission &applicationPermission) override;
        std::set<ApplicationPermission> listApplicationPermissions(const std::string &applicationName = "") override;
        std::set<std::string> getApplicationPermissionsForRole(const ApplicationPermission &applicationPermission, bool lock = true) override;
        std::set<std::string> listAccountsOnApplicationPermission(const ApplicationPermission &applicationPermission, bool lock = true) override;
        std::list<ApplicationPermissionDetails> searchApplicationPermissions(const std::string &appName, std::string sSearchWords, uint64_t limit = 0, uint64_t offset = 0) override;
        bool validateAccountDirectApplicationPermission(const std::string & accountName, const ApplicationPermission & applicationPermission) override;

        // Account bad attempts for pass slot id...
        void resetBadAttemptsOnCredential(const std::string & accountName, const uint32_t & slotId) override;
        void incrementBadAttemptsOnCredential(const std::string & accountName, const uint32_t & slotId) override;

        // Account Credentials:
        bool changeCredential(const std::string &accountName, Credential passwordData, uint32_t slotId) override;

        // Account last login:
        void updateAccountLastLogin(const std::string &accountName, const uint32_t & slotId, const Mantids30::Sessions::ClientDetails & clientDetails) override;
        time_t getAccountLastLogin(const std::string & accountName) override;


        /////////////////////////////////////////////////////////////////////////////////
        // AuthController Slot SlotIds:
        uint32_t addNewAuthenticationSlot(const AuthenticationSlotDetails & details) override;
        bool removeAuthenticationSlot(const uint32_t &slotId) override;
        bool updateAuthenticationSlotDetails(const uint32_t &slotId, const AuthenticationSlotDetails & details) override;
        std::map<uint32_t,AuthenticationSlotDetails> listAuthenticationSlots() override;

        uint32_t addAuthenticationScheme(const std::string &description) override;
        bool updateAuthenticationScheme(const uint32_t &schemeId,const std::string &description) override;
        bool removeAuthenticationScheme(const uint32_t &schemeId) override;
        std::map<uint32_t, std::string> listAuthenticationSchemes() override;

        uint32_t getApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName) override;
        bool setApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName, const uint32_t & schemeId)  override;

        std::set<uint32_t> listAuthenticationSchemesForApplicationActivity(const std::string &appName, const std::string &activityName) override;
        bool addAuthenticationSchemesToApplicationActivity(const std::string &appName, const std::string &roleName, const uint32_t & schemeId) override;
        bool removeAuthenticationSchemeFromApplicationActivity( const std::string &appName, const std::string &roleName, const uint32_t & schemeId ) override;

        std::vector<AuthenticationSchemeUsedSlot> listAuthenticationSlotsUsedByScheme(const uint32_t & schemeId) override;
        bool updateAuthenticationSlotUsedByScheme(const uint32_t & schemeId, const std::list<AuthenticationSchemeUsedSlot> & slotsUsedByScheme) override;

        std::set<uint32_t> listUsedAuthenticationSlotsOnAccount(const std::string & accountName) override;


        // Tokens:
        std::string getAccountConfirmationToken(const std::string & accountName) override;

    };
    class Applications_DB : public Applications
    {
    public:
        Applications_DB(IdentityManager_DB *parent)
            : Applications()
        {
            _parent = parent;
        }
        virtual ~Applications_DB() {}

        /////////////////////////////////////////////////////////////////////////////////
        // applications:
        bool addApplication(const std::string &appName, const std::string &applicationDescription, const std::string &apiKey, const std::string &sOwnerAccountName) override;
        bool removeApplication(const std::string &appName) override;
        bool doesApplicationExist(const std::string &appName) override;

        std::string getApplicationDescription(const std::string &appName) override;
        std::string getApplicationAPIKey(const std::string &appName) override;
        bool updateApplicationAPIKey(const std::string &appName, const std::string &apiKey) override;
        bool updateApplicationDescription(const std::string &appName, const std::string &applicationDescription) override;
        std::set<std::string> listApplications() override;
        bool validateApplicationOwner(const std::string &appName, const std::string &accountName) override;
        bool validateApplicationAccount(const std::string &appName, const std::string &accountName) override;
        std::set<std::string> listApplicationOwners(const std::string &appName) override;
        std::set<std::string> listApplicationAccounts(const std::string &appName) override;
        std::set<std::string> listAccountApplications(const std::string &accountName) override;
        bool addAccountToApplication(const std::string &appName, const std::string &accountName) override;
        bool removeAccountFromApplication(const std::string &appName, const std::string &accountName) override;
        bool addApplicationOwner(const std::string &appName, const std::string &accountName) override;
        bool removeApplicationOwner(const std::string &appName, const std::string &accountName) override;
        std::list<ApplicationDetails> searchApplications(std::string sSearchWords, uint64_t limit = 0, uint64_t offset = 0) override;

        // Weblogin return urls:
        bool addWebLoginRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI) override;
        bool removeWebLoginRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI) override;
        std::list<std::string> listWebLoginRedirectURIsFromApplication(const std::string &appName) override;

        bool setAuthCallbackURIToApplication(const std::string &appName, const std::string &authCallbackURI) override;
        bool removeAuthCallbackURIToApplication(const std::string &appName, const std::string &authCallbackURI) override;
        std::string getAuthCallbackURIFromApplication(const std::string &appName) override;


        // Weblogin origin urls:
        bool addWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl) override;
        bool removeWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl) override;
        std::list<std::string> listWebLoginOriginUrlsFromApplication(const std::string &appName) override;

        // Application Token:
        bool modifyWebLoginJWTConfigForApplication(const ApplicationTokenProperties &tokenInfo) override;
        ApplicationTokenProperties getWebLoginJWTConfigFromApplication(const std::string &appName) override;
        bool setWebLoginJWTSigningKeyForApplication(const std::string &appName, const std::string &signingKey) override;
        std::string getWebLoginJWTSigningKeyForApplication(const std::string &appName) override;
        bool setWebLoginJWTValidationKeyForApplication(const std::string &appName, const std::string &validationKey) override;
        std::string getWebLoginJWTValidationKeyForApplication(const std::string &appName) override;

        bool setApplicationActivities(const std::string &appName, const std::map<std::string, ActivityData> &activities) override;
        bool removeApplicationActivities(const std::string &appName) override;
        std::map<std::string, ActivityData> listApplicationActivities(const std::string &appName) override;

    private:
        IdentityManager_DB *_parent;
    };

    std::list<std::string> getSqlErrorList() const;
    void clearSQLErrorList();


private:

    std::list<std::string> m_sqlErrorList;
    Mantids30::Database::SQLConnector *m_sqlConnector;
};


