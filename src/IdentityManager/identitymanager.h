#pragma once

#include <list>
#include <map>
#include <memory>
#include <set>

#include "ds_account.h"
#include "ds_application.h"

#include "credentialvalidator.h"
#include <Mantids30/Helpers/json.h>
#include <string>
#include <time.h>

#include <Mantids30/DataFormat_JWT/jwt.h>
#include <Mantids30/Threads/mapitem.h>
#include <Mantids30/Threads/mutex_shared.h>

class IdentityManager : public Mantids30::Threads::Safe::MapItem
{
public:
    using ClientDetails = Mantids30::Sessions::ClientDetails;

    IdentityManager();
    virtual ~IdentityManager();

    bool validateAccountForNewAccess(const std::string &accountName,const std::string &appName, Reason &reason,  bool checkValidAppAccount);

    class Accounts
    {
    public:
        Accounts(IdentityManager *m_parent);
        virtual ~Accounts() {}

        bool createAdminAccount(const std::string &accountName);

        /////////////////////////////////////////////////////////////////////////////////
        // account:
        virtual bool addAccount(const std::string &accountName,
                                time_t expirationDate = 0, // Note: use 1 to create an expired account.
                                const AccountFlags &accountFlags = {true, true, false, false}, const std::string &sCreatorAccountName = "")
            = 0;

        // Listing:
        virtual bool doesAccountExist(const std::string &accountName) = 0;
        virtual std::set<std::string> listAccounts() = 0;

        // Account confirmation:
        virtual bool confirmAccount(const std::string &accountName, const std::string &confirmationToken) = 0;

        // The IAM has any admin account?
        virtual bool hasAdminAccount();

        // Account Removing/Disabling/...
        virtual bool removeAccount(const std::string &accountName) = 0;
        virtual bool disableAccount(const std::string &accountName, bool disabled = true) = 0;

        // Account Details:
        virtual AccountDetails getAccountDetails(const std::string &accountName) = 0;
        virtual std::list<AccountDetails> searchAccounts(std::string sSearchWords, size_t limit = 0, size_t offset = 0) = 0;

        // Account Expiration:
        virtual bool changeAccountExpiration(const std::string &accountName, time_t expiration = 0) = 0;
        virtual time_t getAccountExpirationTime(const std::string &accountName) = 0;
        virtual time_t getAccountCreationTime(const std::string &accountName) = 0;
        bool isAccountExpired(const std::string &accountName);

        // Account Flag Permissions:
        virtual AccountFlags getAccountFlags(const std::string &accountName) = 0;
        virtual bool changeAccountFlags(const std::string &accountName, const AccountFlags &accountFlags) = 0;

        // Account role set:
        virtual bool updateAccountRoles(const std::string &accountName, const std::set<std::string> &roleSet) = 0;
        virtual std::set<std::string> getAccountRoles(const std::string &accountName, bool lock = true) = 0;

        // Account block using token:
        virtual std::string getAccountBlockToken(const std::string &accountName) = 0;
        virtual bool blockAccountUsingToken(const std::string &accountName, const std::string &blockToken) = 0;

        // Account Details Fields
        virtual bool addAccountDetailField(const std::string &fieldName, const AccountDetailField &details) = 0;
        virtual bool removeAccountDetailField(const std::string &fieldName) = 0;
        virtual std::map<std::string, AccountDetailField> listAccountDetailFields() = 0;

        // Account Details
        virtual bool changeAccountDetails(const std::string &accountName, const std::map<std::string, std::string> &fieldsValues, bool resetAllValues = false) = 0;
        virtual bool removeAccountDetail(const std::string &accountName, const std::string &fieldName) = 0;

        enum AccountDetailsToShow
        {
            ACCOUNT_DETAILS_ALL,
            ACCOUNT_DETAILS_SEARCH,
            ACCOUNT_DETAILS_COLUMNVIEW,
            ACCOUNT_DETAILS_TOKEN
        };

        virtual std::map<std::string, std::string> getAccountDetailValues(const std::string &accountName, const AccountDetailsToShow &detailsToShow = ACCOUNT_DETAILS_ALL) = 0;

    private:
        IdentityManager *m_parent;
    };
    class Roles
    {
    public:
        virtual ~Roles() {}
        /////////////////////////////////////////////////////////////////////////////////
        // role:
        virtual bool addRole(const std::string &roleName, const std::string &roleDescription) = 0;
        virtual bool removeRole(const std::string &roleName) = 0;
        virtual bool doesRoleExist(const std::string &roleName) = 0;
        virtual bool addAccountToRole(const std::string &roleName, const std::string &accountName) = 0;
        virtual bool removeAccountFromRole(const std::string &roleName, const std::string &accountName, bool lock = true) = 0;
        virtual bool updateRoleDescription(const std::string &roleName, const std::string &roleDescription) = 0;

        virtual std::string getRoleDescription(const std::string &roleName) = 0;
        virtual std::set<std::string> getRolesList() = 0;
        virtual std::set<std::string> getRoleAccounts(const std::string &roleName, bool lock = true) = 0;
        virtual std::list<RoleDetails> searchRoles(std::string sSearchWords, size_t limit = 0, size_t offset = 0) = 0;
    };
    class AuthController : public CredentialValidator
    {
    private:
        IdentityManager *m_parent;
        static json authSlotsToJSON(const std::vector<AuthenticationSchemeUsedSlot> &authSlots);
        void incrementCredentialBadCounts(Reason ret, const std::string &accountName, const Credential &pStoredCredentialData, const uint32_t &slotId, const ClientDetails &clientDetails);

    protected:
        AuthenticationPolicy m_authenticationPolicy;
        virtual Credential retrieveCredential(const std::string &accountName, const uint32_t &slotId, bool *accountFound, bool *authSlotFound) = 0;

    public:
        AuthController(IdentityManager *parent) { m_parent = parent; }
        virtual ~AuthController() {}

        uint32_t initializateDefaultPasswordSchemes(bool *defaultPasswordSchemesExist);

        bool setAccountPasswordOnScheme(const std::string &accountName, std::string *sInitPW, const uint32_t &schemeId);

        std::string genRandomConfirmationToken();

        AuthenticationPolicy getAuthenticationPolicy();
        void setAuthenticationPolicy(const AuthenticationPolicy &newAuthenticationPolicy);

        virtual std::set<ApplicationPermission> getAccountDirectApplicationPermissions(const std::string &accountName, bool lock = true) = 0;

        virtual bool validateAccountApplicationPermission(const std::string &accountName, const ApplicationPermission &applicationPermission) override;

        std::set<ApplicationPermission> getAccountUsableApplicationPermissions(const std::string &accountName);

        virtual bool validateApplicationPermissionOnRole(const std::string &roleName, const ApplicationPermission &applicationPermission, bool lock = true) = 0;
        virtual std::set<ApplicationPermission> getRoleApplicationPermissions(const std::string &roleName, bool lock = true) = 0;

        /////////////////////////////////////////////////////////////////////////////////
        // permissions:
        virtual bool addApplicationPermission(const ApplicationPermission &applicationPermission, const std::string &description) = 0;
        virtual bool removeApplicationPermission(const ApplicationPermission &applicationPermission) = 0;
        virtual bool doesApplicationPermissionExist(const ApplicationPermission &applicationPermission) = 0;
        virtual bool addApplicationPermissionToRole(const ApplicationPermission &applicationPermission, const std::string &roleName) = 0;
        virtual bool removeApplicationPermissionFromRole(const ApplicationPermission &applicationPermission, const std::string &roleName, bool lock = true) = 0;
        virtual bool addApplicationPermissionToAccount(const ApplicationPermission &applicationPermission, const std::string &accountName) = 0;
        virtual bool removeApplicationPermissionFromAccount(const ApplicationPermission &applicationPermission, const std::string &accountName, bool lock = true) = 0;
        virtual bool updateApplicationPermissionDescription(const ApplicationPermission &applicationPermission, const std::string &description) = 0;
        virtual std::string getApplicationPermissionDescription(const ApplicationPermission &applicationPermission) = 0;
        virtual std::set<ApplicationPermission> listApplicationPermissions(const std::string &applicationName = "") = 0;
        virtual std::set<std::string> getApplicationPermissionsForRole(const ApplicationPermission &applicationPermission, bool lock = true) = 0;
        virtual std::set<std::string> listAccountsOnApplicationPermission(const ApplicationPermission &applicationPermission, bool lock = true) = 0;
        virtual std::list<ApplicationPermissionDetails> searchApplicationPermissions(const std::string &appName, std::string sSearchWords, size_t limit = 0, size_t offset = 0) = 0;
        virtual bool validateAccountDirectApplicationPermission(const std::string &accountName, const ApplicationPermission &applicationPermission) = 0;

        // Account bad attempts for pass slot id...
        virtual void resetBadAttemptsOnCredential(const std::string &accountName, const uint32_t &slotId) = 0;
        virtual void incrementBadAttemptsOnCredential(const std::string &accountName, const uint32_t &slotId) = 0;

        // Account Credentials:
        virtual bool changeCredential(const std::string &accountName, Credential passwordData, uint32_t slotId) = 0;

        // Account last login:
        virtual void updateAccountLastAccess(const std::string &accountName, const uint32_t &slotId, const ClientDetails &clientDetails) = 0;
        virtual time_t getAccountLastAccess(const std::string &accountName) = 0;

        /////////////////////////////////////////////////////////////////////////////////
        // authentication:

        /**
         * @brief Authenticates a user's credential based on provided details and optional authentication context.
         *
         * This function validates the user's credentials, checking against account status, authentication policies,
         * and slot-based authentication schemes. It also supports additional authentication context for enhanced flexibility.
         * If authentication fails, the function increments the bad attempt counters for the account and authentication slot.
         *
         * @param clientDetails Contains session-related details for the client attempting authentication (e.g., IP address, session ID).
         * @param accountName The user or account identifier to authenticate.
         * @param password The incoming password or credential to validate against stored data.
         * @param slotId The identifier for the specific authentication slot being used.
         * @param authMode Specifies the mode of authentication (e.g., plain text, hashed). Default is `MODE_PLAIN`.
         * @param challengeSalt Optional salt used in challenge-based authentication methods. Default is an empty string.
         * @param authContext (Optional) A shared pointer to an `AppAuthExtras` object, which provides supplementary
         *        data for authentication, such as:
         *        - Application name (`appName`)
         *        - Authentication scheme ID (`schemeId`)
         *        - Slot scheme hash (`slotSchemeHash`)
         *        - Current slot position (`currentSlotPosition`)
         *        - List of authentication slots (`authSlots`)
         *        This is useful for multi-step or application-specific authentication workflows.
         *
         * @return `Reason` Enum value indicating the result of the authentication attempt:
         *         - `REASON_NONE`: Authentication successful.
         *         - `REASON_ACCOUNT_NOT_IN_APP`: Account is not registered for the specified application.
         *         - `REASON_AUTH_SCHEME_EMPTY`: The authentication scheme has no associated slots.
         *         - `REASON_AUTH_SCHEME_CHANGED`: The slot scheme has changed, indicating a possible race condition.
         *         - `REASON_PASSWORD_INDEX_NOTFOUND`: The specified slot ID or index is invalid.
         *         - `REASON_BAD_ACCOUNT`: The account does not exist or is invalid.
         *         - `REASON_UNCONFIRMED_ACCOUNT`: The account is not confirmed.
         *         - `REASON_DISABLED_ACCOUNT`: The account is disabled or blocked.
         *         - `REASON_EXPIRED_ACCOUNT`: The account has expired or is considered abandoned.
         *         - Other `Reason` codes depending on the implementation of `validateStoredCredential`.
         *
         * @note On failure, the function ensures to increment bad attempt counters for the account and the password slot.
         */
        virtual Reason authenticateCredential(const ClientDetails &clientDetails, const std::string &accountName, const std::string &sPassword, const uint32_t &slotId = 0,
                                              const Mode &authMode = MODE_PLAIN, const std::string &challengeSalt = "", std::shared_ptr<AppAuthExtras> authContext = nullptr) override;

        /**
     * @brief changeAccountAuthenticatedCredential Change the password doing current password authentication
     * @param accountName
     * @param currentPassword
     * @param authMode
     * @param challengeSalt
     * @param newPasswordData New Password Data (hash, salt, expiration, etc)
     * @param slotId AuthController Slot SlotId.
     * @return true if changed, false if not (bad password, etc)
     */
        virtual bool changeAccountAuthenticatedCredential(const std::string &accountName, uint32_t slotId, const std::string &sCurrentPassword, const Credential &newPasswordData,
                                                          const ClientDetails &clientDetails, Mode authMode = MODE_PLAIN, const std::string &challengeSalt = "");
        /**
     * @brief getAccountCredentialPublicData Get information for Salted Password Calculation and expiration info (Not Authenticated)
     * @param accountName Account Name
     * @param found value set to true/false if the account was found or not.
     * @param slotId AuthController Slot SlotId.
     * @return Password Information (Eg. hashing function, salt, expiration, etc)
     */
        virtual Credential getAccountCredentialPublicData(const std::string &accountName, uint32_t slotId) override;

        /**
     * @brief getAccountAllCredentialsPublicData Get a map with slotId->public credential data for an account.
     * @param accountName account ID or user string.
     * @return map with every defined and not defined password.
     */
        std::map<uint32_t, Credential> getAccountAllCredentialsPublicData(const std::string &accountName);

        /////////////////////////////////////////////////////////////////////////////////
        // AuthController Slot SlotIds:
        virtual uint32_t addNewAuthenticationSlot(const AuthenticationSlotDetails &details) = 0;
        virtual bool removeAuthenticationSlot(const uint32_t &slotId) = 0;
        virtual bool updateAuthenticationSlotDetails(const uint32_t &slotId, const AuthenticationSlotDetails &details) = 0;
        virtual std::map<uint32_t, AuthenticationSlotDetails> listAuthenticationSlots() = 0;

        virtual uint32_t addAuthenticationScheme(const std::string &description) = 0;
        virtual bool updateAuthenticationScheme(const uint32_t &schemeId, const std::string &description) = 0;
        virtual bool removeAuthenticationScheme(const uint32_t &schemeId) = 0;
        virtual std::map<uint32_t, std::string> listAuthenticationSchemes() = 0;

        /**
         * @brief Retrieves the default authentication scheme ID for a specific application and activity.
         *
         * This function queries the database to fetch the `defaultSchemeId` for the given application (`appName`)
         * and activity (`activityName`). If no default scheme is set, the function returns
         * `UINT32_MAX` as an indicator.
         *
         * @param appName The name of the application.
         * @param activityName The name of the activity within the application.
         * @return uint32_t The ID of the default authentication scheme, or `UINT32_MAX` if not set.
         *
         * @note This function acquires a read lock (`Lock_RD`) to ensure thread safety while accessing shared resources.
         */
        virtual uint32_t getApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName) = 0;
        /**
         * @brief Sets or updates the default authentication scheme ID for a specific application and activity.
         *
         * This function updates the `defaultSchemeId` in the database for the given application (`appName`) and
         * activity (`activityName`) to the specified `schemeId`.
         *
         * @param appName The name of the application.
         * @param activityName The name of the activity within the application.
         * @param schemeId The ID of the authentication scheme to set as the default.
         * @return bool `true` if the operation succeeds, `false` otherwise.
         *
         * @note This function acquires a write lock (`Lock_RW`) to ensure thread safety while modifying the database.
         */
        virtual bool setApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName, const uint32_t &schemeId) = 0;

        virtual std::set<uint32_t> listAuthenticationSchemesForApplicationActivity(const std::string &appName, const std::string &activityName) = 0;
        virtual bool addAuthenticationSchemesToApplicationActivity(const std::string &appName, const std::string &activityName, const uint32_t &schemeId) = 0;
        virtual bool removeAuthenticationSchemeFromApplicationActivity(const std::string &appName, const std::string &activityName, const uint32_t &schemeId) = 0;

        virtual std::vector<AuthenticationSchemeUsedSlot> listAuthenticationSlotsUsedByScheme(const uint32_t &schemeId) = 0;
        virtual bool updateAuthenticationSlotUsedByScheme(const uint32_t &schemeId, const std::list<AuthenticationSchemeUsedSlot> &slotsUsedByScheme) = 0;

        virtual std::set<uint32_t> listUsedAuthenticationSlotsOnAccount(const std::string &accountName) = 0;

        Credential createNewCredential(const uint32_t &slotId, const std::string &passwordInput, bool forceExpiration = false);

        /**
         * @brief Retrieves the applicable authentication schemes for a user for a specific application activity.
         *
         * This function checks the available authentication schemes for an application activity and determines
         * which schemes are applicable to the user based on the authentication slots the user has.
         *
         * @param app The name of the application.
         * @param activity The name of the activity within the application.
         * @param accountName account ID or user string.
         * @return json A JSON object containing the applicable authentication schemes, their details, and the default scheme.
         */
        json getApplicableAuthenticationSchemesForAccount(const std::string &app, const std::string &activity, const std::string &accountName);
    };
    class Applications
    {
    public:
        virtual ~Applications() {}
        /////////////////////////////////////////////////////////////////////////////////
        // applications:
        virtual bool addApplication(const std::string &appName, const std::string &applicationDescription, const std::string &apiKey, const std::string &sOwnerAccountName) = 0;
        virtual bool removeApplication(const std::string &appName) = 0;
        virtual bool doesApplicationExist(const std::string &appName) = 0;

        virtual std::string getApplicationDescription(const std::string &appName) = 0;
        virtual std::string getApplicationAPIKey(const std::string &appName) = 0;
        virtual bool updateApplicationDescription(const std::string &appName, const std::string &applicationDescription) = 0;
        virtual bool updateApplicationAPIKey(const std::string &appName, const std::string &apiKey) = 0;
        virtual std::string getApplicationNameByAPIKey(const std::string &apiKey) = 0;

        virtual std::set<std::string> listApplications() = 0;
        virtual bool validateApplicationOwner(const std::string &appName, const std::string &accountName) = 0;
        virtual bool validateApplicationAccount(const std::string &appName, const std::string &accountName) = 0;
        virtual std::set<std::string> listApplicationOwners(const std::string &appName) = 0;
        virtual std::set<std::string> listApplicationAccounts(const std::string &appName) = 0;
        virtual std::set<std::string> listAccountApplications(const std::string &accountName) = 0;
        virtual bool addAccountToApplication(const std::string &appName, const std::string &accountName) = 0;
        virtual bool removeAccountFromApplication(const std::string &appName, const std::string &accountName) = 0;
        virtual bool addApplicationOwner(const std::string &appName, const std::string &accountName) = 0;
        virtual bool removeApplicationOwner(const std::string &appName, const std::string &accountName) = 0;
        virtual std::list<ApplicationDetails> searchApplications(std::string sSearchWords, size_t limit = 0, size_t offset = 0) = 0;

        // Weblogin return urls:
        virtual bool addWebLoginRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI) = 0;
        virtual bool removeWebLoginRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI) = 0;
        virtual std::list<std::string> listWebLoginRedirectURIsFromApplication(const std::string &appName) = 0;

        virtual bool setApplicationWebLoginCallbackURI(const std::string &appName, const std::string &callbackURI) = 0;
        virtual std::string getApplicationCallbackURI(const std::string &appName) = 0;

        // Application admited origin URLS:
        virtual bool addWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl) = 0;
        virtual bool removeWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl) = 0;
        virtual std::list<std::string> listWebLoginOriginUrlsFromApplication(const std::string &appName) = 0;

        // A aplication activity can have multiple authentication schemes...
        // by example, some (special) activities can be: transfer_money, edit_details, and so...
        // Activities can be defined here:

        struct ActivityData
        {
            std::string description;
            std::string parentActivity;
        };

        virtual bool setApplicationActivities(const std::string &appName, const std::map<std::string, ActivityData> &activities) = 0;
        virtual bool removeApplicationActivities(const std::string &appName) = 0;
        virtual std::map<std::string, ActivityData> listApplicationActivities(const std::string &appName) = 0;

        // Tokens:
        virtual bool modifyWebLoginJWTConfigForApplication(const ApplicationTokenProperties &tokenInfo) = 0;
        virtual ApplicationTokenProperties getWebLoginJWTConfigFromApplication(const std::string &appName) = 0;
        virtual bool setWebLoginJWTSigningKeyForApplication(const std::string &appName, const std::string &signingKey) = 0;
        virtual std::string getWebLoginJWTSigningKeyForApplication(const std::string &appName) = 0;
        virtual bool setWebLoginJWTValidationKeyForApplication(const std::string &appName, const std::string &signingKey) = 0;
        virtual std::string getWebLoginJWTValidationKeyForApplication(const std::string &appName) = 0;

        std::shared_ptr<Mantids30::DataFormat::JWT> getAppJWTValidator(const std::string &appName);
        std::shared_ptr<Mantids30::DataFormat::JWT> getAppJWTSigner(const std::string &appName);
    };

    Accounts *accounts = nullptr;
    Roles *roles = nullptr;
    Applications *applications = nullptr;
    AuthController *authController = nullptr;

    /**
     * @brief checkConnection Check if the Authentication IdentityManager Connection is Alive.
     * @return true if alive, false otherwise.
     */
    virtual bool checkConnection() { return true; }
    virtual bool initializeDatabase() = 0;

    bool initializeAdminAccountWithPassword(const std::string &accountName, std::string *adminPW, const uint32_t &schemeId, bool *alreadyExist);
    bool initializeApplicationWithScheme(const std::string &appName, const std::string &appDescription, const uint32_t &schemeId, const std::string &owner, bool *alreadyExist);

protected:
    Mantids30::Threads::Sync::Mutex_Shared m_mutex;
};
