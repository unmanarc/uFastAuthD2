#pragma once

#include <Mantids30/Sessions/session.h>
#include <Mantids30/Threads/garbagecollector.h>

#include <mutex>
#include <string>
#include <unordered_map>

#include "ds_authentication.h"

struct TokenCacheKey
{
    bool operator==(const TokenCacheKey &x) const { return (x.accountName == accountName && x.token == token); }
    size_t hash() const { return std::hash<std::string>{}(accountName) ^ std::hash<std::string>{}(token); }

    std::string accountName;
    std::string token;
};

// Define the specialization of std::hash for TokenCacheKey inside the Mantids30::Auth namespace
namespace std {
template<>
struct hash<TokenCacheKey>
{
    size_t operator()(const TokenCacheKey &key) const { return key.hash(); }
};
} // namespace std

struct ApplicationPermission
{
    bool operator<(const ApplicationPermission &x) const
    {
        if (x.appName < appName)
            return true;
        else if (x.appName == appName && x.permissionId < permissionId)
            return true;
        else
            return false;
    }
    std::string appName, permissionId;
};

struct AppAuthExtras
{
    bool keepAuthenticated = false;
    std::string appName;
    uint32_t schemeId = UINT32_MAX;
    uint32_t currentSlotPosition = UINT32_MAX;
    std::string slotSchemeHash;
    std::vector<AuthenticationSchemeUsedSlot> authSlots;
};

class CredentialValidator
{
public:
    CredentialValidator();
    virtual ~CredentialValidator() = default;

    /**
     * @brief Returns the account confirmation token for a given account name.
     * @param accountName The name of the account to get the confirmation token for.
     * @return The confirmation token for the account.
     */
    virtual std::string getAccountConfirmationToken(const std::string &accountName) = 0;

    /**
     * @brief Returns the public data associated with an account's credential for a given account name and auth slot id.
     * @param accountName The name of the account to get the credential public data for.
     * @param slotId The password index to use for retrieving the account credential.
     * @return The public data associated with the account's credential.
     */
    virtual Credential getAccountCredentialPublicData(const std::string &accountName, uint32_t slotId) = 0;

    /**
     * @brief Authenticates a user's credential based on provided details and optional authentication context.
     *
     * This function validates the user's credentials, checking against account status, authentication policies,
     * and slot-based authentication schemes. It also supports additional authentication context for enhanced flexibility.
     * If authentication fails, the function increments the bad attempt counters for the account and authentication slot.
     *
     * @param clientDetails Contains session-related details for the client attempting authentication (e.g., IP address, session ID).
     * @param accountName The account name identifier to authenticate.
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
     * @note This function is virtual and must be implemented by derived classes.
     *       It provides a foundational interface for credential authentication in a slot-based system.
     *
     * @note On failure, the function ensures to increment bad attempt counters for the account and slot ID to
     *       enforce policies such as account locking or throttling after repeated failed attempts.
     */
    virtual Reason authenticateCredential(const Mantids30::Sessions::ClientDetails &clientDetails, const std::string &accountName, const std::string &password, const uint32_t &slotId,
                                          const Mode &authMode = MODE_PLAIN, const std::string &challengeSalt = "", std::shared_ptr<AppAuthExtras> authContext = nullptr)
        = 0;

    /**
     * @brief Validates an account permissions for a given account name and application permission.
     * @param accountName The name of the account to validate the permission for.
     * @param applicationPermission The application permission to validate.
     * @return true if the account permission is valid, false otherwise.
     */
    virtual bool validateAccountApplicationPermission(const std::string &accountName, const ApplicationPermission &applicationPermission) = 0;

    // Cleanup function to remove expired google authenticator tokens
    void cleanupExpiredTokens();
    // Static function to be called from the garbage collector.
    static void cleanupExpiredTokens(void *asv);

    bool getUseTokenCache();
    void setUseTokenCache(bool newUseTokenCache);

protected:
    /**
     * @brief Validates a stored credential against an input password and challenge salt.
     * @param accountName any unique descriptor for the account (eg. UUID, UID, user)
     * @param storedCredential The stored credential to validate.
     * @param passwordInput The input password to use for validation.
     * @param challengeSalt The challenge salt to use for validation.
     * @param authMode The mode to use for authentication.
     * @return A reason indicating whether the stored credential was valid or not.
     */
    Reason validateStoredCredential(const std::string &accountName, const Credential &storedCredential, const std::string &passwordInput, const std::string &challengeSalt, Mode authMode);

private:
    /**
     * @brief validateChallenge Validate the Challenge (SHA256(Pass+Salt))
     * @param passwordFromDB Incoming password from DB
     * @param challengeInput Challenge Input SHA256(Pass+Salt)
     * @param challengeSalt Challenge Salt (Random Value generated by your app, take the security considerations)
     * @return Authentication Response Reason (authenticated or bad password)
     */
    Reason validateChallenge(const std::string &passwordFromDB, const std::string &challengeInput, const std::string &challengeSalt);

    /**
    * @brief Validates a Google Authenticator token for a given account and seed.
    *
    * This function validates the Google Authenticator token by comparing it with the expected token
    * generated using the account name and seed. If the token matches, the function returns true; otherwise, it returns false.
    *
    * @param accountName The account name associated with the token.
    * @param seed        The secret seed used for generating the token.
    * @param tokenInput  The Google Authenticator token to be validated.
    *
    * @return True if the token is valid, false otherwise.
    */
    Reason validateGAuth(const std::string &accountName, const std::string &seed, const std::string &tokenInput);

    // Add a cache to store used tokens with timestamps
    std::unordered_map<TokenCacheKey, time_t> usedTokensCache;

    // Ordered data structure to efficiently remove expired tokens
    std::multimap<time_t, TokenCacheKey> expirationQueue;

    // Mutex for synchronizing access to the cache and expirationQueue
    std::mutex cacheMutex;

    // Garbage collector for authentication tokens cache...
    Mantids30::Threads::GarbageCollector usedTokensCacheGC;

    bool useTokenCache = true;
};
