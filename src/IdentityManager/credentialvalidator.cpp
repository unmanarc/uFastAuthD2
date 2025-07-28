#include "credentialvalidator.h"
#include <Mantids30/Helpers/googleauthenticator.h>

#include <Mantids30/Helpers/crypto.h>
#include <Mantids30/Helpers/encoders.h>

CredentialValidator::CredentialValidator()
{
    usedTokensCacheGC.setGarbageCollectorInterval(5000);
    usedTokensCacheGC.startGarbageCollector(cleanupExpiredTokens, this, "GC:TokensCache");
}

void CredentialValidator::cleanupExpiredTokens()
{
    std::unique_lock<std::mutex> lock(cacheMutex);

    if (useTokenCache)
    {
        auto now = time(nullptr);
        while (!expirationQueue.empty() && (now - expirationQueue.begin()->first) >= 90)
        {
            usedTokensCache.erase(expirationQueue.begin()->second);
            expirationQueue.erase(expirationQueue.begin());
        }
    }
}

void CredentialValidator::cleanupExpiredTokens(void *asv)
{
    CredentialValidator *_asv = (CredentialValidator *) asv;
    _asv->cleanupExpiredTokens();
}

Reason CredentialValidator::validateStoredCredential(const std::string &accountName, const Credential &storedCredential, const std::string &passwordInput, const std::string &challengeSalt,
                                                     Mode authMode)
{
    Reason r = REASON_NOT_IMPLEMENTED;
    //  bool saltedHash = false;
    std::string toCompare;

    switch (storedCredential.slotDetails.passwordFunction)
    {
    case FN_NOTFOUND:
        return REASON_INTERNAL_ERROR;
    case FN_PLAIN:
    {
        toCompare = passwordInput;
    }
    break;
    case FN_SHA256:
    {
        toCompare = Mantids30::Helpers::Crypto::calcSHA256(passwordInput);
    }
    break;
    case FN_SHA512:
    {
        toCompare = Mantids30::Helpers::Crypto::calcSHA512(passwordInput);
    }
    break;
    case FN_SSHA256:
    {
        toCompare = Mantids30::Helpers::Crypto::calcSSHA256(passwordInput, storedCredential.ssalt);
        // saltedHash = true;
    }
    break;
    case FN_SSHA512:
    {
        toCompare = Mantids30::Helpers::Crypto::calcSSHA512(passwordInput, storedCredential.ssalt);
        //saltedHash = true;
    }
    break;
    case FN_GAUTHTIME:
        r = validateGAuth(accountName, storedCredential.hash, passwordInput); // GAuth Time Based Token comparisson (seed,token)
        goto skipAuthMode;
    }

    switch (authMode)
    {
    case MODE_PLAIN:
        r = storedCredential.hash == toCompare ? REASON_AUTHENTICATED : REASON_BAD_PASSWORD; // 1-1 comparisson
        break;
    case MODE_CHALLENGE:
        r = validateChallenge(storedCredential.hash, passwordInput, challengeSalt);
        break;
    }

skipAuthMode:;

    if (storedCredential.isAccountExpired() && r == REASON_AUTHENTICATED)
        r = REASON_EXPIRED_PASSWORD;

    return r;
}

Reason CredentialValidator::validateChallenge(const std::string &passwordFromDB, const std::string &challengeInput, const std::string &challengeSalt)
{
    return challengeInput == Mantids30::Helpers::Crypto::calcSHA256(passwordFromDB + challengeSalt) ? REASON_AUTHENTICATED : REASON_BAD_PASSWORD;
}

Reason CredentialValidator::validateGAuth(const std::string &accountName, const std::string &seed, const std::string &tokenInput)
{
    // Use the mutex to synchronize access to the cache and expirationQueue
    std::unique_lock<std::mutex> lock(cacheMutex);
    TokenCacheKey accountTokenKey = {accountName, tokenInput};

    // Check if the token is already in the cache and within the time limit

    if (useTokenCache)
    {
        auto cacheEntry = usedTokensCache.find(accountTokenKey);
        if (cacheEntry != usedTokensCache.end())
        {
            auto tokenTimestamp = cacheEntry->second;
            auto now = time(nullptr);
            auto elapsedSeconds = now - tokenTimestamp;

            if (elapsedSeconds < 90)
            {
                // Token Already Used.
                return REASON_BAD_PASSWORD;
            }
        }
    }

    // Verify the token and update the cache and expirationQueue if successful
    if (Mantids30::Helpers::TOTP::GoogleAuthenticator::verifyToken(seed, tokenInput))
    {
        // Add token to cache:
        if (useTokenCache)
        {
            auto now = time(nullptr);
            usedTokensCache[accountTokenKey] = now;
            expirationQueue.insert({now, accountTokenKey});
        }
        return REASON_AUTHENTICATED;
    }
    else
    {
        return REASON_BAD_PASSWORD;
    }
}

bool CredentialValidator::getUseTokenCache()
{
    std::unique_lock<std::mutex> lock(cacheMutex);
    return useTokenCache;
}

void CredentialValidator::setUseTokenCache(bool newUseTokenCache)
{
    std::unique_lock<std::mutex> lock(cacheMutex);
    useTokenCache = newUseTokenCache;
    if (!useTokenCache)
    {
        usedTokensCache.clear();
        expirationQueue.clear();
    }
}
