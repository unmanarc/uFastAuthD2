#include "IdentityManager/ds_authentication.h"
#include "identitymanager.h"

#include <Mantids30/Threads/lock_shared.h>
#include <Mantids30/Helpers/random.h>

using namespace Mantids30;

json IdentityManager::AuthController::authSlotsToJSON(const std::vector<AuthenticationSchemeUsedSlot> &authSlots)
{
    json r;
    int i = 0;
    for (const auto &slot : authSlots)
    {
        r[i] = slot.toJSON();
    }
    return r;
}

void IdentityManager::AuthController::incrementCredentialBadCounts(Reason ret, const std::string & accountName, const Credential & pStoredCredentialData, const uint32_t & slotId , const Sessions::ClientDetails &clientDetails)
{
    // Register the change for max attempts...
    if ( !IS_PASSWORD_AUTHENTICATED( ret ) )
    {
        // Increment the counter and disable the account acording to the policy.
        if ( (pStoredCredentialData.badAttempts + 1) >= m_authenticationPolicy.maxTries )
        {
            // Disable the account...
            m_parent->accounts->disableAccount(accountName,true);
        }
        else
        {
            incrementBadAttemptsOnCredential(accountName,slotId);
        }
    }
    else
    {
        // Authenticated:
        updateAccountLastLogin(accountName,slotId,clientDetails);
        resetBadAttemptsOnCredential(accountName,slotId);
    }
}

Reason IdentityManager::AuthController::authenticateCredential(const Sessions::ClientDetails &clientDetails,
                                                               const std::string &accountName,
                                                               const std::string &incomingPassword,
                                                               const uint32_t & slotId,
                                                               const Mode & authMode,
                                                               const std::string &challengeSalt,
                                                               // Extras...
                                                               std::shared_ptr<AppAuthExtras> authContext)
{
    Reason ret = REASON_BAD_ACCOUNT;
    bool accountFound=false, authSlotFound=false;
    Credential pStoredCredentialData;

    // If something changes in between,
    if (1)
    {
        Threads::Sync::Lock_RD lock(m_parent->m_mutex);

        // Process the extras (using scheme/slot/app)...
        if (authContext)
        {
            // app does not exist or user not in app.
            if (!m_parent->applications->validateApplicationAccount(authContext->appName, accountName))
            {
                return REASON_ACCOUNT_NOT_IN_APP;
            }

            // Get authentication slots for the scheme id:
            authContext->authSlots = listAuthenticationSlotsUsedByScheme(authContext->schemeId);

            // Empty slots / bad scheme id:
            if (authContext->authSlots.empty())
            {
                return REASON_AUTH_SCHEME_EMPTY;
            }

            // Slots in position 0:
            if (authContext->currentSlotPosition == 0)
            {
                //Calc the slot scheme hash
                authContext->slotSchemeHash = Helpers::Crypto::calcSHA256(authSlotsToJSON(authContext->authSlots).toStyledString());
            }
            else
            {
                // Slot in other position...

                // Validate position:
                if (authContext->currentSlotPosition >= authContext->authSlots.size())
                {
                    return REASON_PASSWORD_INDEX_NOTFOUND;
                }

                // hash is not compatible (slots changed, prevent race condition)
                if (authContext->slotSchemeHash != Helpers::Crypto::calcSHA256(authSlotsToJSON(authContext->authSlots).toStyledString()))
                {
                    return REASON_AUTH_SCHEME_CHANGED;
                }
            }
        }

        // Check if the retrieved credential
        pStoredCredentialData = retrieveCredential(accountName,slotId, &accountFound, &authSlotFound);

        if (accountFound == false)
            ret = REASON_BAD_ACCOUNT;
        else if (authSlotFound == false)
            ret = REASON_PASSWORD_INDEX_NOTFOUND;
        else
        {
            time_t lastLogin = getAccountLastLogin(accountName);

            // There is no last login.. use the creation date for doing the inactivity calculation...
            if (lastLogin == std::numeric_limits<time_t>::max())
            {
                lastLogin = m_parent->accounts->getAccountCreationTime(accountName);
            }

            auto flags = m_parent->accounts->getAccountFlags(accountName);

            if      (!flags.confirmed)
                return REASON_UNCONFIRMED_ACCOUNT;

            else if (!flags.enabled)
                return REASON_DISABLED_ACCOUNT;

            else if (flags.blocked)
                return REASON_DISABLED_ACCOUNT;

            else if (m_parent->accounts->isAccountExpired(accountName))
                return REASON_EXPIRED_ACCOUNT;

            else if (lastLogin+m_authenticationPolicy.abandonedAccountExpirationSeconds<time(nullptr))
                return REASON_INACTIVE_ACCOUNT;

            else
            {
                ret = validateStoredCredential(accountName,pStoredCredentialData, incomingPassword, challengeSalt, authMode);
            }
        }
    }

    incrementCredentialBadCounts(ret, accountName, pStoredCredentialData,slotId, clientDetails);

    return ret;
}

std::string IdentityManager::AuthController::genRandomConfirmationToken()
{
    return Mantids30::Helpers::Random::createRandomString(64);
}


AuthenticationPolicy IdentityManager::AuthController::getAuthenticationPolicy()
{
    Threads::Sync::Lock_RD lock(m_parent->m_mutex);
    return m_authenticationPolicy;
}

void IdentityManager::AuthController::setAuthenticationPolicy(const AuthenticationPolicy &newAuthenticationPolicy)
{
    Threads::Sync::Lock_RW lock(m_parent->m_mutex);
    m_authenticationPolicy = newAuthenticationPolicy;
}

Credential IdentityManager::AuthController::getAccountCredentialPublicData(const std::string &accountName, uint32_t slotId)
{
    // protective-limited method.
    bool bAccountFound = false;
    bool bSlotIdFound = false;
    Credential credential = retrieveCredential(accountName, slotId, &bAccountFound, &bSlotIdFound);
    return credential.getPublicData();
}

std::map<uint32_t, Credential> IdentityManager::AuthController::getAccountAllCredentialsPublicData(const std::string &accountName)
{
    // TODO: this function can only be accessed if the user has been authenticated...
    Threads::Sync::Lock_RD lock(m_parent->m_mutex);
    std::map<uint32_t, Credential> r;    
    std::set<uint32_t> slotIdsUsedByAccount = listUsedAuthenticationSlotsOnAccount(accountName);
    for (const uint32_t slotId : slotIdsUsedByAccount)
    {
        bool accountFound,authSlotFound;
        Credential credential = retrieveCredential(accountName,slotId,&accountFound,&authSlotFound);
        if (accountFound && authSlotFound)
        {
            r[slotId] = credential.getPublicData();
        }
    }
    return r;
}
/*
std::map<uint32_t,AuthenticationSlotDetails> IdentityManager::AuthController::getAccountAuthenticationSlotsUsedForLogin(const std::string &accountName)
{
    std::map<uint32_t,AuthenticationSlotDetails> r;
    std::set<uint32_t> slotIdsRequiredForLogin = getAuthenticationSlotsRequiredForLogin();

    if (slotIdsRequiredForLogin.empty())
    {
        // Weird... could even be a database error... add impossible's r.
        r[0xFFFFFFFF] = AuthenticationSlotDetails();
        return r;
    }

    std::map<uint32_t,AuthenticationSlotDetails> authenticationSlots = listAuthenticationSlots();

    for (const auto & slotId : listUsedAuthenticationSlotsOnAccount(accountName))
    {
        if (slotIdsRequiredForLogin.find(slotId)!=slotIdsRequiredForLogin.end() && authenticationSlots.find(slotId)!=authenticationSlots.end())
        {
            r[slotId] = authenticationSlots[slotId];
        }
    }

    return r;
}*/


// TODO: this can only be called when authenticated.
bool IdentityManager::AuthController::changeAccountAuthenticatedCredential(const std::string &accountName, uint32_t slotId, const std::string &sCurrentPassword, const Credential &passwordData, const Sessions::ClientDetails &clientInfo, Mode authMode, const std::string &challengeSalt)
{
    {
        Threads::Sync::Lock_RD lock(m_parent->m_mutex);

        auto authSlots = listAuthenticationSlots();

        if ( authSlots.find(slotId) == authSlots.end() )
        {
            // Bad, no slot id available...
            return false;
        }

        if (!authSlots[slotId].isCompatible(passwordData.slotDetails))
        {
            // Bad, not compatible password...
            return false;
        }

        bool accountFound, authSlotFound;

        Credential storedCredential = retrieveCredential(accountName, slotId, &accountFound, &authSlotFound);

        if (!accountFound)
        {
            // Account not found, you can't change this password...
            return false;
        }

        if (authSlotFound)
        {
            // If the slotId has been initialized, authenticate the current credential.
            auto i = authenticateCredential(clientInfo, accountName, sCurrentPassword, slotId, authMode, challengeSalt);
            // Now take the authentication and add/change the credential
            if ( ! (IS_PASSWORD_AUTHENTICATED(i)) )
            {
                // Change the requested index.
                return false;
            }
        }
    }

    // change it here...
    return changeCredential(accountName,passwordData,slotId);
}



bool IdentityManager::AuthController::validateAccountApplicationPermission(const std::string &accountName, const ApplicationPermission & applicationPermission)
{
    Threads::Sync::Lock_RD lock(m_parent->m_mutex);
    if (validateAccountDirectApplicationPermission(accountName,applicationPermission))
    {
        return true;
    }
    for (const std::string & roleName : m_parent->accounts->getAccountRoles(accountName,false))
    {
        if (validateApplicationPermissionOnRole(roleName, applicationPermission,false))
        {
            return true;
        }
    }
    return false;
}

std::set<ApplicationPermission> IdentityManager::AuthController::getAccountUsableApplicationPermissions(const std::string &accountName)
{
    std::set<ApplicationPermission> x;
    Threads::Sync::Lock_RD lock(m_parent->m_mutex);
    // Take permissions from the account
    for (const ApplicationPermission & permission : getAccountDirectApplicationPermissions(accountName,false))
        x.insert(permission);

    // Take the permissions from the belonging roles
    for (const std::string & roleName : m_parent->accounts->getAccountRoles(accountName,false))
    {
        for (const ApplicationPermission & permission : getRoleApplicationPermissions(roleName,false))
            x.insert(permission);
    }
    return x;
}

bool IdentityManager::AuthController::setAccountPasswordOnScheme(
    const std::string &accountName, std::string *sInitPW, const uint32_t &schemeId)
{
    if (schemeId==UINT32_MAX)
        return false;

    *sInitPW = "";
    std::vector<AuthenticationSchemeUsedSlot> authSlots;
    std::string newPass;
    Credential credentialData;

    {
        Threads::Sync::Lock_RD lock(m_parent->m_mutex);
        //std::set<uint32_t> applicationRoleSSOLogin = m_parent->authController->listAuthenticationSchemesForApplicationActivity("IAM","LOGIN");

        authSlots = m_parent->authController->listAuthenticationSlotsUsedByScheme(schemeId);
        // not any slot assigned to this scheme
        if (authSlots.empty())
        {
            return false;
        }

        // not a password...
        if (!authSlots.begin()->details.isTextPasswordFunction())
        {
            return false;
        }
        newPass = Mantids30::Helpers::Random::createRandomString(16);
        credentialData = m_parent->authController->createNewCredential(authSlots.begin()->slotId,newPass,true);
    }

    bool r = m_parent->authController->changeCredential(accountName, credentialData, authSlots.begin()->slotId);

    if (r)
        *sInitPW = newPass;

    return r;

    /*
            &&

            &&
           _parent->m_sqlConnector->query("INSERT INTO iam_accountCredentials "
                                "(`f_AuthSlotId`,`f_accountName`,`hash`,`expiration`,`salt`,`forcedExpiration`)"
                                " VALUES"
                                "('0',:account,:hash,:expiration,:salt,:forcedExpiration);",
                                {
                                    {":account",MAKE_VAR(STRING,accountName)},
                                    {":hash",MAKE_VAR(STRING,credentialData.hash)},
                                    {":expiration",MAKE_VAR(DATETIME,credentialData.expirationTimestamp)},
                                    {":salt",MAKE_VAR(STRING,Mantids30::Helpers::Encoders::toHex(credentialData.ssalt,4))},
                                    {":forcedExpiration",MAKE_VAR(BOOL,credentialData.forceExpiration)}
                                }
                                );*/
    // TODO: pasar esto a slot
    //`totp2FAStepsToleranceWindow`,`function`

}

Credential IdentityManager::AuthController::createNewCredential(const uint32_t & slotId, const std::string & passwordInput, bool forceExpiration)
{
    Credential r;

    auto authSlots = listAuthenticationSlots();

    if (authSlots.find(slotId) == authSlots.end())
    {
        return r;
    }

    r.slotDetails = authSlots[slotId];
    r.forceExpiration = forceExpiration;
    r.expirationTimestamp = time(nullptr)+r.slotDetails.defaultExpirationSeconds;

    switch (r.slotDetails.passwordFunction)
    {
    case FN_NOTFOUND:
    {
        // Do nothing...
    } break;
    case FN_PLAIN:
    {
        r.hash = passwordInput;
    } break;
    case FN_SHA256:
    {
        r.hash = Helpers::Crypto::calcSHA256(passwordInput);
    } break;
    case FN_SHA512:
    {
        r.hash = Helpers::Crypto::calcSHA512(passwordInput);
    } break;
    case FN_SSHA256:
    {
        Mantids30::Helpers::Random::createRandomSalt32(r.ssalt);
        r.hash = Helpers::Crypto::calcSSHA256(passwordInput, r.ssalt);
    } break;
    case FN_SSHA512:
    {
        Mantids30::Helpers::Random::createRandomSalt32(r.ssalt);
        r.hash = Helpers::Crypto::calcSSHA512(passwordInput, r.ssalt);
    } break;
    case FN_GAUTHTIME:
        r.hash = passwordInput;
    }

    return r;
}

json IdentityManager::AuthController::getApplicableAuthenticationSchemesForAccount(
    const std::string &app, const std::string &activity, const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(m_parent->m_mutex);

    // Initialize the result JSON
    json r;
    r["defaultScheme"] = UINT32_MAX;
    std::map<uint32_t, std::string> allSchemes = listAuthenticationSchemes();

    if (!m_parent->applications->validateApplicationAccount(app, accountName))
    {
        // If the user is invalid or not associated, return only the default scheme (reducing risk of user enumeration)
        uint32_t defaultSchemeId = getApplicationActivityDefaultScheme(app, activity);
        if (defaultSchemeId != UINT32_MAX)
        {
            std::vector<AuthenticationSchemeUsedSlot> slots = listAuthenticationSlotsUsedByScheme(defaultSchemeId);
            int i = 0;
            r["defaultScheme"] = defaultSchemeId;
            r["availableSchemes"][defaultSchemeId]["description"] = allSchemes[defaultSchemeId];
            for (const AuthenticationSchemeUsedSlot &slot : slots)
            {
                r["availableSchemes"][defaultSchemeId]["slots"][i++] = slot.toJSON();
            }
            // Add default scheme's slots as empty
        }
        return r;
    }

    // Fetch necessary data
    std::set<uint32_t> availableSchemes = listAuthenticationSchemesForApplicationActivity(app, activity);
    std::set<uint32_t> accountUsedAuthSlots = listUsedAuthenticationSlotsOnAccount(accountName);
    uint32_t defaultScheme = getApplicationActivityDefaultScheme(app, activity);

    // Iterate through available schemes
    for (const uint32_t &schemeId : availableSchemes)
    {
        std::vector<AuthenticationSchemeUsedSlot> slots = listAuthenticationSlotsUsedByScheme(schemeId);
        bool allSlotsAvailable = true;

        // Check if all required slots are available for the user
        for (const AuthenticationSchemeUsedSlot &slot : slots)
        {
            if (accountUsedAuthSlots.find(slot.slotId) == accountUsedAuthSlots.end())
            {
                allSlotsAvailable = false;
                break;
            }
        }

        if (allSlotsAvailable)
        {
            int i = 0;
            r["availableSchemes"][schemeId]["description"] = allSchemes[schemeId];
            for (const AuthenticationSchemeUsedSlot &slot : slots)
            {
                r["availableSchemes"][schemeId]["slots"][i++] = slot.toJSON();
            }

            if (schemeId == defaultScheme)
            {
                r["defaultScheme"] = schemeId;
            }
        }
    }
    return r;
}

uint32_t IdentityManager::AuthController::initializateDefaultPasswordSchemes(bool * defaultPasswordSchemesExist)
{
    uint32_t schemeId, authSlotId;
    bool r = true;

    auto authSchemes = listAuthenticationSchemes();

    if (authSchemes.empty())
    {
        r = r && (authSlotId = addNewAuthenticationSlot(AuthenticationSlotDetails("Master Password", HashFunction::FN_SHA256, "", 3600 * 24 * 365 * 1, 0))) != UINT32_MAX;
        r = r && (schemeId = addAuthenticationScheme("Simple Password Login")) != UINT32_MAX;
        r = r && updateAuthenticationSlotUsedByScheme(schemeId, {AuthenticationSchemeUsedSlot(authSlotId, 0, false)});
        *defaultPasswordSchemesExist = false;
        return !r ? UINT32_MAX : schemeId;
    }

    *defaultPasswordSchemesExist = true;

    // Already initialized, return the first scheme with the description Simple Password Login
    for (const auto &scheme : authSchemes)
    {
        // Look for simple password login scheme:
        if (scheme.second == "Simple Password Login")
        {
            return scheme.first;
        }
    }
    return UINT32_MAX;
}

