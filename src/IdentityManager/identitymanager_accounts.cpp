#include "identitymanager.h"

#include <Mantids30/Threads/lock_shared.h>
#include <Mantids30/Helpers/random.h>



IdentityManager::Users::Users(IdentityManager *m_parent) { this->m_parent = m_parent;}

bool IdentityManager::Users::isAccountExpired(const std::string &accountName)
{
    time_t tAccountExpirationTime = getAccountExpirationTime(accountName);
    if (!tAccountExpirationTime)
        return false;
    return tAccountExpirationTime<time(nullptr);
}



bool IdentityManager::Users::hasSuperUserAccount()
{
    auto accounts = listAccounts();
    for (const std::string & account : accounts)
    {
        if (getAccountFlags(account).superuser)
            return true;
    }
    return false;
}
