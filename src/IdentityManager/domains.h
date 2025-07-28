#pragma once

#include "identitymanager.h"
#include <Mantids30/Threads/map.h>

/**
 * @brief The Domains class provides a manager for managing authentication domains.
 *
 * The Domains class provides a manager for managing authentication domains. An authentication domain is a grouping of related authentication data and policies.
 */
class Domains
{
public:
    Domains();

    /**
     * @brief Adds a new authentication domain with the given domain name and Manager.
     * @param domainName The name of the new authentication domain.
     * @param auth The Manager object to associate with the new domain.
     * @return true if the domain was successfully added, false otherwise.
     */
    bool addDomain(const std::string &domainName, IdentityManager *identityManager);

    /**
     * @brief Opens the authentication domain with the given domain name.
     * @param domainName The name of the authentication domain to open.
     * @return The IdentityManager associated with the opened domain, or nullptr if the domain was not found.
     */
    IdentityManager *openDomain(const std::string &domainName);

    /**
     * @brief Releases the authentication domain with the given domain name.
     * @param domainName The name of the authentication domain to release.
     * @return true if the domain was successfully released, false otherwise.
     */
    bool releaseDomain(const std::string &domainName);

private:
    /**
     * @brief A thread-safe map of authentication domain names to their associated Manager objects.
     */
    Mantids30::Threads::Safe::Map<std::string> m_domainMap;
};
