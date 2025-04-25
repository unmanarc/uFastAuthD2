#include "domains.h"


using namespace Mantids30;

Domains::Domains()
{

}

bool Domains::addDomain(const std::string &domainName, IdentityManager *identityManager)
{
    return m_domainMap.addElement(domainName, identityManager);
}

IdentityManager *Domains::openDomain(const std::string &domainName)
{
    IdentityManager * i = (IdentityManager *)m_domainMap.openElement(domainName);;
    if (i) i->checkConnection();
    return i;
}

bool Domains::releaseDomain(const std::string &domainName)
{
    return m_domainMap.releaseElement(domainName);
}
