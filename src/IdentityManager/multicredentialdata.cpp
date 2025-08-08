#include "multicredentialdata.h"
//#include "retcodes.h"

using namespace Mantids30;

MultiCredentialData::MultiCredentialData()
{
    clear();
}

std::set<uint32_t> MultiCredentialData::getAuthenticationSlotsAvailable()
{
    std::set<uint32_t> r;
    for (const auto &i : m_authenticationsSlots)
        r.insert(i.first);
    return r;
}

CredentialData MultiCredentialData::getAuthentication(const uint32_t &slotId)
{
    if (m_authenticationsSlots.find(slotId) != m_authenticationsSlots.end())
        return m_authenticationsSlots[slotId];

    CredentialData r;
    return r;
}

bool MultiCredentialData::parseJSON(const std::string &sAuthentications)
{
    if (sAuthentications.empty())
        return true;

    json jAuthentications;
    Mantids30::Helpers::JSONReader2 reader;
    if (!reader.parse(sAuthentications, jAuthentications))
        return false;

    return setJSON(jAuthentications);
}

bool MultiCredentialData::setJSON(const json &jAuthentications)
{
    if (!jAuthentications.isObject())
        return false;

    if (jAuthentications.isObject())
    {
        for (const auto &slotId : jAuthentications.getMemberNames())
        {
            if (jAuthentications[slotId].isMember("pass"))
            {
                addAuthentication(strtoul(slotId.c_str(), nullptr, 10), JSON_ASSTRING(jAuthentications[slotId], "pass", ""));
            }
        }
    }

    return true;
}

void MultiCredentialData::clear()
{
    m_authenticationsSlots.clear();
}

void MultiCredentialData::addCredentialData(const CredentialData &auth)
{
    m_authenticationsSlots[auth.m_slotId] = auth;
}

void MultiCredentialData::addAuthentication(uint32_t slotId, const std::string &password)
{
    m_authenticationsSlots[slotId].m_slotId = slotId;
    m_authenticationsSlots[slotId].m_password = password;
}
