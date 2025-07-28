#include "credentialdata.h"

using namespace Mantids30;

CredentialData::CredentialData() {}

CredentialData::CredentialData(const std::string &password, const uint32_t &slotId)
{
    this->m_password = password;
    this->m_slotId = slotId;
}

bool CredentialData::parseJSON(const std::string &sAuth)
{
    json x;

    if (sAuth.empty())
        return true;

    Mantids30::Helpers::JSONReader2 reader;

    if (!reader.parse(sAuth, x))
        return false;
    if (!x.isObject())
        return false;

    return setJSON(x);
}

bool CredentialData::setJSON(const json &jsonObject)
{
    if (jsonObject["pass"].isNull() || jsonObject["slotId"].isNull())
        return false;

    this->m_password = JSON_ASSTRING(jsonObject, "pass", "");
    this->m_slotId = JSON_ASUINT(jsonObject, "slotId", 0);

    return true;
}

json CredentialData::toJSON() const
{
    json x;
    x["pass"] = this->m_password;
    x["slotId"] = this->m_slotId;
    return x;
}
