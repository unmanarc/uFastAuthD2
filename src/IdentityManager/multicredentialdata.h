#pragma once

#include <Mantids30/Helpers/json.h>
#include <set>
#include "credentialdata.h"

class MultiCredentialData
{
public:
    MultiCredentialData();

    /**
     * @brief parseJSON Set the authentication string.
     * @param sAuthentications string in JSON Format.
     * @return if the string have been correctly parsed, returns true, else false.
     */
    bool parseJSON(const std::string & sAuthentications);
    /**
     * @brief Deserializes multiple authentications from a JSON object.
     * @param jsonObject The JSON object containing the multi authentications.
     * @return true if the deserialization was successful, false otherwise.
     */
    bool setJSON(const json & auths);
    /**
     * @brief clear Clear authentications
     */
    void clear();
    /**
     * @brief addCredentialData Manually add an authentication
     * @param auth Authentication object.
     */
    void addCredentialData(const CredentialData & auth);
    /**
     * @brief addAuthentication Add an authentication as slotId+Secret
     * @param slotId Authentication Secret SlotId
     * @param password Secret
     */
    void addAuthentication(uint32_t slotId, const std::string &password);
    /**
     * @brief getAuthenticationSlotsAvailable Get available authentications SlotIds.
     * @return set of authentication slot id's.
     */
    std::set<uint32_t> getAuthenticationSlotsAvailable();
    /**
     * @brief getAuthentication Get authentication object given an authentication slot id.
     * @param slotId Authentication Secret SlotId.
     * @return Authentication Object.
     */
    CredentialData getAuthentication( const uint32_t & slotId );


private:
    std::map<uint32_t,CredentialData> m_authenticationsSlots;
};
