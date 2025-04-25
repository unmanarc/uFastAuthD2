#pragma once

#include <string>
#include <Mantids30/Helpers/json.h>

/**
 * @brief The Data class represents the data associated with an authentication event.
 *
 * This class provides methods for serializing and deserializing authentication data, as well as getters
 * and setters for the password, password slot id, and domain name.
 */
class CredentialData
{
public:
    /**
     * @brief Default constructor.
     */
    CredentialData();

    /**
     * @brief Constructs an authentication data object with the given password, password slot id, and domain name.
     * @param password The password associated with the authentication event.
     * @param slotId The index of the password in the password database.
     */
    CredentialData(const std::string& password, const uint32_t& slotId);

    /**
     * @brief Deserializes authentication data from a string.
     * @param serializedData The string containing the serialized authentication data.
     * @return true if the deserialization was successful, false otherwise.
     */
    bool parseJSON(const std::string& serializedData);

    /**
     * @brief Deserializes authentication data from a JSON object.
     * @param jsonObject The JSON object containing the authentication data.
     * @return true if the deserialization was successful, false otherwise.
     */
    bool setJSON(const json& jsonObject);

    /**
     * @brief Serializes authentication data to a JSON object.
     * @return A JSON object containing the authentication data.
     */
    json toJSON() const;


public:
    std::string m_password;
    uint32_t m_slotId = 0;
};


