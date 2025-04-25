#pragma once

#include <Mantids30/Helpers/json.h>
#include <ctime>
#include <string>

struct AccountDetailField
{
    std::string description;
    std::string regexpValidator;
    bool includeInSearch = true;
    bool includeInColumnView = true;
    bool includeInToken = true;
    std::string fieldType = "TEXTLINE";
    bool isOptionalField = true;

    Json::Value toJSON() const
    {
        Json::Value r;
        r["description"] = description;
        r["regexpValidator"] = regexpValidator;
        r["includeInSearch"] = includeInSearch;
        r["includeInColumnView"] = includeInColumnView;
        r["fieldType"] = fieldType;
        r["isOptionalField"] = isOptionalField;
        return r;
    }

    void fromJSON(const Json::Value &r)
    {
        description = JSON_ASSTRING(r, "description", "");
        regexpValidator = JSON_ASSTRING(r, "regexpValidator", "");
        includeInSearch = JSON_ASBOOL(r, "includeInSearch", true);
        includeInColumnView = JSON_ASBOOL(r, "includeInColumnView", true);
        fieldType = JSON_ASSTRING(r, "fieldType", "TEXTLINE");
        isOptionalField = JSON_ASBOOL(r, "isOptionalField", true);
    }
};
struct AccountFlags
{
    AccountFlags(bool enabled, bool confirmed, bool superuser, bool blocked)
    {
        this->enabled = enabled;
        this->confirmed = confirmed;
        this->superuser = superuser;
        this->blocked = blocked;
    }
    AccountFlags() {}

    Json::Value toJSON() const
    {
        Json::Value r;
        r["enabled"] = enabled;
        r["confirmed"] = confirmed;
        r["superuser"] = superuser;
        r["blocked"] = blocked;
        return r;
    }

    void fromJSON(const Json::Value &r)
    {
        enabled = JSON_ASBOOL(r, "enabled", false);
        confirmed = JSON_ASBOOL(r, "confirmed", false);
        superuser = JSON_ASBOOL(r, "superuser", false);
        blocked = JSON_ASBOOL(r, "blocked", false);
    }

    bool blocked = false;
    bool enabled = false;
    bool confirmed = false;
    bool superuser = false;
};
struct AccountDetails
{
    AccountDetails() {}

    std::map<std::string, AccountDetailField> fields;
    std::map<std::string, std::string> fieldValues;
    std::string accountName, creator;
    AccountFlags accountFlags;
    time_t expirationDate, creationDate;
    bool expired;

    Json::Value toJSON() const
    {
        Json::Value r;

        r["fields"] = json::null;
        for (auto &i : fields)
        {
            r["fields"][i.first] = i.second.toJSON();
        }

        r["fieldValues"] = json::null;
        for (auto &i : fieldValues)
        {
            r["fieldValues"][i.first] = i.second;
        }

        r["accountName"] = accountName;
        r["creator"] = creator;
        r["accountFlags"] = accountFlags.toJSON();
        r["expirationDate"] = expirationDate;
        return r;
    }

    void fromJSON(const Json::Value &r)
    {
        // Deserialize 'fields' map
        const Json::Value &fieldsJson = r["fields"];
        for (Json::ValueConstIterator it = fieldsJson.begin(); it != fieldsJson.end(); ++it)
        {
            AccountDetailField field;
            field.fromJSON(*it);
            fields[it.key().asString()] = field;
        }

        // Deserialize 'fieldValues' map
        const Json::Value &fieldValuesJson = r["fieldValues"];
        for (Json::ValueConstIterator it = fieldValuesJson.begin(); it != fieldValuesJson.end(); ++it)
        {
            fieldValues[it.key().asString()] = it->asString();
        }

        accountName = JSON_ASSTRING(r, "accountName", "");
        creator = JSON_ASSTRING(r, "creator", "");
        accountFlags.fromJSON(r["accountFlags"]);
        expirationDate = JSON_ASUINT64(r, "expirationDate", 0);
        expired = std::time(nullptr) > expirationDate;
    }
};

