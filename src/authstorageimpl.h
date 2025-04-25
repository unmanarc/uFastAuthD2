#pragma once

#include "IdentityManager/identitymanager_db.h"
#include <string>

class AuthStorageImpl
{
public:
    AuthStorageImpl() = default;
    static bool createAuth();

private:
    static bool createPassFile(const std::string &sInitPW);
    static bool createAdmin(IdentityManager_DB *, std::string *sInitPW);
    static bool configureApplication(IdentityManager_DB *, const std::string & owner);
};

