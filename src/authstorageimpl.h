#ifndef AUTHSTORAGEIMPL_H
#define AUTHSTORAGEIMPL_H

#include <string>
#include <mdz_auth_db/manager_db.h>

namespace AUTHSERVER { namespace AUTH {

class AuthStorageImpl
{
public:
    AuthStorageImpl();
    static bool createAuth();
private:
    static bool createPassFile(const std::string &sInitPW);
    static bool createAdmin(Mantids::Authentication::Manager_DB *, std::string *sInitPW);
    static bool resetAdminPwd(Mantids::Authentication::Manager_DB *, std::string *sInitPW);
    static bool createApp(Mantids::Authentication::Manager_DB *);
};

}}

#endif // AUTHSTORAGEIMPL_H
