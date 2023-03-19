#ifndef AUTHSTORAGEIMPL_H
#define AUTHSTORAGEIMPL_H

#include <string>
#include <Mantids29/Auth_DB/manager_db.h>


namespace AUTHSERVER { namespace AUTH {

class AuthStorageImpl
{
public:
    AuthStorageImpl();
    static bool createAuth();
private:
    static bool createPassFile(const std::string &sInitPW);
    static bool createAdmin(Mantids29::Authentication::Manager_DB *, std::string *sInitPW);
    static bool resetAdminPwd(Mantids29::Authentication::Manager_DB *, std::string *sInitPW);
    static bool createApp(Mantids29::Authentication::Manager_DB *);
};

}}

#endif // AUTHSTORAGEIMPL_H
