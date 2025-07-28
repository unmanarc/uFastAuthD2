#ifndef RPC1LOGINSERVER2IMPL_H
#define RPC1LOGINSERVER2IMPL_H

class RPC1LoginServer2Impl
{
public:
    RPC1LoginServer2Impl() = default;

    static bool createRPCListenerCAB();
    static bool createRPCListenerPAB();
};

#endif // RPC1LOGINSERVER2IMPL_H
