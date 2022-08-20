#ifndef RPC_H
#define RPC_H

#include <mdz_net_sockets/socket_streambase.h>
#include <mdz_xrpc_fast/fastrpc.h>

namespace AUTHSERVER { namespace RPC {

class FastRPCImpl : public Mantids::RPC::Fast::FastRPC
{
public:
    FastRPCImpl(uint32_t threadsCount = 16, uint32_t taskQueues = 24) : Mantids::RPC::Fast::FastRPC(threadsCount,taskQueues)
    {
    }
    virtual ~FastRPCImpl()
    {
    }

protected:
    // TODO: report back to the manager_remote.

    void eventUnexpectedAnswerReceived(Mantids::RPC::Fast::FastRPC_Connection *, const std::string &) override;
    void eventFullQueueDrop(Mantids::RPC::Fast::sFastRPCParameters *) override;
    void eventRemotePeerDisconnected(const std::string &, const std::string &, const json &) override;
    void eventRemoteExecutionTimedOut(const std::string &, const std::string &, const json &) override;
private:

};


class LoginRPCServerImpl
{
public:
    LoginRPCServerImpl();
    static bool createRPCListenerCAB();
    static bool createRPCListenerPAB();
//    static void callbackOnRPCConnected(const std::string &key, void * data);

private:
    static bool callbackOnRPCConnect(void *, Mantids::Network::Sockets::Socket_StreamBase *sock, const char *remoteAddr, bool secure);
};

}}

#endif // RPC_H
