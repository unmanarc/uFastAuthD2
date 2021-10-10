#ifndef RPC_H
#define RPC_H

#include <cx2_net_sockets/streamsocket.h>
#include <cx2_xrpc_fast/fastrpc.h>

namespace AUTHSERVER { namespace RPC {

class FastRPCImpl : public CX2::RPC::Fast::FastRPC
{
public:
    FastRPCImpl(uint32_t threadsCount = 16, uint32_t taskQueues = 24) : CX2::RPC::Fast::FastRPC(threadsCount,taskQueues)
    {
    }
    virtual ~FastRPCImpl()
    {
    }

protected:
    // TODO: report back to the manager_remote.

    void eventUnexpectedAnswerReceived(CX2::RPC::Fast::FastRPC_Connection *, const std::string &) override;
    void eventFullQueueDrop(CX2::RPC::Fast::sFastRPCParameters *) override;
    void eventRemotePeerDisconnected(const std::string &, const std::string &, const json &) override;
    void eventRemoteExecutionTimedOut(const std::string &, const std::string &, const json &) override;
private:

};


class LoginRPCServerImpl
{
public:
    LoginRPCServerImpl();
    static bool createRPCListener();
//    static void callbackOnRPCConnected(const std::string &key, void * data);

private:
    static bool callbackOnRPCConnect(void *, CX2::Network::Streams::StreamSocket *sock, const char *remoteAddr, bool secure);
};

}}

#endif // RPC_H
