/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32WOLFSSHSERVER_STM32WOLFSSHSERVER_HPP
#define LIBSMART_STM32WOLFSSHSERVER_STM32WOLFSSHSERVER_HPP

#include <functional>
#include "tx_api.h"
#include "nx_api.h"
#include <wolfssh/ssh.h>

#include "Helper.hpp"
#include "Stm32ThreadxThread.hpp"
#include "setupNetXThread.hpp"
#include "sshKeys.hpp"
#include "Stm32ItmLogger.h"
#include "Stm32WolfSshServerSessionDynamic.hpp"

#define SSH_PORT                        (22)
#define EXAMPLE_HIGHWATER_MARK          (0x3FFF8000)

using namespace Stm32ThreadxThread;
using namespace Stm32ThreadxThread::native;

extern Debugger *DBG;

extern TX_SEMAPHORE port_12_semaphore;
#define SESSION_STACK_SIZE (1024 * 8)
// extern char sessionStack[SESSION_STACK_SIZE];

template<const std::size_t STACK_SIZE_BYTES>
class Stm32WolfSshServer : public Stm32ThreadxThread::static_thread<STACK_SIZE_BYTES> {
public:
    Stm32WolfSshServer(const Stm32ThreadxThread::thread::priority &prio, const char *name)
        : static_thread<STACK_SIZE_BYTES>(
            &Stm32ThreadxThread::BOUNCE(Stm32WolfSshServer<STACK_SIZE_BYTES>, mainSshServerThread),
            (ULONG) this,
            prio,
            name) {
    }

    /*
    Stm32WolfSshServer(void *pstack, uint32_t stackSize, void (*func)(ULONG), ULONG param, const priority &prio,
                       const char *name) : thread(pstack, stackSize, func, param, prio, name) {}

    Stm32WolfSshServer(void *pstack, uint32_t stackSize, const priority &prio,
                       const char *name) : thread(pstack, stackSize,
                                                  &Stm32ThreadxThread::BOUNCE(Stm32WolfSshServer, mainSshServerThread),
                                                  (ULONG) this, prio, name) {}
*/

    [[noreturn]] VOID mainSshServerThread() {
        UINT ret = NX_SUCCESS;
        int wolfRet = WS_SUCCESS;
        char sem_name[] = "SSH server connection available";
        char sock_name[] = "SSH server socket";
        Stm32WolfSshServerSessionDynamic *session = nullptr;


        Debugger_log(DBG, "Stm32WolfSshServer::mainSshServerThread()");


        // Initialize wolfSSH
        wolfRet = wolfSSH_Init();
        if (wolfRet != WS_SUCCESS) {
            Debugger_log(DBG, "%lu: wolfSSH_Init() = 0x%02x", HAL_GetTick(), wolfRet);
            errorHandler();
        }

        // Configure logging and debugging
        //        wolfSSH_SetLoggingCb(wolfSSH_LoggingCallback);
        //        wolfSSH_Debugging_ON();

        // Initialize wolfSSH server context
        wolfContext = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, nullptr);
        if (wolfContext == nullptr) {
            Debugger_log(DBG, "%lu: wolfSSH_CTX_new(): Can not create wolfSSH context object", HAL_GetTick());
            errorHandler();
        }

        // Configure user authentication callback
        wolfSSH_SetUserAuth(wolfContext, wsUserAuth);
        //        wolfSSH_SetUserAuthResult(wolfContext, wsUserAuthResult);

        // Configure server banner
        wolfRet = wolfSSH_CTX_SetBanner(wolfContext, serverBanner);
        if (wolfRet != WS_SUCCESS) {
            Debugger_log(DBG, "%lu: wolfSSH_CTX_SetBanner() = 0x%02x", HAL_GetTick(), wolfRet);
            errorHandler();
        }

        // Configure window packet size
        wolfRet = wolfSSH_CTX_SetWindowPacketSize(wolfContext, 1024 * 4, 1024);
        if (wolfRet != WS_SUCCESS) {
            Debugger_log(DBG, "%lu: wolfSSH_CTX_SetWindowPacketSize() = 0x%02x", HAL_GetTick(), wolfRet);
            errorHandler();
        }

        // Configure private key
        //        wolfRet = wolfSSH_CTX_UsePrivateKey_buffer(wolfContext, rsa_key_der_2048, sizeof_rsa_key_der_2048, WOLFSSH_FORMAT_ASN1)
        wolfRet = wolfSSH_CTX_UsePrivateKey_buffer(wolfContext, ecc_key_der_256, sizeof_ecc_key_der_256,
                                                   WOLFSSH_FORMAT_ASN1);
        if (wolfRet != WS_SUCCESS) {
            Debugger_log(DBG, "%lu: wolfSSH_CTX_UsePrivateKey_buffer() = 0x%02x", HAL_GetTick(), wolfRet);
            errorHandler();
        }

        // Register receive and send callbacks
        wolfSSH_SetIORecv(wolfContext, ioRecv);
        wolfSSH_SetIOSend(wolfContext, ioSend);

        // Create server socket
        ret = nx_tcp_socket_create(&ipInstance_struct, &SSH_sock, sock_name,
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                   NX_NULL, thread_1_disconnect_received);
        if (ret != NX_SUCCESS) {
            // No socket created
            Debugger_log(DBG, "%lu: nx_tcp_socket_create() = 0x%02x", HAL_GetTick(), ret);
            errorHandler();
        }

        // Create connection available semaphore
        tx_semaphore_create(&port_12_semaphore, sem_name, 0);

        // Listen socket
        ret = nx_tcp_server_socket_listen(&ipInstance_struct, SSH_PORT, &SSH_sock, 5,
                                          thread_1_connect_received);
        if (ret != NX_SUCCESS) {
            Debugger_log(DBG, "%lu: nx_tcp_server_socket_listen() = 0x%02x", HAL_GetTick(), ret);
            errorHandler();
        }


        for (;;) {
            Debugger_log(DBG, "%lu: SSH Server waiting for connection...", HAL_GetTick());

            // Wait for new connection
            tx_semaphore_get(&port_12_semaphore, TX_WAIT_FOREVER);


            // Allocate memory for the session object
            UCHAR *sessionObject;
            ret = tx_byte_allocate(byte_pool, reinterpret_cast<void **>(&sessionObject),
                                   sizeof(Stm32WolfSshServerSessionDynamic),
                                   TX_NO_WAIT);
            if (ret != TX_SUCCESS) {
                Debugger_log(DBG, "%lu: tx_byte_allocate() = 0x%02x", millis(), ret);
                assert_param(ret != TX_SUCCESS);
            }

            // Allocate memory for the session thread stack
            UCHAR *sessionStack;
            ret = tx_byte_allocate(byte_pool, reinterpret_cast<void **>(&sessionStack),
                                   SESSION_STACK_SIZE,
                                   TX_NO_WAIT);
            if (ret != TX_SUCCESS) {
                Debugger_log(DBG, "%lu: tx_byte_allocate() = 0x%02x", millis(), ret);
                assert_param(ret != TX_SUCCESS);
            }


            // Create new SSH server session
            session = new(sessionObject) Stm32WolfSshServerSessionDynamic(sessionStack, SESSION_STACK_SIZE,
                                                                          Stm32ThreadxThread::thread::priority(),
                                                                          "SSH session 1");

            session->setSocket(&SSH_sock);
            session->setServerContext(wolfContext);
            session->createThread();
            session->resume();

            // Wait for socket closed
            ret = nx_tcp_socket_state_wait(&SSH_sock, NX_TCP_CLOSED, NX_WAIT_FOREVER);
            if (ret != NX_SUCCESS) {
                Debugger_log(DBG, "%lu: nx_tcp_socket_state_wait() = 0x%02x", HAL_GetTick(), ret);
                errorHandler();
            }

            delete session;
            ret = tx_byte_release(sessionStack);
            if (ret != TX_SUCCESS) {
                Debugger_log(DBG, "%lu: tx_byte_allocate() = 0x%02x", millis(), ret);
                assert_param(ret != TX_SUCCESS);
            }

            ret = tx_byte_release(sessionObject);
            if (ret != TX_SUCCESS) {
                Debugger_log(DBG, "%lu: tx_byte_allocate() = 0x%02x", millis(), ret);
                assert_param(ret != TX_SUCCESS);
            }



            ret = nx_tcp_server_socket_relisten(&ipInstance_struct, SSH_PORT, &SSH_sock);
            if (ret != NX_SUCCESS) {
                Debugger_log(DBG, "%lu: nx_tcp_server_socket_relisten() = 0x%02x", HAL_GetTick(), ret);
                errorHandler();
            }
        }
    }

    static int wsUserAuth(byte authType,
                          WS_UserAuthData *authData,
                          void *ctx) {
        Debugger_log(DBG, "wsUserAuth(...)");
        return WOLFSSH_USERAUTH_SUCCESS;
    }

    constexpr static const char serverBanner[] = "wolfSSH Example Server\n";

    static void thread_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port) {
        Debugger_log(DBG, "thread_1_connect_received()");

        // Simply set the semaphore to wake up the server thread
        tx_semaphore_put(&port_12_semaphore);
    }


    static void thread_1_disconnect_received(NX_TCP_SOCKET *socket) {
        Debugger_log(DBG, "thread_1_disconnect_received()");
    }


    // wolfSSH_SetIORecv
    static int ioRecv(WOLFSSH *ssh, void *buf, word32 sz, void *pReadCtx) {
        auto *readCtx = static_cast<Stm32WolfSshServerSession *>(pReadCtx);
        if (readCtx == nullptr) return WS_CBIO_ERR_GENERAL;
        UINT ret = NX_SUCCESS;
        ULONG bytes_copied = 0;

        if (readCtx->packet == nullptr) {
            // No unfinished packet in context => read a new packet
            ret = nx_tcp_socket_receive(readCtx->socket, &readCtx->packet,
                                        readCtx->ioRecvBlock ? NX_WAIT_FOREVER : NX_NO_WAIT);
            if (ret != NX_SUCCESS) {
                if (ret == NX_NO_PACKET) return WS_CBIO_ERR_WANT_READ;
                Debugger_log(DBG, "%lu: nx_tcp_socket_receive() = 0x%02x", HAL_GetTick(), ret);
                if (ret == NX_NOT_BOUND) return WS_CBIO_ERR_CONN_CLOSE;
                if (ret == NX_WAIT_ABORTED) return WS_CBIO_ERR_WANT_READ;
                if (ret == NX_NOT_CONNECTED) return WS_CBIO_ERR_CONN_RST;
                return WS_CBIO_ERR_GENERAL;
            }

            // Get data length of packet
            ret = nx_packet_length_get(readCtx->packet, &readCtx->packet_length);
            if (ret != NX_SUCCESS) {
                Debugger_log(DBG, "%lu: nx_packet_length_get() = 0x%02x", HAL_GetTick(), ret);
                return WS_CBIO_ERR_GENERAL;
            }
        }

        // Transfer data from packet to the buffer
        ret = nx_packet_data_extract_offset(readCtx->packet, readCtx->packet_offset, buf, sz, &bytes_copied);
        if (ret != NX_SUCCESS) {
            Debugger_log(DBG, "%lu: nx_packet_data_extract_offset() = 0x%02x", HAL_GetTick(), ret);
            return WS_CBIO_ERR_GENERAL;
        }

        // Update offset, if packet is not completely copied
        if (readCtx->packet_offset + bytes_copied < readCtx->packet_length) {
            readCtx->packet_offset += bytes_copied;
            return bytes_copied;
        }

        // Packet completely copied => release packet and clear offset
        ret = nx_packet_release(readCtx->packet);
        if (ret != NX_SUCCESS) {
            Debugger_log(DBG, "%lu: nx_packet_release() = 0x%02x", HAL_GetTick(), ret);
            return WS_CBIO_ERR_GENERAL;
        }
        readCtx->packet = nullptr;
        readCtx->packet_length = 0;
        readCtx->packet_offset = 0;
        return (int) bytes_copied;
    }


    static int ioSend(WOLFSSH *ssh, void *buf, word32 sz, void *pWriteCtx) {
        auto *writeCtx = static_cast<Stm32WolfSshServerSession *>(pWriteCtx);
        //        auto *writeCtx = static_cast<thread_ctx_t *>(pWriteCtx);
        if (writeCtx == nullptr) return WS_CBIO_ERR_GENERAL;
        UINT ret = NX_SUCCESS;
        NX_PACKET *data_packet;

        ret = nx_packet_allocate(&packetPool_struct, &data_packet, NX_TCP_PACKET,
                                 writeCtx->ioSendBlock ? NX_WAIT_FOREVER : NX_NO_WAIT);
        if (ret == NX_NO_PACKET) return WS_CBIO_ERR_WANT_WRITE;
        if (ret != NX_SUCCESS) {
            Debugger_log(DBG, "%lu: nx_packet_allocate() = 0x%02x", HAL_GetTick(), ret);
            return WS_CBIO_ERR_GENERAL;
        }

        ret = nx_packet_data_append(data_packet, buf, sz, &packetPool_struct, NX_NO_WAIT);
        //        if (ret == NX_NO_PACKET) return WS_CBIO_ERR_WANT_WRITE;
        if (ret != NX_SUCCESS) {
            Debugger_log(DBG, "%lu: nx_packet_data_append() = 0x%02x", HAL_GetTick(), ret);
            return WS_CBIO_ERR_GENERAL;
        }

        // send TCP packet
        ret = nx_tcp_socket_send(writeCtx->socket, data_packet, NX_NO_WAIT);
        if (ret == NX_SUCCESS) {
            return sz;
        }
        nx_packet_release(data_packet);
        if (ret == NX_NOT_BOUND) return WS_CBIO_ERR_CONN_CLOSE;
        if (ret == NX_NOT_CONNECTED) return WS_CBIO_ERR_CONN_RST;
        if (ret == NX_WAIT_ABORTED) return WS_CBIO_ERR_WANT_WRITE;

        Debugger_log(DBG, "%lu: nx_tcp_socket_send() = 0x%02x", HAL_GetTick(), ret);
        return WS_CBIO_ERR_GENERAL;
    }


    void setBytePool(TX_BYTE_POOL *bytePool) {
        byte_pool = bytePool;
    }

private:
    WOLFSSH_CTX *wolfContext = {};
    NX_TCP_SOCKET SSH_sock = {};
    TX_BYTE_POOL *byte_pool = {};

    [[noreturn]] virtual VOID errorHandler() {
        for (;;) {
            tx_thread_sleep(1);
        }
    }
};


#endif //LIBSMART_STM32WOLFSSHSERVER_STM32WOLFSSHSERVER_HPP
