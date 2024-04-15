/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBSMART_STM32WOLFSSHSERVERSESSION_HPP
#define LIBSMART_STM32WOLFSSHSERVERSESSION_HPP

#define EXAMPLE_HIGHWATER_MARK          (0x3FFF8000)

//#include <functional>
//#include "tx_api.h"
#include "nx_api.h"
#include <wolfssh/ssh.h>
#include "Stm32ThreadxThread.hpp"
#include "Stm32ItmLogger.h"

using namespace Stm32ThreadxThread;
using namespace Stm32ThreadxThread::native;

extern Debugger *DBG;

class Stm32WolfSshServerSession {
public:
    Stm32WolfSshServerSession() {};

    [[noreturn]] virtual VOID sshServerSessionThread() {
        UINT retNetx = NX_SUCCESS;
        int retWolf = WS_SUCCESS;


        Debugger_log(DBG, "%lu: sshServerSessionThread()", HAL_GetTick());

        // Create a new ssh session object from the server context
        wolfSession = wolfSSH_new(wolfContext);
        if (wolfSession == nullptr) {
            Debugger_log(DBG, "%lu: wolfSSH_new(): Can not create wolfSSH session object", HAL_GetTick());
            errorHandler();
        }

        // Set the highwater mark (???)
        if (defaultHighwater > 0) {
            wolfSSH_SetHighwaterCtx(wolfSession, (void *) wolfContext);
            wolfSSH_SetHighwater(wolfSession, defaultHighwater);
        }

        // Register the context for the session receive callback functions
        wolfSSH_SetIOReadCtx(wolfSession, this);
        wolfSSH_SetIOWriteCtx(wolfSession, this);

        // Set the username required for the SSH connection
        retWolf = wolfSSH_SetUsername(wolfSession, "admin");
        if (retWolf != WS_SUCCESS) {
            Debugger_log(DBG, "%lu: wolfSSH_SetUsername() = 0x%02x", HAL_GetTick(), retWolf);
//                free(wolfContext);
            errorHandler();
        }

        retNetx = nx_tcp_server_socket_accept(socket, NX_WAIT_FOREVER);
        if (retNetx != NX_SUCCESS) {
            Debugger_log(DBG, "%lu: nx_tcp_server_socket_accept() = 0x%02x", HAL_GetTick(), retNetx);
            errorHandler();
        }


        retWolf = WS_SUCCESS;
        do {
//            if (retWolf != WS_SUCCESS) tx_thread_relinquish();
//            if (retWolf != WS_SUCCESS) tx_thread_sleep(1);
            tx_thread_sleep(1);
            retWolf = wolfSSH_accept(wolfSession);
        } while (retWolf == WS_WANT_READ || retWolf == WS_WANT_WRITE);
        if (retWolf != WS_SUCCESS) {
            Debugger_log(DBG, "%lu: wolfSSH_accept() = %d (%s)", HAL_GetTick(), retWolf, wolfSSH_ErrorToName(retWolf) );
            errorHandler();
        }


        word32 SSH_worker_lastChannel = 0;
        uint8_t SSH_buffer[1];

        for (;;) {
            retWolf = wolfSSH_worker(wolfSession, &SSH_worker_lastChannel);
            if (retWolf == WS_CHAN_RXD) {
                int SSH_recv_result = wolfSSH_ChannelIdRead(wolfSession, SSH_worker_lastChannel, SSH_buffer,
                                                            sizeof(SSH_buffer));
                if (SSH_recv_result < 0) {
                    Debugger_log(DBG, "%lu: wolfSSH_ChannelIdRead() = 0x%02x", HAL_GetTick(), SSH_recv_result);
                    errorHandler();
                } else if (SSH_recv_result == 1) {
                    if (SSH_inputstring_pos < sizeof(SSH_inputstring)) {
                        SSH_inputstring[SSH_inputstring_pos++] = SSH_buffer[0];
                        if (SSH_buffer[0] == 0x04) /* Ctrl-D */ closeSession();
//                    if (SSH_buffer[0] == 0x05) /* Ctrl-E */ dump_stats(wolfContext);
                        if (SSH_buffer[0] == 0x06) /* Ctrl-F */ wolfSSH_TriggerKeyExchange(wolfSession);
                        if (SSH_buffer[0] == '\r') received();
                    } else {
                        Debugger_log(DBG, "%lu: ERROR: buffer overflow", HAL_GetTick());
                        errorHandler();
                    }
                } else if (SSH_recv_result > 1) {
                    Debugger_log(DBG, "%lu: ERROR: NOT SUPPORTED", HAL_GetTick());
                    errorHandler();
                }

            } else if (retWolf == WS_SUCCESS) {
                // Success => repeat
            } else {
                Debugger_log(DBG, "%lu: wolfSSH_worker() = %d (%s)", HAL_GetTick(), retWolf, wolfSSH_ErrorToName(retWolf));
                errorHandler();
            }
        }


        errorHandler();
    }

    [[noreturn]] virtual VOID errorHandler() {
        for (;;) {
            tx_thread_sleep(1);
        }
    }


    virtual void closeSession() {
        Debugger_log(DBG, "%lu: Stm32WolfSshServerSession::closeSession()", HAL_GetTick());
        wolfSSH_stream_exit(wolfSession, 0);
        nx_tcp_socket_disconnect(socket, NX_WAIT_FOREVER);
        nx_tcp_server_socket_unaccept(socket);
//        nx_tcp_server_socket_relisten(&ipInstance_struct, SSH_PORT, threadCtx->sock);
        wolfSSH_free(wolfSession);
        wolfSession = nullptr;
    }


    virtual void received() {
        Debugger_log(DBG, "%lu: received: %s", HAL_GetTick(), SSH_inputstring);
        char message[] = "ok\r\n";
        wolfSSH_stream_send(wolfSession, reinterpret_cast<byte *>(message), strlen(message));
        SSH_inputstring_pos = 0;
        memset(SSH_inputstring, 0, sizeof(SSH_inputstring));
    }

    virtual void setServerContext(WOLFSSH_CTX *serverCtx) {
        wolfContext = serverCtx;
    }

    virtual void setSocket(NX_TCP_SOCKET *sock) {
        socket = sock;
    }


public:
    NX_TCP_SOCKET *socket;
    // Used for ioRecv
    NX_PACKET *packet{};
    ULONG packet_length{};
    ULONG packet_offset{};

protected:
    WOLFSSH_CTX *wolfContext;
    WOLFSSH *wolfSession{};


    char SSH_inputstring[1024] = {0};
    uint16_t SSH_inputstring_pos = 0;

    word32 defaultHighwater = EXAMPLE_HIGHWATER_MARK;
};


#endif //LIBSMART_STM32WOLFSSHSERVERSESSION_HPP
