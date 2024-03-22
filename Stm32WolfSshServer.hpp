/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32WOLFSSHSERVER_HPP
#define LIBSMART_STM32WOLFSSHSERVER_HPP


#include <functional>
#include "main.hpp"
#include "tx_api.h"
#include "nx_api.h"
#include <wolfssh/ssh.h>
#include "Stm32ThreadxThread.hpp"
#include "setupNetXThread.hpp"

#define SSH_PORT                                22
#define EXAMPLE_HIGHWATER_MARK 0x3FFF8000


class Stm32WolfSshServer : public Stm32ThreadxThread::thread {
public:
    Stm32WolfSshServer(void *pstack, uint32_t stackSize, void (*func)(ULONG), ULONG param, const priority &prio,
                       const char *name) : thread(pstack, stackSize, func, param, prio, name) {}

    Stm32WolfSshServer(void *pstack, uint32_t stackSize, const priority &prio,
                       const char *name) : thread(pstack, stackSize,
                                                  &Stm32ThreadxThread::BOUNCE(Stm32WolfSshServer, mainSshServerThread),
                                                  (ULONG) this, prio, name) {}


    VOID mainSshServerThread();;

    static int wsUserAuth(byte authType,
                          WS_UserAuthData *authData,
                          void *ctx) {
        Debugger_log(DBG, "wsUserAuth(...)");
        return WOLFSSH_USERAUTH_SUCCESS;
    }

    constexpr static const char serverBanner[] = "wolfSSH Example Server\n";

    static void thread_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port) {
        Debugger_log(DBG, "thread_1_connect_received()");
    }


    static void thread_1_disconnect_received(NX_TCP_SOCKET *socket) {
        Debugger_log(DBG, "thread_1_disconnect_received()");
    }


    // wolfSSH_SetIORecv
    static int ioRecv(WOLFSSH *ssh, void *buf, word32 sz, void *pReadCtx) {
        auto *readCtx = static_cast<thread_ctx_t *>(pReadCtx);
        if (readCtx == nullptr) return WS_CBIO_ERR_GENERAL;
        UINT ret = NX_SUCCESS;
        ULONG bytes_copied = 0;

        if (readCtx->packet == nullptr) {
            // No unfinished packet in context => read a new packet
            ret = nx_tcp_socket_receive(readCtx->sock, &readCtx->packet, TX_WAIT_FOREVER);
            if (ret != NX_SUCCESS) {
                Debugger_log(DBG, "%lu: nx_tcp_socket_receive() = 0x%02x", HAL_GetTick(), ret);
                if (ret == NX_NO_PACKET) return 0;

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
        auto *writeCtx = static_cast<thread_ctx_t *>(pWriteCtx);
        if (writeCtx == nullptr) return WS_CBIO_ERR_GENERAL;
        UINT ret = NX_SUCCESS;
        NX_PACKET *data_packet;

        ret = nx_packet_allocate(&packetPool_struct, &data_packet, NX_TCP_PACKET, NX_NO_WAIT);
        if (ret != NX_SUCCESS) {
            Debugger_log(DBG, "%lu: nx_packet_allocate() = 0x%02x", HAL_GetTick(), ret);
            return WS_CBIO_ERR_GENERAL;
        }

        ret = nx_packet_data_append(data_packet, buf, sz, &packetPool_struct, NX_NO_WAIT);
        if (ret != NX_SUCCESS) {
            Debugger_log(DBG, "%lu: nx_packet_data_append() = 0x%02x", HAL_GetTick(), ret);
            return WS_CBIO_ERR_GENERAL;
        }

        // send TCP packet
        ret = nx_tcp_socket_send(writeCtx->sock, data_packet, TX_WAIT_FOREVER);
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


private:
    using SSH_state_typedef = enum {
        SSH_INIT = 0,
        SSH_SOCKET,
        SSH_BIND,
        SSH_LISTEN,
        SSH_IDLE,
        SSH_ACCEPT_SSH,
        SSH_WORKER,
        SSH_RECEIVED,
        SSH_CLOSE,
        SSH_DISABLED,
        SSH_ERROR,
        SSH_UNKNOWN
    };
    SSH_state_typedef SSH_state = SSH_INIT;
    SSH_state_typedef SSH_state_last = SSH_UNKNOWN;
    char SSH_inputstring[1024] = {0};
    uint16_t SSH_inputstring_pos = 0;
    WOLFSSH_CTX *ctx = nullptr;
    NX_TCP_SOCKET SSH_sock;
    using thread_ctx_t = struct {
        WOLFSSH *ssh;
        NX_TCP_SOCKET *sock;
        NX_PACKET *packet;
        ULONG packet_length;
        ULONG packet_offset;
        word32 id;
        char nonBlock;
    };
    thread_ctx_t *threadCtx = nullptr;
    word32 defaultHighwater = EXAMPLE_HIGHWATER_MARK;


    static int dump_stats(thread_ctx_t *ctx) {
        Debugger_log(DBG, "dump_stats(...)");
        char stats[1024];
        word32 statsSz;
        word32 txCount, rxCount, seq, peerSeq;

        wolfSSH_GetStats(ctx->ssh, &txCount, &rxCount, &seq, &peerSeq);

        WSNPRINTF(stats, sizeof(stats),
                  "Statistics for Thread #%u:\r\n"
                  "  txCount = %u\r\n  rxCount = %u\r\n"
                  "  seq = %u\r\n  peerSeq = %u\r\n",
                  ctx->id, txCount, rxCount, seq, peerSeq);
        statsSz = (word32) strlen(stats);

        fprintf(stderr, "%s", stats);
        return wolfSSH_stream_send(ctx->ssh, (byte *) stats, statsSz);
    }


};


#endif //LIBSMART_STM32WOLFSSHSERVER_HPP
