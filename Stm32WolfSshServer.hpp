/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32WOLFSSHSERVER_HPP
#define LIBSMART_STM32WOLFSSHSERVER_HPP

#include <functional>
#include "tx_api.h"
#include "nx_api.h"
#include <wolfssh/ssh.h>
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
extern char sessionStack[SESSION_STACK_SIZE];

template<const std::size_t STACK_SIZE_BYTES>
class Stm32WolfSshServer : public Stm32ThreadxThread::static_thread<STACK_SIZE_BYTES> {
public:
    Stm32WolfSshServer(const Stm32ThreadxThread::thread::priority &prio, const char *name)
            : static_thread<STACK_SIZE_BYTES>(
            &Stm32ThreadxThread::BOUNCE(Stm32WolfSshServer<STACK_SIZE_BYTES>, mainSshServerThread),
            (ULONG) this,
            prio,
            name),
              defaultHighwater(EXAMPLE_HIGHWATER_MARK) {
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
        bool SSH_state_changed = true;
        UINT threadCount = 0;
        int SSH_accept_status = WS_FATAL_ERROR;
        int SSH_worker_status = WS_FATAL_ERROR;
        int SSH_ret = WS_FATAL_ERROR;
        word32 SSH_worker_lastChannel = 0;
        int SSH_recv_result = -1;
        uint8_t SSH_buffer[1] = {0};
        char sem_name[] = "SSH server connection available";

        Debugger_log(DBG, "Stm32WolfSshServer::mainSshServerThread()");

        ULONG available = 0, total = 0;
        CHAR *bytePool_name = nullptr;


        for (;;) {
            SSH_state_changed = (SSH_state != SSH_state_last);
            SSH_state_last = SSH_state;

            /*
            ret = tx_byte_pool_info_get(&nx_app_byte_pool, &bytePool_name, &available, &total, (TX_THREAD **)TX_NULL, (ULONG *)TX_NULL, (TX_BYTE_POOL **)TX_NULL);
            if(ret != TX_SUCCESS) {
                available = total = 0;
            }
             */


            switch (SSH_state) {
                case SSH_INIT:
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_INIT (%lu / %lu)", available, total);

                    SSH_inputstring_pos = 0;
                    memset(SSH_inputstring, 0, sizeof(SSH_inputstring));

                    wolfRet = wolfSSH_Init();
                    if (wolfRet != WS_SUCCESS) {
                        Debugger_log(DBG, "%lu: wolfSSH_Init() = 0x%02x", HAL_GetTick(), wolfRet);
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }

//                wolfSSH_SetLoggingCb(wolfSSH_LoggingCallback);
                    wolfSSH_Debugging_ON();


                    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, nullptr);
                    if (ctx == nullptr) {
                        Debugger_log(DBG, "%lu: wolfSSH_CTX_new(): Can not create wolfSSH context object",
                                     HAL_GetTick());
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }

                    wolfSSH_SetUserAuth(ctx, wsUserAuth);
//                wolfSSH_SetUserAuthResult(ctx, wsUserAuthResult);

                    wolfRet = wolfSSH_CTX_SetBanner(ctx, serverBanner);
                    if (wolfRet != WS_SUCCESS) {
                        Debugger_log(DBG, "%lu: wolfSSH_CTX_SetBanner() = 0x%02x", HAL_GetTick(), wolfRet);
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }

                    wolfRet = wolfSSH_CTX_SetWindowPacketSize(ctx, 1024 * 4, 1024);
                    if (wolfRet != WS_SUCCESS) {
                        Debugger_log(DBG, "%lu: wolfSSH_CTX_SetWindowPacketSize() = 0x%02x", HAL_GetTick(), wolfRet);
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }


//                keyLoadBuf = (byte*)WMALLOC(EXAMPLE_KEYLOAD_BUFFER_SZ, NULL, 0);
//                bufSz = EXAMPLE_KEYLOAD_BUFFER_SZ;
//                WMEMCPY(keyLoadBuf, (byte*)rsa_key_der_2048, sizeof_rsa_key_der_2048);
//                bufSz = sizeof_rsa_key_der_2048;

//                    wolfRet = wolfSSH_CTX_UsePrivateKey_buffer(ctx, rsa_key_der_2048, sizeof_rsa_key_der_2048, WOLFSSH_FORMAT_ASN1)
                    wolfRet = wolfSSH_CTX_UsePrivateKey_buffer(ctx, ecc_key_der_256, sizeof_ecc_key_der_256,
                                                               WOLFSSH_FORMAT_ASN1);
                    if (wolfRet != WS_SUCCESS) {
                        Debugger_log(DBG, "%lu: wolfSSH_CTX_UsePrivateKey_buffer() = 0x%02x", HAL_GetTick(), wolfRet);
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }


                    // Register receive and send callbacks
                    wolfSSH_SetIORecv(ctx, ioRecv);
                    wolfSSH_SetIOSend(ctx, ioSend);

                    SSH_state = SSH_SOCKET;
                    break;

                case SSH_SOCKET: {
                    char socket_name[] = "SSH socket";
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_SOCKET (%lu / %lu)", available, total);
                    ret = nx_tcp_socket_create(&ipInstance_struct, &SSH_sock, socket_name,
                                               NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                               NX_NULL, thread_1_disconnect_received);
                    if (ret != NX_SUCCESS) {
                        // No socket created
                        Debugger_log(DBG, "%lu: nx_tcp_socket_create() = 0x%02x", HAL_GetTick(), ret);
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                    }
                    SSH_state = SSH_BIND;
                    break;
                }

                case SSH_BIND:
                    SSH_state = SSH_BIND;
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_BIND (%lu / %lu)", available, total);
                    SSH_state = SSH_LISTEN;
                    break;

                case SSH_LISTEN:
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_LISTEN (%lu / %lu)", available, total);

                    tx_semaphore_create(&port_12_semaphore, sem_name, 0);

                    ret = nx_tcp_server_socket_listen(&ipInstance_struct, SSH_PORT, &SSH_sock, 5,
                                                      thread_1_connect_received);
                    if (ret != NX_SUCCESS) {
                        Debugger_log(DBG, "%lu: nx_tcp_server_socket_listen() = 0x%02x", HAL_GetTick(), ret);
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    } else {

                        // Wait for a connection
                        tx_semaphore_get(&port_12_semaphore, TX_WAIT_FOREVER);



//                        void *sessionStack = malloc(1024);

                        // Create new SSH server session
                        auto *session = new Stm32WolfSshServerSessionDynamic(sessionStack, sizeof sessionStack,
                                                                      Stm32ThreadxThread::thread::priority(),
                                                                      "SSH session 1");



                        session->setSocket(&SSH_sock);
                        session->setServerContext(ctx);
                        session->createThread();
                        session->resume();


/*
                        threadCtx = (thread_ctx_t *) malloc(sizeof(thread_ctx_t));
                        if (threadCtx == nullptr) {
                            Debugger_log(DBG, "Couldn't allocate thread context data");
                            tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                            SSH_state = SSH_ERROR;
                            break;
                        }
                        memset(threadCtx, 0, sizeof *threadCtx);
*/

/*
                        threadCtx->ssh = wolfSSH_new(ctx);
                        if (threadCtx->ssh == nullptr) {
                            free(threadCtx);
                            Debugger_log(DBG, "Couldn't allocate SSH data");
                            tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                            SSH_state = SSH_ERROR;
                            break;
                        }
*/

//                    wolfSSH_SetUserAuthCtx(ssh, &pwMapList);

/*
                        if (defaultHighwater > 0) {
                            wolfSSH_SetHighwaterCtx(threadCtx->ssh, (void *) threadCtx->ssh);
                            wolfSSH_SetHighwater(threadCtx->ssh, defaultHighwater);
                        }
*/


                        SSH_state = SSH_IDLE;
                    }
                    break;

                case SSH_IDLE:
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_IDLE (%lu / %lu)", available, total);

                    tx_thread_sleep(1);

/*                    ret = nx_tcp_server_socket_accept(&SSH_sock, NX_WAIT_FOREVER);
                    if (ret == NX_SUCCESS) {

                        wolfSSH_SetIOReadCtx(threadCtx->ssh, threadCtx);
                        wolfSSH_SetIOWriteCtx(threadCtx->ssh, threadCtx);

                        if (wolfSSH_SetUsername(threadCtx->ssh, "admin") != WS_SUCCESS) {
                            free(threadCtx);
                            Debugger_log(DBG, "ERROR: wolfSSH_SetUsername()");
                            tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                            SSH_state = SSH_ERROR;
                        }


//                    threadCtx->ssh = ssh;
                        threadCtx->sock = &SSH_sock;
                        threadCtx->id = threadCount++;
                        threadCtx->nonBlock = 0;

                        SSH_state = SSH_ACCEPT_SSH;
                    }*/
                    break;

                case SSH_ACCEPT_SSH:
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_ACCEPT_SSH (%lu / %lu)", available, total);

                    // https://www.wolfssl.com/documentation/manuals/wolfssh/chapter13.html#wolfssh_accept
//                server_worker(threadCtx);

/*
                    SSH_accept_status = wolfSSH_accept(threadCtx->ssh);
                    if ((SSH_accept_status == WS_WANT_READ) || (SSH_accept_status == WS_WANT_WRITE)) {
                        // Call wolfSSH_accept() again
                    } else if (SSH_accept_status == WS_SUCCESS) {
                        // Success
                        SSH_state = SSH_WORKER;
                        break;
                    } else {
                        Debugger_log(DBG, "wolfSSH_accept(): %s (%i)", wolfSSH_ErrorToName(SSH_accept_status),
                                     SSH_accept_status);
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }
*/

                    break;

                case SSH_WORKER:
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_WORKER (%lu / %lu)", available, total);

/*
                    SSH_worker_status = wolfSSH_worker(threadCtx->ssh, &SSH_worker_lastChannel);
                    if (SSH_worker_status == WS_CHAN_RXD) {
                        SSH_recv_result = wolfSSH_ChannelIdRead(threadCtx->ssh, SSH_worker_lastChannel, SSH_buffer,
                                                                sizeof(SSH_buffer));
                        if (SSH_recv_result < 0) {
                            Debugger_log(DBG, "wolfSSH_ChannelIdRead(): %s (%i)", wolfSSH_ErrorToName(SSH_recv_result),
                                         SSH_recv_result);
                            tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                            SSH_state = SSH_ERROR;
                            break;
                        } else if (SSH_recv_result == 1) {
                            if (SSH_inputstring_pos < sizeof(SSH_inputstring)) {
                                SSH_inputstring[SSH_inputstring_pos++] = SSH_buffer[0];
                                if (SSH_buffer[0] == 0x04) SSH_state = SSH_CLOSE; // Ctrl-D
                                if (SSH_buffer[0] == 0x05) dump_stats(threadCtx); // Ctrl-E
                                if (SSH_buffer[0] == 0x06) wolfSSH_TriggerKeyExchange(threadCtx->ssh); // Ctrl-F
                                if (SSH_buffer[0] == '\r') SSH_state = SSH_RECEIVED;
                            } else {
                                Debugger_log(DBG, "ERROR: buffer overflow");
                                SSH_state = SSH_RECEIVED;
                            }
                        } else if (SSH_recv_result > 1) {
                            Debugger_log(DBG, "ERROR: NOT SUPPORTED");
                            tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                            SSH_state = SSH_ERROR;
                            break;
                        }

                    } else if (SSH_worker_status == WS_SUCCESS) {
                        // Success => repeat
                    } else {
                        Debugger_log(DBG, "wolfSSH_worker(): %s (%i)", wolfSSH_ErrorToName(SSH_worker_status),
                                     SSH_worker_status);
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }
*/
                    break;

                case SSH_RECEIVED: {
                    Debugger_log(DBG, "received: %s", SSH_inputstring);
//                lwip_write(newsock, "ok\r\n", 4);
/*
                    char message[] = "ok\r\n";
                    wolfSSH_stream_send(threadCtx->ssh, reinterpret_cast<byte *>(message), strlen(message));
                    SSH_inputstring_pos = 0;
                    memset(SSH_inputstring, 0, sizeof(SSH_inputstring));
                    SSH_state = SSH_WORKER;
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_RECEIVED (%lu / %lu)", available, total);
                    break;
*/
                }

                case SSH_CLOSE:
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_CLOSE (%lu / %lu)", available, total);
                    wolfSSH_stream_exit(threadCtx->ssh, 0);
                    nx_tcp_socket_disconnect(threadCtx->sock, NX_WAIT_FOREVER);
                    nx_tcp_server_socket_unaccept(threadCtx->sock);
                    nx_tcp_server_socket_relisten(&ipInstance_struct, SSH_PORT, threadCtx->sock);
                    wolfSSH_free(threadCtx->ssh);
                    free(threadCtx);

//                wolfSSH_CTX_free(ctx);
//                if (wolfSSH_Cleanup() != WS_SUCCESS) {
//                    Debugger_log(DBG, "Couldn't clean up wolfSSH");
//                    osDelay(pdMS_TO_TICKS(1000));
//                    SSH_state = SSH_ERROR;
//                    break;
//                }

                    SSH_state = SSH_IDLE;

                    break;


                case SSH_ERROR:
                    if (SSH_state_changed) Debugger_log(DBG, "SSH_ERROR (%lu / %lu)", available, total);
                    break;

                default:
                    if (SSH_state_changed) Debugger_log(DBG, "SSH default");

            }


            tx_thread_sleep(1);
        }
    };

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
//        auto *readCtx = static_cast<thread_ctx_t *>(pReadCtx);
        if (readCtx == nullptr) return WS_CBIO_ERR_GENERAL;
        UINT ret = NX_SUCCESS;
        ULONG bytes_copied = 0;

        if (readCtx->packet == nullptr) {
            // No unfinished packet in context => read a new packet
            ret = nx_tcp_socket_receive(readCtx->socket, &readCtx->packet, TX_WAIT_FOREVER);
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
        auto *writeCtx = static_cast<Stm32WolfSshServerSession *>(pWriteCtx);
//        auto *writeCtx = static_cast<thread_ctx_t *>(pWriteCtx);
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
        ret = nx_tcp_socket_send(writeCtx->socket, data_packet, TX_WAIT_FOREVER);
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
