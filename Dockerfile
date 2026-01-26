# ============================================================================
# Dockerfile - SALVIUM WALLET WASM BUILD (Consolidated)
# ============================================================================
# This is a consolidated version of the layered build:
#   Dockerfile.base-deps -> Dockerfile.base -> Dockerfile.debug
#
# Build: docker build -t salvium-wasm .
# Extract: docker cp $(docker create salvium-wasm):/workspace/build/SalviumWallet.js .
# ============================================================================

FROM emscripten/emsdk:3.1.50

LABEL maintainer="Salvium Wallet WASM Port"
LABEL description="Consolidated WASM build"

RUN apt-get update && apt-get install -y wget python3 clang autoconf automake libtool git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# ============================================================================
# LIBSODIUM 1.0.19
# ============================================================================
RUN wget -q https://download.libsodium.org/libsodium/releases/libsodium-1.0.19-stable.tar.gz \
    && tar -xzf libsodium-1.0.19-stable.tar.gz && rm libsodium-1.0.19-stable.tar.gz

RUN cd libsodium-stable \
    && chmod +x dist-build/emscripten.sh \
    && dist-build/emscripten.sh --standard \
    && mkdir -p /opt/libsodium \
    && cp -r libsodium-js*/lib /opt/libsodium/ \
    && cp -r libsodium-js*/include /opt/libsodium/

# ============================================================================
# OPENSSL 3.0.12 - WITH PTHREAD SUPPORT
# ============================================================================
RUN wget -q https://www.openssl.org/source/openssl-3.0.12.tar.gz \
    && tar -xzf openssl-3.0.12.tar.gz && rm openssl-3.0.12.tar.gz

RUN cd openssl-3.0.12 \
    && ./Configure \
        linux-generic32 \
        no-asm \
        no-shared \
        no-dso \
        no-engine \
        no-afalgeng \
        --prefix=/opt/openssl \
        CC="/emsdk/upstream/emscripten/emcc" \
        CXX="/emsdk/upstream/emscripten/em++" \
        AR="/emsdk/upstream/emscripten/emar" \
        RANLIB="/emsdk/upstream/emscripten/emranlib" \
        CFLAGS="-mbulk-memory -O2" \
    && (make build_generated || make build_generated) \
    && make -j4 libcrypto.a libssl.a \
    && make install_sw

# ============================================================================
# BOOST 1.83.0
# ============================================================================
RUN (wget -q https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.gz \
        || wget -q https://sourceforge.net/projects/boost/files/boost/1.83.0/boost_1_83_0.tar.gz/download -O boost_1_83_0.tar.gz) \
    && tar -xzf boost_1_83_0.tar.gz && rm boost_1_83_0.tar.gz

RUN cd boost_1_83_0 \
    && echo 'using clang : emscripten : em++ ;' > user-config.jam \
    && ./bootstrap.sh --with-toolset=gcc --prefix=/opt/boost \
       --with-libraries=serialization,system,filesystem,chrono,program_options,regex,date_time

RUN cd boost_1_83_0 \
    && ./b2 --user-config=user-config.jam \
        toolset=clang-emscripten \
        target-os=linux \
        threading=single \
        link=static \
        variant=release \
        --prefix=/opt/boost \
        --with-serialization --with-system --with-filesystem \
        --with-chrono --with-program_options --with-regex --with-date_time \
        -j4 install

# ============================================================================
# CLONE SALVIUM SOURCE
# ============================================================================
COPY patches/ /workspace/patches/
RUN git clone --depth 1 --recurse-submodules https://github.com/salvium/salvium.git /workspace/salvium \
    && cd /workspace/salvium \
    && check_patch() { if [ -f "$1" ]; then git apply "$1" || echo "Failed to apply $1"; else echo "Patch $1 not found"; fi; } \
    && echo "Applying v5.41.0 fix..." \
    && check_patch /workspace/patches/v5.41.0-fix-get-sources-index-oob.patch

# ============================================================================
# PATCH: Fix abstract_http_client.h
# ============================================================================
RUN echo "=== Patching abstract_http_client.h for typeinfo emission ===" \
    && sed -i 's/virtual ~abstract_http_client() {}/virtual ~abstract_http_client();/' \
       /workspace/salvium/contrib/epee/include/net/abstract_http_client.h

# ============================================================================
# COPY SOURCE FILES (needed for shadow_headers including unbound.h stub)
# ============================================================================
COPY src/ /workspace/src/

# ============================================================================
# COPY LOCAL SALVIUM-REPO FILES (modified wallet source)
# ============================================================================
COPY salvium-repo/src/wallet/node_rpc_proxy.h /workspace/salvium/src/wallet/node_rpc_proxy.h
COPY salvium-repo/src/wallet/wallet2.h /workspace/salvium/src/wallet/wallet2.h
COPY salvium-repo/src/wallet/tx_builder.h /workspace/salvium/src/wallet/tx_builder.h
COPY salvium-repo/src/common/boost_serialization_helper.h /workspace/salvium/src/common/boost_serialization_helper.h
COPY salvium-repo/src/wallet/wallet2.cpp /workspace/salvium/src/wallet/wallet2.cpp
COPY salvium-repo/src/wallet/tx_builder.cpp /workspace/salvium/src/wallet/tx_builder.cpp

# ============================================================================
# PATCH: Replace threadpool.h with shadow header (no boost::thread)
# ============================================================================
RUN echo "=== Replacing threadpool.h with shadow header ===" \
    && cp /workspace/src/shadow_headers/common/threadpool.h /workspace/salvium/src/common/threadpool.h

# ============================================================================
# ENVIRONMENT VARIABLES
# ============================================================================
ENV INCLUDE_FLAGS="-I/workspace/src/shadow_headers \
    -I/workspace/src/donna64 \
    -I/workspace/src/stubs \
    -I/workspace/salvium/src \
    -I/workspace/salvium/src/wallet \
    -I/workspace/salvium/contrib/epee/include \
    -I/workspace/salvium/external/easylogging++ \
    -I/workspace/salvium/external/rapidjson/include \
    -I/workspace/salvium/external \
    -I/workspace/salvium/external/mx25519/include \
    -I/workspace/salvium/external/supercop/include \
    -I/opt/boost/include \
    -I/opt/libsodium/include \
    -I/opt/openssl/include"

ENV DEFINE_FLAGS="-DEMSCRIPTEN=1 -DNO_HW_DEVICE=1 -DDISABLE_TLS=1 \
    -DBOOST_ASIO_DISABLE_EPOLL=1 -DBOOST_ASIO_DISABLE_EVENTFD=1 \
    -DBOOST_ASIO_DISABLE_TIMERFD=1 -DBOOST_ASIO_DISABLE_KQUEUE=1 \
    -DBOOST_ASIO_DISABLE_DEV_POLL=1 -DAUTO_INITIALIZE_EASYLOGGINGPP \
    -DELPP_NO_DEFAULT_LOG_FILE=1 -DELPP_THREAD_SAFE=1 \
    -Dprivate=public -Dprotected=public"

ENV COMPILE_FLAGS="-std=c++17 -Oz -fPIC -mbulk-memory -msimd128 -fexceptions -DNDEBUG -DBOOST_ASIO_DISABLE_THREADS"
ENV C_COMPILE_FLAGS="-Oz -fPIC -mbulk-memory -msimd128 -DNDEBUG"
ENV CRYPTO_COMPILE_FLAGS="-O3 -fPIC -mbulk-memory -msimd128 -DNDEBUG"

# ============================================================================
# PATCH: boost::mutex -> std::mutex (comprehensive)
# ============================================================================
RUN echo "=== Patching src/ and contrib/epee for WASM (no-threads) ===" \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::mutex/std::mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::recursive_mutex/std::recursive_mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::shared_mutex/std::shared_mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::unique_lock/std::unique_lock/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::lock_guard/std::lock_guard/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::condition_variable/std::condition_variable/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/mutex.hpp/mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/recursive_mutex.hpp/mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/locks.hpp/mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/lock_guard.hpp/mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/condition_variable.hpp/condition_variable/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/thread.hpp/thread/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/future.hpp/future/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread.hpp/thread/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::unique_future/std::future/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::bind/std::bind/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::thread::hardware_concurrency/std::thread::hardware_concurrency/g' \
    && find /workspace/salvium/src/wallet -name "wallet2.*" -print0 | xargs -0 sed -i 's/boost::to_string(\([^)]*\.k_image\))/epee::string_tools::pod_to_hex(\1)/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::to_string/std::to_string/g' \
    && echo "Force patching critical files to be sure" \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/src/ringct/bulletproofs_plus.cc \
    && sed -i 's/boost::lock_guard/std::lock_guard/g' /workspace/salvium/src/ringct/bulletproofs_plus.cc \
    && sed -i 's/\.is_ready()/.wait_for(std::chrono::seconds(0)) == std::future_status::ready/g' /workspace/salvium/contrib/epee/include/net/net_helper.h \
    && sed -i '/#include <boost\/lambda\/bind.hpp>/d' /workspace/salvium/contrib/epee/include/net/net_helper.h \
    && sed -i '/#include <boost\/lambda\/lambda.hpp>/d' /workspace/salvium/contrib/epee/include/net/net_helper.h \
    && sed -i 's/->async_shutdown(boost::lambda::var(ec) = boost::lambda::_1)/->async_shutdown([](const boost::system::error_code\&){})/g' /workspace/salvium/contrib/epee/include/net/net_helper.h \
    && sed -i 's/async_write(\*m_ssl_socket, boost::asio::buffer(data, sz), boost::lambda::var(ec) = boost::lambda::_1)/async_write(*m_ssl_socket, boost::asio::buffer(data, sz), [](const boost::system::error_code\&, std::size_t){})/g' /workspace/salvium/contrib/epee/include/net/net_helper.h \
    && sed -i 's/async_write(m_ssl_socket->next_layer(), boost::asio::buffer(data, sz), boost::lambda::var(ec) = boost::lambda::_1)/async_write(m_ssl_socket->next_layer(), boost::asio::buffer(data, sz), [](const boost::system::error_code\&, std::size_t){})/g' /workspace/salvium/contrib/epee/include/net/net_helper.h \
    && sed -i 's/boost::to_string/std::to_string/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl

RUN mkdir -p /workspace/build

# ============================================================================
# COMPILE EASYLOGGING++
# ============================================================================
RUN echo "=== Compiling easylogging++ ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/external/easylogging++/easylogging++.cc \
       -o /workspace/build/easylogging.o

# ============================================================================
# PATCH: mlocker.cpp for WASM compatibility
# ============================================================================
RUN echo "=== Patching mlocker.cpp/h for WASM ===" \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/contrib/epee/src/mlocker.cpp \
    && sed -i '1s/^/#include <mutex>\n/' /workspace/salvium/contrib/epee/src/mlocker.cpp \
    && sed -i 's/#if defined __GNUC__ \&\& !defined _WIN32/#if defined __GNUC__ \&\& !defined _WIN32 \&\& !defined __EMSCRIPTEN__/' /workspace/salvium/contrib/epee/src/mlocker.cpp \
    && sed -i 's/boost\/thread\/mutex.hpp/mutex/g' /workspace/salvium/contrib/epee/include/mlocker.h \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/contrib/epee/include/mlocker.h \
    && echo "=== Patching crypto.cpp for WASM ===" \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/src/crypto/crypto.cpp \
    && sed -i 's/boost::lock_guard/std::lock_guard/g' /workspace/salvium/src/crypto/crypto.cpp \
    && sed -i 's/boost\/thread\/mutex.hpp/mutex/g' /workspace/salvium/src/crypto/crypto.cpp \
    && sed -i 's/boost\/thread\/lock_guard.hpp/mutex/g' /workspace/salvium/src/crypto/crypto.cpp \
    && echo "=== Patching syncobj.h for WASM ===" \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost::recursive_mutex/std::recursive_mutex/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost::condition_variable/std::condition_variable/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost::unique_lock/std::unique_lock/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost::this_thread::sleep_for/std::this_thread::sleep_for/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost::chrono/std::chrono/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost\/thread\/mutex.hpp/mutex/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost\/thread\/recursive_mutex.hpp/mutex/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost\/thread\/condition_variable.hpp/condition_variable/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost\/thread\/locks.hpp/mutex/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i 's/boost\/thread\/thread.hpp/thread/g' /workspace/salvium/contrib/epee/include/syncobj.h \
    && sed -i '1s/^/#include <mutex>\n#include <condition_variable>\n#include <thread>\n#include <chrono>\n/' /workspace/salvium/contrib/epee/include/syncobj.h \
    && echo "=== Patching abstract_tcp_server2 for WASM ===" \
    && sed -i 's/boost::thread/std::thread/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.h \
    && sed -i 's/boost::thread/std::thread/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.h \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/boost\/thread\/thread.hpp/thread/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.h \
    && sed -i 's/boost\/thread\/thread.hpp/thread/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/const std::thread::attributes& attrs = std::thread::attributes()/int attrs = 0/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.h \
    && sed -i 's/const std::thread::attributes& attrs/int attrs/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/new boost::thread(attrs,/new std::thread(/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/attrs, boost::bind/boost::bind/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/!m_threads\[i\]->try_join_for(ms)/false/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/m_threads\[i\]->interrupt()/((void)0)/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/new boost::thread/new std::thread/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/boost::shared_ptr<boost::thread>/boost::shared_ptr<std::thread>/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.h \
    && sed -i 's/boost::shared_ptr<boost::thread>/boost::shared_ptr<std::thread>/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl \
    && sed -i 's/boost::thread::id/std::thread::id/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.h \
    && sed -i 's/boost::this_thread::get_id()/std::this_thread::get_id()/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl

RUN echo "=== Patching wallet2 for WASM ===" \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/src/wallet/wallet2.h \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/src/wallet/wallet2.cpp \
    && sed -i 's/boost::lock_guard/std::lock_guard/g' /workspace/salvium/src/wallet/wallet2.cpp \
    && sed -i 's/boost::unique_lock/std::unique_lock/g' /workspace/salvium/src/wallet/wallet2.cpp \
    && sed -i 's/boost\/thread\/mutex.hpp/mutex/g' /workspace/salvium/src/wallet/wallet2.h \
    && sed -i 's/boost\/thread\/mutex.hpp/mutex/g' /workspace/salvium/src/wallet/wallet2.cpp \
    && sed -i 's/boost\/thread\/lock_guard.hpp/mutex/g' /workspace/salvium/src/wallet/wallet2.cpp \
    && sed -i 's/boost\/thread\/condition_variable.hpp/condition_variable/g' /workspace/salvium/src/wallet/wallet2.cpp

RUN echo "=== Compiling mlocker stub ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/src/stubs/mlocker_stub.cpp \
       -o /workspace/build/mlocker.o

RUN echo "=== Patching miner for WASM ===" \
    && sed -i 's/boost::thread/std::thread/g' /workspace/salvium/src/cryptonote_basic/miner.h \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/src/cryptonote_basic/miner.h \
    && sed -i 's/boost::condition_variable/std::condition_variable/g' /workspace/salvium/src/cryptonote_basic/miner.h \
    && sed -i 's/std::thread::attributes/int/g' /workspace/salvium/src/cryptonote_basic/miner.h \
    && sed -i 's/boost::logic::tribool/int/g' /workspace/salvium/src/cryptonote_basic/miner.h \
    && sed -i 's/#include <boost\/logic\/tribool_fwd.hpp>//g' /workspace/salvium/src/cryptonote_basic/miner.h \
    && sed -i '1s/^/#include <thread>\n#include <vector>\n/' /workspace/salvium/src/cryptonote_core/blockchain.h \
    && sed -i 's/boost::thread_group/std::vector<std::thread>/g' /workspace/salvium/src/cryptonote_core/blockchain.h \
    && sed -i 's/boost::function/std::function/g' /workspace/salvium/src/cryptonote_core/blockchain.h

RUN echo "#include <cstddef>\n#include <string.h>\nextern \"C\" void *memwipe(void *src, size_t n) { volatile char *p = (volatile char *)src; while (n--) *p++ = 0; return src; }" > /workspace/build/memwipe_stub.c \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/build/memwipe_stub.c \
       -o /workspace/build/memwipe.o

RUN echo "=== Compiling epee string/utility files ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/contrib/epee/src/hex.cpp -o /workspace/build/hex.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/contrib/epee/src/wipeable_string.cpp -o /workspace/build/wipeable_string.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/contrib/epee/src/string_tools.cpp -o /workspace/build/string_tools.o

RUN echo "=== Patching src/ and contrib/epee for WASM (no-threads) ===" \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::mutex/std::mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::recursive_mutex/std::recursive_mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::shared_mutex/std::shared_mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::unique_lock/std::unique_lock/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::lock_guard/std::lock_guard/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost::condition_variable/std::condition_variable/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/mutex.hpp/mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/recursive_mutex.hpp/mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/locks.hpp/mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/lock_guard.hpp/mutex/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/condition_variable.hpp/condition_variable/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/thread.hpp/thread/g' \
    && find /workspace/salvium/src /workspace/salvium/contrib/epee -type f \( -name "*.h" -o -name "*.cpp" -o -name "*.cc" -o -name "*.inl" -o -name "*.hpp" \) -print0 | xargs -0 sed -i 's/boost\/thread\/future.hpp/future/g' \
    && echo "Force patching critical files to be sure" \
    && sed -i 's/boost::mutex/std::mutex/g' /workspace/salvium/src/ringct/bulletproofs_plus.cc \
    && sed -i 's/boost::lock_guard/std::lock_guard/g' /workspace/salvium/src/ringct/bulletproofs_plus.cc \
    && sed -i 's/cond.timed_wait(lock, boost::get_system_time() + boost::posix_time::milliseconds(\([^)]*\)))/cond.wait_for(lock, std::chrono::milliseconds(\1))/g' /workspace/salvium/contrib/epee/include/net/abstract_tcp_server2.inl

RUN echo "=== Compiling Salvium C++ source files ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/crypto.cpp -o /workspace/build/crypto.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/cryptonote_basic/account.cpp -o /workspace/build/account.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/cryptonote_basic/cryptonote_basic_impl.cpp -o /workspace/build/cryptonote_basic_impl.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/cryptonote_basic/cryptonote_format_utils.cpp -o /workspace/build/cryptonote_format_utils.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/cryptonote_basic/cryptonote_format_utils_basic.cpp -o /workspace/build/cryptonote_format_utils_basic.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/ringct/rctOps.cpp -o /workspace/build/rctOps.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/ringct/rctSigs.cpp -o /workspace/build/rctSigs.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/ringct/rctTypes.cpp -o /workspace/build/rctTypes.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/ringct/bulletproofs_plus.cc -o /workspace/build/bulletproofs_plus.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/common/base58.cpp -o /workspace/build/base58.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/src/stubs/util_stub.cpp -o /workspace/build/util.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/device/device.cpp -o /workspace/build/device.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/device/device_default.cpp -o /workspace/build/device_default.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/mnemonics/electrum-words.cpp -o /workspace/build/electrum_words.o

RUN echo "=== Compiling carrot files ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/account.cpp -o /workspace/build/carrot_account.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/account_secrets.cpp -o /workspace/build/carrot_account_secrets.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/address_utils.cpp -o /workspace/build/carrot_address_utils.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/carrot_enote_types.cpp -o /workspace/build/carrot_enote_types.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/core_types.cpp -o /workspace/build/carrot_core_types.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/destination.cpp -o /workspace/build/carrot_destination.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/enote_utils.cpp -o /workspace/build/carrot_enote_utils.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/hash_functions.cpp -o /workspace/build/carrot_hash_functions.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/lazy_amount_commitment.cpp -o /workspace/build/carrot_lazy_amount_commitment.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/output_set_finalization.cpp -o /workspace/build/carrot_output_set_finalization.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/scan.cpp -o /workspace/build/carrot_scan.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/sparc.cpp -o /workspace/build/carrot_sparc.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_impl/format_utils.cpp -o /workspace/build/carrot_impl_format_utils.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_impl/input_selection.cpp -o /workspace/build/carrot_impl_input_selection.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_impl/tx_builder_outputs.cpp -o /workspace/build/carrot_impl_tx_builder_outputs.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_impl/address_device_ram_borrowed.cpp -o /workspace/build/carrot_impl_address_device_ram_borrowed.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_impl/address_utils_compat.cpp -o /workspace/build/carrot_impl_address_utils_compat.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_impl/tx_proposal_utils.cpp -o /workspace/build/carrot_impl_tx_proposal_utils.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/carrot_core/device_ram_borrowed.cpp -o /workspace/build/carrot_device_ram_borrowed.o

RUN echo "=== Compiling wallet/multisig/misc ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/checkpoints/checkpoints.cpp -o /workspace/build/checkpoints.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/src/stubs/message_transporter_stub.cpp -o /workspace/build/message_transporter.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/src/stubs/message_store_stub.cpp -o /workspace/build/message_store.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/wallet/tx_builder.cpp -o /workspace/build/tx_builder.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/src/stubs/ringdb_stub.cpp -o /workspace/build/ringdb.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/wallet/wallet2.cpp -o /workspace/build/wallet2.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/oracle/pricing_record.cpp -o /workspace/build/pricing_record.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/multisig/multisig.cpp -o /workspace/build/multisig.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/multisig/multisig_account.cpp -o /workspace/build/multisig_account.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/multisig/multisig_account_kex_impl.cpp -o /workspace/build/multisig_account_kex_impl.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/multisig/multisig_kex_msg.cpp -o /workspace/build/multisig_kex_msg.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/multisig/multisig_tx_builder_ringct.cpp -o /workspace/build/multisig_tx_builder_ringct.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/multisig/multisig_clsag_context.cpp -o /workspace/build/multisig_clsag_context.o

RUN echo "=== Compiling epee additional ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/contrib/epee/src/portable_storage.cpp -o /workspace/build/portable_storage.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/contrib/epee/src/byte_slice.cpp -o /workspace/build/byte_slice.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/contrib/epee/src/byte_stream.cpp -o /workspace/build/byte_stream.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/contrib/epee/src/file_io_utils.cpp -o /workspace/build/file_io_utils.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/contrib/epee/src/parserse_base_utils.cpp -o /workspace/build/parserse_base_utils.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/contrib/epee/src/http_base.cpp -o /workspace/build/http_base.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/common/perf_timer.cpp -o /workspace/build/perf_timer.o \
    && echo "=== Compiling threadpool STUB (synchronous, no pthreads) ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/src/stubs/threadpool_stub.cpp -o /workspace/build/threadpool.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/common/pruning.cpp -o /workspace/build/pruning.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/cryptonote_core/cryptonote_tx_utils.cpp -o /workspace/build/cryptonote_tx_utils.o

RUN echo "=== Compiling C crypto files (ref10) ===" \
    && emcc ${CRYPTO_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/crypto-ops.c -o /workspace/build/crypto_ops.o \
    && emcc ${CRYPTO_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/crypto-ops-data.c -o /workspace/build/crypto_ops_data.o \
    && emcc ${CRYPTO_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/hash.c -o /workspace/build/hash.o \
    && emcc ${CRYPTO_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/keccak.c -o /workspace/build/keccak.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/random.c -o /workspace/build/random.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/tree-hash.c -o /workspace/build/tree_hash.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/blake256.c -o /workspace/build/blake256.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/blake2b.c -o /workspace/build/blake2b.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/groestl.c -o /workspace/build/groestl.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/jh.c -o /workspace/build/jh.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/skein.c -o /workspace/build/skein.o \
    && emcc ${CRYPTO_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/chacha.c -o /workspace/build/chacha.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/hmac-keccak.c -o /workspace/build/hmac_keccak.o \
    && emcc ${CRYPTO_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/ringct/rctCryptoOps.c -o /workspace/build/rctCryptoOps.o

RUN echo "=== Compiling misc C++ ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/crypto/generators.cpp -o /workspace/build/generators.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/ringct/bulletproofs.cc -o /workspace/build/bulletproofs.o 2>/dev/null || true \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} -c /workspace/salvium/src/ringct/multiexp.cc -o /workspace/build/multiexp.o 2>/dev/null || true

# ============================================================================
# FROM DOCKERFILE.DEBUG: Patch wallet2.cpp for asset_type_output_index
# ============================================================================
RUN echo "=== Patching wallet2.cpp for asset_type_output_index fix ===" \
    && sed -i 's/daemon_resp.outs\[i\].output_id) == td.m_global_output_index)/daemon_resp.outs[i].output_id) == (use_global_outs ? td.m_global_output_index : td.m_asset_type_output_index))/g' \
       /workspace/salvium/src/wallet/wallet2.cpp \
    && echo "wallet2.cpp patched"

# ============================================================================
# FROM DOCKERFILE.DEBUG: Patch random.c for RNG state functions
# ============================================================================
RUN echo "=== Patching random.c for RNG state functions ===" \
    && if ! grep -q "crypto_get_random_state" /workspace/salvium/src/crypto/random.c; then \
         echo "" >> /workspace/salvium/src/crypto/random.c && \
         echo "void crypto_get_random_state(void *out_state) {" >> /workspace/salvium/src/crypto/random.c && \
         echo "  memcpy(out_state, &state, sizeof(union hash_state));" >> /workspace/salvium/src/crypto/random.c && \
         echo "}" >> /workspace/salvium/src/crypto/random.c && \
         echo "" >> /workspace/salvium/src/crypto/random.c && \
         echo "void crypto_set_random_state(const void *in_state) {" >> /workspace/salvium/src/crypto/random.c && \
         echo "  memcpy(&state, in_state, sizeof(union hash_state));" >> /workspace/salvium/src/crypto/random.c && \
         echo "}" >> /workspace/salvium/src/crypto/random.c && \
         echo "Patched random.c with RNG state functions"; \
       else \
         echo "random.c already has RNG state functions"; \
       fi \
    && if ! grep -q "crypto_get_random_state" /workspace/salvium/src/crypto/random.h; then \
         echo "" >> /workspace/salvium/src/crypto/random.h && \
         echo "void crypto_get_random_state(void *out_state);" >> /workspace/salvium/src/crypto/random.h && \
         echo "void crypto_set_random_state(const void *in_state);" >> /workspace/salvium/src/crypto/random.h && \
         echo "Patched random.h with RNG state declarations"; \
       else \
         echo "random.h already has RNG state declarations"; \
       fi \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/src/crypto/random.c -o /workspace/build/random.o \
    && echo "random.c recompiled"

# ============================================================================
# FROM DOCKERFILE.DEBUG: Compile donna64
# ============================================================================
RUN echo "=== Compiling donna64 optimized crypto ===" \
    && emcc ${CRYPTO_COMPILE_FLAGS} -I/workspace/src/donna64 \
       -c /workspace/src/donna64/donna64_fe.c -o /workspace/build/donna64_fe.o \
    && emcc ${CRYPTO_COMPILE_FLAGS} -I/workspace/src/donna64 \
       -c /workspace/src/donna64/donna64_ge.c -o /workspace/build/donna64_ge.o \
    && emcc ${CRYPTO_COMPILE_FLAGS} -I/workspace/src/donna64 \
       -c /workspace/src/donna64/donna64_crypto_hook.c -o /workspace/build/donna64_crypto_hook.o \
    && em++ ${COMPILE_FLAGS} -I/workspace/src/donna64 \
       -c /workspace/src/donna64/donna64_embind.cpp -o /workspace/build/donna64_embind.o \
    && echo "donna64 compilation complete"

# ============================================================================
# FROM DOCKERFILE.DEBUG: Compile WASM bindings
# ============================================================================
RUN echo "=== Compiling WASM bindings ===" \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/src/wasm_node_rpc_proxy_impl.cpp -o /workspace/build/wasm_node_rpc_proxy_impl.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -I/workspace/src/donna64 \
       -c /workspace/src/wasm_bindings.cpp -o /workspace/build/wasm_bindings.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -I/workspace/src/donna64 \
       -c /workspace/src/wasm_bridge.cpp -o /workspace/build/wasm_bridge.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/src/stubs/http_client_stubs.cpp -o /workspace/build/http_client_stubs.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/src/stubs/cn_slow_hash_stub.c -o /workspace/build/cn_slow_hash_stub.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/src/stubs/wallet2_stubs.cpp -o /workspace/build/wallet2_stubs.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/src/stubs/miner_stub.cpp -o /workspace/build/miner_stub.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/src/missing_symbol_stubs.cpp -o /workspace/build/missing_symbol_stubs.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/src/wallet/wallet_rpc_payments.cpp -o /workspace/build/wallet_rpc_payments.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/src/rpc/rpc_payment_signature.cpp -o /workspace/build/rpc_payment_signature.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/src/wallet/wallet2.cpp -o /workspace/build/wallet2.o \
    && em++ ${COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/src/wallet/tx_builder.cpp -o /workspace/build/tx_builder.o \
    && echo "WASM bindings compiled"

# ============================================================================
# FROM DOCKERFILE.DEBUG: Compile mx25519
# ============================================================================
RUN echo "=== Compiling mx25519 ===" \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -I/workspace/salvium/external/mx25519/src \
       -c /workspace/salvium/external/mx25519/src/mx25519.c -o /workspace/build/mx25519.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -I/workspace/salvium/external/mx25519/src \
       -c /workspace/salvium/external/mx25519/src/impl.c -o /workspace/build/mx25519_impl.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -I/workspace/salvium/external/mx25519/src \
       -c /workspace/salvium/external/mx25519/src/portable/scalarmult.c -o /workspace/build/mx25519_scalarmult.o \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -I/workspace/salvium/external/mx25519/src \
       -c /workspace/salvium/external/mx25519/src/scalar.c -o /workspace/build/mx25519_scalar.o \
    && echo "mx25519 compiled"

# ============================================================================
# FROM DOCKERFILE.DEBUG: Compile aligned.c
# ============================================================================
RUN echo "=== Compiling common/aligned.c ===" \
    && emcc ${C_COMPILE_FLAGS} ${INCLUDE_FLAGS} ${DEFINE_FLAGS} \
       -c /workspace/salvium/src/common/aligned.c -o /workspace/build/aligned.o \
    && echo "aligned.c compiled"

# ============================================================================
# FROM DOCKERFILE.DEBUG: Cleanup stale objects
# ============================================================================
RUN rm -f /workspace/build/carrot_scan_unsafe.o \
          /workspace/build/scanning_tools.o \
          /workspace/build/carrot_payment_proposal.o \
    && echo "Removed stale .o files"

# ============================================================================
# FROM DOCKERFILE.DEBUG: Link final WASM output
# ============================================================================
RUN echo "=== Linking final WASM binary ===" \
    && em++ -O3 -fexceptions \
       /workspace/build/*.o \
       -L/opt/boost/lib \
       -L/opt/libsodium/lib \
       -L/opt/openssl/lib \
       -lboost_serialization \
       -lboost_system \
       -lboost_filesystem \
       -lboost_chrono \
       -lboost_program_options \
       -lboost_regex \
       -lsodium \
       -lcrypto \
       -lssl \
       --bind \
       -s WASM=1 \
       -s SHARED_MEMORY=0 \
       -s PTHREAD_POOL_SIZE=0 \
       -s ALLOW_MEMORY_GROWTH=1 \
       -s INITIAL_MEMORY=268435456 \
       -s PROXY_TO_PTHREAD=0 \
       -s MODULARIZE=1 \
       -s EXPORT_NAME="SalviumWallet" \
       -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","FS","getValue","setValue"]' \
       -s EXPORTED_FUNCTIONS='["_fast_generate_key_derivation","_fast_batch_key_derivations","_donna64_get_version","_malloc","_free"]' \
       -s ERROR_ON_UNDEFINED_SYMBOLS=0 \
       -s DISABLE_EXCEPTION_CATCHING=0 \
       -s ENVIRONMENT='web,worker,node' \
       -s ASSERTIONS=0 \
       -o /workspace/build/SalviumWallet.js \
    && echo "=== WASM build complete ==="

# Verify output
RUN ls -la /workspace/build/SalviumWallet.* \
    && echo "Build successful!"
