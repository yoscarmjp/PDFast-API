FROM gcc:latest

# DEPENDENCIES
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake git libboost-all-dev libasio-dev libhiredis-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# REDIS++
WORKDIR /usr/src
RUN git clone --branch 1.3.11 https://github.com/sewenew/redis-plus-plus.git && \
    cd redis-plus-plus && mkdir build && cd build && \
    cmake .. && make && make install
WORKDIR /usr/src/app


# CROW
RUN git clone https://github.com/CrowCpp/Crow.git
WORKDIR /usr/src/app/Crow
RUN mkdir build && cd build && \
    cmake .. -DCROW_BUILD_EXAMPLES=OFF -DCROW_BUILD_TESTS=OFF && \
    make install


# CODE
WORKDIR /usr/src/app
COPY . .

# COMPILE
RUN chmod +x /usr/src/app/compile.sh
RUN /usr/src/app/compile.sh

# PATH
RUN echo "/usr/local/lib" >> /etc/ld.so.conf.d/redis-plus-plus.conf && ldconfig

EXPOSE 8003

CMD ["./app"]