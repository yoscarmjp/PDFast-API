FROM gcc:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake git libboost-all-dev libasio-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

RUN git clone https://github.com/CrowCpp/Crow.git

WORKDIR /usr/src/app/Crow

RUN mkdir build && cd build && \
    cmake .. -DCROW_BUILD_EXAMPLES=OFF -DCROW_BUILD_TESTS=OFF && \
    make install

WORKDIR /usr/src/app

COPY . .

RUN g++ -std=c++17 -lpthread -o app main.cpp

EXPOSE 8003

CMD ["./app"]