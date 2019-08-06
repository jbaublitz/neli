FROM ubuntu

RUN apt-get update && apt-get install -y musl musl-dev musl-tools git curl make wget g++ libisl-0.18-dev
RUN git clone https://github.com/richfelker/musl-cross-make
RUN cd musl-cross-make && echo TARGET=x86_64-linux-musl > config.mak && make
RUN cd musl-cross-make && echo OUTPUT=/usr >> config.mak && make install
