FROM ubuntu

ENV LD_LIBRARY_PATH=/usr/x86_64-linux-musl/lib/
RUN apt-get update && apt-get install -y musl musl-dev musl-tools git curl make wget g++ libisl-0.18-dev
RUN git clone https://github.com/richfelker/musl-cross-make
RUN curl -o rustup.sh --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs
RUN sh rustup.sh -y --default-host=x86_64-unknown-linux-musl --default-toolchain=stable
RUN rustup install nightly-x86_64-unknown-linux-musl
RUN cd musl-cross-make && echo TARGET=x86_64-linux-musl > config.mak && make
RUN cd musl-cross-make && echo OUTPUT=/usr >> config.mak && make install
RUN git clone https://github.com/jbaublitz/neli
