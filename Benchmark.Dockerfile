FROM rust:1.66

WORKDIR /app
COPY . .
RUN cargo test
RUN cargo install cargo-criterion

ENTRYPOINT [ "cargo", "criterion", "--features", "comparator_build" ]
