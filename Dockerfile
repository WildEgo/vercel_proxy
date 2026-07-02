FROM rust:1-slim AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=build /app/target/release/vercel-proxy /vercel-proxy
EXPOSE 3000
ENTRYPOINT ["/vercel-proxy"]
