FROM docker.io/crystallang/crystal:1.0.0-alpine AS builder
WORKDIR /app
COPY ./shard.yml ./shard.yml
RUN shards install
COPY ./src/ ./src/
RUN crystal build ./src/instances.cr -s -p -t

FROM alpine:latest
RUN apk add --no-cache gc pcre libgcc yaml
WORKDIR /app
RUN addgroup -g 1000 -S invidious && \
    adduser -u 1000 -S invidious -G invidious
COPY ./assets/ ./assets/
COPY ./config.yml ./config.yml
COPY --from=builder /app/instances .

EXPOSE 3000
USER invidious
CMD ["/app/instances"]
