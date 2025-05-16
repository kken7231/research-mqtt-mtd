FROM alpine:latest
RUN apk --no-cache add sqlite
WORKDIR /db
CMD ["sh", "-c", "sqlite3 /db/sqlite.db & tail -f /dev/null"]