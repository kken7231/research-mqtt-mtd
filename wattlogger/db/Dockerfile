FROM alpine:latest
RUN apk --no-cache add sqlite
WORKDIR /db
CMD ["sh", "-c", "sqlite3 /db/sensor_data.db & tail -f /dev/null"]