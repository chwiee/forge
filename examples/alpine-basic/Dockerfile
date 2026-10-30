FROM alpine:3.20

RUN apk add curl
RUN echo "temp build data" > /tmp/build.log && mkdir -p /app/data

WORKDIR /app
COPY . .

RUN adduser -D -u 10001 app && chown -R app /app
USER app

ENV APP_ENV=production
EXPOSE 8080
CMD ["sh", "-c", "echo hello from forge && cat /app/hello.txt"]
