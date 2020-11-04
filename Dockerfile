FROM golang:1.13 as builder
RUN mkdir /build
WORKDIR /build
ADD *.go /build/
ADD etcd /build/
ADD kubernetes /build/
WORKDIR /build
RUN CGO_ENABLED=0 GOOS=linux go build -a -o app .

FROM alpine:3.11.3
COPY --from=builder /build/app .
RUN mkdir /etcd
RUN mkdir /kubernetes

RUN cd /etc/ && mkdir /etc/systemd/
RUN cd /etc/systemd && mkdir /etc/systemd/system/
ENTRYPOINT ["sleep"]
CMD [ "3000" ]
