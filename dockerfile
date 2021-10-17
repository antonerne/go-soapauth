FROM golang:1.17.0-alpine3.14

ENV GIN_MODE=release
ENV PORT=5001

WORKDIR /go/src/authserver

COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

EXPOSE ${PORT}

CMD ["authserver"]
