# ---------- BUILD STAGE ----------
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /app


COPY go.mod ./
RUN go mod download


COPY . .


RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o truora ./program

# ---------- RUNTIME STAGE ----------
FROM gcr.io/distroless/base-debian12

WORKDIR /app


COPY --from=builder /app/truora /app/truora

USER nonroot:nonroot

ENTRYPOINT ["/app/truora"]
