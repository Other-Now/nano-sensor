# Build stage -------------------------------------------------------------
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY tests ./tests

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    && cmake --build build -j"$(nproc)" \
    && ctest --test-dir build --output-on-failure

# Runtime stage -----------------------------------------------------------
FROM debian:bookworm-slim

# dpkg-query is what the package collector shells out to, and it is already
# present in the base image. libssl3 is the runtime half of libssl-dev.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/bin/nano-sensor /usr/local/bin/nano-sensor
COPY data /usr/local/share/nano-sensor/data

# The spool must outlive the container. Without a volume here, an agent restart
# discards everything buffered during an outage -- which defeats the one
# property the spool exists to provide.
VOLUME ["/var/lib/nano-sensor"]

# Runs as root deliberately: see the note in deploy/nano-sensor.service. Under
# Kubernetes this pairs with hostPID so /proc shows the node's processes rather
# than the container's four.
WORKDIR /var/lib/nano-sensor

ENTRYPOINT ["/usr/local/bin/nano-sensor"]
CMD ["inventory", "--pretty"]
