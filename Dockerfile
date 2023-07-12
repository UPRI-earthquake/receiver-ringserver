# Basic Dockerfile to run ringserver in a container
# 
# Build container using this command:
#     docker build -t ringserver:latest .
#
# Run container, using host networking (may not work on non-Linux):
#     docker run --network="host" --rm -it ringserver
#
# Run container, using bridge networking (likely impossible to submit data):
#     docker run --network="bridge" -p 18000:18000 --rm -it ringserver


# Build ringserver in a separate container,
# so resulting container does not include compiler tools
FROM centos:7 as buildenv
# Install compiler
RUN yum install -y gcc make
# Install curl build dependencies
RUN yum install -y autoconf libtool
# Install curl runtime dependencies
RUN yum install -y openssl-devel zlib-devel

# Build executable
COPY . /build
RUN cd /build && CFLAGS="-O2" make

# Build ringserver container
FROM centos:7
# Install updates
RUN yum upgrade -y
# Create dir for all files
RUN mkdir /app
# Copy executable and default config from build image
COPY --from=buildenv /build/ringserver /app/ringserver
COPY --from=buildenv /build/doc/ring.conf /app/ring.conf
# Run as non-root user
RUN adduser ringuser && \
    mkdir /app/ring && \
    mkdir /app/auth && \
    chown -R ringuser /app
WORKDIR /app
USER ringuser

# Expose default SeedLink and DataLink ports
EXPOSE 18000
EXPOSE 16000

# Default command is "ringserver"
ENTRYPOINT [ "./ringserver" ]

# Default arguments
CMD [ "./ring.conf" ]

LABEL org.opencontainers.image.source="https://github.com/UPRI-earthquake/receiver-ringserver"
LABEL org.opencontainers.image.description="Base docker image for EarthquakeHub RingServer"
LABEL org.opencontainers.image.authors="earthquake@science.upd.edu.ph"
