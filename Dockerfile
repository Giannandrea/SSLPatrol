FROM bitnami/minideb:buster AS builder
WORKDIR /root/
RUN cat /etc/apt/sources.list | sed -E 's/deb /deb-src /g' >> /etc/apt/sources.list && cat /etc/apt/sources.list \
	&& apt-get update && apt-get upgrade -y && apt-get install -y build-essential git zlib1g-dev sudo \
	&& git clone https://github.com/rbsec/sslscan.git && cd sslscan && apt-get build-dep -y openssl \
	&& (make static -j4 || exit 0)


FROM bitnami/minideb:buster
WORKDIR /root/
COPY --from=builder /root/sslscan/sslscan /usr/bin/
CMD ["sslscan"]



