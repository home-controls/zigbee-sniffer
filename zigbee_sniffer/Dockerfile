ARG BUILD_FROM
FROM ${BUILD_FROM}

# tshark decodes (and with the network key, decrypts) captures for the web page;
# tzdata lets the app read the TZ Supervisor passes, so files are named by local hour
RUN apk add --no-cache tshark tzdata

COPY requirements.lock /tmp/requirements.lock
RUN pip3 install --no-cache-dir --only-binary=:all: --require-hashes -r /tmp/requirements.lock

COPY app /app
# radio images built with this release (the release workflow fills firmware/; empty otherwise)
COPY firmware /firmware
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
