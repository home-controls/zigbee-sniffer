ARG BUILD_FROM
FROM ${BUILD_FROM}

# tshark decodes (and with the network key, decrypts) captures for the web page;
# tzdata lets the app read the TZ Supervisor passes, so files are named by local hour
RUN apk add --no-cache tshark tzdata

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --only-binary=:all: -r /tmp/requirements.txt

COPY app /app
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
