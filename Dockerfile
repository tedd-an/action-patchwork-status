FROM blueztestbot/bluez-build:latest

COPY *.sh /
COPY *.py /
COPY *.ini /

ENTRYPOINT [ "/entrypoint.sh" ]
