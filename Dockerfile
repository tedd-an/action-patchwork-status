FROM blueztestbot/bluez-build:latest

COPY requirements.txt /

RUN pip3 install --no-cache-dir -r /requirements.txt

COPY *.sh /
COPY *.py /
COPY *.ini /

CMD [ "/entrypoint.sh" ]
