FROM python:3.9-slim-buster

RUN apt-get -y update
RUN pip3 install --upgrade pip

COPY . /opt/harvester
WORKDIR /opt/harvester

RUN pip3 install -r requirements.txt
RUN touch /opt/harvester/harvester.log
RUN ln -sf /dev/stdout /opt/harvester/harvester.log \
    && ln -sf /dev/stderr /opt/harvester/harvester.log

# VOLUME [ "./config" ]

#ENV

WORKDIR /opt/napominator
CMD ["..."]