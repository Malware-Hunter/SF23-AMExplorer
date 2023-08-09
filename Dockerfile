FROM python:3.8

ARG DEBIAN_FRONTEND=noninteractive
ARG DEBCONF_NOWARNINGS=yes

RUN apt-get update -qq
RUN apt-get install -y vim
RUN pip install --upgrade pip

WORKDIR /AMExplorer

COPY amexplorer.py utils.py scripts/run_app_in_docker.sh requirements.txt /AMExplorer/
COPY metadata /AMExplorer/metadata

RUN chmod +x run_app_in_docker.sh

RUN pip install -r requirements.txt 

CMD ["./run_app_in_docker.sh"]

