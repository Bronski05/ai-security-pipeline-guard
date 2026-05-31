FROM ubuntu:latest
USER root
RUN apt-get update && apt-get install -y ssh
EXPOSE 22
ENV DB_PASSWORD=supersecretpassword123