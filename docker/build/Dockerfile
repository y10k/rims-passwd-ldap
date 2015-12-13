# local OpenLDAP for rims-passwd-ldap

FROM ubuntu:14.04
MAINTAINER TOKI Yoshinori

RUN echo 'slapd slapd/password1 password detarame' | debconf-set-selections
RUN echo 'slapd slapd/password2 password detarame' | debconf-set-selections
RUN apt-get -y install slapd
RUN apt-get -y install ldap-utils
CMD service slapd start && bash
