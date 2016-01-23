# local OpenLDAP for rims-passwd-ldap

FROM ubuntu:14.04
MAINTAINER TOKI Yoshinori

ADD auth.yml auth.yml
RUN awk '/^pass:/{print "slapd","slapd/password1","password",$2}' auth.yml | debconf-set-selections
RUN awk '/^pass:/{print "slapd","slapd/password2","password",$2}' auth.yml | debconf-set-selections
RUN apt-get -y install slapd
RUN apt-get -y install ldap-utils
ADD modconf.ldif modconf.ldif
RUN service slapd start && ldapmodify -Y EXTERNAL -H ldapi:/// -f modconf.ldif && service slapd stop
CMD service rsyslog start && service slapd start && bash
