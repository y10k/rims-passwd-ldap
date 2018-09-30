# local OpenLDAP for rims-passwd-ldap

FROM ubuntu:18.04
MAINTAINER TOKI Yoshinori

RUN apt-get update

# slapd admin
ADD auth.yml auth.yml
RUN awk '/^pass:/{print "slapd","slapd/password1","password",$2}' auth.yml | debconf-set-selections
RUN awk '/^pass:/{print "slapd","slapd/password2","password",$2}' auth.yml | debconf-set-selections

# slapd and some useful tools
RUN apt-get -y install slapd ldap-utils rsyslog

# slapd setup
ADD modconf.ldif modconf.ldif
RUN service slapd start && ldapmodify -Y EXTERNAL -H ldapi:/// -f modconf.ldif && service slapd stop

CMD service rsyslog start && service slapd start && bash
EXPOSE 389
