FROM ubuntu:16.04

# dependencies ***************************************************
RUN apt-get update
RUN apt-get install -y cmake gcc build-essential
RUN apt-get install -y openssh-server
RUN apt-get install -y vim
# RUN apt-get install -y python
# RUN apt-get install -y git
# RUN apt-get install -y telnet
# RUN apt-get install iproute2 gdbserver less valgrind -y

# ssh setup ******************************************************
RUN mkdir /var/run/sshd
RUN echo 'root:root' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

# ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

# add code ********************************
COPY app/ /opt/app/
COPY test-files/ /opt/tests/

# compile app *****************************
# RUN cd /opt/app && make

# expose ports ****************************
EXPOSE 2222 9999 7777 8888 6666

# run app *********************************
# use this to start ssh daemon
CMD /usr/sbin/sshd -D

# use this to run echo_server automatically
# CMD /opt/echo_server/lisod 7777 8888 lisod.log lisod.lock ./www
