FROM alpine:3.17.2

RUN apk --no-cache add linux-pam-dev libqrencode-dev gcc libc-dev openssl-dev curl
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

ENV PATH $PATH:/root/.cargo/bin
ENV RUSTFLAGS "-C target-feature=-crt-static"

RUN mkdir /root/src
WORKDIR /root/src
ADD ./ /root/src

RUN cargo build --release && \
    strip target/release/libpam_oauth2_df.so

FROM alpine:3.17.2

RUN apk --no-cache add openssh-server openssh-server-pam sed linux-pam libqrencode libssl3 && \
  function add_sshd_config() { \
    sed -zri 's/\n'"$1"'\s+[^\n]*/\n'"$1 $2"'/; t; q1;' /etc/ssh/sshd_config || \
    sed -zri 's/\n#\s*'"$1"'\s+[^\n]*/\n'"$1 $2"'/; t; q1;' /etc/ssh/sshd_config || \
    echo "$1 $2" >> /etc/ssh/sshd_config; \
  }; \
  add_sshd_config PermitRootLogin yes && \
  add_sshd_config UsePAM yes && \
  add_sshd_config StrictModes no && \
  add_sshd_config GatewayPorts yes && \
  add_sshd_config PasswordAuthentication no && \
  add_sshd_config PermitRootLogin yes && \
  add_sshd_config ChallengeResponseAuthentication yes

COPY --from=0 /root/src/target/release/libpam_oauth2_df.so /lib/security/
ADD docker/pam_config /etc/pam.d/sshd.pam
ADD docker/run.sh /

EXPOSE 22

CMD ["/run.sh"]