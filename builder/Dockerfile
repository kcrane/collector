FROM registry.access.redhat.com/ubi8
# FROM quay.io/centos/centos:stream9   # gcc v11 not supported until Abseil bumped to 20200923.3

ARG NPROCS=6
ENV NPROCS=$NPROCS

ARG BUILD_DIR=/install-tmp

USER root

COPY pulp.repo /etc/yum.repos.d/pulp.repo
RUN mv /etc/yum.repos.d/ubi.repo /etc/yum.repos.d/ubi.repo.disabled

RUN dnf -y update \
    && dnf -y install \
        autoconf \
        automake \
        binutils-devel \
        bison \
        ca-certificates \
        clang \
        cmake-3.18.2-9.el8 \
        cracklib-dicts \
        diffutils \
        elfutils-libelf-devel \
        file \
        flex \
        gcc \
        gcc-c++ \
        gdb \
        gettext \
        git \
        glibc-devel \
        libasan \
        libcap-ng-devel \
        libcurl-devel \
        libtool \
        libuuid-devel \
        make \
        openssh-server \
        openssl-devel \
        patchutils \
        passwd \
        pkgconfig \
        python2 \
        rsync \
        tar \
        unzip \
        valgrind \
        wget \
        which \
        bpftool \
    && dnf clean all

# Build dependencies from source
WORKDIR ${BUILD_DIR}

COPY builder builder
COPY third_party third_party

RUN "builder/install/install-dependencies.sh"

RUN rm -rf ${BUILD_DIR}

RUN echo '/usr/local/lib' > /etc/ld.so.conf.d/usrlocallib.conf && ldconfig

# Set up ssh for remote development with IDE
RUN ssh-keygen -A \
   && ( \
    echo 'LogLevel DEBUG2'; \
    echo 'PermitRootLogin yes'; \
    echo 'PasswordAuthentication yes'; \
    echo 'HostKey /etc/sshkeys/ssh_host_ed25519_key'; \
    echo 'HostKeyAlgorithms ssh-ed25519'; \
    echo 'Subsystem sftp /usr/libexec/openssh/sftp-server'; \
  ) > /etc/ssh/sshd_config_remote_development \
  && mkdir /run/sshd

# Add remote development user
RUN useradd -m remoteuser \
  && yes c0llectah | passwd remoteuser || if [[ $? -eq 141 ]]; then true; else exit $?; fi

# Create directory to copy collector source into builder container
RUN mkdir /src && chmod a+rwx /src

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config_remote_development"]
