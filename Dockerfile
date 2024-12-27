FROM amazonlinux:2

# Set up working directories
RUN mkdir -p /opt/app
RUN mkdir -p /opt/app/build
RUN mkdir -p /opt/app/bin/

# Copy in the lambda source
WORKDIR /opt/app
COPY ./*.py /opt/app/
COPY requirements.txt /opt/app/requirements.txt

# Install required packages including bz2 and binutils
RUN yum update -y
RUN amazon-linux-extras enable python3.8
RUN yum install -y python3.8 python3.8-pip cpio yum-utils zip unzip less nss 

# Set python3 and pip3 to point to Python 3.8 explicitly
RUN alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
RUN alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.8 1

# Enable EPEL repository for additional packages
RUN amazon-linux-extras enable epel
RUN yum install -y epel-release

# Install python dependencies
RUN pip3 install -r requirements.txt
RUN rm -rf /root/.cache/pip

# Set library paths for ClamAV
ENV LD_LIBRARY_PATH=/opt/app/bin:/usr/lib64:/lib64:/usr/local/lib64

# Download libraries we need to run in lambda
WORKDIR /tmp
RUN yumdownloader -x \*i686 --archlist=x86_64 clamav clamav-lib clamav-update json-c pcre libprelude gnutls libtasn1 lib64nettle nettle bzip2-libs libtool-ltdl libxml2 libcurl xz-libs
RUN rpm2cpio clamav-0*.rpm | cpio -idmv
RUN rpm2cpio clamav-lib*.rpm | cpio -idmv
RUN rpm2cpio clamav-update*.rpm | cpio -idmv
RUN rpm2cpio json-c*.rpm | cpio -idmv
RUN rpm2cpio pcre*.rpm | cpio -idmv
RUN rpm2cpio gnutls* | cpio -idmv
RUN rpm2cpio nettle* | cpio -idmv
RUN rpm2cpio lib* | cpio -idmv
RUN rpm2cpio *.rpm | cpio -idmv
RUN rpm2cpio libtasn1* | cpio -idmv
RUN rpm2cpio bzip2-libs*.rpm | cpio -idmv
RUN rpm2cpio libtool-ltdl*.rpm | cpio -idmv
RUN rpm2cpio libxml2*.rpm | cpio -idmv
RUN rpm2cpio libcurl*.rpm | cpio -idmv
RUN rpm2cpio xz-libs*.rpm | cpio -idmv

# Copy over the binaries and libraries
RUN cp /tmp/usr/bin/clamscan /tmp/usr/lib64/* /opt/app/bin/

# Create the zip file
WORKDIR /opt/app
RUN zip -r9 --exclude="*test*" /opt/app/build/lambda.zip *.py *.txt bin

WORKDIR /usr/local/lib/python3.8/site-packages
RUN zip -r9 /opt/app/build/lambda.zip *

WORKDIR /opt/app
