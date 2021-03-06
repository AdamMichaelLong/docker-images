FROM unocha/alpine-php-fpm-drupal7:5.6.26-0-1

MAINTAINER orakili <docker@orakili.net>

LABEL org.label-schema.schema-version="1.0" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vendor="UN-OCHA" \
      org.label-schema.version="5.6.26" \
      org.label-schema.name="php-fpm-drupal7-reliefweb" \
      org.label-schema.description="This service provides a php-fpm platform for the reliefweb.int Drupal 7 site with MuPDF and Hoedown." \
      org.label-schema.vcs-url=$VCS_URL \
      org.label-schema.vcs-ref=$VCS_REF

ENV MUPDF_VERSION=1.9a \
    PHP_HOEDOWN_VERSION=0.6.5

COPY run_fpm /

RUN mv -f /run_fpm /etc/services.d/fpm/run && \
    # Install dependencies to build MuPDF and the Hoedown php extension.
    apk add --update-cache --virtual .build-dependencies \
      autoconf \
      build-base \
      git \
      gzip \
      patch \
      php5-dev \
      tar && \
    cd /tmp && \
    # Build and install MuPDF.
    mkdir -p /tmp/mupdf /opt/mupdf/bin &&\
    curl -o mupdf-$MUPDF_VERSION-source.tar.gz http://mupdf.com/downloads/mupdf-$MUPDF_VERSION-source.tar.gz && \
    tar -zxf mupdf-$MUPDF_VERSION-source.tar.gz && \
    cd mupdf-$MUPDF_VERSION-source && \
    # Fix CVE-2016-6265 and CVE-2016-6525.
    curl -sS -g "http://git.ghostscript.com/?p=mupdf.git;a=patch;h=fa1936405b6a84e5c9bb440912c23d532772f958" | patch -p1 && \
    curl -sS -g "http://git.ghostscript.com/?p=mupdf.git;a=patch;h=39b0f07dd960f34e7e6bf230ffc3d87c41ef0f2e" | patch -p1 && \
    HAVE_X11=no make && HAVE_X11=no make prefix=/tmp/mupdf install && \
    mv /tmp/mupdf/bin/mutool /opt/mupdf/bin/mutool && \
    HAVE_X11=no make clean && \
    cd /tmp && rm -rf /tmp/mupdf* && \
    ln -s /opt/mupdf/bin/mutool /usr/bin/mudraw && \
    ln -s /opt/mupdf/bin/mutool /usr/bin/mubusy && \
    # Build and install php-ext-hoedown.
    git clone --recursive --depth=1 --branch=$PHP_HOEDOWN_VERSION https://github.com/orakili/php-ext-hoedown.git /tmp/php-ext-hoedown && \
    cd /tmp/php-ext-hoedown && \
    phpize && ./configure && make && make install && \
    cd /tmp && rm -rf /tmp/php* && \
    echo "extension=/usr/lib/php5/modules/hoedown.so" > /etc/php5/conf.d/hoedown.ini && \
    # Remove build dependencies.
    apk del .build-dependencies && \
    rm -rf /var/cache/apk/*

EXPOSE 9000

# Volumes
# - Conf: /etc/php5/ (php-fpm.conf, php.ini, conf.d)
# - Logs: /var/log/php
# - Data: /srv/www, /var/lib/php/session
