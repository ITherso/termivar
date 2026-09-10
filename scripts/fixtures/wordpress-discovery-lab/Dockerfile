FROM wordpress@sha256:49801e46d08eb27ea68ed62e205bb35b1bb2dc962251bf2292a7d374f9637cee

LABEL org.opencontainers.image.title="Termivar WordPress discovery acceptance fixture" \
      org.opencontainers.image.description="Disposable test-only WordPress metadata fixture" \
      org.opencontainers.image.licenses="GPL-2.0-or-later"

COPY themes/termivar-parent/ /usr/src/wordpress/wp-content/themes/termivar-parent/
COPY themes/termivar-child/ /usr/src/wordpress/wp-content/themes/termivar-child/
COPY plugins/termivar-metadata-lab/ /usr/src/wordpress/wp-content/plugins/termivar-metadata-lab/
COPY plugins/termivar-hidden-lab/ /usr/src/wordpress/wp-content/plugins/termivar-hidden-lab/
COPY plugins/termivar-generator-control/ /usr/src/wordpress/wp-content/plugins/termivar-generator-control/

# The base entrypoint copies this test-owned content into the fresh WordPress
# volume. Building the fixture needs no network after the pinned base is pulled.
RUN find /usr/src/wordpress/wp-content/themes/termivar-parent \
         /usr/src/wordpress/wp-content/themes/termivar-child \
         /usr/src/wordpress/wp-content/plugins/termivar-metadata-lab \
         /usr/src/wordpress/wp-content/plugins/termivar-hidden-lab \
         /usr/src/wordpress/wp-content/plugins/termivar-generator-control \
         -type d -exec chmod 0755 '{}' + \
 && find /usr/src/wordpress/wp-content/themes/termivar-parent \
         /usr/src/wordpress/wp-content/themes/termivar-child \
         /usr/src/wordpress/wp-content/plugins/termivar-metadata-lab \
         /usr/src/wordpress/wp-content/plugins/termivar-hidden-lab \
         /usr/src/wordpress/wp-content/plugins/termivar-generator-control \
         -type f -exec chmod 0644 '{}' +

# Replace the default access-log format with a bounded presence-only audit for
# credential-bearing request headers. Values are never logged. The controller
# requires every parsed access row to carry these three `-`/`1` markers.
RUN printf '%s\n' \
      'SetEnvIf Authorization ".+" termivar_authorization_present=1' \
      'SetEnvIf Cookie ".+" termivar_cookie_present=1' \
      'SetEnvIf Proxy-Authorization ".+" termivar_proxy_authorization_present=1' \
      'LogFormat "%h %l %u %t \"%r\" %>s %b tmv_auth=%{termivar_authorization_present}e tmv_cookie=%{termivar_cookie_present}e tmv_proxy_auth=%{termivar_proxy_authorization_present}e" termivar_bounded' \
      > /etc/apache2/conf-available/termivar-request-audit.conf \
 && a2enconf termivar-request-audit \
 && sed -ri 's#(CustomLog[[:space:]]+\$\{APACHE_LOG_DIR\}/access\.log)[[:space:]]+combined#\1 termivar_bounded#' /etc/apache2/sites-available/000-default.conf \
 && grep -Fq 'CustomLog ${APACHE_LOG_DIR}/access.log termivar_bounded' /etc/apache2/sites-available/000-default.conf

# The pinned base prepares the fresh volume for this identity. Port 8080 avoids
# relying on a privileged-port capability.
RUN sed -ri 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf \
 && sed -ri 's#<VirtualHost \*:80>#<VirtualHost *:8080>#' /etc/apache2/sites-available/000-default.conf \
 && grep -Fxq 'Listen 8080' /etc/apache2/ports.conf \
 && grep -Fq '<VirtualHost *:8080>' /etc/apache2/sites-available/000-default.conf \
 && ! grep -Eq '^Listen[[:space:]]+80$' /etc/apache2/ports.conf \
 && ! grep -Fq '<VirtualHost *:80>' /etc/apache2/sites-available/000-default.conf

USER www-data
