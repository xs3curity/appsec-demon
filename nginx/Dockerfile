FROM nginx:1.30.8-alpine@sha256:8eb04fe3b385090e9aa02961f77398ad09b6bf33ab07f6669a5bb7acce22c0d3

# The base image symlinks these logs to stdout/stderr; unlink them so nginx writes
# real files into the /var/log/nginx bind mount on the host.
RUN unlink /var/log/nginx/access.log \
 && unlink /var/log/nginx/error.log \
 && rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d/
