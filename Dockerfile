FROM python:3.8-alpine
LABEL maintainer="Axelle Apvrille"
LABEL version="0.7"
 
ENV APP_HOME /androscope
ENV DJANGO_SECRET_KEY "default-dockerfile-key-to-be-overridden"
ENV VIRUSTOTAL_APIKEY "default-virustotal-key-to-be-overriden"
ENV DJANGO_WEBSITE_FQDN "default-django-website-fqdn-to-be-overriden"

#pip is installed as root
#ENV PYTHONDONTWRITEBYTECODE 1
# print messages to docker log immediately:
ENV PYTHONUNBUFFERED 1
RUN pip install --upgrade pip
# required to install pillow which is needed by django-simple-captcha
RUN apk add --no-cache jpeg-dev zlib-dev freetype-dev
RUN apk add --no-cache --virtual .build-deps build-base linux-headers

# create user environment
RUN mkdir -p $APP_HOME
WORKDIR $APP_HOME
ENV USERNAME alice
RUN adduser -D $USERNAME

# install Django app, and transfer rights to the user
COPY . $APP_HOME
RUN chown -R $USERNAME $APP_HOME
USER $USERNAME
ENV PATH $PATH:/home/$USERNAME/.local/bin
RUN export PATH=$PATH
RUN pip install --no-cache-dir --user -r requirements.txt

# run it
EXPOSE 8000
RUN python manage.py collectstatic --no-input
CMD [ "gunicorn", "--bind=0.0.0.0:8000", "androscope.wsgi" ]

