FROM python:3.11
 
COPY . .
 
#ENV DB_HOST=192.168.68.125
#ENV DB_NAME=rapifuzz
#ENV DB_USER=rapifuzz
#ENV DB_PASSWORD=rapifuzz@db@12
#ENV DB_PORT=3306
ENV SECRET_KEY=o&wzhz0iut4dv0g^w2m&cegk5$!=b-bh8brg-v3lqqz!vp1%)$
#ENV LICENSE_KEY=8a4999b69f408aa6b37fce5d069cdffea5a3f96545a2ff0f2d3167c633783bb8a62e02cafeeb5a28af03
#ENV DJANGO_SUPERUSER_USERNAME=admin
#ENV DJANGO_SUPERUSER_NAME=admin
#ENV DJANGO_SUPERUSER_EMAIL=admin@rapifuzz.local
#ENV DJANGO_SUPERUSER_PASSWORD=Default1!
#ENV DJANGO_SUPERUSER_IS_ACTIVE=True
#ENV DJANGO_SUPERUSER_EMAIL_VERIFIED=True
 
RUN apt-get update -y
RUN apt-get install python3 -y 
RUN apt-get install python3-pip -y
RUN apt-get install -y default-libmysqlclient-dev 
RUN apt install default-mysql-client -y
RUN pip3 install mysqlclient 
RUN pip3 install django
RUN pip3 install wheel
 
 
RUN chmod +x be_script.sh
RUN ./be_script.sh
RUN pip3 install -r requirements.txt
 
