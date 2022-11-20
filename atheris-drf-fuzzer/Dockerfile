FROM plonkin/atheris-fuzzer:latest

RUN apt-get update && apt-get install -y wget python3-psycopg2

ENV DOCKERIZE_VERSION v0.6.1
RUN wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && tar -C /usr/local/bin -xzvf dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && rm dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz

RUN pip3 install Django==4.1.* djangorestframework==3.14.* coverage==6.5.* pytest==7.1.* pytest-django==4.5.* pytest-cov==4.0.* psycopg2-binary uritemplate==4.1.1 PyYAML==6.0

CMD ["python3"]
