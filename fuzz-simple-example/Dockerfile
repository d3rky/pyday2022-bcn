FROM plonkin/atheris-fuzzer:latest

COPY ./requirements.txt ./requirements.txt
RUN pip3 install -r requirements.txt

ADD ./fuzz_simple_example ./app

WORKDIR /app
