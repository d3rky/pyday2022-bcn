FROM plonkin/atheris-drf-fuzzer:latest

COPY ./requirements.txt ./requirements.txt
RUN pip3 install -r requirements.txt

ADD ./fuzz_drf_example ./app

WORKDIR /app
