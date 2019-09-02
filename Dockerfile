FROM python
LABEL MAINTAINER "Mehtab Zafar"

RUN apt-get update && apt-get install git -y \
    && git clone https://github.com/mzfr/liffy \
    && cd liffy \
    && pip install -r requirements.txt \

WORKDIR /liffy

ENTRYPOINT ["python", "/liffy/liffy.py"]

CMD ["--help"]
