FROM python
LABEL MAINTAINER "Ayush Priya"

RUN apt-get update && apt-get install git -y \
    && git clone https://github.com/mzfr/liffy \
    && cd liffy \
    && pip install -r requirements.txt \
    && wget https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
    && chmod +x msfupdate.erb \
    && ./msfupdate.erb 

WORKDIR /liffy

ENTRYPOINT ["python", "/liffy/liffy.py"]

CMD ["--help"]
