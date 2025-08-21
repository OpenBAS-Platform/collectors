# Declare the build argument
ARG CIRCLE_BRANCH

FROM python:3.13-alpine AS builder

# poetry version available on Ubuntu 24.04
RUN pip3 install poetry==2.1.3

RUN apk update && apk upgrade

ARG installdir=/collector
ADD . ${installdir}
RUN cd ${installdir} && poetry build

FROM python:3.13-alpine AS runner

ARG installdir=/collector
COPY --from=builder ${installdir} ${installdir}
RUN cd ${installdir}/dist && pip3 install --no-cache-dir "$(ls *.whl)[prod]"

RUN if [ "${CIRCLE_BRANCH}" != "main" ] ; then \
        apk add --no-cache git && \
        pip install git+https://github.com/OpenBAS-Platform/client-python@release/current && \
        echo "Forcing release/current version of client-python" ; \
    fi

# necessary for icon location
WORKDIR ${installdir}

CMD ["python3", "-m", "nvd_nist_cve.openbas_nvd_nist_cve"]
