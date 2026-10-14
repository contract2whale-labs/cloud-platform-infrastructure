ARG BASE_IMAGE
FROM ${BASE_IMAGE}
# The pinned official Python base provides the standard library. No foreign-CPU RUN is needed.
USER 65532:65532
WORKDIR /probe
CMD ["python3", "-c", "import time; time.sleep(1200)"]
