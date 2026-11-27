FROM python:3.13.18-slim-trixie@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Pick up Debian security fixes released after the pinned base image was built.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# Remove pip once dependencies are installed: the runtime doesn't need it, and its
# vendored libraries (urllib3, msgpack, setuptools) are a recurring source of CVEs.
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
 && pip uninstall -y pip

COPY . .

# gunicorn's control server writes its socket under $HOME, so the user needs one.
RUN useradd --system --uid 10001 --create-home --home-dir /home/app app
USER 10001

EXPOSE 8000

CMD ["gunicorn", "app:app", "-c", "./gunicorn_config.py"]
