FROM python:3.10

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

COPY gunicorn_config.py /app/gunicorn_config.py

EXPOSE 8000

CMD ["gunicorn", "app:app", "-c", "./gunicorn_config.py"]
