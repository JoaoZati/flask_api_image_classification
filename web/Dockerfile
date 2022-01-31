FROM python:3

RUN pip install pipenv

WORKDIR /web

COPY Pipfile .

COPY Pipfile.lock .

RUN pipenv install --system --deploy

COPY . .

CMD ["python", "app.py"]