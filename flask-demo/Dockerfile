#FROM python:3.8.3-alpine3.11
FROM python:3.8.3
WORKDIR /app
COPY ./app/ /app
#RUN pip install flask flask_pyoidc flask-cors
#RUN pip install flask flask_oidc flask-cors
RUN pip install flask flask-cors pyjwt[crypto] pycrypto
CMD ["python","main.py"]
