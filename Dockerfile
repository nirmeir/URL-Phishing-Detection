FROM python:3.9.13

WORKDIR /app

COPY requirements.txt ./requirements.txt

RUN pip install -r requirements.txt

EXPOSE 8501

COPY ./app.py .

COPY ./model/gbc_DGA.pkl ./model/gbc_DGA.pkl
COPY ./model/RandomForest.pkl ./model/RandomForest.pkl
COPY ./tlds-alpha-by-domain.txt ./tlds-alpha-by-domain.txt

ENTRYPOINT ["streamlit", "run"]

CMD ["app.py"]