FROM python:3.12-slim
WORKDIR /app
COPY ics_risk ./ics_risk
COPY lvsp_eval ./lvsp_eval
COPY examples ./examples
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1000:1000
ENTRYPOINT ["python", "-m", "ics_risk"]
CMD ["serve"]
