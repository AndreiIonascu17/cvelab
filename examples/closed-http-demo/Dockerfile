FROM python:3.13-alpine
ARG VULNERABLE=0
ENV VULNERABLE=${VULNERABLE}
WORKDIR /app
COPY server.py /app/server.py
USER 65534
EXPOSE 8080
CMD ["python", "/app/server.py"]
