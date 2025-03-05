FROM python:3.9-slim

WORKDIR /app

# Install Oracle Instant Client
RUN apt-get update && apt-get install -y libaio1 wget unzip \
    && wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip \
    && unzip instantclient-basiclite-linuxx64.zip \
    && rm -f instantclient-basiclite-linuxx64.zip \
    && mkdir -p /opt/oracle \
    && mv instantclient_* /opt/oracle/instantclient \
    && echo /opt/oracle/instantclient > /etc/ld.so.conf.d/oracle-instantclient.conf \
    && ldconfig \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set Oracle environment variables
ENV LD_LIBRARY_PATH=/opt/oracle/instantclient:$LD_LIBRARY_PATH
ENV PATH=/opt/oracle/instantclient:$PATH

# Copy application files
COPY gateway_router.py .
COPY hooks.py .
COPY requirements.txt .
COPY config.ini .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the server port
EXPOSE 8080

# Run the application
CMD ["python", "gateway_router.py"]