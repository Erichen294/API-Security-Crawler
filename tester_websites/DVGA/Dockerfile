# FROM python:3.7-alpine

# LABEL description="Damn Vulnerable GraphQL Application"
# LABEL github="https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"
# LABEL maintainers="Dolev Farhi & Connor McKinnon & Nick Aleks"

# ARG TARGET_FOLDER=/opt/dvga
# WORKDIR $TARGET_FOLDER/

# RUN apk add --update curl

# RUN adduser -D dvga
# RUN chown dvga. $TARGET_FOLDER/
# USER dvga

# RUN python -m venv venv
# RUN source venv/bin/activate
# RUN pip3 install --upgrade pip --no-warn-script-location --disable-pip-version-check

# ADD --chown=dvga:dvga core /opt/dvga/core
# ADD --chown=dvga:dvga db /opt/dvga/db
# ADD --chown=dvga:dvga static /opt/dvga/static
# ADD --chown=dvga:dvga templates /opt/dvga/templates

# COPY --chown=dvga:dvga app.py /opt/dvga
# COPY --chown=dvga:dvga config.py /opt/dvga
# COPY --chown=dvga:dvga setup.py /opt/dvga/
# COPY --chown=dvga:dvga version.py /opt/dvga/
# COPY --chown=dvga:dvga requirements.txt /opt/dvga/

# RUN pip3 install -r requirements.txt --user --no-warn-script-location
# RUN python setup.py

# EXPOSE 5013/tcp
# CMD ["python", "app.py"]


# FROM python:3.7-alpine

# LABEL description="Damn Vulnerable GraphQL Application"
# LABEL github="https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"
# LABEL maintainers="Dolev Farhi & Connor McKinnon & Nick Aleks"

# ARG TARGET_FOLDER=/opt/dvga
# WORKDIR $TARGET_FOLDER/

# # Install necessary packages for building cffi, gevent, greenlet, etc.
# RUN apk add --update --no-cache gcc libc-dev libffi-dev make python3-dev

# RUN apk add --update curl

# RUN adduser -D dvga
# RUN chown dvga. $TARGET_FOLDER/
# USER dvga

# RUN python -m venv venv
# RUN source venv/bin/activate
# RUN pip3 install --upgrade pip wheel --no-warn-script-location --disable-pip-version-check

# # Explicitly install greenlet before other requirements
# # Specify a version of greenlet that is compatible with your setup
# RUN pip3 install greenlet==0.4.17 --no-warn-script-location

# ADD --chown=dvga:dvga core /opt/dvga/core
# ADD --chown=dvga:dvga db /opt/dvga/db
# ADD --chown=dvga:dvga static /opt/dvga/static
# ADD --chown=dvga:dvga templates /opt/dvga/templates

# COPY --chown=dvga:dvga app.py /opt/dvga
# COPY --chown=dvga:dvga config.py /opt/dvga
# COPY --chown=dvga:dvga setup.py /opt/dvga/
# COPY --chown=dvga:dvga version.py /opt/dvga/
# COPY --chown=dvga:dvga requirements.txt /opt/dvga/

# # Continue with the rest of the requirements
# RUN pip3 install -r requirements.txt --no-warn-script-location
# RUN python setup.py

# EXPOSE 5013/tcp
# CMD ["venv/bin/python", "app.py"]

FROM python:3.7

LABEL description="Damn Vulnerable GraphQL Application"
LABEL github="https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"
LABEL maintainers="Dolev Farhi & Connor McKinnon & Nick Aleks"

ARG TARGET_FOLDER=/opt/dvga
WORKDIR $TARGET_FOLDER/

RUN apt-get update && apt-get install -y \
    gcc \
    libc-dev \
    libffi-dev \
    make \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Add user before copying the application files
RUN adduser --disabled-login dvga

# Copy the application files to the image
COPY --chown=dvga:dvga core /opt/dvga/core
COPY --chown=dvga:dvga db /opt/dvga/db
COPY --chown=dvga:dvga static /opt/dvga/static
COPY --chown=dvga:dvga templates /opt/dvga/templates
COPY --chown=dvga:dvga app.py /opt/dvga
COPY --chown=dvga:dvga config.py /opt/dvga
COPY --chown=dvga:dvga setup.py /opt/dvga/
COPY --chown=dvga:dvga version.py /opt/dvga/
COPY --chown=dvga:dvga requirements.txt /opt/dvga/

RUN chown dvga:dvga $TARGET_FOLDER/
USER dvga

RUN python -m venv venv
# Install pip and other requirements within the virtual environment
RUN venv/bin/pip install --upgrade pip --no-warn-script-location --disable-pip-version-check
RUN venv/bin/pip install -r /opt/dvga/requirements.txt --no-warn-script-location
RUN venv/bin/python setup.py

EXPOSE 5013/tcp
CMD ["venv/bin/python", "app.py"]
