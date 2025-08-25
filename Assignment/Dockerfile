# Dockerfile for PointerAnalysis Framework
# 
# This container provides a complete environment for Java pointer analysis
# using the Soot static analysis toolkit.

FROM openjdk:11-jdk-slim

# Install Python 3 and basic utilities
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the entire project structure
COPY . .

# Create output directories
RUN mkdir -p results facts

# Compile the Java component
RUN javac -cp "bin/sootclasses-trunk-jar-with-dependencies.jar" bin/JarStmtCollector.java

# Set environment variables
ENV JAVA_HOME=/usr/local/openjdk-11
ENV PATH=$PATH:$JAVA_HOME/bin

# Create a non-root user for security
RUN useradd -m -u 1000 analyst && chown -R analyst:analyst /app
USER analyst

# Set the default command to show usage help
CMD ["python3", "main.py", "--help"]

# Labels for documentation
LABEL maintainer="PointerAnalysis Framework"
LABEL description="Java pointer analysis framework using Soot static analysis toolkit"
LABEL version="1.0"

# Expose volume for input JAR files
VOLUME ["/app/jars"]

# Expose volume for results
VOLUME ["/app/results"]