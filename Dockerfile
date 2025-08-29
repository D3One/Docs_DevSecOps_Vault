# Stage 1: Builder stage to compile and install tools
FROM alpine:latest AS builder 

# Install dependencies needed for building tools 
RUN apk add --no-cache \
    git \
    go \
    python3 \
    nodejs \
    npm \
    openssl \
    curl \
    wget \
    make \
    gcc \
    libc-dev \
    # Clean up cache to reduce image size
    && rm -rf /var/cache/apk/*

# Install Trivy (vulnerability scanner for containers)
# RUN wget -O /usr/local/bin/trivy https://github.com/aquasecurity/trivy/releases/latest/download/trivy_linux_64bit \
#    && chmod +x /usr/local/bin/trivy

# Install Kube-Bench (Kubernetes security benchmark tool)
RUN git clone https://github.com/aquasecurity/kube-bench.git /opt/kube-bench \
    && cd /opt/kube-bench && go build -o /usr/local/bin/kube-bench

# Install Checkov (Terraform and cloud infrastructure security scanner)
RUN pip3 install --no-cache-dir checkov

# Install KubeLinter (static analysis tool for Kubernetes YAML files)
RUN go install github.com/stackrox/kube-linter/cmd/kube-linter@latest \
    && mv /root/go/bin/kube-linter /usr/local/bin/

# Install Snyk CLI (vulnerability scanner for dependencies and infrastructure)
RUN npm install -g snyk

# Stage 2: Final image with only necessary runtime components
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    python3 \
    nodejs \
    npm \
    openssl \
    # Create a non-root user for security :cite[6]:cite[9]
    && addgroup -S securitytools && adduser -S devsecops -G securitytools -u 1000 \
    # Clean up cache
    && rm -rf /var/cache/apk/*

# Copy installed tools from the builder stage
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/
COPY --from=builder /usr/local/bin/kube-bench /usr/local/bin/
COPY --from=builder /usr/local/bin/kube-linter /usr/local/bin/
COPY --from=builder /usr/local/bin/checkov /usr/local/bin/
COPY --from=builder /usr/bin/snyk /usr/local/bin/

# Set the working directory to a writable path for the non-root user
WORKDIR /home/devsecops

# Switch to non-root user :cite[6]:cite[9]
USER devsecops

# Set environment variables
ENV PATH="/usr/local/bin:${PATH}"

# Define default command
CMD ["/bin/sh"] 
