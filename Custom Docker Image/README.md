## 🐳 **DevSecOps Tools Docker Image**

### 📖 **Introduction**
This Docker image provides a comprehensive suite of open-source security tools for DevSecOps, SecOps engineers, and students. It includes popular scanners for Docker, Kubernetes, and Terraform configurations, enabling users to perform security assessments, vulnerability scanning, and compliance checks in learning and research environments. The image is optimized for security and efficiency, following best practices like non-root execution, read-only filesystem, and resource constraints.

---

### 🔒 **Security Best Practices Implemented**
1.  **Non-root user execution** to minimize privileges .
2.  **Read-only filesystem** (with exceptions for temporary directories) to prevent unintended modifications .
3.  **Resource limits** (CPU and memory) to prevent resource exhaustion .
4.  **Minimal base image** (Alpine Linux) to reduce attack surface.
5.  **Multi-stage build** to keep the final image small and secure.

---

### 🛠 **Updated Dockerfile with Security Enhancements**
```dockerfile
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
RUN wget -O /usr/local/bin/trivy https://github.com/aquasecurity/trivy/releases/latest/download/trivy_linux_64bit \
    && chmod +x /usr/local/bin/trivy

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
    # Create a non-root user for security 
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

# Switch to non-root user 
USER devsecops

# Set environment variables
ENV PATH="/usr/local/bin:${PATH}"

# Define default command
CMD ["/bin/sh"]
```

---

### ⚙ **Building the Image with Security Options**
Use the following command to build the image with security constraints:
```bash
docker build -t your-dockerhub-username/devsecops-tools:latest .
```

To run the container with enhanced security:
```bash
docker run --rm -it \
  --read-only \  # Make filesystem read-only 
  --tmpfs /tmp \  # Mount a temporary writable directory for tmp
  --user 1000 \  # Run as non-root user 
  --memory="512m" --memory-reservation="256m" \  # Set memory limits 
  --cpus="1.0" \  # Limit CPU usage 
  your-dockerhub-username/devsecops-tools:latest
```

---

### 📋 **Examples of Tool Usage**
Here are quick examples for each tool included in the image. For detailed usage, refer to the official repositories:

1.  **Trivy** (scan a Docker image for vulnerabilities):
    ```bash
    trivy image your-image:tag
    ```
    *Official repo: [https://github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy)*

2.  **Kube-Bench** (run CIS benchmark checks on a Kubernetes cluster):
    ```bash
    kube-bench run --targets=master,node
    ```
    *Official repo: [https://github.com/aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench)*

3.  **Checkov** (scan Terraform files for misconfigurations):
    ```bash
    checkov -d /path/to/terraform/code
    ```
    *Official repo: [https://github.com/bridgecrewio/checkov](https://github.com/bridgecrewio/checkov)*

4.  **KubeLinter** (lint Kubernetes YAML files):
    ```bash
    kube-linter lint /path/to/yaml/file.yaml
    ```
    *Official repo: [https://github.com/stackrox/kube-linter](https://github.com/stackrox/kube-linter)*

5.  **Snyk** (test dependencies for vulnerabilities):
    ```bash
    snyk test --all-projects
    ```
    *Official repo: [https://github.com/snyk/snyk](https://github.com/snyk/snyk)*

---

### 🚀 **Publishing to Docker Hub**
1.  Log in to Docker Hub:
    ```bash
    docker login -u your-dockerhub-username
    ```
2.  Push the image:
    ```bash
    docker push your-dockerhub-username/devsecops-tools:latest
    ```

---

### 🛠 **Alternative Building Methods Without Local Docker**
If you cannot install Docker locally, you can use the following methods to build the image:

1.  **GitHub Actions**: 
    -   Create a repository with the Dockerfile and configure a GitHub Actions workflow to build and push the image to Docker Hub. This uses GitHub's infrastructure without local setup.
    -   Example workflow file (`.github/workflows/docker-build.yml`):
        ```yaml
        name: Build and Push Docker Image
        on:
          push:
            branches: [ main ]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
            - name: Checkout code
              uses: actions/checkout@v4
            - name: Build and push
              uses: docker/build-push-action@v5
              with:
                context: .
                push: true
                tags: your-dockerhub-username/devsecops-tools:latest
                secrets: |
                  {"username": "${{ secrets.DOCKER_USERNAME }}", "password": "${{ secrets.DOCKER_PASSWORD }}"}
        ```
    -   Store your Docker Hub credentials as secrets in the repository settings.

2.  **Online Docker Build Services**:
    -   **Docker Hub Automated Builds**: Connect your GitHub repository to Docker Hub and enable automated builds. Docker Hub will build the image on push to the linked repository.
    -   **CodeFresh, Buddy**: These CI/CD platforms offer free tiers and can build Docker images from a GitHub repository.

3.  **Pre-built Binaries Extraction** (if you only need the tools without the image):
    -   Use methods like extracting binaries from existing Docker images . For example:
        ```bash
        docker create --name temp-container your-dockerhub-username/devsecops-tools:latest
        docker cp temp-container:/usr/local/bin/trivy ./trivy
        docker rm temp-container
        ```

---

### 💡 **Additional Recommendations**
-   **Version Pinning**: In the Dockerfile, pin versions of the tools to ensure stability (e.g., `wget -O /usr/local/bin/trivy https://github.com/aquasecurity/trivy/releases/download/v0.45.1/trivy_0.45.1_Linux-64bit.tar.gz`).
-   **Healthchecks**: Add a HEALTHCHECK instruction to the Dockerfile to monitor container status.
-   **Documentation**: In the README, include examples for each tool and best practices for integration into CI/CD pipelines .
