#FROM python:3.13-slim

# Install dependencies for Rust
#RUN apt-get update && apt-get install -y \
#    build-essential \
#    cmake \
#    clang \
#    libclang-dev \
#    llvm-dev \
#    pkg-config \
#    libssl-dev \
#    cargo \
#    && rm -rf /var/lib/apt/lists/*

# Install Rust with rustup
#RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
#ENV PATH="/root/.cargo/bin:${PATH}"


#WORKDIR /app
#COPY . .

#RUN pip install -r requirements.txt
#RUN maturin build --release
#RUN pip install target/wheels/mfence-*.whl

#CMD ["ls", "target/wheels/mfence-0.1.1-cp313-cp313-manylinux_2_34_x86_64.whl"]

#CMD ["python", "main.py"]
#RUN pip install pytest
#CMD ["pytest"]


# Stage 1: Build
FROM python:3.13-slim AS builder

RUN apt-get update && apt-get install -y \
    build-essential cmake clang libclang-dev llvm-dev pkg-config libssl-dev curl cargo \
    && rm -rf /var/lib/apt/lists/*

# Rust + maturin
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:$PATH"

WORKDIR /app
COPY .. .

RUN pip install --upgrade pip maturin
RUN maturin build --release

# Stage 2: Final
FROM python:3.13-slim AS final

WORKDIR /app

COPY --from=builder /app/target/wheels/*.whl .
RUN pip install *.whl

# Copy other project files if needed
COPY .. .

RUN pip install -r requirements.txt

CMD ["python", "main.py", "--mode", "server", "--ip", "0.0.0.0", "--port", "443"]
