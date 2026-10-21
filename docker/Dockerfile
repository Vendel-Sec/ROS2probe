# The probe (ros2probe): the image the suite runs in, against DaVROS or a real robot.

FROM ros:jazzy-ros-base

ARG DEBIAN_FRONTEND=noninteractive
ARG USERNAME=probe

RUN apt-get update && apt-get install -y --no-install-recommends \
        ros-jazzy-sros2 \
        ros-jazzy-rmw-fastrtps-cpp \
        ros-jazzy-rmw-cyclonedds-cpp \
        ros-jazzy-rmw-zenoh-cpp \
        ros-jazzy-demo-nodes-cpp \
        ros-jazzy-demo-nodes-py \
        ros-jazzy-geometry-msgs \
        ros-jazzy-sensor-msgs \
        ros-jazzy-nav-msgs \
        ros-jazzy-tf2-msgs \
        python3-venv \
        openssl \
        tcpdump \
        tshark \
        dsniff \
        iproute2 \
        iputils-ping \
        net-tools \
        dnsutils \
        openssh-client \
        git \
        curl \
        ca-certificates \
        less \
        vim-tiny \
        sudo \
        jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /usr/local/bin/

# Ubuntu 24.04 already ships a uid 1000 account named "ubuntu". Reuse it.
RUN if id -u 1000 >/dev/null 2>&1; then \
        old="$(id -un 1000)"; \
        if [ "$old" != "${USERNAME}" ]; then \
            usermod -l "${USERNAME}" "$old" && \
            groupmod -n "${USERNAME}" "$(id -gn 1000)" && \
            usermod -d "/home/${USERNAME}" -m "${USERNAME}"; \
        fi; \
    else \
        groupadd -g 1000 "${USERNAME}" && \
        useradd -u 1000 -g 1000 -m -s /bin/bash "${USERNAME}"; \
    fi && \
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/010-${USERNAME} && \
    chmod 0440 /etc/sudoers.d/010-${USERNAME}

# tcpdump needs raw sockets for the wire backend
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump || true

# Let the probe user read captures
RUN usermod -aG wireshark "${USERNAME}" 2>/dev/null || true

# The target runs ROS as uid/gid 1500 and leaves the keystore 0750, so the
# read-only mount at /target-keystore is group-readable and nothing else.
RUN groupadd -g 1500 rostarget 2>/dev/null || true; \
    usermod -aG rostarget "${USERNAME}" 2>/dev/null || true

# ROS without a shell, so `docker compose exec probe uv run pytest` and the DDS
# worker it spawns can import rclpy: what /opt/ros/jazzy/setup.bash exports,
# with its library directories registered with the loader instead.
ENV AMENT_PREFIX_PATH=/opt/ros/jazzy \
    PATH=/opt/ros/jazzy/bin:${PATH} \
    PYTHONPATH=/opt/ros/jazzy/lib/python3.12/site-packages \
    ROS_AUTOMATIC_DISCOVERY_RANGE=SUBNET \
    ROS_PYTHON_VERSION=3 \
    ROS_VERSION=2
RUN printf '%s\n' /opt/ros/jazzy/opt/zenoh_cpp_vendor/lib \
        "/opt/ros/jazzy/lib/$(uname -m)-linux-gnu" \
        /opt/ros/jazzy/lib > /etc/ld.so.conf.d/ros-jazzy.conf && ldconfig

# ROS on every shell, and uv's tooling on PATH.
RUN printf '%s\n' \
        'source /opt/ros/jazzy/setup.bash' \
        'export PATH="$HOME/.local/bin:$PATH"' \
        'export RMW_IMPLEMENTATION=rmw_fastrtps_cpp' \
        '# The probe suite must never inherit the target'\''s security posture.' \
        'unset ROS_SECURITY_ENABLE ROS_SECURITY_STRATEGY ROS_SECURITY_KEYSTORE ROS_SECURITY_ENCLAVE_OVERRIDE' \
        > /etc/profile.d/99-probe-env.sh && \
    cat /etc/profile.d/99-probe-env.sh >> /home/${USERNAME}/.bashrc && \
    chown ${USERNAME}:${USERNAME} /home/${USERNAME}/.bashrc

# uv writes its cache and the venv outside /workspace, so the bind-mounted
# checkout never holds a venv built for the container's Python.
ENV UV_LINK_MODE=copy \
    UV_CACHE_DIR=/home/${USERNAME}/.cache/uv \
    UV_PROJECT_ENVIRONMENT=/home/${USERNAME}/.venv \
    RMW_IMPLEMENTATION=rmw_fastrtps_cpp

RUN install -d -o "${USERNAME}" -g "${USERNAME}" /workspace
USER ${USERNAME}
WORKDIR /workspace

# The venv, built at /workspace like the bind mount that later covers it, so the
# editable install resolves to the live checkout. rclpy is not on PyPI: it lives
# in the ROS distribution, hence the system site packages.
COPY --chown=${USERNAME}:${USERNAME} pyproject.toml uv.lock README.md ./
COPY --chown=${USERNAME}:${USERNAME} src ./src
RUN uv venv --system-site-packages --python /usr/bin/python3 "${UV_PROJECT_ENVIRONMENT}" \
    && uv sync --frozen \
    && "${UV_PROJECT_ENVIRONMENT}/bin/python" -c "import rclpy, pydantic, yaml, pytest, ros2probe"

CMD ["sleep", "infinity"]
