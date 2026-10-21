# ros2probe

A pytest suite that partially automates evaluation of [ros2_attack_tree.md](DaVROS/ros2_attack_tree.md) against a live ROS 2 target. Some leaves (A.1.2, A.4.4, A.4.5) are process controls, that cannot be answered by the suite.

It runs against **[DaVROS](DaVROS/)** (Damn Vulnerable ROS) by default, a git submodule: a deliberately misconfigurable ROS 2 robot, the peer it talks to, and the segment between them.

## 1. Start the probe and the lab

```sh
git clone --recurse-submodules <this repository>
git submodule update --init DaVROS      # if the clone did not fetch it

docker compose up -d --build --wait
docker compose exec probe bash          # a shell in the probe, at /workspace
```

This builds `ros2probe`, where the suite runs, and starts DaVROS beside it: `davros-target`, the simulated robot, and `davros-peer`, its peer, on the `davrosnet` bridge. DaVROS's own `davros-attacker` comes up too, for poking at the lab by hand.

That bridge is the attacker's segment: on the network, no credentials, no account on the robot.

The host tests reach `davros-target` over ssh, exactly as they reach a real robot: DaVROS runs an `sshd` for `auditor`, its assessor account, and the probe reads the key and the pinned host key from the `target-access` volume at `/target-access`. The probe has no docker socket.

[DaVROS/docs/07-davros-topology.md](DaVROS/docs/07-davros-topology.md) diagrams it.

The checkout is bind-mounted at `/workspace`, so edits on the host are live in the probe. The venv lives in the image, at `/home/probe/.venv`, not in the checkout.

## 2. Run the suite

In the probe's shell, or from the host with `docker compose exec probe <command>`:

```sh
uv run pytest                   # every leaf
uv run pytest -m static         # reads keystore, governance, permissions, XML. Uses the local keystore copy.
uv run pytest -m dds            # joins the target's DDS graph with rclpy
uv run pytest -m host           # runs read-only commands on the target host over ssh
uv run pytest -m wire           # decodes a captured RTPS stream
uv run pytest -m net            # reaches other services on the target
```

`uv run pytest --markers` lists all possible markers. `-m leaf` selects every test tied to a tree node.

```sh
uv run pytest -k A.3.15 -v      # one leaf
uv run pytest -ra               # + the reason behind every skip. Read these
uv run pytest tests/branch_b_host    # one branch
```

## 3. Read the result

**A skip is not a pass.**

- `FAILED`: the leaf is present. The message shows the command and its output, or the file and the value.
- `ERROR`: the run is broken. A profile path does not exist, or the host or router is unreachable. Fix the profile and re-run.
- `SKIPPED ... not set`: the profile leaves that section out, so those tests do not apply.
- `SKIPPED undecided: ...`: a backend could not answer this one leaf.

Every outcome is also written to `evidence/<target>/<run>/run.log`, next to the commands that produced it.

## 4. Make the target vulnerable and re-run

The simulated target's DDS-Security layer is hardened by default. Switch posture with a preset, restart it, and go back to step 2 to watch a leaf that passed turn into a finding. From the repository root, on the host:

```sh
cp DaVROS/simulated_target/posture/presets/all-open.env DaVROS/simulated_target/posture/preset.env
docker compose up -d --force-recreate --wait target peer

rm DaVROS/simulated_target/posture/preset.env     # back to hardened
```

The presets live in [DaVROS/simulated_target/posture/presets/](DaVROS/simulated_target/posture/presets/), one per branch A weakness. `all-open` and `never-configured` move the robot to domain 0: set `ros.domain` in the profile to match. Recreate `peer` with `target`: it reads the keystore only when it starts, and the target reprovisions it.

`docker-compose.yml` names its project `davros`, like DaVROS's own compose file, so both drive the same containers and keystore volume.

The same can be done from a browser. The configurator shows every knob of `target.env` as a switch, radio buttons or a text field, starts from any preset, and writes `preset.env` with only the knobs that differ from the baseline. "Save and recreate target" also runs the `docker compose` line above.

```sh
DaVROS/configurator.py    # on the host, http://127.0.0.1:8765
```

### Run the target on Fast DDS, Cyclone DDS or Zenoh

One profile per middleware. Recreate the target, run its profile:

```sh
# Fast DDS (default)
docker compose up -d --build --force-recreate --wait target peer
docker compose exec probe uv run pytest --target targets/sim-lab.yaml

# Cyclone DDS
TARGET_RMW=rmw_cyclonedds_cpp docker compose up -d --build --force-recreate --wait target peer
docker compose exec probe uv run pytest --target targets/sim-lab-cyclone.yaml

# Zenoh
TARGET_RMW=rmw_zenoh_cpp docker compose up -d --build --force-recreate --wait target peer
docker compose exec probe uv run pytest --target targets/sim-lab-zenoh.yaml
```

Leaves that don't apply to the rmw are deselected (Zenoh has no RTPS or DDS-Security).

The target's ROS 2 release is a build argument, default `jazzy`:
```sh
TARGET_ROS_DISTRO=humble docker compose build target
```
The probe is set to `jazzy`. The cross-distro runs are documented: [DaVROS/docs/06-cross-distro-targets.md](DaVROS/docs/06-cross-distro-targets.md).

## 5. Point it at a real target

Copy [targets/template.yaml](targets/template.yaml) and follow the procedure.

The `standalone` service runs the same image on the host's network, so DDS discovery and captures see the robot's segment, and it starts nothing from DaVROS:

```sh
docker compose --profile standalone run --rm standalone uv run pytest --target targets/<robot>.yaml
```

The host backend reaches the robot over ssh (`robot.ssh`), as it does DaVROS. Mount the key and a `known_hosts` into the container, for example by adding `- ~/.ssh/acme:/home/probe/.ssh-acme:ro` to the `standalone` service's volumes.

#### What the ssh account needs

Commands run as the account in `robot.ssh.user`. A few reads need root: the ROS process's `/proc/<pid>/environ` (A.0.x), a keystore only root and ROS can enter, and `sshd -T` (B.0.1). With `ssh.sudo: true` every command runs through `sudo -n`, which needs a passwordless sudo rule. Without it those leaves skip with the reason, B.0.1 reads `sshd_config` and its `Include`s instead, and nothing is reported as a finding that the account merely could not see.

B.2.1 asks whether *the login account* can read an enclave key, so it never goes through sudo. Use an account that is not in the ROS account's group, or the answer is about that group.

The ssh port is your authorized access, so the B.0.2 scan leaves it out.

Only `robot.address` and `ros.rmw` are required. Each section you add widens the suite, leave one out and its tests skip.

To confirm a finding by hand, every leaf in [DaVROS/docs/](DaVROS/docs/) documents the manual validation. Those commands read eight variables, set from the profile's fields:

```sh
export KEYSTORE=/home/probe/acme/keystore-copy               # copies.keystore
export ENVFILE=/home/probe/acme/ros-security.env             # copies.env_file
export XMLPROFILE=/home/probe/acme/fastdds_profile.xml       # copies.profile, or cyclonedds.xml
export DOMAIN=17 IFACE=enp3s0 TARGET=10.20.0.11 ROSUSER=ros  # ros.domain, wire, net, robot
export RUN="ssh pentest@10.20.0.11"                          # robot.ssh

stat -c '%a %U' $KEYSTORE/enclaves/*/key.pem                 # A.1.4
$RUN ls -l /dev/shm                                          # B.2.6
```

The same for the lab, and the Zenoh helpers, are in [DaVROS's README](DaVROS/README.md#3-validate-a-leaf-by-hand). On a Zenoh target, `ZSESSION` is `copies.profile` and `ZROUTER` is `copies.router_config`.

## 6. Arming an intrusive test

By default the suite proves it *could* write to a topic without sending anything: it creates a writer and checks whether the robot's subscriber accepts it. 

Arming is command-line only, so no profile edit can arm a run.

```sh
uv run pytest --target targets/client.yaml                              # nothing published (normal)
uv run pytest --target targets/client.yaml --arm                        # writes, no actuation payload
uv run pytest --target targets/client.yaml --arm --allow-actuation-payload   # one message per actuation topic
```

The message is all-zero unless you set `ros.payloads` (keyed by an actuation topic; a non-actuation key is rejected at load):

```yaml
ros:
  payloads:
    /cmd_vel:
      linear: {x: 0.0, y: 0.0, z: 0.0}
```

**On real hardware:** `--arm` can move the robot. Put it on blocks, keep payloads inert, drop the flags when done.

## 7. Logs

Every backend logs its results, so a run leaves a record of commands that were run and intermediate results:

```
evidence/<target name>/<UTC timestamp>/
  run.log       one line per result
  capture.pcap  the capture the wire decode was taken from
  files/        the keystore, copied verbatim
```

## Layout

```
tests/                 one directory per branch, one module per leaf group
src/ros2probe/         the library the tests call
targets/               target profiles, one per engagement
docker/                the probe image and its entrypoint
docker-compose.yml     the probe, plus DaVROS's compose file through include
DaVROS/                submodule: the lab, its posture presets and the attack tree documentation
```
