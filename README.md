# Federated DRL Kubernetes Autoscaler

A research proof-of-concept exploring **federated deep reinforcement learning for
Kubernetes autoscaling**. Each logical Kubernetes client trains a local PPO agent
that decides pod replica scaling from live Prometheus metrics; a central server
aggregates the policy weights with FedAvg — no raw workload data ever leaves a
client. Runs entirely on local Minikube (CPU only, no cloud, no GPU).

> Runs entirely on local Minikube — CPU only, no cloud, no GPU. Three parts build on each
> other: the monitored workload service, the PPO autoscaling agent, and the federated
> aggregation layer.

## Architecture

```
 Locust (steady/burst)  ──HTTP──▶  cpu-workload service  ──/metrics──▶  Prometheus
        (host)                     (Deployment in fed-drl)              (monitoring ns)
                                          ▲                                   │
                                   kubectl scale                       validate_metrics.py
```

The `cpu-workload` service exposes four signals on `/metrics` — the RL state the
agent consumes:

| Signal        | Prometheus source                       |
|---------------|-----------------------------------------|
| cpu           | `process_cpu_seconds_total`             |
| memory        | `process_resident_memory_bytes`         |
| request_rate  | `http_requests_total`                   |
| latency       | `http_request_duration_seconds`         |

## Prerequisites

- Docker (running), Minikube, kubectl
- Python 3.11 with the project dependencies:
  ```bash
  conda create -y -n raza_project python=3.11
  conda run -n raza_project pip install -r requirements.txt
  ```

## Quick start

```bash
./setup.sh          # start Minikube, build the image, deploy app + Prometheus
```

Then verify the four setup acceptance checks:

```bash
# 1) App runs in Minikube
kubectl get pods -n fed-drl

# 2) Manual scaling works
kubectl scale deployment cpu-workload -n fed-drl --replicas=3
kubectl get pods -n fed-drl        # 3 pods; scale back with --replicas=1

# 3) Drive load (either profile), via a port-forward
kubectl port-forward svc/cpu-workload -n fed-drl 8000:80 &
locust -f load_testing/locustfile.py --profile steady --host http://localhost:8000 --headless
#                                     --profile burst  ... for the burst profile

# 4) Prometheus returns all four signals (run while/just after load is driven)
kubectl port-forward svc/prometheus -n monitoring 9090:9090 &
python scripts/validate_metrics.py --prometheus-url http://localhost:9090
```

Prometheus UI/API: port-forward as above and open `http://localhost:9090`. The
NodePort `http://$(minikube ip):30090` also works, but on macOS with the Docker
driver that IP is slow/unreliable — prefer the port-forward.

## PPO autoscaling agent

A Stable-Baselines3 **PPO** agent reads the four signals and decides scale down / hold /
scale up. It is trained in two stages:

```
 Stage A: rl_agent/  train PPO in a workload simulator (fast, no pods)
 Stage B: autoscaler/  run that policy live — Prometheus → state → PPO → scale pods
```

```bash
# Stage A — train and evaluate in the simulator (no cluster needed)
conda run -n raza_project python -m rl_agent.train --stage sim
conda run -n raza_project python -m rl_agent.evaluate

# Stage B — live autoscaling (cluster up + port-forwards first)
# 1) drive load so the agent has something to react to. The profile's stages
#    decide how long it runs (steady = 5 min, burst = ~6.5 min); add --run-time
#    to stop after a fixed duration instead:
conda run -n raza_project locust -f load_testing/locustfile.py \
  --profile steady --host http://localhost:8000 --headless --run-time 300s &

# 2) run the agent against the live cluster
conda run -n raza_project python -m autoscaler.controller --dry-run --steps 8   # decide only
conda run -n raza_project python -m autoscaler.controller --steps 8             # actually scale
```

## Federated learning

Instead of one agent, three logical clients each train their **own** PPO on their **own**
workload — **A** = steady, **B** = burst, **C** = periodic. A central **FastAPI** server
collects only the clients' **model weights** (never their raw metrics or workload data),
averages them with **FedAvg** (weighted by how much each client trained), and hands back a
single **global model**. This is the privacy promise of federated learning: clients learn a
shared scaling policy without exposing their private traffic.

```
        Client A (steady)  ─┐
        Client B (burst)   ─┼─▶  weights only  ─▶  FastAPI server
        Client C (periodic)─┘   (+ transition count)   │  FedAvg (weighted)
                ▲                                       │
                └──────────  global model  ◀───────────┘
```

Weights ride the wire as compressed PyTorch `state_dict`s (gzip + base64 inside JSON);
rounds are **synchronous** (the server waits for all three clients before aggregating);
a simple shared token guards every endpoint (HTTPS is future work for this local PoC).

```bash
# Start the aggregation server
conda run -n raza_project uvicorn federated.server:app --port 8080

# Run a client (repeat for --client-id A / B / C)
conda run -n raza_project python -m federated.client --client-id A --server http://localhost:8080

# Or run the whole thing end-to-end — server + 3 clients, N synchronous rounds
conda run -n raza_project python -m experiments.federated_ppo.run_round
```

The end-to-end run writes `results/federated_ppo/<seed>/round_log.csv` (per-round client
submissions + global model version) and saves the final global model. All federated tunables
— client roster, rounds, per-client timesteps, token, seed — live in `federated/config.yaml`.

## Configuration

All tunables live in config files — no magic numbers in code:

- `application/config.yaml` — service port, `/work` CPU budget, latency buckets, SLA.
- `load_testing/workload_profiles/{steady,burst}.yaml` — user schedule, think time.
- `rl_agent/config.yaml` — RL state/reward/PPO settings and the Stage-B autoscaler config.

Environment variables override the app config (e.g. `WORK_MAX_MS`, `APP_PORT`).

## Development

```bash
conda run -n raza_project pytest -q          # unit tests
conda run -n raza_project ruff check .       # lint
conda run -n raza_project ruff format .      # format
```

## Repository layout

```
application/   FastAPI cpu-workload service + Dockerfile
kubernetes/    namespaces, deployment, service, prometheus/
rl_agent/      PPO simulator, reward, training, evaluation (Stage A)
autoscaler/    live controller — Prometheus reader, state builder, K8s scaler (Stage B)
federated/     FastAPI aggregation server, client, FedAvg, weight serialization
experiments/   federated_ppo/ end-to-end round orchestrator
load_testing/  locustfile + steady/burst workload profiles
scripts/       validate_metrics.py (Prometheus signal check)
tests/         pytest suite
setup.sh       one-command local bring-up
```

## How the agent decides to scale

The agent doesn't use fixed rules like "if CPU > 80% add a pod". It **learns** a policy by
chasing a reward. Every step it sees the five normalized signals
`[cpu, memory, request_rate, latency, replica_count]` and picks one move — scale down, hold,
or scale up — then gets a score:

```
reward = -(w1·latency + w2·replicas + w3·sla_violation + w4·scaling_freq)
```

Everything is a penalty, so the best score is 0. In plain terms the agent is rewarded for
**keeping latency under the 500 ms SLA while using as few pods as possible and not flapping**.
Over thousands of practice steps in the simulator it discovers the behaviour that scores best:
**add pods when load/latency climb, release them when idle, otherwise hold.** That same
learned policy then runs live — the only difference is where the five signals come from
(Prometheus instead of the simulator).

**The federated global model is the exact same kind of agent.** FedAvg does not create a new
type of controller — it just **averages the weights** of the three clients' PPO agents into
one PPO policy. So the global model scales pods on the same basis (the same state, the same
three actions, the same reward-driven behaviour); it has simply learned from all three
workloads — steady, burst, and periodic — instead of only one. You would run it exactly like
the Stage-B agent above, loading the aggregated weights in place of a single client's.
