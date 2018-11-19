import time
from functools import partial as p

from helpers.assertions import has_datapoint_with_dim
from helpers.util import ensure_always, run_agent, run_service, wait_for

CONFIG = """
observers:
  - type: docker
monitors:
  - type: collectd/nginx
    discoveryRule: container_name =~ "nginx-basic-discovery" && port == 80
"""


def test_basic_service_discovery():
    with run_agent(CONFIG) as [backend, _, _]:
        with run_service("nginx", name="nginx-basic-discovery"):
            assert wait_for(
                p(has_datapoint_with_dim, backend, "container_name", "nginx-basic-discovery")
            ), "Didn't get nginx datapoints"
        # Let nginx be removed by docker observer and collectd restart
        time.sleep(5)
        backend.datapoints.clear()
        assert ensure_always(lambda: not has_datapoint_with_dim(backend, "container_name", "nginx-basic-discovery"), 10)
