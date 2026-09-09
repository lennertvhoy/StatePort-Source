"""Defense in depth: canonical control paths must fail before plan rendering."""
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'packages/release-contracts/src')]
import test_provision_execution_host as fixtures  # noqa: E402
from stateport_release import execution_host_provisioning as prov  # noqa: E402

PREFIX = 'accepted/' + '0' * 64 + '/stateport-control/'


@pytest.mark.parametrize('path', [
    '', 'accepted', 'accepted/revision/stateport-control/web.container',
    '/' + PREFIX + 'web.container', PREFIX + '../escape.container',
    PREFIX + '../../escape.container', PREFIX + './web.container',
    PREFIX + '/web.container', PREFIX + 'nested/web.container',
    PREFIX + 'nested\\web.container', PREFIX + 'web.service',
    PREFIX + 'web.container\n', PREFIX.replace('stateport-control', 'foreign') + 'web.container',
])
def test_control_materialization_refuses_noncanonical_path(path):
    verified = fixtures._verified()
    with pytest.raises(prov.ReleaseContractError, match='noncanonical'):
        prov.render_provisioning_plan(verified.target, verified.index.document['signed']['images'],
            verification_basis='signature-verified-test',
            control_plane_materialization={path: b'[Container]\nContainerName=stateport-web\n'})


@pytest.mark.parametrize('name', ['stateport-web.container', 'stateport-web.network'])
def test_control_materialization_accepts_exact_canonical_basename(name):
    verified = fixtures._verified()
    plan = prov.render_provisioning_plan(verified.target, verified.index.document['signed']['images'],
        verification_basis='signature-verified-test',
        control_plane_materialization={PREFIX + name: b'[Container]\nContainerName=stateport-web\n'})
    assert any(row['path'] == prov.CONTROL_QUADLET_DIR + '/' + name for row in plan['writes'])


def test_existing_privileged_fd_executor_already_refuses_traversal():
    with pytest.raises(prov.ProvisioningRefusal, match='unsafe'):
        prov._host_parts(prov.CONTROL_QUADLET_DIR + '/../../escape.container')
