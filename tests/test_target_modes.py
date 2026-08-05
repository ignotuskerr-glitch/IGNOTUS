from main import _is_domain_name


def test_domain_detection_excludes_ip_literals():
    assert _is_domain_name("vps64602.publiccloud.com.br")
    assert not _is_domain_name("191.252.200.164")
    assert not _is_domain_name("2001:db8::1")
