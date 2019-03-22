import os

import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


@pytest.mark.parametrize("name", [
    ("pam_ccreds"),
    ("pam_cracklib"),
])
def test_local_packages(host, name):
    pkg = host.package(name)
    assert not pkg.is_installed


def test_local_pwquality_configuration_file(host):
    f = host.file('/etc/security/pwquality.conf')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('ucredit = -1')
    assert f.contains('lcredit = -1')
    assert f.contains('dcredit = -1')
    assert f.contains('ocredit = -1')
    assert f.contains('difok = 8')
    assert f.contains('minclass = 4')
    assert f.contains('maxrepeat = 4')
    assert f.contains('maxclassrepeat = 4')
    assert f.contains('minlen = 15')


def test_local_pam_passwd_configuration_file(host):
    f = host.file('/etc/pam.d/passwd')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('password[ \t ]*required[ \t ]*pam_pwquality.so retry=3')


def test_local_pam_system_auth_configuration_file(host):
    f = host.file('/etc/pam.d/system-auth')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('password[ \t]*sufficient[ \t]*pam_unix.so try_first_pass use_authtok nullok sha512 shadow')  # noqa: E501
    assert f.contains('auth[ \t]*required[ \t]*pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=never')  # noqa: E501
    assert f.contains('auth[ \t]*\[default=die\][ \t]*pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=never')  # noqa: E501
    assert f.contains('account[ \t]*required[ \t]*pam_faillock.so')


def test_local_pam_password_auth_configuration_file(host):
    f = host.file('/etc/pam.d/password-auth')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('password[ \t]*sufficient[ \t]*pam_unix.so try_first_pass use_authtok nullok sha512 shadow remember=5')  # noqa: E501
    assert f.contains('auth[ \t]*required[ \t]*pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=never')  # noqa: E501
    assert f.contains('auth[ \t]*\[default=die\][ \t]*pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=never')  # noqa: E501
    assert f.contains('account[ \t]*required[ \t]*pam_faillock.so')


def test_local_pam_postlogin_configuration_file(host):
    f = host.file('/etc/pam.d/postlogin')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('session[ \t]*required[ \t]*pam_lastlog.so noupdate showfailed')  # noqa: E501


def test_local_pam_limits_core_file(host):
    f = host.file('/etc/security/limits.d/99-ansible-security-core.conf')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('*[ \t]*-[ \t]*core[ \t]*0')


def test_local_pam_limits_maxlogins_file(host):
    f = host.file('/etc/security/limits.d/99-ansible-security-maxlogins.conf')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('*[ \t]*hard[ \t]*maxlogins[ \t]*10')


def test_local_authconfig_configuration_file(host):
    f = host.file('/etc/sysconfig/authconfig')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('PASSWDALGORITHM=sha512')
    assert f.contains('USEPWQUALITY=yes')


def test_local_libuser_configuration_file(host):
    f = host.file('/etc/libuser.conf')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('crypt_style = sha512')


def test_local_useradd_configuration_file(host):
    f = host.file('/etc/default/useradd')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('^INACTIVE=0$')


def test_local_login_defs_configuration_file(host):
    f = host.file('/etc/login.defs')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('^ENCRYPT_METHOD SHA512$')
    assert f.contains('^PASS_MIN_DAYS 1$')
    assert f.contains('^PASS_MAX_DAYS 90$')
    assert f.contains('^FAIL_DELAY 4$')
    assert f.contains('^UMASK 077$')
    assert f.contains('^CREATE_HOME yes$')


def test_local_securetty_configuration_file(host):
    f = host.file('/etc/securetty')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o400
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('^console$')
    assert f.contains('^vc/1$')
    assert f.contains('^vc/2$')
    assert f.contains('^tty1$')
    assert f.contains('^tty2$')
    assert f.contains('^tty3$')


def test_local_sysconfig_init_configuration_file(host):
    f = host.file('/etc/sysconfig/init')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('^PROMPT=yes$')
    assert f.contains('^SINGLE=/usr/sbin/sulogin$')
