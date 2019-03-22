# Local accounts hardening

Adds the ability to enforce a policy to manage local accounts.

- STIG compliance
- Ensure deprecated PAM modules are not present
- Ensure deprecated host access are not present (shost, rhost and similar)
- [Manages pwquality policies.](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/chap-Hardening_Your_System_with_Tools_and_Services.html#sec-Password_Security)
- Ensures SHA512 is used consistently to hash passwords.
- Ensures no accounts with UID 0 exist other than`root`.
- [Configure faillock](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/chap-Hardening_Your_System_with_Tools_and_Services.html)
- [Controls `root` access.](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Controlling_Root_Access.html)
- Ensure critical files have appropriate permissions and security context
- Enforce a sensible `umask`.
- Prevent information leakage via coredumps
- Limit the number of concurrent sessions for all accounts and/or account types.
- Report non-compliant scenarios:
  - Print warning about accounts with password lifetimes under 24 hours
  - Print warning for accounts with a password lifetime over 60 days
  - Print warning for groups in /etc/passwd that are not in /etc/group
  - Print warnings for non-root users with UID 0
  - Print warning for local interactive users without a home directory assigned
  - Print warning for users with an assigned home directory that does not exist
  - Users must provide a password for privilege escalation.
  - Users must re-authenticate for privilege escalation.

## Requirements

None. This role does not install packages.

## Role Variables

- From `defaults/main.yml`

```yml
## Authentication (auth)
# Set the package install state for distribution packages
# Options are 'present' and 'latest'
security_package_state: present
stig_id: 'rhel7'
## Accounts (accounts)
# Set minimum password lifetime to 1 day for interactive accounts.
security_set_minimum_password_lifetime: no                   # V-71927
security_set_maximum_password_lifetime: no                   # V-71931

# Disallow logins from accounts with blank/null passwords via PAM.
security_disallow_blank_password_login: 'yes'                  # V-71937
# Apply password quality rules.
# NOTE: The security_pwquality_apply_rules variable is a "master switch".
# Set the 'security_pwquality_apply_rules' variable to 'yes' to apply all of
# the password quality rules. Each rule can be disabled with a value of 'no'.
security_pwquality_apply_rules: 'yes'
security_pwquality_require_uppercase: 'yes'                    # V-71903
security_pwquality_require_lowercase: 'yes'                    # V-71905
security_pwquality_require_numeric: 'yes'                      # V-71907
security_pwquality_require_special: 'yes'                      # V-71909
security_pwquality_require_characters_changed: 'yes'           # V-71911
security_pwquality_require_character_classes_changed: 'yes'    # V-71913
security_pwquality_limit_repeated_characters: 'yes'            # V-71915
security_pwquality_limit_repeated_character_classes: 'yes'     # V-71917
security_pwquality_require_minimum_password_length: 'yes'      # V-71935
# Use pwquality when passwords are changed or established.
security_enable_pwquality_password_set: 'yes'                   # V-73159
# Ensure passwords are stored using SHA512.
security_password_encrypt_method: SHA512                     # V-71921
# Ensure user/group admin utilities only store encrypted passwords.
security_libuser_crypt_style_sha512: 'yes'                     # V-71923
# Set a minimum/maximum lifetime limit for user passwords.
security_password_min_lifetime_days: 1                      # V-71925
security_password_max_lifetime_days: 90                     # V-71929
security_password_min_length: 15                            # CCE-27123-9
# Set a delay (in seconds) between failed login attempts.
security_shadow_utils_fail_delay: 4                          # V-71951
# Set a umask for all authenticated users.
security_shadow_utils_umask: '077'                         # V-71995
# Create home directories for new users by default.
security_shadow_utils_create_home: 'yes'                       # V-72013
# How many old user password to remember to prevent password re-use.
security_password_remember_password: 5                      # V-71933
# Disable user accounts if the password expires.
security_disable_account_if_password_expires: 'yes'             # V-71941
# Lock user accounts with excessive login failures. See documentation.
security_pam_faillock_enable: 'yes'        # V-71945 / V-71943 / RHEL-07-010373
security_pam_faillock_interval: 900
security_pam_faillock_attempts: 3
security_pam_faillock_deny_root: 'yes'                         # RHEL-07-010373
security_pam_faillock_unlock_time: never                    # V-71943
# Limit the number of concurrent connections per account.
security_rhel7_concurrent_session_limit: 10                 # V-72217
# Disable creation of core dumps.
security_rhel7_core_limit: 0                                # V-72057
# Remove .shosts and shosts.equiv files.
security_rhel7_remove_shosts_files: 'yes'                       # V-72277
# Remove /etc/hosts.equiv file.
security_rhel7_remove_hosts_equiv_file: 'yes'                       # V-72277
# Remove .rhosts files.
security_rhel7_remove_rhosts_files: 'yes'                       # V-72277
security_rhel7_auth_root_ttys:
  - console
  - vc/1
  - vc/2
  - tty1
  - tty2
  - tty3
security_rhel7_init_prompt: 'True'
security_rhel7_init_single: 'True'
```

- From `vars/main.yml`

```yml
# RHEL 7 STIG: Packages to add/remove
stig_packages_rhel7:
  - packages:
      - pam_ccreds
      - pam_cracklib
    state: absent
    enabled: 'True'
# Password quality settings
#
# Each dictionary has this structure:
#
#   parameter: the pwquality parameter to set
#   value: the value of the parameter
#   stig_id: the STIG id number
#   description: description of the control from the STIG
#   enabled: whether the change should be applied
#
password_quality_rhel7:
  - parameter: ucredit
    value: -1
    stig_id: V-71903
    description: "Password must contain at least one upper-case character"
    enabled: "{{ security_pwquality_require_uppercase }}"
  - parameter: lcredit
    value: -1
    stig_id: V-71905
    description: "Password must contain at least one lower-case character"
    enabled: "{{ security_pwquality_require_lowercase }}"
  - parameter: dcredit
    value: -1
    stig_id: V-71907
    description: "Password must contain at least one numeric character"
    enabled: "{{ security_pwquality_require_numeric }}"
  - parameter: ocredit
    value: -1
    stig_id: V-71909
    description: "Password must contain at least one special character"
    enabled: "{{ security_pwquality_require_special }}"
  - parameter: difok
    value: 8
    stig_id: V-71911
    description: "Password must have at least eight characters changed"
    enabled: "{{ security_pwquality_require_characters_changed }}"
  - parameter: minclass
    value: 4
    stig_id: V-71913
    description: "Password must have at least four character classes changed"
    enabled: "{{ security_pwquality_require_character_classes_changed }}"
  - parameter: maxrepeat
    value: 4
    stig_id: V-71915
    # yamllint disable-line rule:line-length
    description: "Password must have at most four characters repeated consecutively"
    enabled: "{{ security_pwquality_limit_repeated_characters }}"
  - parameter: maxclassrepeat
    value: 4
    stig_id: V-71917
    # yamllint disable-line rule:line-length
    description: "Password must have at most four characters in the same character class repeated consecutively"
    enabled: "{{ security_pwquality_limit_repeated_character_classes }}"
  - parameter: minlen
    value: 15
    stig_id: V-71935
    description: "Passwords must be a minimum of 15 characters in length"
    enabled: "{{ security_pwquality_require_minimum_password_length }}"

## shadow-utils settings
# This variable is used in main/rhel7stig/auth.yml to set shadow file-related
# configurations in /etc/login.defs.
#
# Each dictionary has this structure:
#
#   parameter: the parameter to set
#   value: the value for the parameter
#   stig_id: the STIG ID number for the requirement
#
shadow_utils_rhel7:
  - parameter: ENCRYPT_METHOD
    value: "{{ security_password_encrypt_method | default('') }}"
    stig_id: V-71921
    ansible_os_family: all
  - parameter: PASS_MIN_DAYS
    value: "{{ security_password_min_lifetime_days | default('') }}"
    stig_id: V-71925
    ansible_os_family: all
  - parameter: PASS_MAX_DAYS
    value: "{{ security_password_max_lifetime_days | default('') }}"
    stig_id: V-71929
    ansible_os_family: all
  - parameter: PASS_MIN_LEN
    value: "{{ security_password_min_length | default('') }}"
    stig_id: V-72013
    ansible_os_family: all
  - parameter: FAIL_DELAY
    value: "{{ security_shadow_utils_fail_delay | default('') }}"
    stig_id: V-71951
    ansible_os_family: all
  - parameter: UMASK
    value: "{{ security_shadow_utils_umask | default('') }}"
    stig_id: V-71995
    ansible_os_family: all
  - parameter: CREATE_HOME
    value: "{{ security_shadow_utils_create_home | default('') }}"
    stig_id: V-72013
    ansible_os_family: all
```

## Dependencies

This role requires the `ansible-os-hardening-selinux` role to be used for security
context enforcement.
Some files related to the `ansible-os-hardening-sudo` role are also inspected for
compliance.

## Example Playbook

Example of how to use this role:

```yml
    - hosts: servers
      roles:
         - { role: ansible-os-hardening-selinux }
         - { role: ansible-os-hardening-sudo }
         - { role: ansible-os-hardening-local-accounts }
```

## Contributing

This repository uses [git-flow](http://nvie.com/posts/a-successful-git-branching-model/).
To contribute to the role, create a new feature branch (`feature/foo_bar_baz`),
write [Molecule](http://molecule.readthedocs.io/en/master/index.html) tests for the new functionality
and submit a pull request targeting the `develop` branch.

Happy hacking!

## License

GPLv3

## Author Information

[David Sastre](david.sastre@redhat.com)
