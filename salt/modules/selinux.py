# -*- coding: utf-8 -*-
'''
Execute calls on selinux

.. note::
    This module requires the ``semanage``, ``setsebool``, and ``semodule``
    commands to be available on the minion. On RHEL-based distributions,
    ensure that the ``policycoreutils`` and ``policycoreutils-python``
    packages are installed. If not on a Fedora or RHEL-based distribution,
    consult the selinux documentation for your distribution to ensure that the
    proper packages are installed.
'''

# Import python libs
from __future__ import absolute_import
import os
import re

# Import salt libs
import salt.utils
import salt.utils.decorators as decorators
from salt.exceptions import CommandExecutionError, SaltInvocationError

# Import 3rd-party libs
import salt.ext.six as six
from collections import Iterable

try:
    handle = None
    import selinux
    import semanage
    HAS_SEMANAGE = True

    SELINUX_ACTIVE = (selinux.is_selinux_enabled() == 1)
    SELINUX_IS_MLS = (selinux.is_selinux_mls_enabled() == 1)
    (rc, policy_name) = selinux.selinux_getpolicytype()
    if rc >= 0:
        SELINUX_POLICY = policy_name

    handle = semanage.semanage_handle_create()
    ## 0 == selinux disabled, 1 == selinux enabled, -1 == error
    assert(semanage.semanage_is_managed(handle) == 1)
    ## 0 == connect succesful
    assert(semanage.semanage_connect(handle) == 0)
    assert(semanage.semanage_access_check(handle) >= semanage.SEMANAGE_CAN_WRITE)

    protocol_map = {
        'tcp': semanage.SEMANAGE_PROTO_TCP,
        'udp': semanage.SEMANAGE_PROTO_UDP,
    }
except ImportError:
    HAS_SEMANAGE = False
except AssertionError:
    SEMANAGE_ACTIVE = False
finally:
    if handle:
        if semanage.semanage_is_connected(handle) == 1:
            assert(semanage.semanage_disconnect(handle) == 0)
        semanage.semanage_handle_destroy(handle)


_SELINUX_FILETYPES = {
        'a': 'all files',
        'f': 'regular file',
        'd': 'directory',
        'c': 'character device',
        'b': 'block device',
        's': 'socket',
        'l': 'symbolic link',
        'p': 'named pipe'}


def __virtual__():
    '''
    Check if the os is Linux, and then if selinux is running in permissive or
    enforcing mode.
    '''
    required_cmds = ('semanage', 'setsebool', 'semodule')

    # Iterate over all of the commands this module uses and make sure
    # each of them are available in the standard PATH to prevent breakage
    for cmd in required_cmds:
        if not salt.utils.which(cmd):
            return (False, cmd + ' is not in the path')
    # SELinux only makes sense on Linux *obviously*
    if __grains__['kernel'] == 'Linux':
        return 'selinux'
    if not SELINUX_ACTIVE or not HAS_SEMANAGE:
        return (False, 'Module only works on Linux with selinux enabled')
    return (False, 'Module only works on Linux with selinux installed')


def _range_to_tuple(port_range):
    if isinstance(port_range, basestring) and '-' in port_range:
        lo, hi = [ int(n) for n in port_range.split('-', 2) ]
    elif isinstance(port_range, Iterable):
        lo, hi = [ int(n) for n in port_range[0:2] ]
    else:
        lo = hi = int(port_range)
    return (lo, hi)


# Cache the SELinux directory to not look it up over and over
@decorators.memoize
def selinux_fs_path():
    '''
    Return the location of the SELinux VFS directory

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.selinux_fs_path
    '''
    # systems running systemd (e.g. Fedora 15 and newer)
    # have the selinux filesystem in a different location
    try:
        for directory in ('/sys/fs/selinux', '/selinux'):
            if os.path.isdir(directory):
                if os.path.isfile(os.path.join(directory, 'enforce')):
                    return directory
        return None
    # If selinux is Disabled, the path does not exist.
    except AttributeError:
        return None


def getenforce():
    '''
    Return the mode selinux is running in

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.getenforce
    '''
    _selinux_fs_path = selinux_fs_path()
    if _selinux_fs_path is None:
        return 'Disabled'
    try:
        enforce = os.path.join(_selinux_fs_path, 'enforce')
        with salt.utils.fopen(enforce, 'r') as _fp:
            if _fp.readline().strip() == '0':
                return 'Permissive'
            else:
                return 'Enforcing'
    except (IOError, OSError, AttributeError):
        return 'Disabled'


def getconfig():
    '''
    Return the selinux mode from the config file

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.getconfig
    '''
    try:
        config = '/etc/selinux/config'
        with salt.utils.fopen(config, 'r') as _fp:
            for line in _fp:
                if line.strip().startswith('SELINUX='):
                    return line.split('=')[1].capitalize().strip()
    except (IOError, OSError, AttributeError):
        return None
    return None


def setenforce(mode):
    '''
    Set the SELinux enforcing mode

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.setenforce enforcing
    '''
    if isinstance(mode, six.string_types):
        if mode.lower() == 'enforcing':
            mode = '1'
            modestring = 'Enforcing'
        elif mode.lower() == 'permissive':
            mode = '0'
            modestring = 'Permissive'
        elif mode.lower() == 'disabled':
            mode = '0'
            modestring = 'Disabled'
        else:
            return 'Invalid mode {0}'.format(mode)
    elif isinstance(mode, int):
        if mode:
            mode = '1'
        else:
            mode = '0'
    else:
        return 'Invalid mode {0}'.format(mode)

    # enforce file does not exist if currently disabled.  Only for toggling enforcing/permissive
    if getenforce() != 'Disabled':
        enforce = os.path.join(selinux_fs_path(), 'enforce')
        try:
            with salt.utils.fopen(enforce, 'w') as _fp:
                _fp.write(mode)
        except (IOError, OSError) as exc:
            msg = 'Could not write SELinux enforce file: {0}'
            raise CommandExecutionError(msg.format(str(exc)))

    config = '/etc/selinux/config'
    try:
        with salt.utils.fopen(config, 'r') as _cf:
            conf = _cf.read()
        try:
            with salt.utils.fopen(config, 'w') as _cf:
                conf = re.sub(r"\nSELINUX=.*\n", "\nSELINUX=" + modestring + "\n", conf)
                _cf.write(conf)
        except (IOError, OSError) as exc:
            msg = 'Could not write SELinux config file: {0}'
            raise CommandExecutionError(msg.format(str(exc)))
    except (IOError, OSError) as exc:
        msg = 'Could not read SELinux config file: {0}'
        raise CommandExecutionError(msg.format(str(exc)))

    return getenforce()


def getsebool(boolean):
    '''
    Return the information on a specific selinux boolean

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.getsebool virt_use_usb
    '''
    return list_sebool().get(boolean, {})


def setsebool(boolean, value, persist=False):
    '''
    Set the value for a boolean

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.setsebool virt_use_usb off
    '''
    if persist:
        cmd = 'setsebool -P {0} {1}'.format(boolean, value)
    else:
        cmd = 'setsebool {0} {1}'.format(boolean, value)
    return not __salt__['cmd.retcode'](cmd, python_shell=False)


def setsebools(pairs, persist=False):
    '''
    Set the value of multiple booleans

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.setsebools '{virt_use_usb: on, squid_use_tproxy: off}'
    '''
    if not isinstance(pairs, dict):
        return {}
    if persist:
        cmd = 'setsebool -P '
    else:
        cmd = 'setsebool '
    for boolean, value in six.iteritems(pairs):
        cmd = '{0} {1}={2}'.format(cmd, boolean, value)
    return not __salt__['cmd.retcode'](cmd, python_shell=False)


def list_sebool():
    '''
    Return a structure listing all of the selinux booleans on the system and
    what state they are in

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.list_sebool
    '''
    bdata = __salt__['cmd.run']('semanage boolean -l').splitlines()
    ret = {}
    for line in bdata[1:]:
        if not line.strip():
            continue
        comps = line.split()
        ret[comps[0]] = {'State': comps[1][1:],
                         'Default': comps[3][:-1],
                         'Description': ' '.join(comps[4:])}
    return ret


def get_seport(protocol, port_range =None, port =None):
    '''
    Return the specific selinux label attached to the given port, if
    it exists

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.get_seport protocol=tcp port=80
    '''
    proto = protocol_map[protocol]
    if port is not None:
        lo = hi = int(port)
    elif port_range is not None:
        lo, hi = _range_to_tuple(port_range)
    else:
        raise SaltInvocationError('get_seport: either port or port_range must be specified')

    ret = {}
    try:
        obj = pkey = None
        handle = semanage.semanage_handle_create()
        assert(semanage.semanage_connect(handle) == 0)

        (rc, pkey) = semanage.semanage_port_key_create(handle, lo, hi, proto)
        assert(rc >= 0)
        (rc, obj) = semanage.semanage_port_query(handle, pkey)
        assert(rc >= 0)

        if obj:
            con = semanage.semanage_port_get_con(obj)
            (rc, context_str) = semanage.semanage_context_to_string(handle, con)
            assert(rc >= 0)
            ret['protocol'] = semanage.semanage_port_get_proto_str(proto)
            low = semanage.semanage_port_get_low(obj)
            high = semanage.semanage_port_get_high(obj)
            if low == high:
                ret['port'] = low
            else:
                ret['port_range'] = (low, high)
            context = semanage.semanage_port_get_con(obj)
            (rc, context_str) = semanage.semanage_context_to_string(handle, context)
            assert(rc >= 0)
            ret['context'] = context_str

    finally:
        if obj:
            semanage.semanage_port_free(obj)
        if pkey:
            semanage.semanage_port_key_free(pkey)
        if handle:
            if semanage.semanage_is_connected(handle) == 1:
                assert(semanage.semanage_disconnect(handle) == 0)
            semanage.semanage_handle_destroy(handle)

    return ret


def set_seport(context, protocol, port_range =None, port =None):
    '''
    Set the selinux label for the given port

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.set_seport protocol=tcp port=80 context=system_u:object_r:http_port_t:s0
    '''
    proto = protocol_map[protocol]
    if port is not None:
        lo = hi = int(port)
    elif port_range is not None:
        lo, hi = _range_to_tuple(port_range)
    else:
        raise SaltInvocationError('get_seport: either port or port_range must be specified')

    if not isinstance(context, dict):
        context = _context_string_to_dict(context)
    else:
        base = { 'sel_user': 'system_u', 'sel_role': 'object_r', 'sel_level': 's0' }
        base.update(context)
        if 'sel_type' not in context:
            raise SaltInvocationError('context must include the selinux type')
        context = base

    ret = {}
    try:
        obj = pkey = ctx = None
        handle = semanage.semanage_handle_create()
        assert(semanage.semanage_connect(handle) == 0)

        (rc, pkey) = semanage.semanage_port_key_create(handle, lo, hi, proto)
        assert(rc >= 0)
        (rc, obj) = semanage.semanage_port_query(handle, pkey)
        assert(rc >= 0)

        if obj: # port definition exists, check if it's correct
            # a context obtained through _get_con should not be manually freed
            _ctx = semanage.semanage_port_get_con(obj)
            (rc, cur_context_str) = semanage.semanage_context_to_string(handle, _ctx)
            assert(rc >= 0)
            if cur_context_str != _context_dict_to_string(context):
                semanage.semanage_context_set_user(handle, _ctx, context['sel_user'])
                semanage.semanage_context_set_role(handle, _ctx, context['sel_role'])
                semanage.semanage_context_set_type(handle, _ctx, context['sel_type'])
                if SELINUX_IS_MLS:
                    semanage.semanage_context_set_mls(handle, _ctx, context['sel_level'])
                assert(semanage.semanage_begin_transaction(handle) >= 0)
                #semanage.semanage_port_set_con(handle, obj, _ctx)
                assert(semanage.semanage_port_modify_local(handle, pkey, obj) >= 0)
                assert(semanage.semanage_commit(handle) >= 0)
                (rc, new_context_str) = semanage.semanage_context_to_string(handle, _ctx)
                assert(rc >= 0)
                ret['context'] = { 'old': cur_context_str, 'new': new_context_str }

        else: # object does not yet exist
            (rc, obj) = semanage.semanage_port_create(handle)
            assert(rc >= 0)
            semanage.semanage_port_set_proto(obj, proto)
            semanage.semanage_port_set_range(obj, lo, hi)
            # a context obtained through _context_create should be manually freed
            (rc, ctx) = semanage.semanage_context_create(handle)
            assert(rc >= 0)
            semanage.semanage_context_set_user(handle, ctx, context['sel_user'])
            semanage.semanage_context_set_role(handle, ctx, context['sel_role'])
            semanage.semanage_context_set_type(handle, ctx, context['sel_type'])
            if SELINUX_IS_MLS:
                semanage.semanage_context_set_mls(handle, ctx, context['sel_level'])
            semanage.semanage_port_set_con(handle, obj, ctx)
            assert(semanage.semanage_begin_transaction(handle) >= 0)
            assert(semanage.semanage_port_modify_local(handle, pkey, obj) >= 0)
            assert(semanage.semanage_commit(handle) >= 0)
            (rc, new_context_str) = semanage.semanage_context_to_string(handle, ctx)
            assert(rc >= 0)
            elem = {
                'protocol': semanage.semanage_port_get_proto_str(proto),
                'context': new_context_str,
            }
            if lo == hi:
                elem['port'] = lo
            else:
                elem['port_range'] = (lo, hi)
            ret['new'] = [ elem ]

    finally:
        if pkey:
            semanage.semanage_port_key_free(pkey)
        if obj:
            semanage.semanage_port_free(obj)
        if ctx:
            semanage.semanage_context_free(ctx)
        if handle:
            if semanage.semanage_is_connected(handle) == 1:
                assert(semanage.semanage_disconnect(handle) == 0)
            semanage.semanage_handle_destroy(handle)

    return ret


def list_seport():
    '''
    Return a structure listing all of the selinux ports on the system and
    what state they are in

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.list_seport
    '''

    ret = []
    try:
        handle = semanage.semanage_handle_create()
        assert(semanage.semanage_connect(handle) == 0)
        (rc, plist) = semanage.semanage_port_list_local(handle)
        assert(rc >= 0)
        for p in plist:
            d = {}
            proto = semanage.semanage_port_get_proto(p)
            d['protocol'] = semanage.semanage_port_get_proto_str(proto)
            low = semanage.semanage_port_get_low(p)
            high = semanage.semanage_port_get_high(p)
            if low == high:
                d['port'] = low
            else:
                d['port_range'] = (low, high)
            context = semanage.semanage_port_get_con(p)
            (rc, context_str) = semanage.semanage_context_to_string(handle, context)
            assert(rc >= 0)
            d['context'] = context_str
            ret.append(d)

    finally:
        if handle:
            if semanage.semanage_is_connected(handle) == 1:
                assert(semanage.semanage_disconnect(handle) == 0)
            semanage.semanage_handle_destroy(handle)

    return ret


def getsemod(module):
    '''
    Return the information on a specific selinux module

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.getsemod mysql

    .. versionadded:: 2016.3.0
    '''
    return list_semod().get(module, {})


def setsemod(module, state):
    '''
    Enable or disable an SELinux module.

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.setsemod nagios Enabled

    .. versionadded:: 2016.3.0
    '''
    if state.lower() == 'enabled':
        cmd = 'semodule -e {0}'.format(module)
    elif state.lower() == 'disabled':
        cmd = 'semodule -d {0}'.format(module)
    return not __salt__['cmd.retcode'](cmd)


def install_semod(module_path):
    '''
    Install custom SELinux module from file

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.install_semod [salt://]path/to/module.pp

    .. versionadded:: develop
    '''
    if module_path.find('salt://') == 0:
        module_path = __salt__['cp.cache_file'](module_path)
    cmd = 'semodule -i {0}'.format(module_path)
    return not __salt__['cmd.retcode'](cmd)


def remove_semod(module):
    '''
    Remove SELinux module

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.remove_semod module_name

    .. versionadded:: develop
    '''
    cmd = 'semodule -r {0}'.format(module)
    return not __salt__['cmd.retcode'](cmd)


def list_semod():
    '''
    Return a structure listing all of the selinux modules on the system and
    what state they are in

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.list_semod

    .. versionadded:: 2016.3.0
    '''
    helptext = __salt__['cmd.run']('semodule -h').splitlines()
    semodule_version = ''
    for line in helptext:
        if line.strip().startswith('full'):
            semodule_version = 'new'

    if semodule_version == 'new':
        mdata = __salt__['cmd.run']('semodule -lfull').splitlines()
        ret = {}
        for line in mdata:
            if not line.strip():
                continue
            comps = line.split()
            if len(comps) == 4:
                ret[comps[1]] = {'Enabled': False,
                                 'Version': None}
            else:
                ret[comps[1]] = {'Enabled': True,
                                 'Version': None}
    else:
        mdata = __salt__['cmd.run']('semodule -l').splitlines()
        ret = {}
        for line in mdata:
            if not line.strip():
                continue
            comps = line.split()
            if len(comps) == 3:
                ret[comps[0]] = {'Enabled': False,
                                 'Version': comps[1]}
            else:
                ret[comps[0]] = {'Enabled': True,
                                 'Version': comps[1]}
    return ret


def _validate_filetype(filetype):
    '''
    Checks if the given filetype is a valid SELinux filetype specification.
    Throws an SaltInvocationError if it isn't.
    '''
    if filetype not in _SELINUX_FILETYPES.keys():
        raise SaltInvocationError('Invalid filetype given: {0}'.format(filetype))
    return True


def _context_dict_to_string(context):
    '''
    Converts an SELinux file context from a dict to a string.
    '''
    return '{sel_user}:{sel_role}:{sel_type}:{sel_level}'.format(**context)


def _context_string_to_dict(context):
    '''
    Converts an SELinux file context from string to dict.
    '''
    if not re.match('[^:]+:[^:]+:[^:]+:[^:]+$', context):
        raise SaltInvocationError('Invalid SELinux context string: {0}. ' +
                                  'Expected "sel_user:sel_role:sel_type:sel_level"')
    context_list = context.split(':', 3)
    ret = {}
    for index, value in enumerate(['sel_user', 'sel_role', 'sel_type', 'sel_level']):
        ret[value] = context_list[index]
    return ret


def _filetype_id_to_string(filetype='a'):
    '''
    Translates SELinux filetype single-letter representation
    to a more human-readable version (which is also used in `semanage fcontext -l`).
    '''
    _validate_filetype(filetype)
    return _SELINUX_FILETYPES.get(filetype, 'error')


def fcontext_get_policy(name, filetype=None, sel_type=None, sel_user=None, sel_level=None):
    '''
    Returns the current entry in the SELinux policy list as a dictionary.
    Returns None if no exact match was found
    Returned keys are:
    - filespec (the name supplied and matched)
    - filetype (the descriptive name of the filetype supplied)
    - sel_user, sel_role, sel_type, sel_level (the selinux context)
    For a more in-depth explanation of the selinux context, go to
    https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security-Enhanced_Linux/chap-Security-Enhanced_Linux-SELinux_Contexts.html

    name: filespec of the file or directory. Regex syntax is allowed.
    filetype: The SELinux filetype specification.
              Use one of [a, f, d, c, b, s, l, p].
              See also `man semanage-fcontext`.
              Defaults to 'a' (all files)

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.fcontext_get_policy my-policy
    '''
    if filetype:
        _validate_filetype(filetype)
    re_spacer = '[ ]{2,}'
    cmd_kwargs = {'spacer': re_spacer,
                  'filespec': re.escape(name),
                  'sel_user': sel_user or '[^:]+',
                  'sel_role': '[^:]+',  # se_role for file context is always object_r
                  'sel_type': sel_type or '[^:]+',
                  'sel_level': sel_level or '[^:]+'}
    cmd_kwargs['filetype'] = '[[:alpha:] ]+' if filetype is None else _filetype_id_to_string(filetype)
    cmd = 'semanage fcontext -l | egrep ' + \
          "'^{filespec}{spacer}{filetype}{spacer}{sel_user}:{sel_role}:{sel_type}:{sel_level}$'".format(**cmd_kwargs)
    current_entry_text = __salt__['cmd.shell'](cmd)
    if current_entry_text == '':
        return None
    ret = {}
    current_entry_list = re.split(re_spacer, current_entry_text)
    ret['filespec'] = current_entry_list[0]
    ret['filetype'] = current_entry_list[1]
    ret.update(_context_string_to_dict(current_entry_list[2]))
    return ret


def fcontext_add_or_delete_policy(action, name, filetype=None, sel_type=None, sel_user=None, sel_level=None):
    '''
    Sets or deletes the SELinux policy for a given filespec and other optional parameters.
    Returns the result of the call to semanage.
    Note that you don't have to remove an entry before setting a new one for a given
    filespec and filetype, as adding one with semanage automatically overwrites a
    previously configured SELinux context.

    name: filespec of the file or directory. Regex syntax is allowed.
    file_type: The SELinux filetype specification.
              Use one of [a, f, d, c, b, s, l, p].
              See also ``man semanage-fcontext``.
              Defaults to 'a' (all files)
    sel_type: SELinux context type. There are many.
    sel_user: SELinux user. Use ``semanage login -l`` to determine which ones are available to you
    sel_level: The MLS range of the SELinux context.

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.fcontext_add_or_delete_policy add my-policy
    '''
    if action not in ['add', 'delete']:
        raise SaltInvocationError('Actions supported are "add" and "delete", not "{0}".'.format(action))
    cmd = 'semanage fcontext --{0}'.format(action)
    if filetype is not None:
        _validate_filetype(filetype)
        cmd += ' --ftype {0}'.format(filetype)
    if sel_type is not None:
        cmd += ' --type {0}'.format(sel_type)
    if sel_user is not None:
        cmd += ' --seuser {0}'.format(sel_user)
    if sel_level is not None:
        cmd += ' --range {0}'.format(sel_level)
    cmd += ' ' + re.escape(name)
    return __salt__['cmd.run_all'](cmd)


def fcontext_policy_is_applied(name, recursive=False):
    '''
    Returns an empty string if the SELinux policy for a given filespec is applied,
    returns string with differences in policy and actual situation otherwise.

    name: filespec of the file or directory. Regex syntax is allowed.

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.fcontext_policy_is_applied my-policy
    '''
    cmd = 'restorecon -n -v '
    if recursive:
        cmd += '-R '
    cmd += re.escape(name)
    return __salt__['cmd.run_all'](cmd).get('stdout')


def fcontext_apply_policy(name, recursive=False):
    '''
    Applies SElinux policies to filespec using `restorecon [-R] filespec`.
    Returns dict with changes if succesful, the output of the restorecon command otherwise.

    name: filespec of the file or directory. Regex syntax is allowed.
    recursive: Recursively apply SELinux policies.

    CLI Example:

    .. code-block:: bash

        salt '*' selinux.fcontext_apply_policy my-policy
    '''
    ret = {}
    changes_text = fcontext_policy_is_applied(name, recursive)
    cmd = 'restorecon -v -F '
    if recursive:
        cmd += '-R '
    cmd += re.escape(name)
    apply_ret = __salt__['cmd.run_all'](cmd)
    ret.update(apply_ret)
    if apply_ret['retcode'] == 0:
        changes_list = re.findall('restorecon reset (.*) context (.*)->(.*)$', changes_text, re.M)
        if len(changes_list) > 0:
            ret.update({'changes': {}})
        for item in changes_list:
            filespec = item[0]
            old = _context_string_to_dict(item[1])
            new = _context_string_to_dict(item[2])
            intersect = {}
            for key, value in six.iteritems(old):
                if new.get(key) == value:
                    intersect.update({key: value})
            for key in intersect:
                del old[key]
                del new[key]
            ret['changes'].update({filespec: {'old': old, 'new': new}})
    return ret
