# Copyright (c) 2014 NetApp, Inc.
# Copyright (c) 2014 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
NetApp ONTAP system interface.
"""

import copy
import math
import sys
import time
import uuid

from cinder import exception
from cinder.openstack.common import excutils
from cinder.openstack.common import log as logging
from cinder.openstack.common import timeutils
from cinder import units
from cinder import utils
from cinder.volume import driver
from cinder.volume.drivers.netapp.api import NaApiError
from cinder.volume.drivers.netapp.api import NaElement
from cinder.volume.drivers.netapp.api import NaServer
from cinder.volume.drivers.netapp.options import netapp_7mode_opts
from cinder.volume.drivers.netapp.options import netapp_basicauth_opts
from cinder.volume.drivers.netapp.options import netapp_cluster_opts
from cinder.volume.drivers.netapp.options import netapp_connection_opts
from cinder.volume.drivers.netapp.options import netapp_provisioning_opts
from cinder.volume.drivers.netapp.options import netapp_transport_opts
from cinder.volume.drivers.netapp import ssc_utils
from cinder.volume.drivers.netapp.utils import get_volume_extra_specs
from cinder.volume.drivers.netapp.utils import provide_ems
from cinder.volume.drivers.netapp.utils import set_safe_attr
from cinder.volume.drivers.netapp.utils import validate_instantiation
from cinder.volume import volume_types


LOG = logging.getLogger(__name__)


class NetAppLun(object):
    """Represents a LUN on NetApp storage."""

    def __init__(self, handle, name, size, metadata_dict):
        self.handle = handle
        self.name = name
        self.size = size
        self.metadata = metadata_dict or {}

    def get_metadata_property(self, prop):
        """Get the metadata property of a LUN."""
        if prop in self.metadata:
            return self.metadata[prop]
        name = self.name
        msg = _("No metadata property %(prop)s defined for the"
                " LUN %(name)s")
        msg_fmt = {'prop': prop, 'name': name}
        LOG.debug(msg % msg_fmt)

    def __str__(self, *args, **kwargs):
        return 'NetApp Lun[handle:%s, name:%s, size:%s, metadata:%s]'\
               % (self.handle, self.name, self.size, self.metadata)


class filer(object):
    ''' A NetApp Filer object '''

    IGROUP_PREFIX = 'openstack-'
    
    def __init__(self, *args, **kwargs):
        """Instantiate a client for NetApp server api communication.
        """

        host_filer = kwargs['hostname']
        LOG.debug(_('Using NetApp filer: %s') % host_filer)
        self.client = NaServer(host=host_filer,
                               server_type=NaServer.SERVER_TYPE_FILER,
                               transport_type=kwargs['transport_type'],
                               style=NaServer.STYLE_LOGIN_PASSWORD,
                               username=kwargs['login'],
                               password=kwargs['password'])
        self.lun_table = {}

    def get_ontapi_version(self):
        """Gets the supported ontapi version."""
        ontapi_version = NaElement('system-get-ontapi-version')
        res = self.client.invoke_successfully(ontapi_version, False)
        major = res.get_child_content('major-version')
        minor = res.get_child_content('minor-version')
        return (major, minor)

    def create_lun(self, volume, lun, size, metadata, qos_policy_group=None):
        """Issues api request for creating lun on volume."""
        path = '/vol/%s/%s' % (volume, lun)
        lun_create = NaElement.create_node_with_children(
            'lun-create-by-size',
            **{'path': path, 'size': size,
                'ostype': metadata['OsType'],
                'space-reservation-enabled': metadata['SpaceReserved']})
        if qos_policy_group:
            lun_create.add_new_child('qos-policy-group', qos_policy_group)
        self.client.invoke_successfully(lun_create, True)

    def destroy_lun(self, path, force=True):
        """Destroys the lun at the path."""
        lun_destroy = NaElement.create_node_with_children(
            'lun-destroy',
            **{'path': path})
        if force:
            lun_destroy.add_new_child('force', 'true')
        self.client.invoke_successfully(lun_destroy, True)
        seg = path.split("/")
        LOG.debug(_("Destroyed LUN %s") % seg[-1])

    def map_lun(self, name, initiator, initiator_type='iscsi', lun_id=None):
        """Maps lun to the initiator and returns lun id assigned."""
        metadata = self.get_lun_attr(name, 'metadata')
        os = metadata['OsType']
        path = metadata['Path']
        if not self._is_supported_os(os):
            os = 'default'
        igroup_name = self._get_or_create_igroup(initiator,
                                                 initiator_type, os)
        lun_map = NaElement.create_node_with_children(
            'lun-map', **{'path': path,
                          'initiator-group': igroup_name})
        if lun_id:
            lun_map.add_new_child('lun-id', lun_id)
        try:
            result = self.client.invoke_successfully(lun_map, True)
            return result.get_child_content('lun-id-assigned')
        except NaApiError as e:
            code = e.code
            message = e.message
            msg = _('Error mapping lun. Code :%(code)s, Message:%(message)s')
            msg_fmt = {'code': code, 'message': message}
            exc_info = sys.exc_info()
            LOG.warn(msg % msg_fmt)
            (igroup, lun_id) = self._find_mapped_lun_igroup(path, initiator)
            if lun_id is not None:
                return lun_id
            else:
                raise exc_info[0], exc_info[1], exc_info[2]

    def get_lun_attr(self, name, attr):
        """Get the lun attribute if found else None."""
        try:
            attr = getattr(self.get_lun(name), attr)
            return attr
        except exception.VolumeNotFound as e:
            LOG.error(_("Message: %s"), e.msg)
        except Exception as e:
            LOG.error(_("Error getting lun attribute. Exception: %s"), str(e))
        return None

    def _is_supported_os(self, os):
        """Checks if the os type supplied is NetApp supported."""
        return os in ['linux', 'aix', 'hpux', 'windows', 'solaris',
                      'netware', 'vmware', 'openvms', 'xen', 'hyper_v']

    def _get_or_create_igroup(self, initiator, initiator_type='iscsi',
                              os='default'):
        """Checks for an igroup for an initiator.

        Creates igroup if not found.
        """

        igroups = self._get_igroup_by_initiator(initiator=initiator)
        igroup_name = None
        for igroup in igroups:
            if igroup['initiator-group-os-type'] == os:
                if igroup['initiator-group-type'] == initiator_type or \
                        igroup['initiator-group-type'] == 'mixed':
                    if igroup['initiator-group-name'].startswith(
                            self.IGROUP_PREFIX):
                        igroup_name = igroup['initiator-group-name']
                        break
        if not igroup_name:
            igroup_name = self.IGROUP_PREFIX + str(uuid.uuid4())
            self._create_igroup(igroup_name, initiator_type, os)
            self._add_igroup_initiator(igroup_name, initiator)
        return igroup_name

    def unmap_lun(self, path, initiator):
        """Unmaps a lun from given initiator."""
        (igroup_name, lun_id) = self._find_mapped_lun_igroup(path, initiator)
        lun_unmap = NaElement.create_node_with_children(
            'lun-unmap',
            **{'path': path, 'initiator-group': igroup_name})
        try:
            self.client.invoke_successfully(lun_unmap, True)
        except NaApiError as e:
            msg = _("Error unmapping lun. Code :%(code)s,"
                    " Message:%(message)s")
            msg_fmt = {'code': e.code, 'message': e.message}
            exc_info = sys.exc_info()
            LOG.warn(msg % msg_fmt)
            # if the lun is already unmapped
            if e.code == '13115' or e.code == '9016':
                pass
            else:
                raise exc_info[0], exc_info[1], exc_info[2]

    def _create_igroup(self, igroup, igroup_type='iscsi', os_type='default'):
        """Creates igroup with specified args."""
        igroup_create = NaElement.create_node_with_children(
            'igroup-create',
            **{'initiator-group-name': igroup,
               'initiator-group-type': igroup_type,
               'os-type': os_type})
        self.client.invoke_successfully(igroup_create, True)

    def _add_igroup_initiator(self, igroup, initiator):
        """Adds initiators to the specified igroup."""
        igroup_add = NaElement.create_node_with_children(
            'igroup-add',
            **{'initiator-group-name': igroup,
               'initiator': initiator})
        self.client.invoke_successfully(igroup_add, True)

    def _get_igroup_by_initiator(self, initiator):
        """Get igroups by initiator."""
        raise NotImplementedError()

    def do_direct_resize(self, path, new_size_bytes, force=True):
        """Uses the resize api to resize the lun."""
        seg = path.split("/")
        LOG.info(_("Resizing lun %s directly to new size."), seg[-1])
        lun_resize = NaElement("lun-resize")
        lun_resize.add_new_child('path', path)
        lun_resize.add_new_child('size', new_size_bytes)
        if force:
            lun_resize.add_new_child('force', 'true')
        self.client.invoke_successfully(lun_resize, True)

    def get_lun_geometry(self, path):
        """Gets the lun geometry."""
        geometry = {}
        lun_geo = NaElement("lun-get-geometry")
        lun_geo.add_new_child('path', path)
        try:
            result = self.client.invoke_successfully(lun_geo, True)
            geometry['size'] = result.get_child_content("size")
            geometry['bytes_per_sector'] =\
                result.get_child_content("bytes-per-sector")
            geometry['sectors_per_track'] =\
                result.get_child_content("sectors-per-track")
            geometry['tracks_per_cylinder'] =\
                result.get_child_content("tracks-per-cylinder")
            geometry['cylinders'] =\
                result.get_child_content("cylinders")
            geometry['max_resize'] =\
                result.get_child_content("max-resize-size")
        except Exception as e:
            LOG.error(_("Lun %(path)s geometry failed. Message - %(msg)s")
                      % {'path': path, 'msg': e.message})
        return geometry

    def get_volume_options(self, volume_name):
        """Get the value for the volume option."""
        opts = []
        vol_option_list = NaElement("volume-options-list-info")
        vol_option_list.add_new_child('volume', volume_name)
        result = self.client.invoke_successfully(vol_option_list, True)
        options = result.get_child_by_name("options")
        if options:
            opts = options.get_children()
        return opts

    def move_lun(self, path, new_path):
        """Moves the lun at path to new path."""
        seg = path.split("/")
        new_seg = new_path.split("/")
        LOG.debug(_("Moving lun %(name)s to %(new_name)s.")
                  % {'name': seg[-1], 'new_name': new_seg[-1]})
        lun_move = NaElement("lun-move")
        lun_move.add_new_child("path", path)
        lun_move.add_new_child("new-path", new_path)
        self.client.invoke_successfully(lun_move, True)

    def get_lun_by_args(self, **args):
        """Retrieves luns with specified args."""
        raise NotImplementedError()

    def _find_mapped_lun_igroup(self, path, initiator, os=None):
        """Find the igroup for mapped lun with initiator."""
        raise NotImplementedError()

    def clone_lun(self, name, new_name, space_reserved='true',
                   src_block=0, dest_block=0, block_count=0):
        """Clone LUN with the given name to the new name."""
        raise NotImplementedError()

    def _create_lun_meta(self, lun):
        raise NotImplementedError()

    def add_lun_to_table(self, lun):
        """Adds LUN to cache table."""
        if not isinstance(lun, NetAppLun):
            msg = _("Object is not a NetApp LUN.")
            raise exception.VolumeBackendAPIException(data=msg)
        self.lun_table[lun.name] = lun

    def get_lun(self, name):
        """Gets LUN from cache table.

        Refreshes cache if lun not found in cache.
        """
        lun = self.lun_table.get(name)
        if lun is None:
            self.get_lun_list()
            lun = self.lun_table.get(name)
            if lun is None:
                raise exception.VolumeNotFound(volume_id=name)
        return lun

    def get_lun_list(self):
        """Gets the list of luns on filer."""
        raise NotImplementedError()

    def _extract_and_populate_luns(self, api_luns):
        """Extracts the luns from api.

        Populates in the lun table.
        """

        for lun in api_luns:
            meta_dict = self._create_lun_meta(lun)
            path = lun.get_child_content('path')
            (rest, splitter, name) = path.rpartition('/')
            handle = self.create_lun_handle(meta_dict)
            size = lun.get_child_content('size')
            discovered_lun = NetAppLun(handle, name,
                                       size, meta_dict)
            self.add_lun_to_table(discovered_lun)

    def create_lun_handle(self, metadata):
        """Returns lun handle based on filer type."""
        raise NotImplementedError()

    def _is_naelement(self, elem):
        """Checks if element is NetApp element."""
        if not isinstance(elem, NaElement):
            raise ValueError('Expects NaElement')

    def get_iscsi_service_details(self):
        raise NotImplementedError()

    def get_target_details(self):
        raise NotImplementedError()


class cdotFiler(filer):
    ''' A NetApp CDOT Filer object '''
    
    DEFAULT_VS = 'openstack'
    
    def __init__(self, *args, **kwargs):
        """Instantiate a client for NetApp server api communication."""

        super(cdotFiler, self).__init__(*args, **kwargs)
        self.vserver = kwargs['vserver']
        self.vserver = self.vserver if self.vserver else self.DEFAULT_VS
        # We set vserver in client permanently.
        # To use tunneling enable_tunneling while invoking api
        self.client.set_vserver(self.vserver)
        # Default values to run first api
        self.client.set_api_version(1, 15)
        (major, minor) = self.get_ontapi_version()
        self.client.set_api_version(major, minor)
        self.stale_vols = set()

    def get_lun_list(self):
        """Gets the list of luns on filer.

        Gets the luns from cluster with vserver.
        """

        tag = None
        while True:
            api = NaElement('lun-get-iter')
            api.add_new_child('max-records', '100')
            if tag:
                api.add_new_child('tag', tag, True)
            lun_info = NaElement('lun-info')
            lun_info.add_new_child('vserver', self.vserver)
            query = NaElement('query')
            query.add_child_elem(lun_info)
            api.add_child_elem(query)
            result = self.client.invoke_successfully(api)
            if result.get_child_by_name('num-records') and\
                    int(result.get_child_content('num-records')) >= 1:
                attr_list = result.get_child_by_name('attributes-list')
                self._extract_and_populate_luns(attr_list.get_children())
            tag = result.get_child_content('next-tag')
            if tag is None:
                break

    def get_iscsi_service_details(self):
        """Returns iscsi iqn."""
        iscsi_service_iter = NaElement('iscsi-service-get-iter')
        result = self.client.invoke_successfully(iscsi_service_iter, True)
        if result.get_child_content('num-records') and\
                int(result.get_child_content('num-records')) >= 1:
            attr_list = result.get_child_by_name('attributes-list')
            iscsi_service = attr_list.get_child_by_name('iscsi-service-info')
            return iscsi_service.get_child_content('node-name')
        LOG.debug(_('No iscsi service found for vserver %s') % (self.vserver))
        return None

    def get_target_details(self):
        """Gets the target portal details."""
        iscsi_if_iter = NaElement('iscsi-interface-get-iter')
        result = self.client.invoke_successfully(iscsi_if_iter, True)
        tgt_list = []
        if result.get_child_content('num-records')\
                and int(result.get_child_content('num-records')) >= 1:
            attr_list = result.get_child_by_name('attributes-list')
            iscsi_if_list = attr_list.get_children()
            for iscsi_if in iscsi_if_list:
                d = dict()
                d['address'] = iscsi_if.get_child_content('ip-address')
                d['port'] = iscsi_if.get_child_content('ip-port')
                d['tpgroup-tag'] = iscsi_if.get_child_content('tpgroup-tag')
                d['interface-enabled'] = iscsi_if.get_child_content(
                    'is-interface-enabled')
                tgt_list.append(d)
        return tgt_list

    def create_lun_handle(self, metadata):
        """Returns lun handle based on filer type."""
        return '%s:%s' % (self.vserver, metadata['Path'])

    def _get_igroup_by_initiator(self, initiator):
        """Get igroups by initiator."""
        tag = None
        igroup_list = []
        while True:
            igroup_iter = NaElement('igroup-get-iter')
            igroup_iter.add_new_child('max-records', '100')
            if tag:
                igroup_iter.add_new_child('tag', tag, True)
            query = NaElement('query')
            igroup_iter.add_child_elem(query)
            igroup_info = NaElement('initiator-group-info')
            query.add_child_elem(igroup_info)
            igroup_info.add_new_child('vserver', self.vserver)
            initiators = NaElement('initiators')
            igroup_info.add_child_elem(initiators)
            initiators.add_node_with_children('initiator-info',
                                              **{'initiator-name': initiator})
            des_attrs = NaElement('desired-attributes')
            des_ig_info = NaElement('initiator-group-info')
            des_attrs.add_child_elem(des_ig_info)
            des_ig_info.add_node_with_children('initiators',
                                               **{'initiator-info': None})
            des_ig_info.add_new_child('vserver', None)
            des_ig_info.add_new_child('initiator-group-name', None)
            des_ig_info.add_new_child('initiator-group-type', None)
            des_ig_info.add_new_child('initiator-group-os-type', None)
            igroup_iter.add_child_elem(des_attrs)
            result = self.client.invoke_successfully(igroup_iter, False)
            tag = result.get_child_content('next-tag')
            if result.get_child_content('num-records') and\
                    int(result.get_child_content('num-records')) > 0:
                attr_list = result.get_child_by_name('attributes-list')
                igroups = attr_list.get_children()
                for igroup in igroups:
                    ig = dict()
                    ig['initiator-group-os-type'] = igroup.get_child_content(
                        'initiator-group-os-type')
                    ig['initiator-group-type'] = igroup.get_child_content(
                        'initiator-group-type')
                    ig['initiator-group-name'] = igroup.get_child_content(
                        'initiator-group-name')
                    igroup_list.append(ig)
            if tag is None:
                break
        return igroup_list

    def clone_lun(self, name, new_name, space_reserved='true',
                   src_block=0, dest_block=0, block_count=0):
        """Clone LUN with the given handle to the new name."""
        metadata = self.get_lun_attr(name, 'metadata')
        volume = metadata['Volume']
        # zAPI can only handle 2^24 blocks per range
        bc_limit = 2 ** 24  # 8GB
        # zAPI can only handle 32 block ranges per call
        br_limit = 32
        z_limit = br_limit * bc_limit  # 256 GB
        z_calls = int(math.ceil(block_count / float(z_limit)))
        zbc = block_count
        if z_calls == 0:
            z_calls = 1
        for call in range(0, z_calls):
            if zbc > z_limit:
                block_count = z_limit
                zbc -= z_limit
            else:
                block_count = zbc
            clone_create = NaElement.create_node_with_children(
                'clone-create',
                **{'volume': volume, 'source-path': name,
                   'destination-path': new_name,
                   'space-reserve': space_reserved})
            if block_count > 0:
                block_ranges = NaElement("block-ranges")
                segments = int(math.ceil(block_count / float(bc_limit)))
                bc = block_count
                for segment in range(0, segments):
                    if bc > bc_limit:
                        block_count = bc_limit
                        bc -= bc_limit
                    else:
                        block_count = bc
                    block_range = NaElement.create_node_with_children(
                        'block-range',
                        **{'source-block-number': str(src_block),
                           'destination-block-number': str(dest_block),
                           'block-count': str(block_count)})
                    block_ranges.add_child_elem(block_range)
                    src_block += int(block_count)
                    dest_block += int(block_count)
                clone_create.add_child_elem(block_ranges)
            self.client.invoke_successfully(clone_create, True)
        LOG.debug(_("Cloned LUN with new name %s") % new_name)
        lun = self.get_lun_by_args(vserver=self.vserver, path='/vol/%s/%s'
                                    % (volume, new_name))
        if len(lun) == 0:
            msg = _("No cloned lun named %s found on the filer")
            raise exception.VolumeBackendAPIException(data=msg % (new_name))
        clone_meta = self._create_lun_meta(lun[0])
        self.add_lun_to_table(NetAppLun('%s:%s' % (clone_meta['Vserver'],
                                                    clone_meta['Path']),
                                         new_name,
                                         lun[0].get_child_content('size'),
                                         clone_meta))
        self.update_stale_vols(
            volume=ssc_utils.NetAppVolume(volume, self.vserver))

    def get_lun_by_args(self, **args):
        """Retrieves lun with specified args."""
        lun_iter = NaElement('lun-get-iter')
        lun_iter.add_new_child('max-records', '100')
        query = NaElement('query')
        lun_iter.add_child_elem(query)
        query.add_node_with_children('lun-info', **args)
        luns = self.client.invoke_successfully(lun_iter)
        attr_list = luns.get_child_by_name('attributes-list')
        return attr_list.get_children()

    def _find_mapped_lun_igroup(self, path, initiator, os=None):
        """Find the igroup for mapped lun with initiator."""
        initiator_igroups = \
            self._get_igroup_by_initiator(initiator=initiator)
        lun_maps = self._get_lun_map(path)
        if initiator_igroups and lun_maps:
            for igroup in initiator_igroups:
                igroup_name = igroup['initiator-group-name']
                if igroup_name.startswith(self.IGROUP_PREFIX):
                    for lun_map in lun_maps:
                        if lun_map['initiator-group'] == igroup_name:
                            return (igroup_name, lun_map['lun-id'])
        return (None, None)

    def _get_lun_map(self, path):
        """Gets the lun map by lun path."""
        tag = None
        map_list = []
        while True:
            lun_map_iter = NaElement('lun-map-get-iter')
            lun_map_iter.add_new_child('max-records', '100')
            if tag:
                lun_map_iter.add_new_child('tag', tag, True)
            query = NaElement('query')
            lun_map_iter.add_child_elem(query)
            query.add_node_with_children('lun-map-info', **{'path': path})
            result = self.client.invoke_successfully(lun_map_iter, True)
            tag = result.get_child_content('next-tag')
            if result.get_child_content('num-records') and \
                    int(result.get_child_content('num-records')) >= 1:
                attr_list = result.get_child_by_name('attributes-list')
                lun_maps = attr_list.get_children()
                for lun_map in lun_maps:
                    lun_m = dict()
                    lun_m['initiator-group'] = lun_map.get_child_content(
                        'initiator-group')
                    lun_m['lun-id'] = lun_map.get_child_content('lun-id')
                    lun_m['vserver'] = lun_map.get_child_content('vserver')
                    map_list.append(lun_m)
            if tag is None:
                break
        return map_list

    def _create_lun_meta(self, lun):
        """Creates lun metadata dictionary."""
        self._is_naelement(lun)
        meta_dict = {}
        self._is_naelement(lun)
        meta_dict['Vserver'] = lun.get_child_content('vserver')
        meta_dict['Volume'] = lun.get_child_content('volume')
        meta_dict['Qtree'] = lun.get_child_content('qtree')
        meta_dict['Path'] = lun.get_child_content('path')
        meta_dict['OsType'] = lun.get_child_content('multiprotocol-type')
        meta_dict['SpaceReserved'] = \
            lun.get_child_content('is-space-reservation-enabled')
        return meta_dict

    @utils.synchronized('update_stale')
    def update_stale_vols(self, volume=None, reset=False):
        """Populates stale vols with vol and returns set copy if reset."""
        if volume:
            self.stale_vols.add(volume)
        if reset:
            set_copy = copy.deepcopy(self.stale_vols)
            self.stale_vols.clear()
            return set_copy


class sevenFiler(filer):
    ''' A NetApp 7Mode Filer object '''
    
    def __init__(self, *args, **kwargs):
        """Instantiate a client for NetApp server api communication."""

        super(sevenFiler, self).__init__(*args, **kwargs)

    def check_for_setup_error(self):
        """Check that the driver is working and can communicate."""
        api_version = self.client.get_api_version()
        if api_version:
            major, minor = api_version
            if major == 1 and minor < 9:
                msg = _("Unsupported ONTAP version."
                        " ONTAP version 7.3.1 and above is supported.")
                raise exception.VolumeBackendAPIException(data=msg)
        else:
            msg = _("Api version could not be determined.")
            raise exception.VolumeBackendAPIException(data=msg)

    def _get_igroup_by_initiator(self, initiator):
        """Get igroups by initiator."""
        igroup_list = NaElement('igroup-list-info')
        result = self.client.invoke_successfully(igroup_list, True)
        igroups = []
        igs = result.get_child_by_name('initiator-groups')
        if igs:
            ig_infos = igs.get_children()
            if ig_infos:
                for info in ig_infos:
                    initiators = info.get_child_by_name('initiators')
                    init_infos = initiators.get_children()
                    if init_infos:
                        for init in init_infos:
                            if init.get_child_content('initiator-name')\
                                    == initiator:
                                d = dict()
                                d['initiator-group-os-type'] = \
                                    info.get_child_content(
                                        'initiator-group-os-type')
                                d['initiator-group-type'] = \
                                    info.get_child_content(
                                        'initiator-group-type')
                                d['initiator-group-name'] = \
                                    info.get_child_content(
                                        'initiator-group-name')
                                igroups.append(d)
        return igroups

    def get_filer_volumes(self, volume=None):
        """Returns list of filer volumes in api format."""
        vol_request = NaElement('volume-list-info')
        if volume:
            vol_request.add_new_child('volume', volume)
        res = self.client.invoke_successfully(vol_request, True)
        volumes = res.get_child_by_name('volumes')
        if volumes:
            return volumes.get_children()
        return []

    def get_lun_by_args(self, **args):
        """Retrieves luns with specified args."""
        lun_info = NaElement.create_node_with_children('lun-list-info', **args)
        result = self.client.invoke_successfully(lun_info, True)
        luns = result.get_child_by_name('luns')
        return luns.get_children()

    def get_target_details(self):
        """Gets the target portal details."""
        iscsi_if_iter = NaElement('iscsi-portal-list-info')
        result = self.client.invoke_successfully(iscsi_if_iter, True)
        tgt_list = []
        portal_list_entries = result.get_child_by_name(
            'iscsi-portal-list-entries')
        if portal_list_entries:
            portal_list = portal_list_entries.get_children()
            for iscsi_if in portal_list:
                d = dict()
                d['address'] = iscsi_if.get_child_content('ip-address')
                d['port'] = iscsi_if.get_child_content('ip-port')
                d['tpgroup-tag'] = iscsi_if.get_child_content('tpgroup-tag')
                tgt_list.append(d)
        return tgt_list

    def get_iscsi_service_details(self):
        """Returns iscsi iqn."""
        iscsi_service_iter = NaElement('iscsi-node-get-name')
        result = self.client.invoke_successfully(iscsi_service_iter, True)
        return result.get_child_content('node-name')

    def get_vol_luns(self, vol_name):
        """Gets the luns for a volume."""
        api = NaElement('lun-list-info')
        if vol_name:
            api.add_new_child('volume-name', vol_name)
        result = self.client.invoke_successfully(api, True)
        luns = result.get_child_by_name('luns')
        return luns.get_children()

    def _find_mapped_lun_igroup(self, path, initiator, os=None):
        """Find the igroup for mapped lun with initiator."""
        lun_map_list = NaElement.create_node_with_children(
            'lun-map-list-info',
            **{'path': path})
        result = self.client.invoke_successfully(lun_map_list, True)
        igroups = result.get_child_by_name('initiator-groups')
        if igroups:
            igroup = None
            lun_id = None
            found = False
            igroup_infs = igroups.get_children()
            for ig in igroup_infs:
                initiators = ig.get_child_by_name('initiators')
                init_infs = initiators.get_children()
                for info in init_infs:
                    if info.get_child_content('initiator-name') == initiator:
                        found = True
                        igroup = ig.get_child_content('initiator-group-name')
                        lun_id = ig.get_child_content('lun-id')
                        break
                if found:
                    break
        return (igroup, lun_id)

    def clone_lun(self, name, new_name, space_reserved='true',
                   src_block=0, dest_block=0, block_count=0):
        """Clone LUN with the given handle to the new name."""
        metadata = self.get_lun_attr(name, 'metadata')
        path = metadata['Path']
        (parent, splitter, name) = path.rpartition('/')
        clone_path = '%s/%s' % (parent, new_name)
        # zAPI can only handle 2^24 blocks per range
        bc_limit = 2 ** 24  # 8GB
        # zAPI can only handle 32 block ranges per call
        br_limit = 32
        z_limit = br_limit * bc_limit  # 256 GB
        z_calls = int(math.ceil(block_count / float(z_limit)))
        zbc = block_count
        if z_calls == 0:
            z_calls = 1
        for call in range(0, z_calls):
            if zbc > z_limit:
                block_count = z_limit
                zbc -= z_limit
            else:
                block_count = zbc
            clone_start = NaElement.create_node_with_children(
                'clone-start', **{'source-path': path,
                                  'destination-path': clone_path,
                                  'no-snap': 'true'})
            if block_count > 0:
                block_ranges = NaElement("block-ranges")
                # zAPI can only handle 2^24 block ranges
                bc_limit = 2 ** 24  # 8GB
                segments = int(math.ceil(block_count / float(bc_limit)))
                bc = block_count
                for segment in range(0, segments):
                    if bc > bc_limit:
                        block_count = bc_limit
                        bc -= bc_limit
                    else:
                        block_count = bc
                    block_range = NaElement.create_node_with_children(
                        'block-range',
                        **{'source-block-number': str(src_block),
                            'destination-block-number': str(dest_block),
                            'block-count': str(block_count)})
                    block_ranges.add_child_elem(block_range)
                    src_block += int(block_count)
                    dest_block += int(block_count)
                clone_start.add_child_elem(block_ranges)
            result = self.client.invoke_successfully(clone_start, True)
            clone_id_el = result.get_child_by_name('clone-id')
            cl_id_info = clone_id_el.get_child_by_name('clone-id-info')
            vol_uuid = cl_id_info.get_child_content('volume-uuid')
            clone_id = cl_id_info.get_child_content('clone-op-id')
            if vol_uuid:
                self._check_clone_status(clone_id, vol_uuid, name, new_name)
        self.vol_refresh_voluntary = True
        luns = self.get_lun_by_args(path=clone_path)
        if luns:
            cloned_lun = luns[0]
            self._set_space_reserve(clone_path, space_reserved)
            clone_meta = self._create_lun_meta(cloned_lun)
            handle = self.create_lun_handle(clone_meta)
            self.add_lun_to_table(
                NetAppLun(handle, new_name,
                          cloned_lun.get_child_content('size'),
                          clone_meta))
        else:
            raise NaApiError('ENOLUNENTRY', 'No Lun entry found on the filer')

    def _set_space_reserve(self, path, enable):
        """Sets the space reserve info."""
        space_res = NaElement.create_node_with_children(
            'lun-set-space-reservation-info',
            **{'path': path, 'enable': enable})
        self.client.invoke_successfully(space_res, True)

    def _check_clone_status(self, clone_id, vol_uuid, name, new_name):
        """Checks for the job till completed."""
        clone_status = NaElement('clone-list-status')
        cl_id = NaElement('clone-id')
        clone_status.add_child_elem(cl_id)
        cl_id.add_node_with_children(
            'clone-id-info',
            **{'clone-op-id': clone_id, 'volume-uuid': vol_uuid})
        running = True
        clone_ops_info = None
        while running:
            result = self.client.invoke_successfully(clone_status, True)
            status = result.get_child_by_name('status')
            ops_info = status.get_children()
            if ops_info:
                for info in ops_info:
                    if info.get_child_content('clone-state') == 'running':
                        time.sleep(1)
                        break
                    else:
                        running = False
                        clone_ops_info = info
                        break
        else:
            if clone_ops_info:
                fmt = {'name': name, 'new_name': new_name}
                if clone_ops_info.get_child_content('clone-state')\
                        == 'completed':
                    LOG.debug(_("Clone operation with src %(name)s"
                                " and dest %(new_name)s completed") % fmt)
                else:
                    LOG.debug(_("Clone operation with src %(name)s"
                                " and dest %(new_name)s failed") % fmt)
                    raise NaApiError(
                        clone_ops_info.get_child_content('error'),
                        clone_ops_info.get_child_content('reason'))

    def _create_lun_meta(self, lun):
        """Creates lun metadata dictionary."""
        self._is_naelement(lun)
        meta_dict = {}
        self._is_naelement(lun)
        meta_dict['Path'] = lun.get_child_content('path')
        meta_dict['OsType'] = lun.get_child_content('multiprotocol-type')
        meta_dict['SpaceReserved'] = lun.get_child_content(
            'is-space-reservation-enabled')
        return meta_dict

    def create_lun_handle(self, metadata):
        """Returns lun handle based on filer type."""
        if self.vfiler:
            owner = '%s:%s' % (self.configuration.netapp_server_hostname,
                               self.vfiler)
        else:
            owner = self.configuration.netapp_server_hostname
        return '%s:%s' % (owner, metadata['Path'])
