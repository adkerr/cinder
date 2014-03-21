# Copyright (c) 2012 NetApp, Inc.
# Copyright (c) 2012 OpenStack Foundation
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
Volume driver for NetApp iSCSI storage systems.

This driver requires NetApp Clustered Data ONTAP or 7-mode
storage systems with installed iSCSI licenses.
"""

from cinder import exception
from cinder.openstack.common import excutils
from cinder.openstack.common import log as logging
from cinder.openstack.common import timeutils
from cinder import units
from cinder import utils
from cinder.volume import driver
from cinder.volume.drivers.netapp.api import NaApiError
from cinder.volume.drivers.netapp.ontap import NetAppLun
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

from cinder.volume.drivers.netapp.ontap import cdotFiler as cdot
from cinder.volume.drivers.netapp.ontap import sevenFiler as seven_mode


LOG = logging.getLogger(__name__)


class NetAppDirectISCSIDriver(driver.ISCSIDriver):
    """NetApp Direct iSCSI volume driver."""

    VERSION = "1.0.0"

    required_flags = ['netapp_transport_type', 'netapp_login',
                      'netapp_password', 'netapp_server_hostname',
                      'netapp_server_port']

    def __init__(self, *args, **kwargs):
        super(NetAppDirectISCSIDriver, self).__init__(*args, **kwargs)
        validate_instantiation(**kwargs)
        self.configuration.append_config_values(netapp_connection_opts)
        self.configuration.append_config_values(netapp_basicauth_opts)
        self.configuration.append_config_values(netapp_transport_opts)
        self.configuration.append_config_values(netapp_provisioning_opts)

    def _do_custom_setup(self):
        """Does custom setup depending on the type of filer."""
        raise NotImplementedError()

    def _check_flags(self):
        """Ensure that the flags we care about are set."""
        required_flags = self.required_flags
        for flag in required_flags:
            if not getattr(self.configuration, flag, None):
                msg = _('%s is not set') % flag
                raise exception.InvalidInput(reason=msg)

    def do_setup(self, context):
        """Setup the NetApp Volume driver.

        Called one time by the manager after the driver is loaded.
        Validate the flags we care about and setup NetApp
        client.
        """

        self._check_flags()
        self._do_custom_setup()

    def check_for_setup_error(self):
        """Check that the driver is working and can communicate.

        Discovers the LUNs on the NetApp server.
        """

        self.filer.lun_table = {}
        self.filer.get_lun_list()
        LOG.debug(_("Success getting LUN list from server"))

    def create_volume(self, volume):
        """Driver entry point for creating a new volume."""
        default_size = '104857600'  # 100 MB
        gigabytes = 1073741824L  # 2^30
        name = volume['name']
        if int(volume['size']) == 0:
            size = default_size
        else:
            size = str(int(volume['size']) * gigabytes)
        metadata = {}
        metadata['OsType'] = 'linux'
        metadata['SpaceReserved'] = 'true'
        extra_specs = get_volume_extra_specs(volume)
        self._create_lun_on_eligible_vol(name, size, metadata, extra_specs)
        LOG.debug(_("Created LUN with name %s") % name)
        handle = self.filer.create_lun_handle(metadata)
        self.filer.add_lun_to_table(NetAppLun(handle, name, size, metadata))

    def delete_volume(self, volume):
        """Driver entry point for destroying existing volumes."""
        name = volume['name']
        metadata = self.filer.get_lun_attr(name, 'metadata')
        if not metadata:
            msg = _("No entry in LUN table for volume/snapshot %(name)s.")
            msg_fmt = {'name': name}
            LOG.warn(msg % msg_fmt)
            return
        self.filer.destroy_lun(metadata['Path'])
        self.filer.lun_table.pop(name)

    def ensure_export(self, context, volume):
        """Driver entry point to get the export info for an existing volume."""
        handle = self.filer.get_lun_attr(volume['name'], 'handle')
        return {'provider_location': handle}

    def create_export(self, context, volume):
        """Driver entry point to get the export info for a new volume."""
        handle = self.filer.get_lun_attr(volume['name'], 'handle')
        return {'provider_location': handle}

    def remove_export(self, context, volume):
        """Driver entry point to remove an export for a volume.

        Since exporting is idempotent in this driver, we have nothing
        to do for unexporting.
        """

        pass

    def initialize_connection(self, volume, connector):
        """Driver entry point to attach a volume to an instance.

        Do the LUN masking on the storage system so the initiator can access
        the LUN on the target. Also return the iSCSI properties so the
        initiator can find the LUN. This implementation does not call
        _get_iscsi_properties() to get the properties because cannot store the
        LUN number in the database. We only find out what the LUN number will
        be during this method call so we construct the properties dictionary
        ourselves.
        """

        initiator_name = connector['initiator']
        name = volume['name']
        lun_id = self.filer.map_lun(name, initiator_name, 'iscsi', None)
        msg = _("Mapped LUN %(name)s to the initiator %(initiator_name)s")
        msg_fmt = {'name': name, 'initiator_name': initiator_name}
        LOG.debug(msg % msg_fmt)
        iqn = self.filer.get_iscsi_service_details()
        target_details_list = self.filer.get_target_details()
        msg = _("Successfully fetched target details for LUN %(name)s and "
                "initiator %(initiator_name)s")
        msg_fmt = {'name': name, 'initiator_name': initiator_name}
        LOG.debug(msg % msg_fmt)

        if not target_details_list:
            msg = _('Failed to get LUN target details for the LUN %s')
            raise exception.VolumeBackendAPIException(data=msg % name)
        target_details = None
        for tgt_detail in target_details_list:
            if tgt_detail.get('interface-enabled', 'true') == 'true':
                target_details = tgt_detail
                break
        if not target_details:
            target_details = target_details_list[0]

        if not target_details['address'] and target_details['port']:
            msg = _('Failed to get target portal for the LUN %s')
            raise exception.VolumeBackendAPIException(data=msg % name)
        if not iqn:
            msg = _('Failed to get target IQN for the LUN %s')
            raise exception.VolumeBackendAPIException(data=msg % name)

        properties = {}
        properties['target_discovered'] = False
        (address, port) = (target_details['address'], target_details['port'])
        properties['target_portal'] = '%s:%s' % (address, port)
        properties['target_iqn'] = iqn
        properties['target_lun'] = lun_id
        properties['volume_id'] = volume['id']

        auth = volume['provider_auth']
        if auth:
            (auth_method, auth_username, auth_secret) = auth.split()
            properties['auth_method'] = auth_method
            properties['auth_username'] = auth_username
            properties['auth_password'] = auth_secret

        return {
            'driver_volume_type': 'iscsi',
            'data': properties,
        }

    def create_snapshot(self, snapshot):
        """Driver entry point for creating a snapshot.

        This driver implements snapshots by using efficient single-file
        (LUN) cloning.
        """

        vol_name = snapshot['volume_name']
        snapshot_name = snapshot['name']
        lun = self.filer.get_lun(vol_name)
        self.filer.clone_lun(lun.name, snapshot_name, 'false')

    def delete_snapshot(self, snapshot):
        """Driver entry point for deleting a snapshot."""
        self.delete_volume(snapshot)
        LOG.debug(_("Snapshot %s deletion successful") % snapshot['name'])

    def create_volume_from_snapshot(self, volume, snapshot):
        """Driver entry point for creating a new volume from a snapshot.

        Many would call this "cloning" and in fact we use cloning to implement
        this feature.
        """

        vol_size = volume['size']
        snap_size = snapshot['volume_size']
        snapshot_name = snapshot['name']
        new_name = volume['name']
        self.filer.clone_lun(snapshot_name, new_name, 'true')
        if vol_size != snap_size:
            try:
                self.extend_volume(volume, volume['size'])
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(
                        _("Resizing %s failed. Cleaning volume."), new_name)
                    self.delete_volume(volume)

    def terminate_connection(self, volume, connector, **kwargs):
        """Driver entry point to unattach a volume from an instance.

        Unmask the LUN on the storage system so the given initiator can no
        longer access it.
        """

        initiator_name = connector['initiator']
        name = volume['name']
        metadata = self.filer.get_lun_attr(name, 'metadata')
        path = metadata['Path']
        self.filer.unmap_lun(path, initiator_name)
        msg = _("Unmapped LUN %(name)s from the initiator "
                "%(initiator_name)s")
        msg_fmt = {'name': name, 'initiator_name': initiator_name}
        LOG.debug(msg % msg_fmt)

    def _create_lun_on_eligible_vol(self, name, size, metadata,
                                    extra_specs=None):
        """Creates an actual lun on filer."""
        raise NotImplementedError()

    def create_cloned_volume(self, volume, src_vref):
        """Creates a clone of the specified volume."""
        vol_size = volume['size']
        src_vol = self.filer.get_lun(src_vref['name'])
        src_vol_size = src_vref['size']
        new_name = volume['name']
        self.filer.clone_lun(src_vol.name, new_name, 'true')
        if vol_size != src_vol_size:
            try:
                self.extend_volume(volume, volume['size'])
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(
                        _("Resizing %s failed. Cleaning volume."), new_name)
                    self.delete_volume(volume)

    def get_volume_stats(self, refresh=False):
        """Get volume stats.

        If 'refresh' is True, run update the stats first.
        """

        if refresh:
            self._update_volume_stats()

        return self._stats

    def _update_volume_stats(self):
        """Retrieve stats info from volume group."""
        raise NotImplementedError()

    def extend_volume(self, volume, new_size):
        """Extend an existing volume to the new size."""
        name = volume['name']
        path = self.filer.get_lun(name).metadata['Path']
        curr_size_bytes = str(self.filer.get_lun(name).size)
        new_size_bytes = str(int(new_size) * units.GiB)
        # Reused by clone scenarios.
        # Hence comparing the stored size.
        if curr_size_bytes != new_size_bytes:
            lun_geometry = self.filer.get_lun_geometry(path)
            if (lun_geometry and lun_geometry.get("max_resize")
                    and int(lun_geometry.get("max_resize")) >=
                    int(new_size_bytes)):
                self.filer.do_direct_resize(path, new_size_bytes)
            else:
                self._do_sub_clone_resize(path, new_size_bytes)
            self.filer.get_lun(name).size = new_size_bytes
        else:
            LOG.info(_("No need to extend volume %s"
                       " as it is already the requested new size."), name)

    def _get_vol_option(self, volume_name, option_name):
        """Get the value for the volume option."""
        value = None
        options = self.filer.get_volume_options(volume_name)
        for opt in options:
            if opt.get_child_content('name') == option_name:
                value = opt.get_child_content('value')
                break
        return value

    def _do_sub_clone_resize(self, path, new_size_bytes):
        """Does sub lun clone after verification.

            Clones the block ranges and swaps
            the luns also deletes older lun
            after a successful clone.
        """
        seg = path.split("/")
        LOG.info(_("Resizing lun %s using sub clone to new size."), seg[-1])
        name = seg[-1]
        vol_name = seg[2]
        lun = self.filer.get_lun(name)
        metadata = lun.metadata
        compression = self._get_vol_option(vol_name, 'compression')
        if compression == "on":
            msg = _('%s cannot be sub clone resized'
                    ' as it is hosted on compressed volume')
            raise exception.VolumeBackendAPIException(data=msg % name)
        else:
            block_count = self._get_lun_block_count(path)
            if block_count == 0:
                msg = _('%s cannot be sub clone resized'
                        ' as it contains no blocks.')
                raise exception.VolumeBackendAPIException(data=msg % name)
            new_lun = 'new-%s' % (name)
            self.filer.create_lun(vol_name, new_lun, new_size_bytes, metadata)
            try:
                self.filer.clone_lun(name, new_lun, block_count=block_count)
                self._post_sub_clone_resize(path)
            except Exception:
                with excutils.save_and_reraise_exception():
                    new_path = '/vol/%s/%s' % (vol_name, new_lun)
                    self.filer.destroy_lun(new_path)

    def _post_sub_clone_resize(self, path):
        """Try post sub clone resize in a transactional manner."""
        st_tm_mv, st_nw_mv, st_del_old = None, None, None
        seg = path.split("/")
        LOG.info(_("Post clone resize lun %s"), seg[-1])
        new_lun = 'new-%s' % (seg[-1])
        tmp_lun = 'tmp-%s' % (seg[-1])
        tmp_path = "/vol/%s/%s" % (seg[2], tmp_lun)
        new_path = "/vol/%s/%s" % (seg[2], new_lun)
        try:
            st_tm_mv = self.filer.move_lun(path, tmp_path)
            st_nw_mv = self.filer.move_lun(new_path, path)
            st_del_old = self.filer.destroy_lun(tmp_path)
        except Exception as e:
            if st_tm_mv is None:
                msg = _("Failure staging lun %s to tmp.")
                raise exception.VolumeBackendAPIException(data=msg % (seg[-1]))
            else:
                if st_nw_mv is None:
                    self.filer.move_lun(tmp_path, path)
                    msg = _("Failure moving new cloned lun to %s.")
                    raise exception.VolumeBackendAPIException(
                        data=msg % (seg[-1]))
                elif st_del_old is None:
                    LOG.error(_("Failure deleting staged tmp lun %s."),
                              tmp_lun)
                else:
                    LOG.error(_("Unknown exception in"
                                " post clone resize lun %s."), seg[-1])
                    LOG.error(_("Exception details: %s") % (e.__str__()))

    def _get_lun_block_count(self, path):
        """Gets block counts for the lun."""
        LOG.debug(_("Getting lun block count."))
        lun_infos = self.filer.get_lun_by_args(path=path)
        if not lun_infos:
            seg = path.split('/')
            msg = _('Failure getting lun info for %s.')
            raise exception.VolumeBackendAPIException(data=msg % seg[-1])
        lun_info = lun_infos[-1]
        bs = int(lun_info.get_child_content('block-size'))
        ls = int(lun_info.get_child_content('size'))
        block_count = ls / bs
        return block_count


class NetAppDirectCmodeISCSIDriver(NetAppDirectISCSIDriver):
    """NetApp C-mode iSCSI volume driver."""

    DEFAULT_VS = 'openstack'

    def __init__(self, *args, **kwargs):
        super(NetAppDirectCmodeISCSIDriver, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(netapp_cluster_opts)

    def _do_custom_setup(self):
        """Does custom setup for ontap cluster."""
        self.filer = cdot(
            transport_type=self.configuration.netapp_transport_type,
            login=self.configuration.netapp_login,
            password=self.configuration.netapp_password,
            hostname=self.configuration.netapp_server_hostname,
            port=self.configuration.netapp_server_port,
            vserver = self.configuration.netapp_vserver)
        self.ssc_vols = None


    def check_for_setup_error(self):
        """Check that the driver is working and can communicate."""
        ssc_utils.check_ssc_api_permissions(self.filer.client)
        super(NetAppDirectCmodeISCSIDriver, self).check_for_setup_error()

    def _create_lun_on_eligible_vol(self, name, size, metadata,
                                    extra_specs=None):
        """Creates an actual lun on filer."""
        req_size = float(size) *\
            float(self.configuration.netapp_size_multiplier)
        qos_policy_group = None
        if extra_specs:
            qos_policy_group = extra_specs.pop('netapp:qos_policy_group', None)
        volumes = self._get_avl_volumes(req_size, extra_specs)
        if not volumes:
            msg = _('Failed to get vol with required'
                    ' size and extra specs for volume: %s')
            raise exception.VolumeBackendAPIException(data=msg % name)
        for volume in volumes:
            try:
                self.filer.create_lun(volume.id['name'], name, size, metadata,
                                      qos_policy_group=qos_policy_group)
                metadata['Path'] = '/vol/%s/%s' % (volume.id['name'], name)
                metadata['Volume'] = volume.id['name']
                metadata['Qtree'] = None
                return
            except NaApiError as ex:
                msg = _("Error provisioning vol %(name)s on "
                        "%(volume)s. Details: %(ex)s")
                LOG.error(msg % {'name': name,
                                 'volume': volume.id['name'],
                                 'ex': ex})
            finally:
                self.filer.update_stale_vols(volume=volume)

    def _get_avl_volumes(self, size, extra_specs=None):
        """Get the available volume by size, extra_specs."""
        result = []
        volumes = ssc_utils.get_volumes_for_specs(
            self.ssc_vols, extra_specs)
        if volumes:
            sorted_vols = sorted(volumes, reverse=True)
            for vol in sorted_vols:
                if int(vol.space['size_avl_bytes']) >= int(size):
                    result.append(vol)
        return result

    def _update_volume_stats(self):
        """Retrieve stats info from volume group."""

        LOG.debug(_("Updating volume stats"))
        data = {}
        netapp_backend = 'NetApp_iSCSI_Cluster_direct'
        backend_name = self.configuration.safe_get('volume_backend_name')
        data["volume_backend_name"] = (
            backend_name or netapp_backend)
        data["vendor_name"] = 'NetApp'
        data["driver_version"] = '1.0'
        data["storage_protocol"] = 'iSCSI'

        data['total_capacity_gb'] = 0
        data['free_capacity_gb'] = 0
        data['reserved_percentage'] = 0
        data['QoS_support'] = False
        self._update_cluster_vol_stats(data)
        provide_ems(self, self.filer.client, data, netapp_backend)
        self._stats = data

    def _update_cluster_vol_stats(self, data):
        """Updates vol stats with cluster config."""
        sync = True if self.ssc_vols is None else False
        ssc_utils.refresh_cluster_ssc(self, self.filer.client,
                                      self.filer.vserver,
                                      synchronous=sync)
        if self.ssc_vols:
            data['netapp_mirrored'] = 'true'\
                if self.ssc_vols['mirrored'] else 'false'
            data['netapp_unmirrored'] = 'true'\
                if len(self.ssc_vols['all']) > len(self.ssc_vols['mirrored'])\
                else 'false'
            data['netapp_dedup'] = 'true'\
                if self.ssc_vols['dedup'] else 'false'
            data['netapp_nodedup'] = 'true'\
                if len(self.ssc_vols['all']) > len(self.ssc_vols['dedup'])\
                else 'false'
            data['netapp_compression'] = 'true'\
                if self.ssc_vols['compression'] else 'false'
            data['netapp_nocompression'] = 'true'\
                if len(self.ssc_vols['all']) >\
                len(self.ssc_vols['compression'])\
                else 'false'
            data['netapp_thin_provisioned'] = 'true'\
                if self.ssc_vols['thin'] else 'false'
            data['netapp_thick_provisioned'] = 'true'\
                if len(self.ssc_vols['all']) >\
                len(self.ssc_vols['thin']) else 'false'
            if self.ssc_vols['all']:
                vol_max = max(self.ssc_vols['all'])
                data['total_capacity_gb'] =\
                    int(vol_max.space['size_total_bytes']) / units.GiB
                data['free_capacity_gb'] =\
                    int(vol_max.space['size_avl_bytes']) / units.GiB
            else:
                data['total_capacity_gb'] = 0
                data['free_capacity_gb'] = 0
        else:
            LOG.warn(_("Cluster ssc is not updated. No volume stats found."))

    @utils.synchronized("refresh_ssc_vols")
    def refresh_ssc_vols(self, vols):
        """Refreshes ssc_vols with latest entries."""
        self.ssc_vols = vols

    def delete_volume(self, volume):
        """Driver entry point for destroying existing volumes."""
        lun = self.filer.get_lun(volume['name'])
        netapp_vol = None
        if lun:
            netapp_vol = lun.get_metadata_property('Volume')
        super(NetAppDirectCmodeISCSIDriver, self).delete_volume(volume)
        if netapp_vol:
            self.filer.update_stale_vols(
                volume=ssc_utils.NetAppVolume(netapp_vol, self.filer.vserver))


class NetAppDirect7modeISCSIDriver(NetAppDirectISCSIDriver):
    """NetApp 7-mode iSCSI volume driver."""

    def __init__(self, *args, **kwargs):
        super(NetAppDirect7modeISCSIDriver, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(netapp_7mode_opts)

    def _do_custom_setup(self):
        """Does custom setup depending on the type of filer."""
        self.filer = seven_mode(
            transport_type=self.configuration.netapp_transport_type,
            login=self.configuration.netapp_login,
            password=self.configuration.netapp_password,
            hostname=self.configuration.netapp_server_hostname,
            port=self.configuration.netapp_server_port)
        self.vfiler = self.configuration.netapp_vfiler
        self.volume_list = self.configuration.netapp_volume_list
        if self.volume_list:
            self.volume_list = self.volume_list.split(',')
            self.volume_list = [el.strip() for el in self.volume_list]
        (major, minor) = self.get_ontapi_version()
        self.filer.client.set_api_version(major, minor)
        if self.vfiler:
            self.filer.client.set_vfiler(self.vfiler)
        self.vol_refresh_time = None
        self.vol_refresh_interval = 1800
        self.vol_refresh_running = False
        self.vol_refresh_voluntary = False
        # Setting it infinite at set up
        # This will not rule out backend from scheduling
        self.total_gb = 'infinite'
        self.free_gb = 'infinite'

    def check_for_setup_error(self):
        """Check that the driver is working and can communicate."""
        self.filer.check_for_setup_error()
        super(NetAppDirect7modeISCSIDriver, self).check_for_setup_error()

    def _create_lun_on_eligible_vol(self, name, size, metadata,
                                    extra_specs=None):
        """Creates an actual lun on filer."""
        req_size = float(size) *\
            float(self.configuration.netapp_size_multiplier)
        volume = self._get_avl_volume_by_size(req_size)
        if not volume:
            msg = _('Failed to get vol with required size for volume: %s')
            raise exception.VolumeBackendAPIException(data=msg % name)
        self.filer.create_lun(volume['name'], name, size, metadata)
        metadata['Path'] = '/vol/%s/%s' % (volume['name'], name)
        metadata['Volume'] = volume['name']
        metadata['Qtree'] = None
        self.vol_refresh_voluntary = True

    def _get_avl_volume_by_size(self, size):
        """Get the available volume by size."""
        vols = self.filer.get_filer_volumes()
        for vol in vols:
            avl_size = vol.get_child_content('size-available')
            state = vol.get_child_content('state')
            if float(avl_size) >= float(size) and state == 'online':
                avl_vol = dict()
                avl_vol['name'] = vol.get_child_content('name')
                avl_vol['block-type'] = vol.get_child_content('block-type')
                avl_vol['type'] = vol.get_child_content('type')
                avl_vol['size-available'] = avl_size
                if self.volume_list:
                    if avl_vol['name'] in self.volume_list:
                        return avl_vol
                elif self._get_vol_option(avl_vol['name'], 'root') != 'true':
                        return avl_vol
        return None

    def get_lun_list(self):
        """Gets the list of luns on filer."""
        lun_list = []
        if self.volume_list:
            for vol in self.volume_list:
                try:
                    luns = self.filer.get_vol_luns(vol)
                    if luns:
                        lun_list.extend(luns)
                except NaApiError:
                    LOG.warn(_("Error finding luns for volume %s."
                               " Verify volume exists.") % (vol))
        else:
            luns = self.filer.get_vol_luns(None)
            lun_list.extend(luns)
        self._extract_and_populate_luns(lun_list)

    def _update_volume_stats(self):
        """Retrieve status info from volume group."""
        LOG.debug(_("Updating volume stats"))
        data = {}
        netapp_backend = 'NetApp_iSCSI_7mode_direct'
        backend_name = self.configuration.safe_get('volume_backend_name')
        data["volume_backend_name"] = (
            backend_name or 'NetApp_iSCSI_7mode_direct')
        data["vendor_name"] = 'NetApp'
        data["driver_version"] = self.VERSION
        data["storage_protocol"] = 'iSCSI'
        data['reserved_percentage'] = 0
        data['QoS_support'] = False
        self._get_capacity_info(data)
        provide_ems(self, self.filer.client, data, netapp_backend,
                    server_type="7mode")
        self._stats = data

    def _get_lun_block_count(self, path):
        """Gets block counts for the lun."""
        bs = super(
            NetAppDirect7modeISCSIDriver, self)._get_lun_block_count(path)
        api_version = self.filer.client.get_api_version()
        if api_version:
            major = api_version[0]
            minor = api_version[1]
            if major == 1 and minor < 15:
                bs = bs - 1
        return bs

    def _get_capacity_info(self, data):
        """Calculates the capacity information for the filer."""
        if (self.vol_refresh_time is None or self.vol_refresh_voluntary or
                timeutils.is_newer_than(self.vol_refresh_time,
                                        self.vol_refresh_interval)):
            try:
                job_set = set_safe_attr(self, 'vol_refresh_running', True)
                if not job_set:
                    LOG.warn(
                        _("Volume refresh job already running. Returning..."))
                    return
                self.vol_refresh_voluntary = False
                self._refresh_capacity_info()
                self.vol_refresh_time = timeutils.utcnow()
            except Exception as e:
                LOG.warn(_("Error refreshing vol capacity. Message: %s"), e)
            finally:
                set_safe_attr(self, 'vol_refresh_running', False)
        data['total_capacity_gb'] = self.total_gb
        data['free_capacity_gb'] = self.free_gb

    def _refresh_capacity_info(self):
        """Gets the latest capacity information."""
        LOG.info(_("Refreshing capacity info for %s."), self.filer.client)
        total_bytes = 0
        free_bytes = 0
        vols = self.filer.get_filer_volumes()
        for vol in vols:
            volume = vol.get_child_content('name')
            if self.volume_list and not volume in self.volume_list:
                continue
            state = vol.get_child_content('state')
            inconsistent = vol.get_child_content('is-inconsistent')
            invalid = vol.get_child_content('is-invalid')
            if (state == 'online' and inconsistent == 'false'
                    and invalid == 'false'):
                total_size = vol.get_child_content('size-total')
                if total_size:
                    total_bytes = total_bytes + int(total_size)
                avl_size = vol.get_child_content('size-available')
                if avl_size:
                    free_bytes = free_bytes + int(avl_size)
        self.total_gb = total_bytes / units.GiB
        self.free_gb = free_bytes / units.GiB

    def delete_volume(self, volume):
        """Driver entry point for destroying existing volumes."""
        super(NetAppDirect7modeISCSIDriver, self).delete_volume(volume)
        self.vol_refresh_voluntary = True
