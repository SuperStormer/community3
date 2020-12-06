# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from abc import ABC, abstractmethod
import logging

from typing import Iterator, List, Tuple, Union, NamedTuple
from volatility.framework import renderers, interfaces, contexts, constants, class_subclasses
from volatility.framework.renderers import format_hints
from volatility.framework.configuration import requirements
from volatility.framework.symbols import linux
from .checks import symbol_table_distinguisher, CheckSymbolExists, CheckTypeExists, \
    CheckMember, CheckTypes
from volatility.plugins.linux import lsmod

vollog = logging.getLogger(__name__)

Proto = NamedTuple('Proto', [('name', str), ('hooks', Union[Tuple, Tuple[str, ...]])])
PROTO_NOT_IMPLEMENTED = Proto(name='UNSPEC', hooks=tuple())


class ABCNetfilter(ABC):
    """Netfilter Abstract Base class.

    This class allows to handle the different Netfilter implementations, providing also constants, helpers and common
    routines.
    """

    PROTO_HOOKS = (
        PROTO_NOT_IMPLEMENTED,
        Proto(name='INET',
              hooks=('PRE_ROUTING',
                     'LOCAL_IN',
                     'FORWARD',
                     'LOCAL_OUT',
                     'POST_ROUTING')),
        Proto(name='IPV4',
              hooks=('PRE_ROUTING',
                     'LOCAL_IN',
                     'FORWARD',
                     'LOCAL_OUT',
                     'POST_ROUTING')),
        Proto(name='ARP',
              hooks=('IN',
                     'OUT',
                     'FORWARD')),
        PROTO_NOT_IMPLEMENTED,
        Proto(name='NETDEV',
              hooks=('INGRESS',)),
        PROTO_NOT_IMPLEMENTED,
        Proto(name='BRIDGE',
              hooks=('PRE_ROUTING',
                     'LOCAL_IN',
                     'FORWARD',
                     'LOCAL_OUT',
                     'POST_ROUTING')),
        PROTO_NOT_IMPLEMENTED,
        PROTO_NOT_IMPLEMENTED,
        Proto(name='IPV6',
              hooks=('PRE_ROUTING',
                     'LOCAL_IN',
                     'FORWARD',
                     'LOCAL_OUT',
                     'POST_ROUTING')),
        PROTO_NOT_IMPLEMENTED,
        Proto(name='DECNET',
              hooks=('PRE_ROUTING',
                     'LOCAL_IN',
                     'FORWARD',
                     'LOCAL_OUT',
                     'POST_ROUTING',
                     'HELLO',
                     'ROUTE')),
    )

    symtab_checks = lambda context, symbol_table: False

    def __init__(self, context, layer_name, vmlinux_symbols):
        self.context = context
        self.layer_name = layer_name
        self.vmlinux_symbols = vmlinux_symbols

        self.vmlinux = contexts.Module(context, vmlinux_symbols, layer_name, 0)

        modules = lsmod.Lsmod.list_modules(context, layer_name, vmlinux_symbols)
        self.handlers = linux.LinuxUtilities.generate_kernel_handler_info(context, layer_name, vmlinux_symbols, modules)

    @classmethod
    def run_all(
            cls, context: interfaces.context.ContextInterface, layer_name: str, vmlinux_symbols: str
    ) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        """It calls each subclass symtab_checks() to test the required symbols,
        type, subtypes, etc so that the respective Netfitler implementation is
        processed accordingly.

        Args:
            context: The context to retrieve required elements (layers, symbol
            tables) from layer_name: The name of the layer on which to operate
            vmlinux_symbols: The name of the table containing the kernel
            symbols

        Yields:
            Process objects
        """

        nfimp_inst = None
        for subclass in class_subclasses(cls):
            if not subclass.symtab_checks(context=context, symbol_table=vmlinux_symbols):
                vollog.log(constants.LOGLEVEL_VVVV,
                           "NetFilter implementation %s doesn't match this memory dump", subclass.__name__)
                continue

            vollog.log(constants.LOGLEVEL_VVVV, "NetFilter implementation %s matches!", subclass.__name__)
            nfimp_inst = subclass(context, layer_name, vmlinux_symbols)
            # More than one class could be executed for an specific kernel
            # version i.e. Netfilter Ingress hooks
            yield from nfimp_inst.run()

        if nfimp_inst is None:
            vollog.error("Unsupported Netfilter kernel implementation")

    @abstractmethod
    def run(self) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        """Walks through the specific Netfiler hook tables for a particular kernel implementation."""

    def _proto_hook_loop(self) -> Iterator[Tuple[int, str, int, str]]:
        """It flattens the protocol families and hooks"""
        for proto_idx, proto in enumerate(ABCNetfilter.PROTO_HOOKS):
            if proto == PROTO_NOT_IMPLEMENTED:
                continue
            if proto.name not in self.subscribed_protocols():
                continue  # This protocol is not managed in this object
            for hook_idx, hook_name in enumerate(proto.hooks):
                yield proto_idx, proto.name, hook_idx, hook_name

    def subscribed_protocols(self) -> Tuple[str, ...]:
        """Allows to select which PROTO_HOOKS protocols will be processed by the Netfiler subclass.
        Except for the Ingress hook handlers which only reponds to the 'NETDEV' protocol, all the other ones respond to
        the protocols below.
        """
        return ('IPV4', 'ARP', 'BRIDGE', 'IPV6', 'DECNET')

    def get_module_name_for_address(self, addr) -> str:
        """Helper to obtain the module and symbol name in the format needed for the output of this plugin."""
        module_name, symbol_name = linux.LinuxUtilities.lookup_module_address(self.context, self.handlers, addr)
        if module_name == 'UNKNOWN':
            module_name = None

        if symbol_name != 'N/A':
            module_name = "[{}]".format(symbol_name)

        return module_name

    def get_symbol_fullname(self, symbol_basename: str) -> str:
        """Given a short symbol or type name, it returns its full name"""
        return self.vmlinux_symbols + constants.BANG + symbol_basename


class NetfilterImp_to_4_2_8(ABCNetfilter):
    """Until kernel v4.2.8, Netfilter hooks were implemented as a doubly-linked list of 'struct nf_hook_ops' type. One
    doubly-linked list per protocol and per hook type, as follows:
        struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];
    """
    symtab_checks = symbol_table_distinguisher(
        CheckSymbolExists(symbol_name='nf_hooks')
    )

    def run(self) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        nf_hooks = self.vmlinux.object_from_symbol(symbol_name='nf_hooks')
        for proto_idx, proto_name, hook_idx, hook_name in self._proto_hook_loop():
            proto_hook_list = nf_hooks[proto_idx][hook_idx]
            nf_hooks_ops_name = self.get_symbol_fullname('nf_hook_ops')
            for nf_hook_ops in proto_hook_list.to_list(nf_hooks_ops_name, 'list'):
                module_name = self.get_module_name_for_address(nf_hook_ops.hook)
                hooked = module_name is not None
                yield 0, proto_name, hook_name, nf_hook_ops.priority, format_hints.Hex(nf_hook_ops.hook), hooked, \
                    module_name


class NetfilterImp_4_3_to_4_8_17(ABCNetfilter):
    """Netfilter hooks were added to network namepaces in v4.3.
    It is still implemented as a doubly-linked list of 'struct nf_hook_ops' type but inside a network namespace. Again,
    one doubly-linked list per protocol and per hook type, as follows:
        struct list_head net_namespace_list;  # <- 'struct net' type
        struct net { ... struct netns_nf nf; ... }
        struct netns_nf { ... struct list_head hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]; ... }
    """
    symtab_checks = symbol_table_distinguisher(
        CheckSymbolExists(symbol_name='net_namespace_list'),
        CheckTypes(
            type_names=('array', 'array', 'list_head'),
            from_obj=CheckMember(
                member_name='hooks',
                from_obj=CheckTypeExists(type_name='netns_nf')
            )
        )
    )

    def run(self) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        nethead = self.vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        for netidx, net in enumerate(nethead.to_list(self.get_symbol_fullname('net'), 'list')):
            for proto_idx, proto_name, hook_idx, hook_name in self._proto_hook_loop():
                proto_hook_list = net.nf.hooks[proto_idx][hook_idx]
                for nf_hook_ops in proto_hook_list.to_list(self.get_symbol_fullname('nf_hook_ops'), 'list'):
                    module_name = self.get_module_name_for_address(nf_hook_ops.hook)
                    hooked = module_name is not None
                    yield netidx, proto_name, hook_name, nf_hook_ops.priority, format_hints.Hex(nf_hook_ops.hook), \
                        hooked, module_name


class NetfilterImp_4_9_to_4_13_16(ABCNetfilter):
    """From kernels v4.9 to v4.13.16, the doubly-linked lists of netfilter hooks were replaced by an array of arrays of
    nf_hook_entry pointers in a singly-linked lists.
        struct list_head net_namespace_list;  # <- 'struct net' type
        struct net { ... struct netns_nf nf; ... }
        struct netns_nf { ... struct nf_hook_entry __rcu *hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]; ... }
    """
    symtab_checks = symbol_table_distinguisher(
        CheckSymbolExists(symbol_name='net_namespace_list'),
        CheckTypes(
            type_names=('array', 'array', 'pointer', 'nf_hook_entry'),
            from_obj=CheckMember(
                member_name='hooks',
                from_obj=CheckTypeExists(type_name='netns_nf')
            )
        ),
    )

    def run(self) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        nethead = self.vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        for netidx, net in enumerate(nethead.to_list(self.get_symbol_fullname('net'), 'list')):
            for proto_idx, proto_name, hook_idx, hook_name in self._proto_hook_loop():
                nf_hook_entry_ptr = net.nf.hooks[proto_idx][hook_idx]
                while nf_hook_entry_ptr:
                    nf_hook_entry = nf_hook_entry_ptr.dereference()
                    orig_ops = nf_hook_entry.orig_ops.dereference()

                    module_name = self.get_module_name_for_address(orig_ops.hook)
                    hooked = module_name is not None
                    yield netidx, proto_name, hook_name, orig_ops.priority, format_hints.Hex(orig_ops.hook), hooked, \
                        module_name

                    nf_hook_entry_ptr = nf_hook_entry_ptr.next


class NetfilterImp_4_14_to_4_15_18(ABCNetfilter):
    """From kernels v4.14 to v4.15.18, nf_hook_ops was removed from struct nf_hook_entry. Instead, it was stored
    adjacent  in memory to the nf_hook_entry array, in the new struct 'nf_hook_entries'.
    However, this nf_hooks_ops array 'orig_ops' is not part of the nf_hook_entries struct definition. So, we have to
    craft it by hand.
        struct list_head net_namespace_list;  # <- 'struct net' type
        struct net { ... struct netns_nf nf; ... }
        struct netns_nf { ... struct nf_hook_entries *hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]; ... }
        struct nf_hook_entries {
            u16                         num_hook_entries; /* plus padding */
            struct nf_hook_entry        hooks[];
            //const struct nf_hook_ops *orig_ops[];
        }
    """
    symtab_checks = symbol_table_distinguisher(
        CheckSymbolExists(symbol_name='net_namespace_list'),
        CheckTypes(
            type_names=('array', 'array', 'pointer', 'nf_hook_entries'),
            from_obj=CheckMember(
                member_name='hooks',
                from_obj=CheckTypeExists(type_name='netns_nf')
            )
        ),
    )

    def run(self) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        nethead = self.vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        for netidx, net in enumerate(nethead.to_list(self.get_symbol_fullname('net'), 'list')):
            for proto_idx, proto_name, hook_idx, hook_name in self._proto_hook_loop():
                nf_hook_entries_ptr = net.nf.hooks[proto_idx][hook_idx]
                if not nf_hook_entries_ptr:
                    continue
                nf_hook_entries = nf_hook_entries_ptr.dereference()

                nf_hook_entry_size = self.vmlinux.get_type('nf_hook_entry').size
                orig_ops_addr = (nf_hook_entries.hooks.vol.offset
                                 + nf_hook_entry_size * nf_hook_entries.num_hook_entries)
                orig_ops = self.vmlinux.object(object_type='array',
                                               offset=orig_ops_addr,
                                               subtype=self.vmlinux.get_type('pointer'),
                                               count=nf_hook_entries.num_hook_entries)

                for orig_ops_ptr in orig_ops:  # type: ignore
                    orig_ops = orig_ops_ptr.dereference().cast(self.get_symbol_fullname('nf_hook_ops'))
                    module_name = self.get_module_name_for_address(orig_ops.hook)
                    hooked = module_name is not None
                    yield netidx, proto_name, hook_name, orig_ops.priority, format_hints.Hex(orig_ops.hook), hooked, \
                        module_name


class NetfilterImp_4_16_to_latest(ABCNetfilter):
    """From kernels v4.16 to the current latest version (v5.8) The multidimensional array of nf_hook_entries was split
    in one-dimensional array per each protocol.
        struct list_head net_namespace_list;  # <- 'struct net' type
        struct net { ... struct netns_nf nf; ... }
        struct netns_nf  {
            struct nf_hook_entries *hooks_ipv4[NF_INET_NUMHOOKS];
            struct nf_hook_entries *hooks_ipv6[NF_INET_NUMHOOKS];
            struct nf_hook_entries *hooks_arp[NF_ARP_NUMHOOKS];
            struct nf_hook_entries *hooks_bridge[NF_INET_NUMHOOKS];
            struct nf_hook_entries *hooks_decnet[NF_DN_NUMHOOKS]; ...
        }
        struct nf_hook_entries {
            u16                         num_hook_entries; /* plus padding */
            struct nf_hook_entry        hooks[];
            //const struct nf_hook_ops *orig_ops[];
        }
    """
    symtab_checks = symbol_table_distinguisher(
        CheckSymbolExists(symbol_name='net_namespace_list'),
        CheckMember(
            member_name='hooks_ipv4',
            from_obj=CheckTypeExists(type_name='netns_nf')
        ),
    )

    def run(self) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        nethead = self.vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        for netidx, net in enumerate(nethead.to_list(self.get_symbol_fullname('net'), 'list')):
            for _proto_idx, proto_name, hook_idx, hook_name in self._proto_hook_loop():
                nf_member_hook_name = "hooks_" + proto_name.lower()
                if not net.nf.has_member(nf_member_hook_name):
                    continue

                nf_hook_entries_ptr = net.nf.member(nf_member_hook_name)[hook_idx]
                if not nf_hook_entries_ptr:
                    continue
                nf_hook_entries = nf_hook_entries_ptr.dereference()
                nf_hook_entry_size = self.vmlinux.get_type('nf_hook_entry').size
                orig_ops_addr = (nf_hook_entries.hooks.vol.offset
                                 + nf_hook_entry_size * nf_hook_entries.num_hook_entries)
                orig_ops_arr = self.vmlinux.object(object_type='array',
                                                   offset=orig_ops_addr,
                                                   subtype=self.vmlinux.get_type('pointer'),
                                                   count=nf_hook_entries.num_hook_entries)

                for orig_ops_ptr in orig_ops_arr:  # type: ignore
                    orig_ops = orig_ops_ptr.dereference().cast(self.get_symbol_fullname('nf_hook_ops'))

                    module_name = self.get_module_name_for_address(orig_ops.hook)
                    hooked = module_name is not None

                    yield netidx, proto_name, hook_name, orig_ops.priority, format_hints.Hex(orig_ops.hook), hooked, \
                        module_name


class ABCNetfilterIngress(ABCNetfilter):
    """Netfilter Ingress Abstract Base class to handle the Netfilter Ingress hooks.

    Netfilter Ingress hooks are set per network interface which belongs to a network namespace.
    """

    def subscribed_protocols(self):
        """Ingress hooks only use the 'NETDEV' protocol."""
        return ('NETDEV',)


class NetfilterIngressImp_4_2_to_4_8_17(ABCNetfilterIngress):
    """Netfilter Ingress hooks are set per network interface which belongs to a network namespace.
    This first version was implemented using a doubly-linked list of nf_hook_ops, per network device.
        struct list_head net_namespace_list;  <- 'struct net' type
        struct net { ... struct list_head dev_base_head; ... } <- doubly-linked list of net_device
        struct net_device { ... struct list_head nf_hooks_ingress; ... } <- doubly-linked list of nf_hook_ops
    """
    symtab_checks = symbol_table_distinguisher(
        CheckSymbolExists(symbol_name='net_namespace_list'),
        CheckTypes(
            type_names=('list_head',),
            from_obj=CheckMember(
                member_name='nf_hooks_ingress',
                from_obj=CheckTypeExists(type_name='net_device')
            )
        ),
    )

    def run(self) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        nethead = self.vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        for netidx, net in enumerate(nethead.to_list(self.get_symbol_fullname('net'), 'list')):
            for net_device in net.dev_base_head.to_list(self.get_symbol_fullname('net_device'), 'dev_list'):
                for _proto_idx, proto_name, _hook_idx, hook_name in self._proto_hook_loop():
                    for orig_ops in net_device.nf_hooks_ingress.to_list(self.get_symbol_fullname('nf_hook_ops'), 'list'):
                        module_name = self.get_module_name_for_address(orig_ops.hook)
                        hooked = module_name is not None
                        yield netidx, proto_name, hook_name, orig_ops.priority, format_hints.Hex(orig_ops.hook), \
                            hooked, module_name


class NetfilterIngressImp_4_9_to_4_13_16(ABCNetfilterIngress):
    """In 4.9 it was changed to a simple singly-linked list.
        struct nf_hook_entry * nf_hooks_ingress;
    """
    symtab_checks = symbol_table_distinguisher(
        CheckSymbolExists(symbol_name='net_namespace_list'),
        CheckTypes(
            type_names=('pointer', 'nf_hook_entry'),
            from_obj=CheckMember(
                member_name='nf_hooks_ingress',
                from_obj=CheckTypeExists(
                    type_name='net_device'))),
    )

    def run(self) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        nethead = self.vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        for netidx, net in enumerate(nethead.to_list(self.get_symbol_fullname('net'), 'list')):
            for net_device in net.dev_base_head.to_list(self.get_symbol_fullname('net_device'), 'dev_list'):
                for _proto_idx, proto_name, _hook_idx, hook_name in self._proto_hook_loop():
                    nf_hooks_ingress_ptr = net_device.nf_hooks_ingress
                    while nf_hooks_ingress_ptr:
                        nf_hook_entry = nf_hooks_ingress_ptr.dereference()
                        orig_ops = nf_hook_entry.orig_ops.dereference()

                        module_name = self.get_module_name_for_address(orig_ops.hook)
                        hooked = module_name is not None
                        yield netidx, proto_name, hook_name, orig_ops.priority, format_hints.Hex(orig_ops.hook), \
                            hooked, module_name

                        nf_hooks_ingress_ptr = nf_hooks_ingress_ptr.next


class NetfilterIngressImp_4_14_to_latest(ABCNetfilterIngress):
    """In 4.14 the hook list was converted to an array of pointers inside the struct nf_hook_entries.
        struct nf_hook_entries * nf_hooks_ingress;
        struct nf_hook_entries {
            u16 num_hook_entries; // padding
            struct nf_hook_entry hooks[];
        }
    """
    symtab_checks = symbol_table_distinguisher(
        CheckTypes(
            type_names=('pointer', 'nf_hook_entries'),
            from_obj=CheckMember(
                member_name='nf_hooks_ingress',
                from_obj=CheckTypeExists(type_name='net_device')
            )
        ),
        CheckSymbolExists(symbol_name='net_namespace_list')
    )

    def run(self) -> Iterator[Tuple[int, str, str, int, format_hints.Hex, bool, str]]:
        nethead = self.vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        for netidx, net in enumerate(nethead.to_list(self.get_symbol_fullname('net'), 'list')):
            for net_device in net.dev_base_head.to_list(self.get_symbol_fullname('net_device'), 'dev_list'):
                for _proto_idx, proto_name, _hook_idx, hook_name in self._proto_hook_loop():
                    if not net_device.nf_hooks_ingress:
                        continue
                    nf_hook_entries = net_device.nf_hooks_ingress.dereference()

                    nf_hook_entry_size = self.vmlinux.get_type('nf_hook_entry').size
                    orig_ops_addr = (nf_hook_entries.hooks.vol.offset
                                     + nf_hook_entry_size * nf_hook_entries.num_hook_entries)
                    orig_ops_arr = self.vmlinux.object(object_type='array',
                                                       offset=orig_ops_addr,
                                                       subtype=self.vmlinux.get_type('pointer'),
                                                       count=nf_hook_entries.num_hook_entries)
                    for orig_ops_ptr in orig_ops_arr:  # type: ignore
                        orig_ops = orig_ops_ptr.dereference().cast(self.get_symbol_fullname('nf_hook_ops'))

                        module_name = self.get_module_name_for_address(orig_ops.hook)
                        hooked = module_name is not None
                        yield netidx, proto_name, hook_name, orig_ops.priority, format_hints.Hex(orig_ops.hook), \
                            hooked, module_name


class Netfilter(interfaces.plugins.PluginInterface):
    """Lists Netfilter hooks"""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(
            cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name='primary',
                description='Memory layer for the kernel',
                architectures=['Intel32', 'Intel64']),
            requirements.SymbolTableRequirement(
                name='vmlinux',
                description='Linux kernel symbols'),
            requirements.PluginRequirement(
                name='lsmod',
                plugin=lsmod.Lsmod,
                version=(1, 0, 0)),
        ]

    def _generator(self) -> Iterator[Tuple[int, Tuple[int, str, str, int, format_hints.Hex, bool, str]]]:
        for values in ABCNetfilter.run_all(context=self.context,
                                           layer_name=self.config['primary'],
                                           vmlinux_symbols=self.config['vmlinux']):
            yield (0, values)

    def run(self):
        return renderers.TreeGrid([('NS', int),
                                   ('Proto', str),
                                   ('Hook', str),
                                   ('Priority', int),
                                   ('Handler', format_hints.Hex),
                                   ('IsHooked', bool),
                                   ('Module', str)],
                                  self._generator())
