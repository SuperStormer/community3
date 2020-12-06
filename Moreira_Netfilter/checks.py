# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from abc import ABC, abstractmethod
import logging

from typing import Callable, Tuple, Union
from volatility.framework import interfaces, constants

vollog = logging.getLogger(__name__)


class Check(ABC):
    """Check Abstract Base class.

    This class defines the interface that all the checks below must support.
    """
    @abstractmethod
    def check(self, context: interfaces.context.ContextInterface, symbol_table: str) -> bool:
        """Returns true when the element evaluated exists and meets the specified conditions by being evaluated against
        a symbol table.
        In cases where the Check accepts another Check object as one of its parameters, the parent is responsible for
        calling the child object, creating a chain of check calls. If the child object fails, the parent must return
        false immediatly breaking the chain. The only exception is the CheckNot object."""


class CheckSymbolExists(Check):
    """Class to check if a symbol exists in the symbol table."""
    def __init__(self, symbol_name: str):
        self.symbol_name = symbol_name

    def check(self, context: interfaces.context.ContextInterface, symbol_table: str) -> bool:
        """Returns true when the Symbol 'symbol_name' exists."""
        symbol_fullname = symbol_table + constants.BANG + self.symbol_name
        return context.symbol_space.has_symbol(symbol_fullname)


class CheckTypeExists(Check):
    """Class to check if a type exists in the symbol table."""
    def __init__(self, type_name: str):
        self.type_name = type_name

    def check(self, context: interfaces.context.ContextInterface, symbol_table: str) -> bool:
        """Returns true when the Type 'type_name' exists."""
        type_fullname = symbol_table + constants.BANG + self.type_name
        return context.symbol_space.has_type(type_fullname)


class CheckMember(Check):
    """Class to check if a Type or a Symbol has a specific member."""
    def __init__(self, member_name: str, from_obj: Union[CheckSymbolExists, CheckTypeExists]):
        self.member_name = member_name
        self.from_obj = from_obj

    def check(self, context: interfaces.context.ContextInterface, symbol_table: str) -> bool:
        """Returns true when the Type or Symbol contain a member called 'member_name'."""
        if not self.from_obj.check(context, symbol_table):
            return False

        space_basename = symbol_table + constants.BANG
        if isinstance(self.from_obj, CheckSymbolExists):
            symbol_fullname = space_basename + self.from_obj.symbol_name
            symbol = context.symbol_space.get_symbol(symbol_fullname)
            type_fullname = symbol.type_name
        elif isinstance(self.from_obj, CheckTypeExists):
            type_fullname = space_basename + self.from_obj.type_name
        else:
            raise TypeError("Unknown type of object")

        elem_type = context.symbol_space.get_type(str(type_fullname))
        return elem_type.has_member(self.member_name)


class CheckTypes(Check):
    """Class to check if a member is of a specific Type.

    As it reads the types from right to left, the Types of, for instance:
        struct foo *bar[x][y];
    Are:
        ('array', 'array', 'pointer', 'foo')
    """
    def __init__(self, type_names: Union[str, Tuple[str, ...]], from_obj: Union[CheckSymbolExists, CheckMember]):
        self.type_names = type_names if isinstance(type_names, tuple) else (type_names,)
        self.from_obj = from_obj

    def check(self, context: interfaces.context.ContextInterface, symbol_table: str) -> bool:
        """Returns true when the tuple 'type_names' matches with the list of types of the given member or symbol in
        'from_obj'."""
        if not self.from_obj.check(context, symbol_table):
            return False

        space_basename = symbol_table + constants.BANG
        if isinstance(self.from_obj, CheckSymbolExists):
            symbol_fullname = space_basename + self.from_obj.symbol_name
            symbol = context.symbol_space.get_symbol(symbol_fullname)
            type_fullname = symbol.type_name
            elem = context.symbol_space.get_type(str(type_fullname))
        elif isinstance(self.from_obj, CheckMember):
            # FIXME: Same as CheckMember, we need some refactoring here
            if isinstance(self.from_obj.from_obj, CheckSymbolExists):
                symbol_fullname = space_basename + self.from_obj.from_obj.symbol_name
                symbol = context.symbol_space.get_symbol(symbol_fullname)
                type_fullname = symbol.type_name
            elif isinstance(self.from_obj.from_obj, CheckTypeExists):
                type_fullname = space_basename + self.from_obj.from_obj.type_name
            else:
                raise TypeError("Unknown type of object")

            elem_type = context.symbol_space.get_type(type_fullname)  # type: ignore
            elem = elem_type.members[self.from_obj.member_name][1]

        type_fullname = str(elem.type_name)
        type_basename = type_fullname.split(constants.BANG)[1]
        types = list()
        while type_basename in ('array', 'pointer'):
            types.append(type_basename)
            elem = elem.subtype
            type_fullname = str(elem.type_name)
            type_basename = type_fullname.split(constants.BANG)[1]
        types.append(type_basename)

        res = tuple(types) == self.type_names
        if not res:
            vollog.log(constants.LOGLEVEL_VVVV, "CheckTypes: Kernel %s != Plugin %s", tuple(types), self.type_names)
        return res


class CheckNot(Check):
    """Class to check if the child Check was not true. It is useful when using along with the other Checks to invert
    the result of child expression. For instance, to check that a symbol name does not exist in a symbol table or a
    type does not have a specific member.
    """
    def __init__(self, from_obj: Union[CheckSymbolExists, CheckTypeExists, CheckMember]):
        self.from_obj = from_obj

    def check(self, context: interfaces.context.ContextInterface, symbol_table: str) -> bool:
        """Returns true when the child returned false and viceversa."""
        return not self.from_obj.check(context, symbol_table)


def symbol_table_distinguisher(*checks: Union[CheckSymbolExists, CheckTypeExists, CheckMember, CheckTypes]) \
        -> Callable[[interfaces.context.ContextInterface, str], bool]:
    """Distinguishes a symbol table as being above a particular point.

    Args:
        checks: Variable number of symbols, types or members of types to be above the required point.

    Example: To check if the struct 'netns_nf' has a member called 'hooks' which type, from right to left, is:
             (array, array, list_head) as below:
                struct netns_nf {
                    struct list_head hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];
                    ...
                }
             and the symbol table contains also a symbol called 'net_namespace_list' the list of checks needed are:
                symbol_table_distinguisher(
                    CheckSymbolExists(symbol_name='net_namespace_list'),
                    CheckTypes(
                        type_names=('array', 'array', 'list_head'),
                        from_obj=CheckMember(
                            member_name='hooks',
                            from_obj=CheckTypeExists(type_name='netns_nf')
                        )
                    )
                )

    Returns:
        A function that takes a context and a symbol table name and determines whether that symbol table passes the
        distinguishing checks
    """

    def method(context: interfaces.context.ContextInterface, symbol_table: str) -> bool:
        for check_obj in checks:
            if not check_obj.check(context, symbol_table):
                return False
        return True
    return method
