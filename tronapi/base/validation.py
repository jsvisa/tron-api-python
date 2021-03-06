# --------------------------------------------------------------------------------------------
# Copyright (c) iEXBase. All rights reserved.
# Licensed under the MIT License.
# See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from _sha256 import sha256
from typing import Any

import base58
from eth_utils import function_abi_to_4byte_selector, apply_formatter_to_array

from tronapi.base.toolz import compose, groupby, valfilter, valmap

from tronapi.base.abi import (
    filter_by_type,
    abi_to_signature,
    is_recognized_type,
    is_string_type,
    is_bytes_type,
    is_address_type,
    is_int_type,
    is_uint_type,
    is_bool_type,
    sub_type_of_array_type,
    is_array_type,
    length_of_array_type,
)
from tronapi.utils.help import hex_to_base58
from tronapi.utils.hexadecimal import is_hex, encode_hex, is_0x_prefixed
from tronapi.utils.types import (
    is_text,
    is_list_like,
    is_dict,
    is_string,
    is_bytes,
    is_boolean,
    is_integer,
)


def _prepare_selector_collision_msg(duplicates):
    dup_sel = valmap(apply_formatter_to_array(abi_to_signature), duplicates)
    joined_funcs = valmap(lambda f: ", ".join(f), dup_sel)
    func_sel_msg_list = [
        funcs + " have selector " + sel for sel, funcs in joined_funcs.items()
    ]
    return " and\n".join(func_sel_msg_list)


def is_address(value: str) -> bool:
    """Checks if the given string in a supported value is an address
    in any of the known formats.

    Args:
        value (str): Address

    """
    if is_checksum_address(value):
        return True
    elif is_hex_address(value):
        return True

    return False


def is_hex_address(value: Any) -> bool:
    """
    Checks if the given string of text type is an address in hexadecimal encoded form.
    """
    if len(value) != 42:
        return False
    elif not is_text(value):
        return False
    elif not is_hex(value):
        return False
    else:
        return is_address(hex_to_base58(value))


def is_checksum_address(value: str) -> bool:
    if len(value) != 34:
        return False

    address = base58.b58decode(value)
    if len(address) != 25:
        return False

    if address[0] != 0x41:
        return False

    check_sum = sha256(sha256(address[:-4]).digest()).digest()[:4]
    if address[-4:] == check_sum:
        return True


def validate_abi(abi):
    """
    Helper function for validating an ABI
    """
    if not is_list_like(abi):
        raise ValueError("'abi' is not a list")

    if not all(is_dict(e) for e in abi):
        raise ValueError("'abi' is not a list of dictionaries")

    functions = filter_by_type("function", abi)
    selectors = groupby(compose(encode_hex, function_abi_to_4byte_selector), functions)
    duplicates = valfilter(lambda funcs: len(funcs) > 1, selectors)
    if duplicates:
        raise ValueError(
            "Abi contains functions with colliding selectors. "
            "Functions {0}".format(_prepare_selector_collision_msg(duplicates))
        )


def validate_abi_type(abi_type):
    """
    Helper function for validating an abi_type
    """
    if not is_recognized_type(abi_type):
        raise ValueError("Unrecognized abi_type: {abi_type}".format(abi_type=abi_type))


def validate_abi_value(abi_type, value):
    """
    Helper function for validating a value against the expected abi_type
    Note: abi_type 'bytes' must either be python3 'bytes' object or ''
    """
    if is_array_type(abi_type) and is_list_like(value):
        # validate length
        specified_length = length_of_array_type(abi_type)
        if specified_length is not None:
            if specified_length < 1:
                raise TypeError(
                    "Invalid abi-type: {abi_type}. Length of fixed sized arrays"
                    "must be greater than 0.".format(abi_type=abi_type)
                )
            if specified_length != len(value):
                raise TypeError(
                    "The following array length does not the length specified"
                    "by the abi-type, {abi_type}: {value}".format(
                        abi_type=abi_type, value=value
                    )
                )

        # validate sub_types
        sub_type = sub_type_of_array_type(abi_type)
        for v in value:
            validate_abi_value(sub_type, v)
        return
    elif is_bool_type(abi_type) and is_boolean(value):
        return
    elif is_uint_type(abi_type) and is_integer(value) and value >= 0:
        return
    elif is_int_type(abi_type) and is_integer(value):
        return
    elif is_address_type(abi_type):
        is_address(value)
        return
    elif is_bytes_type(abi_type):
        if is_bytes(value):
            return
        elif is_string(value):
            if is_0x_prefixed(value):
                return
            else:
                raise TypeError(
                    "ABI values of abi-type 'bytes' must be either"
                    "a python3 'bytes' object or an '0x' prefixed string."
                )
    elif is_string_type(abi_type) and is_string(value):
        return

    raise TypeError(
        "The following abi value is not a '{abi_type}': {value}".format(
            abi_type=abi_type, value=value
        )
    )
