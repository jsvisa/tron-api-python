# --------------------------------------------------------------------------------------------
# Copyright (c) PeckShield. All rights reserved.
# Licensed under the MIT License.
# --------------------------------------------------------------------------------------------

import binascii
from tronapi.module import Module
from tronapi.exceptions import InvalidTronError

# The Parity trace struct as below,
# see more from https://wiki.parity.io/JSONRPC-trace-module#trace_transaction
# {
#   "action": {
#     "callType": "call",
#     "from": "0x1c39ba39e4735cb65978d4db400ddd70a72dc750",
#     "gas": "0x13e99",
#     "input": "0x16c72721",
#   },
#   "blockHash": "0x7eb25504e4c202cf3d62fd585d3e238f592c780cca82dacb2ed3cb5b38883add",
#   "blockNumber": 3068185,
#   "result": {
#     "gasUsed": "0x183",
#     "output": "0x0000000000000000000000000000000000000000000000000000000000000001"
#   },
#   "subtraces": 0,
#   "traceAddress": [
#     0
#   ],
#   "transactionHash": "0x17104ac9d3312d8c136b7f44d4b8b47852618065ebfa534bd2d3b5ef218ca1f3", # noqa
#   "transactionPosition": 2,
#   "type": "call"
# }

# call: https://etherscan.io/vmtrace?txhash=0x17104ac9d3312d8c136b7f44d4b8b47852618065ebfa534bd2d3b5ef218ca1f3&type=parity#raw # noqa
# create: https://etherscan.io/vmtrace?txhash=0x1d7962380457e66f47800dfc4596293402ff46f5148e0bf1f021b9ebaf05296c&type=parity#raw # noqa
# suicide: https://etherscan.io/vmtrace?txhash=0xab1883e8ddc7532237a8053dd276236e728798dd6f1fa87dda4c59bdc6b2a846&type=parity#raw # noqa
# reverted: https://etherscan.io/vmtrace?txhash=0xa713a3bbadb029fd186302ef59b4beac04aa02bfd52e7647ddb6d557e73aee48&type=parity#raw # noqa


class Trace(Module):
    def get_transaction(self, transaction_id: str, is_confirm: bool = False):
        """Query transaction based on id

        Args:
            transaction_id (str): transaction id
            is_confirm (bool):
        """

        method = "walletsolidity" if is_confirm else "wallet"
        response = self.tron.manager.request(
            "/{}/gettransactionbyid".format(method), {"value": transaction_id}
        )

        if not response:
            raise InvalidTronError("Transaction not found")

        return response

    def get_transaction_info(self, tx_id):
        """Query transaction fee based on id

        Args:
            tx_id (str): Transaction Id

        Returns:
            Transaction fee，block height and block creation time

        """
        response = self.tron.manager.request(
            "/wallet/gettransactioninfobyid", {"value": tx_id}
        )

        subtraces = {}
        if response.get("internal_transactions") is not None:
            traces = {}
            prev_trace_address = []
            prev_deep = -1
            for inner_tx in response["internal_transactions"]:
                inner_tx["action"] = {}
                inner_tx["result"] = {}
                action = inner_tx["action"]
                result = inner_tx["result"]

                note = binascii.unhexlify(inner_tx["note"]).decode()

                for value_or_token in inner_tx["callValueInfo"]:
                    if value_or_token.get("callValue") is not None:
                        action["value"] = hex(value_or_token.get("callValue"))
                        break
                if action.get("value") is None:
                    action["value"] = hex(0)

                # handle by 'type'
                inner_tx["type"] = note
                if note in ("call", "delegatecall", "calldata"):
                    inner_tx["type"] = "call"
                    action["callType"] = note
                    action["input"] = inner_tx.get("input", "")
                    action["to"] = inner_tx["transferTo_address"]
                    result["output"] = inner_tx.get("output", "")

                    action["from"] = inner_tx["caller_address"]
                    action["gas"] = hex(inner_tx.get("feeLimit", 0))
                    result["gasUsed"] = hex(inner_tx.get("feeUsed", 0))

                elif note in ("create"):
                    action["init"] = inner_tx.get("input", "")
                    result["code"] = inner_tx.get("output", "")
                    result["address"] = inner_tx["transferTo_address"]

                    action["from"] = inner_tx["caller_address"]
                    action["gas"] = hex(inner_tx.get("feeLimit", 0))
                    result["gasUsed"] = hex(inner_tx.get("feeUsed", 0))

                elif note in ("suicide"):
                    action["address"] = inner_tx["caller_address"]
                    action["refundAddress"] = inner_tx["transferTo_address"]
                    action["balance"] = action["value"]
                    del action["value"]

                    # set to null, ref to Parity's implement
                    inner_tx["result"] = None

                if "deep" not in inner_tx:
                    inner_tx["deep"] = 0

                at = inner_tx["deep"]

                x = len(prev_trace_address) - 1
                if x < 0:
                    prev_trace_address.append(0)
                elif at == prev_deep:
                    prev_trace_address[x] = prev_trace_address[x] + 1
                elif at == prev_deep + 1:
                    prev_trace_address.append(0)
                elif at < prev_deep:
                    # set to the previous deep's one
                    prev_trace_address = traces[at][:]
                    prev_trace_address[-1] = prev_trace_address[-1] + 1
                else:
                    raise InvalidTronError(
                        "current trace's deep({}) > previous trace's deep({})".format(
                            at, prev_deep
                        )
                    )

                # deep copy
                inner_tx["traceAddress"] = prev_trace_address[:]
                traces.update({at: prev_trace_address[:]})
                k = ",".join(str(e) for e in prev_trace_address[:-1])
                inner_tx["_traceAt"] = ",".join(str(e) for e in prev_trace_address)
                subtraces.update({k: subtraces.get(k, 0) + 1})

                prev_deep = inner_tx["deep"]

                # FIXME: get the detail error message
                if inner_tx.get("rejected", False) is True:
                    inner_tx["error"] = "Rejected"
                    del inner_tx["rejected"]

                # TODO: traceAddress and subtraces
                for k in (
                    "input",
                    "output",
                    "feeLimit",
                    "feeUsed",
                    "note",
                    "deep",
                    "nonce",
                    "index",
                    "caller_address",
                    "transferTo_address",
                ):
                    if k in inner_tx:
                        del inner_tx[k]

            for inner_tx in response["internal_transactions"]:
                inner_tx["subtraces"] = subtraces.get(inner_tx["_traceAt"], 0)
                del inner_tx["_traceAt"]

        return (response, subtraces.get("", 0))

    def trace_transaction(
        self,
        tx_hash: str,
        tx_pos: int = None,
        blk_num: int = None,
        blk_hash: str = None,
    ):
        tx = self.get_transaction(tx_hash)

        result = []
        if (
            tx.get("raw_data") is not None
            and tx["raw_data"].get("contract") is not None
            and len(tx["raw_data"]["contract"]) == 1
            and tx["raw_data"]["contract"][0].get("type") == "TriggerSmartContract"
        ):
            parameter = tx["raw_data"]["contract"][0]["parameter"]["value"]
            trace_0 = {
                "action": {
                    "callType": "call",
                    "from": parameter["owner_address"],
                    "gas": hex(tx["raw_data"]["fee_limit"]),
                    "input": parameter["data"],
                    "to": parameter["contract_address"],
                    "value": hex(parameter["call_value"]),
                },
                "blockHash": blk_hash,
                "blockNumber": blk_num,
                "result": {"gasUsed": "?", "output": "?"},
                "subtraces": 0,
                "traceAddress": [],
                "transactionHash": tx_hash,
                "transactionPosition": tx_pos,
                "type": "call",
            }

            (tx_info, trace_0_subtraces) = self.get_transaction_info(tx_hash)
            if blk_num is None:
                blk_num = tx_info["blockNumber"]
                trace_0["blockNumber"] = blk_num
            elif blk_num != tx_info["blockNumber"]:
                raise InvalidTronError(
                    "blockNumber for tx({}) not equal, given is '{}', "
                    "in get_transaction_info is '{}'".format(
                        tx_hash, blk_num, tx_info["blockNumber"]
                    )
                )

            trace_0["subtraces"] = trace_0_subtraces
            trace_0["result"] = {
                "gasUsed": hex(tx_info["fee"]),
                "output": tx_info["contractResult"][0],
            }

            result.append(trace_0)
            if tx_info.get("internal_transactions") is not None:
                for trace in tx_info["internal_transactions"]:
                    trace.update(
                        {
                            "blockHash": blk_hash,
                            "blockNumber": blk_num,
                            "transactionHash": tx_hash,
                            "transactionPosition": tx_pos,
                        }
                    )
                    result.append(trace)
            return result
