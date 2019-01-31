#!/usr/bin/env python

import sys
import json
import time
import threading
import multiprocessing
from tronapi import Tron, HttpProvider
from solc import compile_source

# node = HttpProvider("https://api.trongrid.io")
# node = HttpProvider("https://api.shasta.trongrid.io")
# node = HttpProvider("http://127.0.0.1:16667")
node = HttpProvider("http://192.168.1.102:16667")

tron = Tron(full_node=node, solidity_node=node, event_server=node)

# witness
tron.private_key = "b02acf099041048d851e8cef55abc6c00f3854f2f644e2a1dc896c282c4f51ae"
tron.default_address = "TKFPkTRw8hPgcCwXsRS5VLXddZYdc9DXhN"

# tron.private_key = "d1986647bcf3c921c674a17b3fccab28b58f01a69cef83634cd10ab4b53d178f"
# tron.default_address = "TFvkNekonRzy7667p6AaBBTvKbHYcUMehg"

# tron.private_key = "aae2224e6ee7b522a3de00bfd00734d5dc23ec3fea2ec05de82d5e5f05858f06"
# tron.default_address = "TQDercM3hTpQL4JsAbiTyCP8jN2NYg6n5y"

# Solidity source code
contract_source_code = """
pragma solidity ^0.4.23;

contract Hello {
    string public message;
    int public text =12345;

    function Hello(string initialMessage) public {
        message = initialMessage;
    }

    function setMessage(string newMessage) public {
        message = newMessage;
    }

    function getMessage() public returns(string) {
        return message;
    }

    function getText(int _text) public returns(bool) {
        text = _text;
        return true;
    }
    function getText() public returns(int) {
        return text;
    }
}

"""


contract_source_code = """
pragma solidity ^0.4.23;

contract Factory {
    address[] newContracts;
    uint256 number;

    function createContract (string name) returns (address newAddr) {
        // number = 1;
        //return 0;
        address newContract = new Contract(name);
        // newContracts.push(newContract);
        // suicide(newContract);
        // suicide(msg.sender);
        newContract.call(bytes4(keccak256("setM(uint256)")), 2);
        newContract.call(bytes4(keccak256("setM(uint256)")), 1);
        newContract.delegatecall(bytes4(keccak256("setN(uint256)")), 1);
        newContract.callcode(bytes4(keccak256("setM(uint256)")), 1);
        return newContract;
    }

    function getNameByIndex (uint256 index) returns (string name) {
        Contract con = Contract(newContracts[index]);
        return con.name();
    }
}

contract Contract {
    string public name;
    uint256 public n;

    function Contract (string _name) {
        name = _name;
    }

    function setN(uint256 _n) returns(uint256) {
        n = _n;
        return 256;
    }

    function setM(uint256 _n) returns(uint256) {
        // suicide(msg.sender);
        // suicide(tx.origin);
        address newContract = new Child("new");
        newContract.call(bytes4(keccak256("setN(uint256)")), 1);
        return 128;
        // newContract.delegatecall(bytes4(keccak256("setN(uint256)")), 3);
    }
}

contract Child {
    string public name;
    uint256 public n;

    function Child (string _name) {
        name = _name;
    }

    function setN(uint256 _n) returns(uint256) {
        n = _n;
        if (n == 2) {
            revert();
        } else if (n == 3) {
            suicide(msg.sender);
        }
        return n;
    }
}
"""

compiled_sol = compile_source(contract_source_code)
contract_interface = compiled_sol["<stdin>:Factory"]

contract = tron.trx.contract(
    abi=contract_interface["abi"], bytecode=contract_interface["bin"]
)

# Submit the transaction that deploys the contract
tx_data = contract.deploy(
    fee_limit=10 ** 9, call_value=0, consume_user_resource_percent=50
)

sign = tron.trx.sign(tx_data)
result = tron.trx.broadcast(sign)

if result.get("result") is None or result["result"] is not True:
    print("Failed:", result)
    sys.exit(1)

contract_address = result["transaction"]["contract_address"]
print("contract address is ", result["transaction"]["contract_address"])
tx_id = result["transaction"]["txID"]
tx_info = tron.trx.get_transaction_info(tx_id)
print(json.dumps(tx_info, indent=4))

# sys.exit(0)

g_queue = multiprocessing.Queue()


def init_queue(tasks_count=1):
    print("init g_queue start")
    while not g_queue.empty():
        g_queue.get()
    for _index in range(tasks_count):
        g_queue.put(_index)
    print("init g_queue end")
    return


def multithread(task, tasks=1000, threads=5):
    init_queue(tasks)
    time_0 = time.time()
    thread_list = [threading.Thread(target=task, args=(i,)) for i in range(threads)]
    for t in thread_list:
        t.start()
    for t in thread_list:
        if t.is_alive():
            t.join()
    print("END", time.time() - time_0, "\n")


def multiprocess(task, count=multiprocessing.cpu_count()):
    init_queue()
    time_0 = time.time()
    process_list = [
        multiprocessing.Process(target=task, args=(i,)) for i in range(count)
    ]
    for p in process_list:
        p.start()
    for p in process_list:
        if p.is_alive():
            p.join()
    print("END", time.time() - time_0, "\n")


def task(task_id):
    while not g_queue.empty():
        try:
            data = g_queue.get(block=True, timeout=1)
            tx = tron.transaction_builder.trigger_smart_contract(
                contract_address,
                "createContract(string)",
                parameters=[{"type": "string", "value": "Iij"}],
            )
            print(tx)

            result = tron.trx.sign_and_broadcast(tx["transaction"])
            tx_id = result["transaction"]["txID"]
            print(tx_id)
            tx_info = tron.trx.get_transaction_info(tx_id)
            print(json.dumps(tx_info, indent=4))

            print("IOTask[%s] finish data: %s" % (task_id, data))
        except Exception as excep:
            print("IOTask[%s] error: %s" % (task_id, str(excep)))
    print("Task[%s] end" % task_id)
    return


multithread(task, tasks=1)
