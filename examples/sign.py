from tronapi import Tron
from tronapi import HttpProvider

full_node = HttpProvider("https://api.trongrid.io")
solidity_node = HttpProvider("https://api.trongrid.io")
event_server = HttpProvider("https://api.trongrid.io")

tron = Tron(full_node=full_node, solidity_node=solidity_node, event_server=event_server)
tron.private_key = "private_key"
tron.default_address = "default address"

# create transaction
create_tx = tron.transaction_builder.send_transaction("to", 1, "from")

# offline sign
offline_sign = tron.trx.sign(create_tx)


# online sign (Not recommended)
online_sign = tron.trx.online_sign(create_tx)
