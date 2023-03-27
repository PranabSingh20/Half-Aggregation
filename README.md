# Half-Aggregation

To run the project use command 
`python run.py -n <number of users>`

This scripts executes the following in order:
1. Generates public, private keys for `n` users and saves them in `secretkeys.json` and `publickeys.json`
2. Generates random messages and saves them into `messages.json`, signs them and saves the signature in `signatures.json` (User defined messages can also be done will be discussed below)
3. Generates an aggregate sign for all the signatures and saves them into `aggregatesign.json`
4. Verifies the aggregate signature 

For verifying user defined messages execute the following

1. `python keygen.py -n <number of users>`
2. `python sign -m <n space seperated mesages>`
3. `python aggSign.py`
4. `python aggVerify.py`

You can also verify a single signature using (public keys, signature, message) by 

Syntax: `python verify.py -s <signature> -p <public_key> -m <message>`
  
You can also play around with editing the json files to check if wrong combination fails verification or not.
