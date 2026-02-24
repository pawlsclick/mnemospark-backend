# mnenospark overview

1. This repo is the cloned OpenRouter repo, it is used to build the mnemospark OpenClaw plugin, which has a mnemospark client and mnemospark proxy, collectively known as: mnemospark.
2. The directory examples contains working concepts of how to build the mnemospark backend. The backend will be hosted in AWS as Lambda functions, Dynamo DB and other resources to support the mnemospark client and proxy.
3. The file .company/infrastructure_design/internet_facing_API.md describes the addtional AWS infrastructure required to support and secure the mnemospark backend.
4. The directory .company is a work in progress list of files that help direct how the mnenospark product (OpenClaw plugin + Backend) all function.

# repo changes required

1. The directory examples will need to be moved to it's own GitHub repo set to private for development of the mnemospark backend.
2. The name of the new repo is: mnemospark-backend
3. This repo is available now
4. This repo will also hold all of the cloudformation scripts required to build and maintain the mnemospark-backend. See: The file .company/infrastructure_design/internet_facing_API.md
5. The net effect will be two repos: (1) mnenospark - this is where OpenClaw users will go to install mnemospark and (2) mnenospark-backend

# mnenospark base use case

mnenospark is an OpenClaw plugin that allows the OpenClaw main agent to purchase services with USDC using x402 protocol transactions. The first service it supports is purchasing storage on AWS using S3 buckets. This will allow the OpenClaw agent to: build a backup file, obtain a quote for storage, which builds a reservation, purchase the storage using the reservation, upload the file, list the file in the S3 bucket, download the file and delete the file. The agent is charged a monthly fee for the service, which is paid in USDC using x402 protocol transactions. mnenospark will support other services beyond storage in the future.

# mnenospark system components

1. **mnenospark-client** - a modification of the existing OpenRouter plugin, re-built for the mnenospark usecase as the OpenClaw plugin with a client
2. **mnenospark-proxy** — modification of the existing OpenRouter proxy for the mnemospark use case. Listens on **port 7120** by default (client and OpenClaw talk to the proxy at `http://127.0.0.1:7120`). Configurable via `MNEMOSPARK_PROXY_PORT`.
3. **mnemospark-backend** — Internet-facing Lambda REST API with supporting Lambda functions, Dynamo DB and other resources

## mnemospark-backend API architecture

The backend exposes **one internet-facing REST API** (API Gateway). API Gateway routes each request **by path** to a **specific Lambda function**. Each Lambda has a single responsibility and a least-privilege IAM role (e.g. cost Lambdas only need BCM; storage Lambda needs S3 and Secrets Manager; quote/payment Lambda needs DynamoDB and chain access).

| Client command         | HTTP method and path                                | Lambda responsibility                                                                                                                                                                                                                               |
| ---------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| price-storage          | `POST /price-storage`                               | Price-storage Lambda: calls storage cost + data transfer cost, adds markup, creates quote, writes to DynamoDB (1h TTL). Design patterns: examples/s3-cost-estimate-api, examples/data-transfer-cost-estimate-api.                                   |
| (cost building blocks) | `POST /estimate/storage`                            | S3 storage cost Lambda: BCM Pricing Calculator only (returns estimated cost for storage GB).                                                                                                                                                        |
| (cost building blocks) | `POST /estimate/transfer`                           | Data transfer cost Lambda: BCM Pricing Calculator only (returns estimated cost for egress/transfer).                                                                                                                                                |
| upload                 | `POST /storage/upload`                              | Upload Lambda: quote lookup (DynamoDB), payment verification (EIP-712/USDC), request object from proxy, S3 upload (bucket per wallet, client-held encryption), DynamoDB transaction log. Design pattern: examples/object_storage_management_aws.py. |
| ls                     | `GET /storage/ls` or `POST /storage/ls`             | Object storage Lambda: list object metadata (name + size) in wallet bucket.                                                                                                                                                                         |
| download               | `GET /storage/download` or `POST /storage/download` | Object storage Lambda: get object from S3, decrypt, stream or return to proxy.                                                                                                                                                                      |
| delete                 | `POST /storage/delete` or `DELETE /storage/delete`  | Object storage Lambda: delete object from wallet bucket (and bucket if empty).                                                                                                                                                                      |

Proxy/client call the single API base URL; the path determines which Lambda handles the request.

## mnenospark-backend housekeeping rules

A Lambda function will need to do the following:

- Object storage is a paid-for service; build a scheduled job to check if payment has been received per `<object-id>` stored.
- **Billing interval:** The client is charged every **30 days** (client cron sends x402 payment). The backend expects payment to be received within **32 days** of the last due date (i.e. a **2-day grace period**). If payment is not confirmed by the 32-day deadline, the `<object-id>` will be deleted.
- **Recipient wallet:** USDC payments must be received at the backend recipient wallet: `0x47D241ae97fE37186AC59894290CA1c54c060A6c` (Base mainnet). Configure this via deployment (e.g. env `MNEMOSPARK_RECIPIENT_WALLET`).

## mnenospark file locations

- Logs: `~/.openclaw/mnemospark/object.log`
- Wallet Directory: if `~/.openclaw/blockrun` exists use it as the wallet directory, if not `~/.openclaw/mnemospark/key`
- Wallet Key: if `~/.openclaw/blockrun/wallet.key` exists use it as the wallet key, if not `~/.openclaw/mnemospark/key/wallet.key`
- Key store (KEK per wallet): `~/.openclaw/mnemospark/keys` — files like <wallet_short_hash>.key

## full workflow

The complete workflow of mnenospark described from the point of view of the mnemospark client initiating a command.

### mnemospark-client commands

These are the "slash commands" that are supported by the mnemospark plugin:

- /cloud
- /cloud help
- /cloud backup
- /cloud price-storage
- /cloud upload
- /cloud ls
- /cloud download
- /cloud delete
- /wallet

### cloud command

/cloud and /cloud help

What this command does:

1. Displays the help message on how to use the other commands available
2. Shows each command and the required or optional arguments

### help command

/cloud help

What this command does:

1. Displays the help message on how to use the other commands available
2. Shows each command and the required or optional arguments

### backup command

/cloud backup `<file>` or `<directory>`

Argument descriptions:  
`<file>` file on local file system  
`<directory>` direcotry on local file system

What this command does:  
Only on MacOS or Linux

1. Takes the arguments `<file>` or `<directory>` from the local file system
2. Checks for /tmp directory
3. Checks available disk space in /tmp directory
4. tar and gzip the file and or directory and save to /tmp (do not exceed available disk space), the file name is the `<object-id>`
5. Hash256 the file, this is the `<object-id-hash>`
6. Determine the file size in gb, this is the `<object-size-gb>`
7. Create a log file with the storage object identifier `<object-id>` and `<object-id-hash>` and `<object-size-gb>`
8. Prints message to user: Your object-id is `<object-id>` your object-id-hash is `<object-id-hash>` and your object-size is `<object-size-gb>`
9. If error "Cannot build storage object"

### price-storage command

/cloud price-storage --wallet-address `<addr>` --object-id `<object-id>` --object-id-hash `<object-id-hash>` --gb `<object-size-gb>` --provider `<provider>` --region `<location>`

Argument descriptions:

- --wallet-address `<addr>` the agent's crypto wallet on the Base blockchain
- --object-id `<object-id>` created from the backup command and in the log file
- --object-id-hash `<object-id-hash>` created from the backup command and in the log file
- --gb `<object-size-gb>` created from the backup command and in the log file
- --provider `<provider>` from an array of providers, only supported provided for MVP is aws
- --region `<location>` from an array of regions, only supported regions for MVP are aws regions with S3 buckets

What this command does:

1. Takes the arguments --wallet-address `<addr>` --object-id `<object-id>` --object-id-hash `<object-id-hash>` --gb `<object-size-gb>` --provider `<provider>` --region `<location>`
2. Sends to **mnenospark-proxy**  
   _pass workflow to_

**mnenospark-proxy**

1.  Accepts command from **mnenospark-client**
2.  Sends command to **mnenospark-backend**
3.  Waits for response
4.  Fails gracefully if errors  
    _pass workflow to_

**mnenospark-backend**  
 **Backend path:** `POST /price-storage` → price-storage Lambda (orchestrator: storage cost + transfer cost + markup + DynamoDB quote).

1.  Accepts command from **mnenospark-proxy**
2.  Runs the Lamda function to get storage costs, as an example design pattern see: examples/s3-cost-estimate-api
3.  Runs the Lamda function to get egress data transfer costs, as an example design pattern see: examples/data-transfer-cost-estimate-api
4.  Adds storage costs, data transfer costs, and a service fee markup, to create `storage-price`
5.  Builds a quote with `quote-id` and inserts the quote as a row into the Dynamo DB, quote contains: `<YYYY-MM-DD HH:MM:SS>`,`<quote-id>`,`<storage-price>`,`<addr>`,`<object-id>`,`<object-id-hash>`,`<object-size-gb>`,`<provider>`,`<location>`
6.  The `quote-id` row is deleted after 1 hour from the Dynamo DB
7.  Response to return: `<YYYY-MM-DD HH:MM:SS>`,`<quote-id>`,`<storage-price>`,`<addr>`,`<object-id>`,`<object-id-hash>`,`<object-size-gb>`,`<provider>`,`<location>`
8.  Fails gracefully if execution errors, returns response to **mnenospark-proxy**
9.  Success returns response to **mnenospark-proxy**  
    _pass workflow to_

**mnenospark-proxy**

1.  Accepts response from **mnenospark-backend**
2.  Expects: `<YYYY-MM-DD HH:MM:SS>`,`<quote-id>`,`<storage-price>`,`<addr>`,`<object-id>`,`<object-id-hash>`,`<object-size-gb>`,`<provider>`,`<location>`
3.  Returns response to **mnenospark-client**  
    _return workflow to_

**mnenospark-client**

1. Accepts response from **mnenospark-proxy**
2. Writes to log file: `<YYYY-MM-DD HH:MM:SS>`,`<quote-id>`,`<storage-price>`,`<addr>`,`<object-id>`,`<object-id-hash>`,`<object-size-gb>`,`<provider>`,`<location>`
3. Print message to user: Your storage quote `<quote-id>` is valid for 1 hour, the storage price is `<storage-price>` for `<object-id>` with file size of `<object-size-gb>` in `<provider>` `<location>`
4. Print message to user: If you accept this quote run the command /cloud upload --quote-id `<quote-id>` --wallet-address `<addr>` --object-id `<object-id>`
5. If error, print message "Cannot price storage"

### upload command

/cloud upload --quote-id `<quote-id>` --wallet-address `<addr>` --object-id `<object-id>` --object-id-hash `<object-id-hash>`

Argument descriptions:

- --quote-id `<quote-id>` the quote-id returned from the price-storage command and in the log file
- --wallet-address `<addr>` the agent's crypto wallet on the Base blockchain
- --object-id `<object-id>` created from the backup command and in the log file
- --object-id-hash `<object-id-hash>` created from the backup command and in the log file

Example code: examples/object_storage_management_aws.py

What this command does:

1. Takes the arguments --quote-id `<quote-id>` --wallet-address `<addr>` --object-id `<object-id>` --object-id-hash `<object-id-hash>`
2. Sends to **mnenospark-proxy**  
   _pass workflow to_

**mnenospark-proxy**

1. Accepts command from **mnenospark-client**
2. Check wallet --wallet-address `<addr>` on the Base blockchain for USDC balance > `<storage-price>` for `<quote-id>`
3. If --wallet-address `<addr>` USDC balance is > `<storage-price>` for `<quote-id>` continue workflow and have client signs a payment authorization (EIP-712)
4. If --wallet-address `<addr>` USDC balance is < `<storage-price>` for `<quote-id>` end workflow
5. Continue workflow
6. Sends command to **mnenospark-backend**
7. Waits for response
8. Fails gracefully if errors  
   _pass workflow to_

**mnenospark-backend**
**Backend path:** `POST /storage/upload` → upload Lambda (quote lookup, payment verification, S3 upload, DynamoDB transaction log).

1. Accepts command from **mnenospark-proxy**
2. Expects: --quote-id `<quote-id>` --wallet-address `<addr>` --object-id `<object-id>` --object-id-hash `<object-id-hash>`
3. Expects: client payment authorization (EIP-712)
4. Locates `<quote-id>` in Dynamo DB, if found continue workflow, if not found end workflow error: no quote
5. Matches `<object-id-hash>` from **mnenospark-proxy** to `<object-id-hash>` in in Dynamo DB for `<quote-id>`, if found contine workflow, if not found end workflow error: no quote mismatch
6. Verifies signature + terms, then settles USDC payment on the Base blockchain, gets the blockchain transaction id `<trans-id>`, example see: .company/clawrouter_wallet_gen_payment_eip712.md
7. If payment is verified continue workflow, if not end workflow error: payment failed
8. Checks to see if the user has a S3 bucket tied to the users wallet address, if yes use the existing bucket, if not create the bucket, in the region and create the wallet address hash
9. Request `<object-id>` from **mnenospark-proxy**
10. Transfer the `<object-id>` to the S3 bucket
11. Log transaction in the Dynamo DB: `<YYYY-MM-DD HH:MM:SS>`,`<quote-id>`,`<addr>`,`<addr-hash>`,`<trans-id>`,`<storage-price>`,`<object-id>`,`<object-id-key>`,`<provider>`,`<bucket-name>`,`<location>`
12. Response to return: `<quote-id>`,`<addr>`,`<addr-hash>`,`<trans-id>`,`<storage-price>`,`<object-id>`,`<object-key>`,`<provider>`,`<bucket-name>`,`<location>`
13. Fails gracefully if execution errors, returns response to **mnenospark-proxy**
14. Success returns response to **mnenospark-proxy**  
    _pass workflow to_

**mnenospark-proxy**

1. Accepts response from **mnenospark-backend**
2. Expects: `<quote-id>`,`<addr>`,`<addr-hash>`,`<trans-id>`,`<storage-price>`,`<object-id>`,`<object-key>`,`<provider>`,`<bucket-name>`,`<location>`
3. Returns response to **mnenospark-client**  
   _returns workflow to_

**mnenospark-client**

1. Accepts response from **mnenospark-proxy**
2. Writes to log file: `<YYYY-MM-DD HH:MM:SS>`,`<quote-id>`,`<addr>`,`<addr-hash>`,`<trans-id>`,`<storage-price>`,`<object-id>`,`<object-key>`,`<provider>`,`<bucket-name>`,`<location>`
3. Print message to user: Your file `<object-id>` with key `<object-key>` has been stored using `<provider>` in `<bucket-name>` `<location>`
4. Builds a cron job to send x402 payment of USDC `<storage-price>` **every 30 days** for `<object-id>` matching the `<quote-id>` and `<storage-price>`. The cron job should notify the user that payment will be sent; if payment is not sent, the backend will delete the `<object-id>` after the **32-day deadline** (30-day billing interval + 2-day grace period).

### ls command

/cloud ls --wallet-address `<addr>` --object-key `<s3-key>`

Argument descriptions:

- --wallet-address `<addr>` the agent's crypto wallet on the Base blockchain
- --object-key `<s3-key>` the key returned from the upload operation

Example code: examples/object_storage_management_aws.py

What this command does:

1. Takes the arguments --wallet-address `<addr>` --object-key `<s3-key>`
2. Sends to **mnenospark-proxy**  
   _pass workflow to_

**mnenospark-proxy**

1. Accepts command from **mnenospark-client**
2. Takes the arguments
3. Sends command to **mnenospark-backend**
4. Waits for response
5. Fails gracefully if errors  
   _pass workflow to_

**mnenospark-backend**  
**Backend path:** `GET /storage/ls` or `POST /storage/ls` → object storage Lambda (list object metadata: name + size).

1.  Accepts command from **mnenospark-proxy**
2.  Expects: --wallet-address `<addr>` --object-key `<s3-key>`
3.  Queries the associated S3 bucket, list object in S3 (name + size). Returns result dict with success, key, size_bytes, bucket, error.
4.  Sends query output to **mnenospark-proxy**  
    _pass workflow to_

**mnenospark-proxy**

1.  Accepts response from **mnenospark-backend**
2.  Returns response to **mnenospark-client**  
    _returns workflow to_

**mnenospark-client**

1. Accepts response from **mnenospark-proxy**
2. Print message to user: `<object-id>` with `<s3-key>` is `<size-bytes>` in `<bucket-name>`

### download command

/cloud download --wallet-address `<addr>` --object-key `<s3-key>`

Argument descriptions:

- --wallet-address `<addr>` the agent's crypto wallet on the Base blockchain
- --object-key `<s3-key>` the key returned from the upload operation

Example code: examples/object_storage_management_aws.py

What this command does:

1. Takes the arguments --wallet-address `<addr>` --object-key `<s3-key>`
2. Sends to **mnenospark-proxy**  
   _pass workflow to_

**mnenospark-proxy**

1. Accepts command from **mnenospark-client**
2. Takes the arguments
3. Sends command to **mnenospark-backend**
4. Waits for response
5. Fails gracefully if errors  
   _pass workflow to_

**mnenospark-backend**  
**Backend path:** `GET /storage/download` or `POST /storage/download` → object storage Lambda (get object, decrypt, stream or return to proxy).

1.  Accepts command from **mnenospark-proxy**
2.  Expects: --wallet-address `<addr>` --object-key `<s3-key>`
3.  Queries the associated S3 bucket locates the file and streams it to the proxy
4.  Sends file stream output to **mnenospark-proxy**  
    _pass workflow to_

**mnenospark-proxy**

1.  Accepts response from **mnenospark-backend**
2.  Writes file to disk
3.  Returns response to **mnenospark-client**  
    _returns workflow to_

**mnenospark-client**

1. Accepts response from **mnenospark-proxy**
2. Print message to user: File `<s3-key>` downloaded

### delete command

/cloud delete --wallet-address `<addr>` --object-key `<s3-key>`

Argument descriptions:

- --wallet-address `<addr>` the agent's crypto wallet on the Base blockchain
- --object-key `<s3-key>` the key returned from the upload operation

Example code: examples/object_storage_management_aws.py

What this command does:

1. Takes the arguments --wallet-address `<addr>` --object-key `<s3-key>`
2. Sends to **mnenospark-proxy**  
   _pass workflow to_

**mnenospark-proxy**

1. Accepts command from **mnenospark-client**
2. Takes the arguments
3. Sends command to **mnenospark-backend**
4. Waits for response
5. Fails gracefully if errors  
   _pass workflow to_

**mnenospark-backend**  
**Backend path:** `POST /storage/delete` or `DELETE /storage/delete` → object storage Lambda (delete object; delete bucket if empty).

1.  Accepts command from **mnenospark-proxy**
2.  Expects: --wallet-address `<addr>` --object-key `<s3-key>`
3.  Queries the associated S3 bucket locates the file and deletes it
4.  Sends response to **mnenospark-proxy**  
    _pass workflow to_

**mnenospark-proxy**

1.  Accepts response from **mnenospark-backend**
2.  Returns response to **mnenospark-client**  
    _returns workflow to_

**mnenospark-client**

1. Accepts response from **mnenospark-proxy**
2. Print message to user: File `<s3-key>` deleted

### wallet command

/wallet

What this command does: follows the existing implementation in the repo, and prints the balance of the wallet in either `~/.openclaw/blockrun` if it exists, or the mnemospark wallet directory, if not `~/.openclaw/mnemospark/key`
