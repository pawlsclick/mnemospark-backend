import base64
import io
import importlib.util
import json
import sys
import time
from pathlib import Path
import unittest
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_typed_data


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "wallet-authorizer" / "app.py"
    module_spec = importlib.util.spec_from_file_location("wallet_authorizer_app", module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load wallet authorizer module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


def _resource_arn(method: str, path: str) -> str:
    normalized_path = path.lstrip("/")
    return f"arn:aws:execute-api:test-region:123456789012:apiid/prod/{method.upper()}/{normalized_path}"


def _build_wallet_header(
    method: str,
    path: str,
    wallet_address: str,
    private_key: str,
    timestamp: int | None = None,
    chain_id: int = 8453,
) -> str:
    resolved_timestamp = int(time.time()) if timestamp is None else int(timestamp)
    payload = {
        "method": method.upper(),
        "path": path,
        "walletAddress": wallet_address,
        "nonce": "0x" + ("11" * 32),
        "timestamp": str(resolved_timestamp),
    }
    signable = encode_typed_data(
        domain_data={
            "name": app.DOMAIN_NAME,
            "version": app.DOMAIN_VERSION,
            "chainId": chain_id,
            "verifyingContract": app.VERIFYING_CONTRACT,
        },
        message_types=app.MNEMOSPARK_REQUEST_TYPES,
        message_data=payload,
    )
    signature = Account.sign_message(signable, private_key).signature.hex()
    encoded_payload = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("utf-8")
    envelope = {
        "payloadB64": encoded_payload,
        "signature": signature,
        "address": wallet_address,
    }
    return base64.b64encode(
        json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    ).decode("utf-8")


def _make_request_event(
    method: str,
    path: str,
    wallet_header: str | None = None,
    body: dict[str, object] | None = None,
    query: dict[str, str] | None = None,
    request_id: str | None = "api-gw-request-1",
) -> dict[str, object]:
    event: dict[str, object] = {
        "type": "REQUEST",
        "methodArn": _resource_arn(method, path),
        "httpMethod": method.upper(),
        "resource": path,
        "path": path,
        "headers": {},
        "queryStringParameters": query,
        "requestContext": {},
    }
    if request_id:
        event["requestContext"] = {"requestId": request_id}
    if wallet_header is not None:
        event["headers"] = {"X-Wallet-Signature": wallet_header}
    if body is not None:
        event["body"] = json.dumps(body)
    return event


def _policy_effect(response: dict[str, object]) -> str:
    policy_document = response["policyDocument"]
    assert isinstance(policy_document, dict)
    statements = policy_document["Statement"]
    assert isinstance(statements, list)
    statement = statements[0]
    assert isinstance(statement, dict)
    return str(statement["Effect"])


class WalletAuthorizerTests(unittest.TestCase):
    def setUp(self):
        self.signer = Account.create("mnemospark-authorizer-tests")
        self.other_signer = Account.create("mnemospark-authorizer-tests-other")
        self.wallet_address = self.signer.address

    def test_storage_upload_valid_signature_allows_with_wallet_context(self):
        wallet_header = _build_wallet_header(
            method="POST",
            path="/storage/upload",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
        )
        event = _make_request_event(
            method="POST",
            path="/storage/upload",
            wallet_header=wallet_header,
            body={"wallet_address": self.wallet_address},
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Allow")
        self.assertEqual(response.get("context"), {"walletAddress": self.wallet_address.lower()})

    def test_price_storage_missing_header_is_denied(self):
        event = _make_request_event(
            method="POST",
            path="/price-storage",
            body={"wallet_address": self.wallet_address},
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Deny")

    def test_storage_route_missing_header_is_denied(self):
        event = _make_request_event(
            method="POST",
            path="/storage/upload",
            body={"wallet_address": self.wallet_address},
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Deny")

    def test_storage_upload_confirm_missing_header_is_denied(self):
        event = _make_request_event(
            method="POST",
            path="/storage/upload/confirm",
            body={"wallet_address": self.wallet_address},
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Deny")

    def test_payment_settle_valid_signature_allows(self):
        wallet_header = _build_wallet_header(
            method="POST",
            path="/payment/settle",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
        )
        event = _make_request_event(
            method="POST",
            path="/payment/settle",
            wallet_header=wallet_header,
            body={"wallet_address": self.wallet_address},
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Allow")
        self.assertEqual(response.get("context"), {"walletAddress": self.wallet_address.lower()})

    def test_invalid_signature_is_denied(self):
        wallet_header = _build_wallet_header(
            method="POST",
            path="/storage/upload",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
        )
        header_payload = json.loads(base64.b64decode(wallet_header).decode("utf-8"))
        header_payload["signature"] = "0x" + ("00" * 65)
        invalid_header = base64.b64encode(
            json.dumps(header_payload, separators=(",", ":")).encode("utf-8")
        ).decode("utf-8")

        event = _make_request_event(
            method="POST",
            path="/storage/upload",
            wallet_header=invalid_header,
            body={"wallet_address": self.wallet_address},
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Deny")

    def test_old_timestamp_is_rejected(self):
        stale_timestamp = int(time.time()) - app.MAX_SIGNATURE_AGE_SECONDS - 1
        wallet_header = _build_wallet_header(
            method="POST",
            path="/storage/upload",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
            timestamp=stale_timestamp,
        )
        event = _make_request_event(
            method="POST",
            path="/storage/upload",
            wallet_header=wallet_header,
            body={"wallet_address": self.wallet_address},
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Deny")

    def test_storage_wallet_mismatch_is_denied(self):
        wallet_header = _build_wallet_header(
            method="POST",
            path="/storage/upload",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
        )
        event = _make_request_event(
            method="POST",
            path="/storage/upload",
            wallet_header=wallet_header,
            body={"wallet_address": self.other_signer.address},
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Deny")

    def test_storage_ls_get_with_query_wallet_is_allowed(self):
        wallet_header = _build_wallet_header(
            method="GET",
            path="/storage/ls",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
        )
        event = _make_request_event(
            method="GET",
            path="/storage/ls",
            wallet_header=wallet_header,
            query={"wallet_address": self.wallet_address, "object_key": "backup.tar.gz"},
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Allow")
        self.assertEqual(response.get("context"), {"walletAddress": self.wallet_address.lower()})

    def test_storage_ls_web_session_post_is_allowed(self):
        wallet_header = _build_wallet_header(
            method="POST",
            path="/storage/ls-web/session",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
        )
        event = _make_request_event(
            method="POST",
            path="/storage/ls-web/session",
            wallet_header=wallet_header,
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Allow")
        self.assertEqual(response.get("context"), {"walletAddress": self.wallet_address.lower()})

    def test_token_authorizer_event_is_supported(self):
        wallet_header = _build_wallet_header(
            method="POST",
            path="/price-storage",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
        )
        event = {
            "type": "TOKEN",
            "authorizationToken": wallet_header,
            "methodArn": _resource_arn("POST", "/price-storage"),
        }

        response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Allow")
        self.assertEqual(response.get("context"), {"walletAddress": self.wallet_address.lower()})

    def test_debug_log_reports_dict_body_length(self):
        wallet_header = _build_wallet_header(
            method="POST",
            path="/storage/upload",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
        )
        event = _make_request_event(
            method="POST",
            path="/storage/upload",
            wallet_header=wallet_header,
        )
        event["body"] = {"wallet_address": self.wallet_address}

        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
            response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Allow")
        out = stdout.getvalue()
        self.assertIn("authorizer_debug_after_verify", out)
        self.assertIn('"validation_outcome":"wallet_proof_valid"', out)
        self.assertIn('"wallet_header_present":true', out)

    @patch.dict("os.environ", {"WALLET_AUTH_EVENTS_TABLE_NAME": "wallet-auth-events"}, clear=False)
    def test_deny_decision_writes_best_effort_auth_event(self):
        event = _make_request_event(
            method="POST",
            path="/storage/upload",
            body={"wallet_address": self.wallet_address},
        )
        mock_ddb_client = unittest.mock.Mock()

        with patch.object(app, "_dynamodb_client", return_value=mock_ddb_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Deny")
        mock_ddb_client.put_item.assert_called_once()
        put_item_kwargs = mock_ddb_client.put_item.call_args.kwargs
        self.assertEqual(put_item_kwargs["TableName"], "wallet-auth-events")
        self.assertEqual(put_item_kwargs["Item"]["result"]["S"], "deny")
        self.assertEqual(put_item_kwargs["Item"]["reason"]["S"], "missing_wallet_header")
        self.assertEqual(put_item_kwargs["Item"]["request_id"]["S"], "api-gw-request-1")

    @patch.dict("os.environ", {"WALLET_AUTH_EVENTS_TABLE_NAME": "wallet-auth-events"}, clear=False)
    def test_allow_decision_writes_auth_event_with_recovered_wallet(self):
        wallet_header = _build_wallet_header(
            method="POST",
            path="/storage/upload",
            wallet_address=self.wallet_address,
            private_key=self.signer.key,
        )
        event = _make_request_event(
            method="POST",
            path="/storage/upload",
            wallet_header=wallet_header,
        )
        mock_ddb_client = unittest.mock.Mock()

        with patch.object(app, "_dynamodb_client", return_value=mock_ddb_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(_policy_effect(response), "Allow")
        mock_ddb_client.put_item.assert_called_once()
        put_item_kwargs = mock_ddb_client.put_item.call_args.kwargs
        self.assertEqual(put_item_kwargs["TableName"], "wallet-auth-events")
        self.assertEqual(put_item_kwargs["Item"]["result"]["S"], "allow")
        self.assertEqual(put_item_kwargs["Item"]["wallet_address"]["S"], self.wallet_address.lower())
        self.assertEqual(put_item_kwargs["Item"]["request_id"]["S"], "api-gw-request-1")
