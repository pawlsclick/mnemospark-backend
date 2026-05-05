"""
Entry point for the discovery Lambda function.

Kept in the flat services/ layout so SAM can use CodeUri: services with a simple handler.
"""

from __future__ import annotations

from discovery.app import lambda_handler  # noqa: F401

