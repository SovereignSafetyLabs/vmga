"""Hermes tool schemas for VMGA mailbox actions."""

MAIL_SEARCH = {
    "name": "mail_search",
    "description": "Search mailbox metadata using VMGA-governed read path",
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query text",
            },
            "max_results": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 10,
            },
            "thread_id": {
                "type": "string",
                "description": "Optional thread correlation identifier",
            },
            "actor_id": {
                "type": "string",
                "description": "Calling actor id (optional)",
            },
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}

MAIL_GET = {
    "name": "mail_get",
    "description": "Read a mailbox message through VMGA read policy",
    "inputSchema": {
        "type": "object",
        "properties": {
            "message_id": {
                "type": "string",
                "description": "Message identifier to read",
            },
            "session_id": {
                "type": "string",
                "description": "Hermes session identifier",
            },
            "actor_id": {
                "type": "string",
                "description": "Calling actor id",
            },
        },
        "required": ["message_id"],
        "additionalProperties": False,
    },
}

MAIL_GET_ATTACHMENT = {
    "name": "mail_get_attachment",
    "description": "Fetch attachment metadata/route via VMGA",
    "inputSchema": {
        "type": "object",
        "properties": {
            "message_id": {
                "type": "string",
                "description": "Message identifier",
            },
            "attachment_id": {
                "type": "string",
                "description": "Attachment identifier",
            },
            "actor_id": {
                "type": "string",
                "description": "Calling actor id",
            },
            "session_id": {
                "type": "string",
                "description": "Hermes session identifier",
            },
        },
        "required": ["message_id", "attachment_id"],
        "additionalProperties": False,
    },
}

MAIL_CREATE_DRAFT = {
    "name": "mail_create_draft",
    "description": "Create a draft proposal via VMGA governance",
    "inputSchema": {
        "type": "object",
        "properties": {
            "recipients": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Recipients for the draft",
            },
            "subject": {
                "type": "string",
                "description": "Draft subject",
            },
            "content": {
                "type": "string",
                "description": "Draft content",
            },
            "thread_id": {
                "type": "string",
                "description": "Optional source thread identifier",
            },
            "message_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Messages referenced by the draft",
            },
            "justification": {
                "type": "string",
                "description": "Optional review justification",
            },
            "actor_id": {
                "type": "string",
                "description": "Calling actor id",
            },
            "session_id": {
                "type": "string",
                "description": "Hermes session identifier",
            },
        },
        "required": ["recipients", "content"],
        "additionalProperties": False,
    },
}

MAIL_SEND = {
    "name": "mail_send",
    "description": "Submit a send proposal via VMGA governance",
    "inputSchema": {
        "type": "object",
        "properties": {
            "recipients": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Recipients for the message",
            },
            "subject": {
                "type": "string",
                "description": "Message subject",
            },
            "content": {
                "type": "string",
                "description": "Message content",
            },
            "thread_id": {
                "type": "string",
                "description": "Optional source thread identifier",
            },
            "message_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Referenced messages",
            },
            "broker_url": {
                "type": "string",
                "description": "Optional override for the VMGA broker",
            },
            "actor_id": {
                "type": "string",
                "description": "Calling actor id",
            },
            "session_id": {
                "type": "string",
                "description": "Hermes session identifier",
            },
        },
        "required": ["recipients", "content"],
        "additionalProperties": False,
    },
}
