"""Hermes VMGA integration plugin package."""

from pathlib import Path

from . import schemas, tools


def _hermes_schema(tool_schema):
    """Convert VMGA's MCP-style inputSchema to Hermes' OpenAI-style parameters."""
    return {
        "name": tool_schema["name"],
        "description": tool_schema.get("description", ""),
        "parameters": tool_schema["inputSchema"],
    }


def register(ctx):
    """Register VMGA-backed Hermes tools and plugin-provided skill."""
    ctx.register_tool(
        name="mail_search",
        toolset="vmga_mail",
        schema=_hermes_schema(schemas.MAIL_SEARCH),
        handler=tools.mail_search,
    )
    ctx.register_tool(
        name="mail_get",
        toolset="vmga_mail",
        schema=_hermes_schema(schemas.MAIL_GET),
        handler=tools.mail_get,
    )
    ctx.register_tool(
        name="mail_get_attachment",
        toolset="vmga_mail",
        schema=_hermes_schema(schemas.MAIL_GET_ATTACHMENT),
        handler=tools.mail_get_attachment,
    )
    ctx.register_tool(
        name="mail_archive",
        toolset="vmga_mail",
        schema=_hermes_schema(schemas.MAIL_ARCHIVE),
        handler=tools.mail_archive,
    )
    ctx.register_tool(
        name="mail_apply_label",
        toolset="vmga_mail",
        schema=_hermes_schema(schemas.MAIL_APPLY_LABEL),
        handler=tools.mail_apply_label,
    )
    ctx.register_tool(
        name="mail_create_draft",
        toolset="vmga_mail",
        schema=_hermes_schema(schemas.MAIL_CREATE_DRAFT),
        handler=tools.mail_create_draft,
    )
    ctx.register_tool(
        name="mail_send",
        toolset="vmga_mail",
        schema=_hermes_schema(schemas.MAIL_SEND),
        handler=tools.mail_send,
    )

    skills_dir = Path(__file__).parent / "skills"
    for child in sorted(skills_dir.iterdir()):
        if not child.is_dir():
            continue
        skill_path = child / "SKILL.md"
        if skill_path.is_file():
            ctx.register_skill(child.name, skill_path)


__all__ = ["register", "schemas", "tools"]
