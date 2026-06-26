"""Auto-generated custom tool: save_zip_file"""

from clearwing.agent.tooling import tool


@tool
async def save_zip_file(path: str, data_b64: str) -> dict:
    """Save binary zip data to a local file."""
    import base64
    import os

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(base64.b64decode(data_b64))
    return {"success": True, "path": path, "size": len(base64.b64decode(data_b64))}
