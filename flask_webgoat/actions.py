import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
    # Set up logging for security monitoring
    logger = logging.getLogger('security_logger')
    
    user_info = session.get("user_info", None)
    if user_info is None:
        logger.warning("Attempt to log entry without valid user_info in session")
        return jsonify({"error": "no user_info found in session"})
        
    access_level = user_info[2]
    if access_level > 2:
        logger.warning(f"User with insufficient access level ({access_level}) attempted to log entry")
        return jsonify({"error": "access level < 2 is required for this action"})
        
    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"})
        
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    # Define whitelist pattern for filenames - only allowing alphanumeric, underscore, hyphen
    # and period (for extension)
    # Replaced previous blacklist approach with positive security model (whitelist)
    filename_pattern = re.compile(r'^[a-zA-Z0-9_-.]+$')
    if not filename_pattern.match(filename_param):
        logger.warning(f"Possible directory traversal attempt with filename: {filename_param}")
        return jsonify({"error": "Invalid filename format. Only alphanumeric characters, underscores, hyphens, and periods are allowed."})

    # Proper extension handling - preserve original name but enforce .txt extension
    base_name = os.path.splitext(filename_param)[0]
    safe_filename = f"{base_name}.txt"
    
    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    
    # Create user directory if it doesn't exist
    try:
        user_dir_path = Path(user_dir).resolve()
        if not user_dir_path.exists():
            user_dir_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create user directory: {str(e)}")
        return jsonify({"error": "Failed to access user directory"})
    
    # Construct the target path and normalize it
    target_path = (user_dir_path / safe_filename).resolve()
    
    # Additional security check to ensure the target path remains within user_dir_path
    # This is a defense-in-depth measure in case of path manipulation bypass
    if not str(target_path).startswith(str(user_dir_path)):
        logger.warning(f"Path traversal attempt detected: {safe_filename} -> {target_path}")
        return jsonify({"error": "Invalid file path"})
    
    # Improved error handling for file operations
    try:
        with target_path.open("w", encoding="utf-8") as open_file:
            open_file.write(text_param)
    except IOError as e:
        logger.error(f"Failed to write to file {target_path}: {str(e)}")
        return jsonify({"error": f"Failed to write to file: {str(e)}"})
    
    logger.info(f"Successfully wrote log entry to {safe_filename} for user {user_id}")
    return jsonify({"success": True})



@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    # vulnerability: Remote Code Execution
    res = subprocess.run(
        ["ps aux | grep " + name + " | awk '{print $11}'"],
        shell=True,
        capture_output=True,
    )
    if res.stdout is None:
        return jsonify({"error": "no stdout returned"})
    out = res.stdout.decode("utf-8")
    names = out.split("\n")
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
